using System.Text;
using System.Text.Json;
using System.Security.Cryptography;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using SentinelAI.Core.Persistence;
using SentinelAI.Hosting;

namespace SentinelAI.Core;

/// <summary>One-shot local administrator setup; never starts the HTTP host or accepts a service context.</summary>
internal static class AdministratorSetupCommand
{
    private const int MaximumInputBytes = 16 * 1024;
    private const string StateCommand = "--administrator-state";
    private const string InitializeCommand = "--initialize-administrator";

    internal static bool IsSetupCommand(string[] arguments) =>
        arguments.Any(argument => argument.StartsWith("--administrator-", StringComparison.Ordinal) ||
                                  argument.StartsWith("--initialize-", StringComparison.Ordinal));

    internal static async Task<int> RunAsync(string[] arguments, Stream input, TextWriter output,
        bool isWindowsService, bool isInputRedirected, CancellationToken cancellationToken = default)
    {
        var status = "unavailable";
        try
        {
            if (arguments.Length != 3 || arguments[1] != "--config" ||
                arguments[0] is not (StateCommand or InitializeCommand))
            {
                status = "invalid-input";
            }
            else if (isWindowsService ||
                     Environment.GetEnvironmentVariable("SENTINELAI_BOOTSTRAP_USERNAME") is not null ||
                     Environment.GetEnvironmentVariable("SENTINELAI_BOOTSTRAP_PASSWORD") is not null)
            {
                status = "unavailable";
            }
            else
            {
                var pilot = PilotHostConfiguration.Read(arguments[1..], agent: false);
                var configuration = new ConfigurationBuilder().AddInMemoryCollection(pilot.Values!).Build();
                var hasher = new PasswordHasher<AdminRecord>(Options.Create(new PasswordHasherOptions
                {
                    IterationCount = AdminStore.PasswordHashIterations
                }));
                var admins = new AdminStore(configuration, hasher, NullLogger<AdminStore>.Instance);

                if (arguments[0] == StateCommand)
                {
                    status = await admins.ReadSetupStateAsync(cancellationToken) == AdministratorSetupState.Initialized ?
                        "initialized" : "required";
                }
                else if (!isInputRedirected)
                {
                    status = "invalid-input";
                }
                else
                {
                    var credentials = await ReadCredentialsAsync(input, cancellationToken);
                    if (credentials is null)
                    {
                        status = "invalid-input";
                    }
                    else
                    {
                        // Existing storage must already be private and readable; do not repair
                        // or adopt a shared/corrupt database while processing a password.
                        _ = await admins.ReadSetupStateAsync(cancellationToken);
                        status = await admins.InitializeWithCredentialsAsync(credentials.Value.Username,
                            credentials.Value.Password, cancellationToken) == AdministratorInitializationResult.Created ?
                            "created" : "already-initialized";
                    }
                }
            }
        }
        catch (Exception)
        {
            // Paths, SQLite details, and input contents must never reach output or logs.
            status = "unavailable";
        }

        await output.WriteLineAsync(JsonSerializer.Serialize(new { status }));
        return status is "created" or "already-initialized" or "required" or "initialized" ? 0 : 1;
    }

    private static async Task<(string Username, string Password)?> ReadCredentialsAsync(
        Stream input, CancellationToken cancellationToken)
    {
        var bytes = new byte[MaximumInputBytes + 1];
        try
        {
            var length = 0;
            while (length < bytes.Length)
            {
                var read = await input.ReadAsync(bytes.AsMemory(length), cancellationToken);
                if (read == 0) break;
                length += read;
            }
            if (length is 0 or > MaximumInputBytes) return null;

            // Reject malformed UTF-8 before parsing JSON, including overlong encodings.
            try { _ = new UTF8Encoding(false, true).GetCharCount(bytes, 0, length); }
            catch (DecoderFallbackException) { return null; }

            try
            {
                using var document = JsonDocument.Parse(bytes.AsMemory(0, length),
                    new JsonDocumentOptions { MaxDepth = 2 });
                if (document.RootElement.ValueKind != JsonValueKind.Object) return null;
                string? username = null;
                string? password = null;
                var count = 0;
                foreach (var property in document.RootElement.EnumerateObject())
                {
                    count++;
                    if (property.Value.ValueKind != JsonValueKind.String) return null;
                    if (property.NameEquals("username") && username is null)
                        username = property.Value.GetString();
                    else if (property.NameEquals("password") && password is null)
                        password = property.Value.GetString();
                    else
                        return null;
                }

                username = username?.Trim();
                if (count != 2 || username is null || username.Length is < 1 or > 128 ||
                    username.Any(char.IsControl) || password is null || password.Length is < 12 or > 1024)
                    return null;
                return (username, password);
            }
            catch (JsonException)
            {
                return null;
            }
        }
        finally
        {
            CryptographicOperations.ZeroMemory(bytes);
        }
    }
}
