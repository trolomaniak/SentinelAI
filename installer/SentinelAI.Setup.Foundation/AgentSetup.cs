using System.Globalization;
using System.Net;
using System.Net.Http.Headers;
using System.Net.Security;
using System.Security.Authentication;
using System.Security.Cryptography;
using System.Text.Json;
using SentinelAI.Enrollment;
using static SentinelAI.Localization.Localizer;

namespace SentinelAI.Setup.Foundation;

/// <summary>Exit codes of SentinelAI-Agent-Setup.exe (MVP-2), documented in docs/SETUP.md.</summary>
public enum AgentSetupExitCode
{
    Success = 0,
    Failed = 1,
    InvalidArguments = 2,
    InvalidCode = 3,
    CoreUnreachable = 4,
    PinMismatch = 5,
    CodeRefused = 6,
    AlreadyInstalled = 7,
    InstallFailed = 8,
    EnrollmentNotAcknowledged = 9,
    UninstallFailed = 10,
    NotInstalled = 11,
    RollbackFailed = 12
}

public enum SetupMode { Interactive, Uninstall, QuietInstall, QuietUninstall, QuietUpgrade }

/// <summary>
/// The Setup host's command line. The native wrapper accepts only its allow-listed options and forwards them in this
/// canonical form: "--image &lt;handle&gt;" (its own read-only, verified image), then nothing, "--uninstall",
/// "--uninstall --quiet", "--quiet --codefile &lt;full path&gt;", or (MVP-7, the full Setup's unattended upgrade)
/// "--upgrade --quiet".
/// </summary>
public sealed record SetupArguments(SetupMode Mode, long ImageHandle, string? CodeFile = null)
{
    public static bool TryParse(IReadOnlyList<string> arguments, out SetupArguments? parsed)
    {
        parsed = null;
        if (arguments.Count < 2 || arguments[0] != "--image" || arguments[1].Length is <= 0 or > 20 || arguments[1][0] == '0' ||
            !long.TryParse(arguments[1], NumberStyles.None, CultureInfo.InvariantCulture, out var image)) return false;
        parsed = arguments.Skip(2).ToArray() switch
        {
            [] => new(SetupMode.Interactive, image),
            ["--uninstall"] => new(SetupMode.Uninstall, image),
            ["--uninstall", "--quiet"] => new(SetupMode.QuietUninstall, image),
            ["--upgrade", "--quiet"] => new(SetupMode.QuietUpgrade, image),
            ["--quiet", "--codefile", var path] when path.Length <= 32767 && Path.IsPathFullyQualified(path) && !path.Contains('\0') =>
                new(SetupMode.QuietInstall, image, path),
            _ => null
        };
        return parsed is not null;
    }
}

internal enum AgentCodeCheck { Usable, Refused, PinMismatch, Unreachable }
internal enum AgentSetupInstallationKind { Fresh, Installed, Blocked }
internal sealed record AgentSetupInstallation(AgentSetupInstallationKind Kind, string? Version = null);
internal enum AgentInstallOutcome { Installed, NotAcknowledged, Failed, RollbackFailed }

/// <summary>Asks Core, over TLS pinned to the code's certificate, whether the code can still enroll. Never consumes it.</summary>
internal interface IAgentCodeProbe
{
    Task<AgentCodeCheck> CheckAsync(EnrollmentCode code, CancellationToken token);
}

internal interface IAgentSetupWorker
{
    Task<AgentSetupInstallation> InspectAsync(CancellationToken token);
    /// <summary>Installs and enrolls the Agent; on failure removes everything it created.</summary>
    Task<AgentInstallOutcome> InstallAsync(EnrollmentCode code, CancellationToken token);
    Task UninstallAsync(CancellationToken token);
}

internal static class AgentSetupWorkflow
{
    /// <summary>Nothing on this computer changes before the code is proven usable with the pinned Core.</summary>
    public static async Task<AgentSetupExitCode> InstallAsync(EnrollmentCode code, IAgentSetupWorker worker, IAgentCodeProbe probe,
        IProgress<string> progress, CancellationToken token)
    {
        progress.Report(T("Checking this computer..."));
        AgentSetupInstallation state;
        try { state = await worker.InspectAsync(token).ConfigureAwait(false); }
        catch (Exception) when (!token.IsCancellationRequested) { return AgentSetupExitCode.InstallFailed; }
        if (state.Kind != AgentSetupInstallationKind.Fresh) return AgentSetupExitCode.AlreadyInstalled;
        progress.Report(T("Checking SentinelAI Core at the address in the code..."));
        var check = await probe.CheckAsync(code, token).ConfigureAwait(false);
        if (check != AgentCodeCheck.Usable)
            return check switch
            {
                AgentCodeCheck.Refused => AgentSetupExitCode.CodeRefused,
                AgentCodeCheck.PinMismatch => AgentSetupExitCode.PinMismatch,
                _ => AgentSetupExitCode.CoreUnreachable
            };
        token.ThrowIfCancellationRequested();
        progress.Report(T("Installing SentinelAI Agent..."));
        return await worker.InstallAsync(code, token).ConfigureAwait(false) switch
        {
            AgentInstallOutcome.Installed => AgentSetupExitCode.Success,
            AgentInstallOutcome.NotAcknowledged => AgentSetupExitCode.EnrollmentNotAcknowledged,
            AgentInstallOutcome.RollbackFailed => AgentSetupExitCode.RollbackFailed,
            _ => AgentSetupExitCode.InstallFailed
        };
    }

    public static async Task<AgentSetupExitCode> UninstallAsync(IAgentSetupWorker worker, IProgress<string> progress, CancellationToken token)
    {
        progress.Report(T("Checking this computer..."));
        try
        {
            if ((await worker.InspectAsync(token).ConfigureAwait(false)).Kind != AgentSetupInstallationKind.Installed) return AgentSetupExitCode.NotInstalled;
            progress.Report(T("Removing SentinelAI Agent..."));
            await worker.UninstallAsync(token).ConfigureAwait(false);
            return AgentSetupExitCode.Success;
        }
        catch (Exception) when (!token.IsCancellationRequested) { return AgentSetupExitCode.UninstallFailed; }
    }

    /// <summary>Reads a code file. The code is a secret: the bytes are cleared and nothing about them is reported.</summary>
    public static bool TryReadCodeFile(string path, out EnrollmentCode? code)
    {
        code = null;
        byte[]? bytes = null;
        try
        {
            using var stream = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read, 1, FileOptions.None);
            if (stream.Length is <= 0 or > EnrollmentCode.MaximumFileBytes) return false;
            bytes = new byte[stream.Length];
            stream.ReadExactly(bytes);
            return EnrollmentCode.TryParseFile(bytes, out code);
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException or ArgumentException or NotSupportedException)
        {
            return false;
        }
        finally { if (bytes is not null) CryptographicOperations.ZeroMemory(bytes); }
    }

    public static string Describe(AgentSetupExitCode code, bool uninstall) => code switch
    {
        AgentSetupExitCode.Success when uninstall => T("SentinelAI Agent was removed from this computer, with its enrollment and data."),
        AgentSetupExitCode.Success => T("SentinelAI Agent is installed and enrolled with SentinelAI Core."),
        AgentSetupExitCode.InvalidArguments => T("Run Agent Setup without options, with /quiet /codefile <path>, /uninstall or /uninstall /quiet."),
        AgentSetupExitCode.InvalidCode => T("This is not a valid SentinelAI enrollment code. Check that the whole code was copied, or open the code file again. Nothing was changed."),
        AgentSetupExitCode.CoreUnreachable => T("SentinelAI Core could not be reached at the address in the code. Check that this computer is on the same network as the central SentinelAI computer and that it is running, then try again. Nothing was changed."),
        AgentSetupExitCode.PinMismatch => T("The computer at the address in the code is not the SentinelAI Core that created the code: its certificate does not match. Nothing was changed. Ask your administrator for a new code."),
        AgentSetupExitCode.CodeRefused => T("SentinelAI Core refused the code: it expired, was already used or was revoked. Nothing was changed. Ask your administrator for a new code."),
        AgentSetupExitCode.AlreadyInstalled => T("A SentinelAI Agent is already installed on this computer, by Agent Setup or as part of the central SentinelAI installation. Nothing was changed."),
        AgentSetupExitCode.EnrollmentNotAcknowledged => T("SentinelAI Core did not confirm the enrollment in time, so Setup removed the Agent again. Ask your administrator for a new code if this one now shows as used."),
        AgentSetupExitCode.UninstallFailed => T("SentinelAI Agent could not be removed completely. Run the uninstall again."),
        AgentSetupExitCode.NotInstalled => T("SentinelAI Agent is not installed on this computer by Agent Setup. Nothing was changed."),
        AgentSetupExitCode.RollbackFailed => T("Installation failed and Setup could not remove everything it had installed. Run SentinelAI-Agent-Setup.exe /uninstall to finish removing it, then try again."),
        _ when uninstall => T("SentinelAI Agent could not be removed completely. Run the uninstall again."),
        _ => T("Installation failed. Setup removed what it had installed.")
    };

    /// <summary>The worker's private stdin request. Only the install request carries the code's Core, pin and token.</summary>
    public static int WriteWorkerRequest(byte[] buffer, string action, string workDirectory, SetupMetadata metadata, EnrollmentCode? code)
    {
        if (buffer.Length < 8192 || action is not ("agent-inspect" or "agent-install" or "agent-uninstall") || workDirectory.Length is <= 0 or > 260 ||
            metadata.Product != SetupMetadata.AgentProduct || metadata.KeyId.Length is <= 0 or > 64 || metadata.Channel is not ("stable" or "pilot" or "beta") ||
            (action == "agent-install") != (code is not null) ||
            code is not null && (!SetupWorkflow.ValidCertificateSha256(code.CertificateSha256) || !SetupWorkflow.ValidEnrollmentToken(code.EnrollmentToken)))
            throw new InvalidDataException("Invalid setup request.");
        using var stream = new MemoryStream(buffer, 0, 8192, writable: true, publiclyVisible: true);
        stream.SetLength(0);
        using (var writer = new Utf8JsonWriter(stream))
        {
            writer.WriteStartObject(); writer.WriteString("action", action); writer.WriteString("workDirectory", workDirectory);
            writer.WriteString("keyId", metadata.KeyId); writer.WriteString("channel", metadata.Channel); writer.WriteString("version", metadata.Version);
            // Credential-free actions carry exact empty strings, never null.
            writer.WriteString("coreUrl", code is null ? "" : code.CoreUrl.GetLeftPart(UriPartial.Authority));
            writer.WriteString("coreCertificateSha256", code?.CertificateSha256 ?? "");
            writer.WriteString("enrollmentToken", code?.EnrollmentToken ?? "");
            writer.WriteEndObject(); writer.Flush();
        }
        if (stream.Length >= 8192) throw new InvalidDataException("Setup request is too large.");
        stream.WriteByte((byte)'\n');
        return checked((int)stream.Length);
    }

    public static AgentSetupInstallation ParseState(string marker)
    {
        var fields = marker.Length <= 128 ? marker.Split('|') : [];
        AgentSetupInstallation? state = fields switch
        {
            ["STATE", "Fresh", ""] => new(AgentSetupInstallationKind.Fresh),
            ["STATE", "Blocked", ""] => new(AgentSetupInstallationKind.Blocked),
            ["STATE", "Installed", var version] when SetupWorkflow.IsVersion(version) => new(AgentSetupInstallationKind.Installed, version),
            _ => null
        };
        return state ?? throw new InvalidDataException("Invalid setup state.");
    }
}

internal sealed class HttpAgentCodeProbe(TimeSpan? timeout = null) : IAgentCodeProbe
{
    public async Task<AgentCodeCheck> CheckAsync(EnrollmentCode code, CancellationToken token)
    {
        var expected = Convert.FromHexString(code.CertificateSha256);
        var presented = false;
        var matched = false;
        using var handler = new SocketsHttpHandler
        {
            // The same trust as the installed Agent: Core's own certificate, accepted when and only when its SHA-256 matches.
            UseProxy = false,
            AllowAutoRedirect = false,
            ConnectTimeout = TimeSpan.FromSeconds(10),
            SslOptions =
            {
                EnabledSslProtocols = SslProtocols.Tls12 | SslProtocols.Tls13,
                RemoteCertificateValidationCallback = (_, certificate, _, errors) =>
                {
                    presented = certificate is not null && (errors & SslPolicyErrors.RemoteCertificateNotAvailable) == 0;
                    matched = presented && CryptographicOperations.FixedTimeEquals(SHA256.HashData(certificate!.GetRawCertData()), expected);
                    return matched;
                }
            }
        };
        using var client = new HttpClient(handler) { Timeout = timeout ?? TimeSpan.FromSeconds(20) };
        var body = new byte[256];
        try
        {
            int length;
            using (var stream = new MemoryStream(body, 0, body.Length, writable: true, publiclyVisible: true))
            {
                stream.SetLength(0);
                using (var writer = new Utf8JsonWriter(stream))
                {
                    writer.WriteStartObject(); writer.WriteString("enrollmentToken", code.EnrollmentToken); writer.WriteEndObject();
                }
                length = checked((int)stream.Length);
            }
            using var content = new ByteArrayContent(body, 0, length);
            content.Headers.ContentType = new MediaTypeHeaderValue("application/json");
            using var request = new HttpRequestMessage(HttpMethod.Post, new Uri(code.CoreUrl, "/api/agent/enrollment-check")) { Content = content };
            using var response = await client.SendAsync(request, HttpCompletionOption.ResponseHeadersRead, token).ConfigureAwait(false);
            return response.StatusCode switch
            {
                HttpStatusCode.NoContent => AgentCodeCheck.Usable,
                HttpStatusCode.Gone => AgentCodeCheck.Refused,
                _ => AgentCodeCheck.Unreachable
            };
        }
        catch (HttpRequestException) when (presented && !matched) { return AgentCodeCheck.PinMismatch; }
        catch (HttpRequestException) { return AgentCodeCheck.Unreachable; }
        catch (OperationCanceledException) when (!token.IsCancellationRequested) { return AgentCodeCheck.Unreachable; }
        finally { CryptographicOperations.ZeroMemory(body); }
    }
}
