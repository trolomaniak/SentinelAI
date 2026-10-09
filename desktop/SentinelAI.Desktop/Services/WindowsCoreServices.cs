using System.Diagnostics;
using System.IO;
using System.Net;
using System.Net.Http;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Text.Json;
using Microsoft.Win32.SafeHandles;
using SentinelAI.Desktop.Foundation;

namespace SentinelAI.Desktop.Services;

/// <summary>Fixed local installation, private setup pipes and authenticated socket ownership.</summary>
public sealed class WindowsCoreServices : ICoreEndpointTrust, IDisposable
{
    public IAuthenticationClient CreateAuthenticationClient() => new HttpAuthenticationClient(this, CreatePeerTrustedHandler());

    // Setup links this same authoritative implementation. Its one-use enrollment
    // requests must verify the established Core peer before writing credentials.
    internal static SocketsHttpHandler CreatePeerTrustedHandler() => new()
    {
        AllowAutoRedirect = false, UseProxy = false, UseCookies = false, Credentials = null,
        ConnectCallback = ConnectToCoreAsync, ConnectTimeout = TimeSpan.FromSeconds(3),
        PooledConnectionLifetime = TimeSpan.FromMinutes(2)
    };
    public IAdministratorSetupClient CreateAdministratorSetupClient() => new LocalAdministratorSetupClient();
    public Task<bool> IsTrustedAsync(Uri origin, CancellationToken token)
    {
        token.ThrowIfCancellationRequested();
        try
        {
            if (origin != WindowsInstallationTrust.Origin) return Task.FromResult(false);
            var service = WindowsNativeCore.ReadService();
            if (service is not null) return Task.FromResult(TrustedService(service));
            using var installation = WindowsInstallationTrust.ValidateOperatorInstallation();
            return Task.FromResult(true);
        }
        catch { token.ThrowIfCancellationRequested(); return Task.FromResult(false); }
    }
    private static bool TrustedService(WindowsNativeCore.ServiceRecord service)
    {
        WindowsInstallationTrust.RejectReadableReparsePoints(WindowsInstallationTrust.ExecutablePath);
        WindowsInstallationTrust.RejectReadableReparsePoints(WindowsInstallationTrust.ConfigurationPath);
        return string.Equals(service.Account, "NT SERVICE\\SentinelAICore", StringComparison.OrdinalIgnoreCase) && WindowsNativeCore.MatchesImageCommand(service.Image);
    }
    private static async ValueTask<Stream> ConnectToCoreAsync(SocketsHttpConnectionContext context, CancellationToken token)
    {
        if (context.DnsEndPoint.Host != "127.0.0.1" || context.DnsEndPoint.Port != 5000) throw new IOException("Local Core connection unavailable.");
        var service = WindowsNativeCore.ReadService();
        FileStream? installation = null;
        SafeProcessHandle? process = null;
        var socket = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp);
        try
        {
            int processId;
            if (service is not null)
            {
                if (!TrustedService(service) || service.State != 4 || service.ProcessId <= 0) throw new IOException("Local Core service unavailable.");
                processId = service.ProcessId;
            }
            else
            {
                installation = WindowsInstallationTrust.ValidateOperatorInstallation();
                var listeners = WindowsNativeCore.TcpConnections().Where(row => row.State == 2 && row.Address.Equals(IPAddress.Loopback) && row.Port == 5000).ToArray();
                if (listeners.Length != 1) throw new IOException("Local Core console unavailable.");
                processId = listeners[0].ProcessId;
            }
            try { process = WindowsNativeCore.HoldCoreProcess(processId); }
            catch (System.ComponentModel.Win32Exception error) when (service is not null && error.NativeErrorCode == 5)
            {
                // Ordinary users may query SCM while the service process DACL
                // denies even limited process inspection. SCM owns its process
                // handle and supplies the authoritative live PID; verify that
                // same registration/PID again after connecting below.
            }
            if (service is null && (process is null || !WindowsNativeCore.MatchesConsoleCommand(process))) throw new IOException("Local Core console unavailable.");
            await socket.ConnectAsync(new IPEndPoint(IPAddress.Loopback, 5000), token).ConfigureAwait(false);
            var local = (IPEndPoint)socket.LocalEndPoint!;
            var deadline = Stopwatch.StartNew();
            while (deadline.Elapsed < TimeSpan.FromSeconds(2))
            {
                token.ThrowIfCancellationRequested();
                var peers = WindowsNativeCore.TcpConnections().Where(row => row.State == 5 && row.Address.Equals(IPAddress.Loopback) && row.Port == 5000 && row.RemoteAddress.Equals(local.Address) && row.RemotePort == local.Port).ToArray();
                if (peers.Length == 1 && peers[0].ProcessId == processId && (process is null || WindowsNativeCore.IsRunning(process)))
                {
                    var current = WindowsNativeCore.ReadService();
                    if (service is not null && (current is null || current.State != 4 || current.ProcessId != processId || !TrustedService(current))) throw new IOException("Core changed during connection.");
                    // HTTP cannot write credentials until ConnectCallback returns.
                    // The established connection belongs to the held Core process;
                    // a later process binding its port cannot receive this stream.
                    return new NetworkStream(socket, ownsSocket: true);
                }
                if (peers.Length != 0 || process is not null && !WindowsNativeCore.IsRunning(process)) break;
                await Task.Delay(25, token).ConfigureAwait(false);
            }
            throw new IOException("Core connection ownership could not be verified.");
        }
        catch { socket.Dispose(); throw; }
        finally { process?.Dispose(); installation?.Dispose(); }
    }
    public static bool OpenElevatedSetup()
    {
        try
        {
            var executable = Path.Combine(AppContext.BaseDirectory, "SentinelAI.Desktop.exe");
            if (!File.Exists(executable)) return false;
            using var process = Process.Start(new ProcessStartInfo(executable)
            {
                UseShellExecute = true, Verb = "runas", Arguments = "--setup-administrator", WorkingDirectory = AppContext.BaseDirectory
            });
            return process is not null;
        }
        catch { return false; }
    }
    public void Dispose() { }
}

internal sealed class LocalAdministratorSetupClient : IAdministratorSetupClient
{
    private readonly CancellationTokenSource _lifetime = new();
    private bool _disposed;
    public async Task<AdministratorSetupState> GetStateAsync(CancellationToken token)
    {
        var result = await RunAsync(initialize: false, "", ReadOnlyMemory<char>.Empty, token).ConfigureAwait(false);
        return result switch
        {
            "required" => AdministratorSetupState.Required, "initialized" => AdministratorSetupState.Initialized,
            "permission-required" => AdministratorSetupState.PermissionRequired, "untrusted" => AdministratorSetupState.UntrustedInstallation,
            _ => AdministratorSetupState.Unavailable
        };
    }
    public async Task<AdministratorSetupResult> InitializeAsync(string username, ReadOnlyMemory<char> password, CancellationToken token)
    {
        if (string.IsNullOrWhiteSpace(username) || username.Trim().Length > 128 || username.Any(char.IsControl) || password.Length is < 12 or > 1024) return AdministratorSetupResult.InvalidInput;
        var result = await RunAsync(true, username.Trim(), password, token).ConfigureAwait(false);
        return result switch
        {
            "created" => AdministratorSetupResult.Created, "already-initialized" => AdministratorSetupResult.AlreadyInitialized,
            "invalid-input" => AdministratorSetupResult.InvalidInput, "permission-required" => AdministratorSetupResult.PermissionRequired,
            "untrusted" => AdministratorSetupResult.UntrustedInstallation, _ => AdministratorSetupResult.Unavailable
        };
    }
    private async Task<string> RunAsync(bool initialize, string username, ReadOnlyMemory<char> password, CancellationToken token)
    {
        token.ThrowIfCancellationRequested();
        if (_disposed) return "unavailable";
        using var deadline = CancellationTokenSource.CreateLinkedTokenSource(token, _lifetime.Token);
        deadline.CancelAfter(TimeSpan.FromSeconds(30));
        Process? process = null;
        byte[]? input = null;
        try
        {
            using var executable = WindowsInstallationTrust.ValidateOperatorInstallation();
            var start = new ProcessStartInfo(WindowsInstallationTrust.ExecutablePath)
            {
                WorkingDirectory = WindowsInstallationTrust.CodeDirectory, UseShellExecute = false, CreateNoWindow = true,
                RedirectStandardOutput = true, RedirectStandardError = true, RedirectStandardInput = initialize
            };
            start.ArgumentList.Add(initialize ? "--initialize-administrator" : "--administrator-state");
            start.ArgumentList.Add("--config"); start.ArgumentList.Add(WindowsInstallationTrust.ConfigurationPath);
            start.Environment.Remove("SENTINELAI_BOOTSTRAP_USERNAME"); start.Environment.Remove("SENTINELAI_BOOTSTRAP_PASSWORD");
            process = Process.Start(start) ?? throw new IOException();
            var output = ReadBoundedAsync(process.StandardOutput.BaseStream, deadline.Token);
            var errors = ReadBoundedAsync(process.StandardError.BaseStream, deadline.Token);
            if (initialize)
            {
                // Preallocate enough for the bounded input; no growing stream can
                // leave an unwiped previous password buffer behind.
                input = new byte[16 * 1024];
                using var memory = new MemoryStream(input, 0, input.Length, writable: true, publiclyVisible: true);
                memory.SetLength(0);
                using (var writer = new Utf8JsonWriter(memory))
                {
                    writer.WriteStartObject(); writer.WriteString("username", username); writer.WriteString("password", password.Span); writer.WriteEndObject(); writer.Flush();
                }
                await process.StandardInput.BaseStream.WriteAsync(input.AsMemory(0, checked((int)memory.Length)), deadline.Token).ConfigureAwait(false);
                await process.StandardInput.BaseStream.FlushAsync(deadline.Token).ConfigureAwait(false);
                process.StandardInput.Close();
                CryptographicOperations.ZeroMemory(input);
            }
            await process.WaitForExitAsync(deadline.Token).ConfigureAwait(false);
            var bytes = await output.ConfigureAwait(false);
            var errorBytes = await errors.ConfigureAwait(false);
            try
            {
                if (errorBytes.Length != 0 || process.ExitCode is not (0 or 1)) return "unavailable";
                using var document = JsonDocument.Parse(bytes, new JsonDocumentOptions { MaxDepth = 2 });
                var fields = document.RootElement.EnumerateObject().ToArray();
                if (fields.Length != 1 || fields[0].Name != "status" || fields[0].Value.ValueKind != JsonValueKind.String) return "unavailable";
                var status = fields[0].Value.GetString() ?? "unavailable";
                return process.ExitCode == 0 && status is "required" or "initialized" or "created" or "already-initialized" ? status :
                    process.ExitCode == 1 && status == "invalid-input" ? status : "unavailable";
            }
            finally { CryptographicOperations.ZeroMemory(bytes); CryptographicOperations.ZeroMemory(errorBytes); }
        }
        catch (UnauthorizedAccessException) { return "permission-required"; }
        catch (System.ComponentModel.Win32Exception error) when (error.NativeErrorCode == 5) { return "permission-required"; }
        catch (InvalidDataException) { return "untrusted"; }
        catch { token.ThrowIfCancellationRequested(); return "unavailable"; }
        finally
        {
            if (input is not null) CryptographicOperations.ZeroMemory(input);
            if (process is not null)
            {
                try { if (!process.HasExited) { process.Kill(); await process.WaitForExitAsync().ConfigureAwait(false); } }
                catch { }
                process.Dispose();
            }
        }
    }
    private static async Task<byte[]> ReadBoundedAsync(Stream stream, CancellationToken token)
    {
        using var result = new MemoryStream();
        var buffer = new byte[1024];
        try
        {
            while (true)
            {
                var count = await stream.ReadAsync(buffer, token).ConfigureAwait(false);
                if (count == 0) return result.ToArray();
                if (result.Length + count > 4096) throw new InvalidDataException();
                result.Write(buffer, 0, count);
            }
        }
        finally { CryptographicOperations.ZeroMemory(buffer); CryptographicOperations.ZeroMemory(result.GetBuffer()); }
    }
    public void Dispose() { if (_disposed) return; _disposed = true; _lifetime.Cancel(); _lifetime.Dispose(); }
}
