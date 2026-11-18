using System.Diagnostics;
using System.IO;
using System.Net.Http;
using System.Security.Cryptography;
using System.ServiceProcess;
using System.Text.Json;
using SentinelAI.Contracts.Backups;
using SentinelAI.Desktop.Foundation;

namespace SentinelAI.Desktop.Services;

internal sealed class WindowsBackupRecoveryService : IBackupRecoveryWorker, IBackupRecoveryHost
{
    private static readonly JsonSerializerOptions Json = new(JsonSerializerDefaults.Web) { MaxDepth = 4 };
    private static void ValidateOwnedService()
    {
        if (!WindowsBackupRecoveryLauncher.IsElevated()) throw new UnauthorizedAccessException();
        var service = WindowsNativeCore.ReadService();
        if (service is null || !string.Equals(service.Account, "NT SERVICE\\SentinelAICore", StringComparison.OrdinalIgnoreCase) || !WindowsNativeCore.MatchesImageCommand(service.Image))
            throw new InvalidDataException("Core service ownership is unavailable.");
    }
    public async Task<BackupRecoveryResult> ExecuteAsync(BackupRecoveryRequest request, ReadOnlyMemory<char> password, CancellationToken cancellationToken)
    {
        ValidateOwnedService();
        using var trusted = WindowsInstallationTrust.ValidateOperatorInstallation();
        using var input = new MemoryStream();
        using (var writer = new Utf8JsonWriter(input))
        {
            writer.WriteStartObject();
            writer.WriteString("operation", request.Operation);
            writer.WriteString("archivePath", request.ArchivePath);
            writer.WriteString("recoveryKeyPath", request.RecoveryKeyPath);
            if (password.IsEmpty) writer.WriteNull("passphrase"); else writer.WriteString("passphrase", password.Span);
            writer.WriteString("mode", request.Mode);
            if (request.ConfirmedArchiveId is { } id) writer.WriteString("confirmedArchiveId", id); else writer.WriteNull("confirmedArchiveId");
            writer.WriteString("expectedArchiveSha256", request.ExpectedArchiveSha256);
            writer.WriteString("confirmation", request.Confirmation);
            writer.WriteEndObject();
        }
        var raw = input.GetBuffer();
        try
        {
            if (input.Length > BackupRecoveryContract.MaximumInputBytes) return new(BackupRecoveryContract.InvalidInput);
            var start = new ProcessStartInfo(WindowsInstallationTrust.ExecutablePath)
            {
                UseShellExecute = false, CreateNoWindow = true, RedirectStandardInput = true, RedirectStandardOutput = true, RedirectStandardError = true,
                StandardInputEncoding = new System.Text.UTF8Encoding(false),
                WorkingDirectory = WindowsInstallationTrust.CodeDirectory
            };
            start.ArgumentList.Add(BackupRecoveryContract.Command); start.ArgumentList.Add("--config"); start.ArgumentList.Add(WindowsInstallationTrust.ConfigurationPath);
            start.Environment.Remove("SENTINELAI_BOOTSTRAP_USERNAME"); start.Environment.Remove("SENTINELAI_BOOTSTRAP_PASSWORD");
            using var process = Process.Start(start) ?? throw new IOException("Recovery worker unavailable.");
            using var deadline = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
            deadline.CancelAfter(TimeSpan.FromMinutes(5));
            try
            {
                var output = ReadBoundedAsync(process.StandardOutput.BaseStream, BackupRecoveryContract.MaximumOutputBytes, deadline.Token);
                var errors = ReadBoundedAsync(process.StandardError.BaseStream, 4096, deadline.Token);
                await process.StandardInput.BaseStream.WriteAsync(raw.AsMemory(0, checked((int)input.Length)), deadline.Token);
                process.StandardInput.Close();
                await process.WaitForExitAsync(deadline.Token);
                var bytes = await output;
                var diagnostic = await errors; // Never display worker stderr: paths and framework details are not UI messages.
                CryptographicOperations.ZeroMemory(diagnostic);
                try { return ParseResult(bytes); }
                finally { CryptographicOperations.ZeroMemory(bytes); }
            }
            catch
            {
                try { if (!process.HasExited) process.Kill(entireProcessTree: true); } catch { }
                throw;
            }
        }
        finally { CryptographicOperations.ZeroMemory(raw); }
    }
    private static BackupRecoveryResult ParseResult(byte[] bytes)
    {
        using var document = JsonDocument.Parse(bytes, new JsonDocumentOptions { MaxDepth = 4 });
        var root = document.RootElement;
        if (root.ValueKind != JsonValueKind.Object || root.EnumerateObject().Any(p => p.Name is not ("outcome" or "preview" or "pendingArchiveId")) ||
            root.EnumerateObject().GroupBy(p => p.Name).Any(g => g.Count() != 1)) throw new InvalidDataException("Invalid recovery result.");
        var result = JsonSerializer.Deserialize<BackupRecoveryResult>(bytes, Json) ?? throw new InvalidDataException("Invalid recovery result.");
        if (result.Outcome is not ("ready" or "verified" or "restored" or "rolledBack" or "committed" or "pending" or "invalidInput" or "unavailable" or "rejected" or "serviceRunning" or "identityMismatch")) throw new InvalidDataException("Unknown recovery result.");
        if (result.Preview is { } preview)
        {
            var fields = root.GetProperty("preview");
            if (fields.EnumerateObject().Count() != 8 || fields.EnumerateObject().GroupBy(p => p.Name).Any(group => group.Count() != 1) || fields.EnumerateObject().Any(p => p.Name is not ("archiveId" or "createdUtc" or "coreInstallationId" or "organizationId" or "administratorCount" or "endpointCount" or "archiveSha256" or "mode")) ||
                preview.ArchiveId == Guid.Empty || preview.CoreInstallationId == Guid.Empty || preview.OrganizationId == Guid.Empty || preview.CreatedUtc.Offset != TimeSpan.Zero ||
                preview.AdministratorCount is < 1 or > 10000 || preview.EndpointCount is < 0 or > 1000000 || preview.ArchiveSha256.Length != 64 || !preview.ArchiveSha256.All(c => c is >= '0' and <= '9' or >= 'a' and <= 'f') ||
                preview.Mode is not (BackupRecoveryContract.SameMachine or BackupRecoveryContract.Migration)) throw new InvalidDataException("Invalid recovery preview.");
        }
        if (result.PendingArchiveId == Guid.Empty || result.Outcome == BackupRecoveryContract.Verified && result.Preview is null) throw new InvalidDataException("Incomplete recovery result.");
        return result;
    }
    private static async Task<byte[]> ReadBoundedAsync(Stream stream, int limit, CancellationToken token)
    {
        using var output = new MemoryStream();
        var buffer = new byte[1024];
        while (true)
        {
            var count = await stream.ReadAsync(buffer, token);
            if (count == 0) break;
            if (output.Length + count > limit) throw new InvalidDataException("Recovery output exceeds its bound.");
            output.Write(buffer, 0, count);
        }
        return output.ToArray();
    }
    public Task<bool> IsRunningAsync(CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested(); ValidateOwnedService();
        return Task.FromResult(WindowsNativeCore.ReadService()!.State != 1);
    }
    public async Task StopAsync(CancellationToken cancellationToken)
    {
        ValidateOwnedService();
        using var trusted = WindowsInstallationTrust.ValidateOperatorInstallation();
        var initialPid = WindowsNativeCore.ReadService()!.ProcessId;
        using var service = new ServiceController("SentinelAICore");
        service.Refresh();
        if (service.Status != ServiceControllerStatus.Stopped && service.Status != ServiceControllerStatus.StopPending) service.Stop();
        var limit = DateTimeOffset.UtcNow.AddSeconds(40);
        while (DateTimeOffset.UtcNow < limit)
        {
            cancellationToken.ThrowIfCancellationRequested(); ValidateOwnedService(); service.Refresh();
            if (service.Status == ServiceControllerStatus.Stopped)
            {
                if (initialPid > 0)
                {
                    try { using var process = Process.GetProcessById(initialPid); using var deadline = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken); deadline.CancelAfter(TimeSpan.FromSeconds(10)); await process.WaitForExitAsync(deadline.Token); }
                    catch (ArgumentException) { }
                }
                return;
            }
            await Task.Delay(100, cancellationToken);
        }
        throw new System.TimeoutException("Core did not stop within its recovery deadline.");
    }
    public async Task<bool> StartAndCheckAsync(CancellationToken cancellationToken)
    {
        ValidateOwnedService();
        using var trusted = WindowsInstallationTrust.ValidateOperatorInstallation();
        using var service = new ServiceController("SentinelAICore");
        service.Refresh();
        if (service.Status == ServiceControllerStatus.Stopped) service.Start();
        using var http = new HttpClient(WindowsCoreServices.CreatePeerTrustedHandler()) { Timeout = TimeSpan.FromSeconds(3) };
        var limit = DateTimeOffset.UtcNow.AddSeconds(45);
        while (DateTimeOffset.UtcNow < limit)
        {
            cancellationToken.ThrowIfCancellationRequested(); ValidateOwnedService();
            try
            {
                using var response = await http.GetAsync(new Uri(WindowsInstallationTrust.Origin, "api/health"), HttpCompletionOption.ResponseHeadersRead, cancellationToken);
                if (response.IsSuccessStatusCode && response.Content.Headers.ContentLength is null or <= 1024)
                {
                    using var body = await response.Content.ReadAsStreamAsync(cancellationToken);
                    var bytes = await ReadBoundedAsync(body, 1024, cancellationToken);
                    using var json = JsonDocument.Parse(bytes);
                    if (json.RootElement.ValueKind == JsonValueKind.Object && json.RootElement.EnumerateObject().Count() == 1 && json.RootElement.GetProperty("status").GetString() == "healthy") return true;
                }
            }
            catch (Exception error) when (error is HttpRequestException or IOException or JsonException or InvalidDataException or TaskCanceledException) { cancellationToken.ThrowIfCancellationRequested(); }
            await Task.Delay(250, cancellationToken);
        }
        return false;
    }
}
