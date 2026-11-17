using System.Diagnostics;
using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Runtime.Versioning;
using System.Security.AccessControl;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.ServiceProcess;
using System.Text.Json;
using SentinelAI.Backup;
using SentinelAI.Contracts.Backups;
using SentinelAI.Contracts.Enrollment;
using SentinelAI.Contracts.Heartbeat;
using SentinelAI.Hosting;

/// <summary>Opt-in acceptance against the already owned, elevated native service fixture. No production test flags.</summary>
internal static class BackupWindowsAcceptance
{
    private static readonly JsonSerializerOptions Json = new(JsonSerializerDefaults.Web);
    private sealed record FixtureInput(string Username, string Password, string? RecoveryKeyBase64);
    private sealed record WorkerReply(int ExitCode, BackupRecoveryResult Result);

    public static async Task<int> RunAsync(string[] args, Stream input)
    {
        if (!OperatingSystem.IsWindows() || args.Length != 5 || args[0] != "--native-backup-acceptance") return 1;
        return await RunWindowsAsync(args, input);
    }

    [SupportedOSPlatform("windows")]
    private static async Task<int> RunWindowsAsync(string[] args, Stream input)
    {
        var stage = "input";
        var checks = 0;
        void Check(bool condition, string message)
        {
            checks++;
            if (!condition) throw new InvalidOperationException(message);
        }
        byte[]? key = null;
        byte[]? inputBytes = null;
        var initiallyRunning = false;
        var changedService = false;
        var committed = false;
        string? core = null, config = null;
        try
        {
            using var deadline = new CancellationTokenSource(TimeSpan.FromMinutes(5));
            var cancellation = deadline.Token;
            inputBytes = await ReadBoundedAsync(input, 16 * 1024, cancellation);
            var fixture = JsonSerializer.Deserialize<FixtureInput>(inputBytes, Json) ?? throw new InvalidDataException();
            Check(fixture.Username.Length is > 0 and <= 128 && fixture.Password.Length is >= 12 and <= 1024, "fixture-input");
            core = Path.GetFullPath(args[1]); config = Path.GetFullPath(args[2]);
            var origin = new Uri(args[3]);
            Check(origin.IsLoopback && origin.Scheme == "http" && File.Exists(core) && File.Exists(config), "owned-fixture-paths");
            var data = Path.GetDirectoryName(config)!;
            var privateRoot = Path.GetFullPath(args[4]);
            Check(Directory.Exists(privateRoot) && (File.GetAttributes(privateRoot) & FileAttributes.ReparsePoint) == 0, "private-fixture-root");
            var work = Path.Combine(privateRoot, "Backup-Recovery-Test-" + Guid.NewGuid().ToString("N"));
            Directory.CreateDirectory(work);
            var protectedFiles = new[] { config, Path.Combine(data, "pilot-installation.json"), Path.Combine(data, "core-service-installation.json") };
            var protectedHashes = protectedFiles.ToDictionary(path => path, path => SHA256.HashData(File.ReadAllBytes(path)));
            var aclPaths = protectedFiles.Append(Path.Combine(data, "sentinelai.db")).ToArray();
            var protectedAcls = aclPaths.ToDictionary(path => path, ReadSecurity);
            var certificate = ReadCertificate(config);
            using var http = new HttpClient(new HttpClientHandler { UseProxy = false, AllowAutoRedirect = false })
            { BaseAddress = origin, Timeout = TimeSpan.FromSeconds(30) };
            async Task<string> LoginAsync()
            {
                using var response = await http.PostAsJsonAsync("/api/auth/login", new { username = fixture.Username, password = fixture.Password }, cancellation);
                response.EnsureSuccessStatusCode();
                using var json = JsonDocument.Parse(await response.Content.ReadAsByteArrayAsync(cancellation));
                return json.RootElement.GetProperty("accessToken").GetString() ?? throw new InvalidDataException();
            }
            async Task<HttpResponseMessage> AdminAsync(HttpMethod method, string path, string bearer, HttpContent? body = null)
            {
                using var request = new HttpRequestMessage(method, path) { Content = body };
                request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", bearer);
                return await http.SendAsync(request, cancellation);
            }
            async Task<BackupStatus> StatusAsync(string bearer)
            {
                using var response = await AdminAsync(HttpMethod.Get, "/api/admin/backups", bearer);
                response.EnsureSuccessStatusCode();
                return await response.Content.ReadFromJsonAsync<BackupStatus>(Json, cancellation) ?? throw new InvalidDataException();
            }
            async Task<EnrollmentTokenResponse> TokenAsync(string bearer)
            {
                using var response = await AdminAsync(HttpMethod.Post, "/api/admin/enrollment-tokens", bearer);
                response.EnsureSuccessStatusCode();
                return await response.Content.ReadFromJsonAsync<EnrollmentTokenResponse>(Json, cancellation) ?? throw new InvalidDataException();
            }
            async Task<EnrollmentResponse> EnrollAsync(string bearer)
            {
                var token = await TokenAsync(bearer);
                using var response = await http.PostAsJsonAsync("/api/agent/enroll", new EnrollmentRequest(Guid.NewGuid(), token.Token), cancellation);
                response.EnsureSuccessStatusCode();
                return await response.Content.ReadFromJsonAsync<EnrollmentResponse>(Json, cancellation) ?? throw new InvalidDataException();
            }
            async Task<HttpStatusCode> HeartbeatAsync(EnrollmentResponse agent)
            {
                using var request = new HttpRequestMessage(HttpMethod.Post, "/api/agent/heartbeat")
                { Content = JsonContent.Create(new HeartbeatRequest(agent.InstallationId)) };
                request.Headers.Authorization = new AuthenticationHeaderValue("SentinelAgent", agent.EndpointId.ToString("D") + "." + agent.AgentCredential);
                using var response = await http.SendAsync(request, cancellation);
                return response.StatusCode;
            }
            async Task<string> LanguageAsync()
            {
                using var response = await http.GetAsync("/api/language", cancellation);
                response.EnsureSuccessStatusCode();
                using var json = JsonDocument.Parse(await response.Content.ReadAsByteArrayAsync(cancellation));
                return json.RootElement.GetProperty("language").GetString() ?? throw new InvalidDataException();
            }

            stage = "key-setup";
            var bearer = await LoginAsync();
            var status = await StatusAsync(bearer);
            key = fixture.RecoveryKeyBase64 is null ? RandomNumberGenerator.GetBytes(32) : Convert.FromBase64String(fixture.RecoveryKeyBase64);
            Check(key.Length == 32, "recovery-key-size");
            var ownerPassphrase = Convert.ToBase64String(RandomNumberGenerator.GetBytes(32));
            var ownerKey = RecoveryKeyFile.Create(key, ownerPassphrase);
            var keyPath = Path.Combine(work, "owner-recovery.sakey");
            try
            {
                await using var keyFile = new FileStream(keyPath, FileMode.CreateNew, FileAccess.Write, FileShare.None);
                await keyFile.WriteAsync(ownerKey, cancellation); keyFile.Flush(true);
            }
            finally { CryptographicOperations.ZeroMemory(ownerKey); }
            if (fixture.RecoveryKeyBase64 is null)
            {
                Check(status.Policy.RecoveryKeyId is null, "fixture-key-not-fresh");
                using var request = new HttpRequestMessage(HttpMethod.Put, "/api/admin/backups/key") { Content = new ByteArrayContent(key) };
                request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", bearer);
                request.Headers.IfMatch.Add(new EntityTagHeaderValue("\"" + status.Policy.Version + "\""));
                request.Content.Headers.ContentType = new MediaTypeHeaderValue("application/octet-stream");
                using var response = await http.SendAsync(request, cancellation);
                response.EnsureSuccessStatusCode();
                status = await StatusAsync(bearer);
            }
            Check(key.Length == 32 && status.Policy.RecoveryKeyId == BackupArchive.KeyId(key) && !status.Policy.Enabled, "fixture-key-state");
            var originalLanguage = await LanguageAsync();
            var originalAgent = await EnrollAsync(bearer);
            Check(await HeartbeatAsync(originalAgent) == HttpStatusCode.OK, "prebackup-agent-auth");
            var unusedToken = await TokenAsync(bearer);

            stage = "snapshot";
            using (var response = await AdminAsync(HttpMethod.Post, "/api/admin/backups", bearer)) response.EnsureSuccessStatusCode();
            var pending = Stopwatch.StartNew();
            do
            {
                await Task.Delay(100, cancellation);
                status = await StatusAsync(bearer);
                Check(pending.Elapsed < TimeSpan.FromMinutes(2), "snapshot-timeout");
            } while (status.Busy);
            var completed = status.LastAttempt ?? throw new InvalidDataException();
            Check(completed is { Kind: "create", Outcome: "succeeded", ArchiveId: not null }, "snapshot-failed");
            var archive = status.Archives.Single(item => item.ArchiveId == completed.ArchiveId);
            var archivePath = Path.Combine(data, "backups", archive.ArchiveId.ToString("N") + ".sab");
            Check(archive.VerificationState == "verified" && File.Exists(archivePath), "snapshot-not-verified");

            stage = "post-snapshot-change";
            var laterAgent = await EnrollAsync(bearer);
            Check(await HeartbeatAsync(laterAgent) == HttpStatusCode.OK, "later-agent-auth");
            using (var response = await AdminAsync(HttpMethod.Put, "/api/admin/settings/language", bearer,
                       JsonContent.Create(new { language = originalLanguage == "pl" ? "en" : "pl" }))) response.EnsureSuccessStatusCode();
            Check(await LanguageAsync() != originalLanguage, "post-snapshot-change-not-applied");
            var requestPreview = new BackupRecoveryRequest(BackupRecoveryContract.Preview, archivePath, keyPath, ownerPassphrase);

            stage = "negative-recovery";
            var badPassword = await WorkerAsync(core, config, requestPreview with { Passphrase = ownerPassphrase + "-wrong" }, cancellation);
            Check(badPassword.ExitCode != 0 && badPassword.Result.Outcome == BackupRecoveryContract.Rejected, "wrong-password-accepted");
            var tamperedPath = Path.Combine(work, "tampered.sab");
            File.Copy(archivePath, tamperedPath);
            await using (var tampered = new FileStream(tamperedPath, FileMode.Open, FileAccess.ReadWrite, FileShare.None))
            {
                tampered.Position = tampered.Length / 2;
                var value = tampered.ReadByte(); tampered.Position--; tampered.WriteByte((byte)(value ^ 1)); tampered.Flush(true);
            }
            var tamperedReply = await WorkerAsync(core, config, requestPreview with { ArchivePath = tamperedPath }, cancellation);
            Check(tamperedReply.ExitCode != 0 && tamperedReply.Result.Outcome == BackupRecoveryContract.Rejected, "tampered-archive-accepted");
            var preview = await WorkerAsync(core, config, requestPreview, cancellation);
            Check(preview.ExitCode == 0 && preview.Result is { Outcome: BackupRecoveryContract.Verified, Preview: not null }, "preview-rejected");
            var verified = preview.Result.Preview!;
            Check(verified.ArchiveId == archive.ArchiveId && verified.CoreInstallationId == status.CoreInstallationId &&
                  verified.OrganizationId == status.OrganizationId && verified.EndpointCount >= 1, "preview-identity-changed");
            var restore = requestPreview with
            {
                Operation = BackupRecoveryContract.Restore, ConfirmedArchiveId = verified.ArchiveId,
                ExpectedArchiveSha256 = verified.ArchiveSha256, Confirmation = BackupRecoveryContract.RestoreConfirmation
            };
            var activeReply = await WorkerAsync(core, config, restore, cancellation);
            Check(activeReply.ExitCode != 0 && activeReply.Result.Outcome == BackupRecoveryContract.ServiceRunning, "live-service-replacement-accepted");

            stage = "cold-restore";
            using (var service = new ServiceController("SentinelAICore"))
            {
                service.Refresh(); initiallyRunning = service.Status == ServiceControllerStatus.Running;
                Check(initiallyRunning, "fixture-service-not-running");
                using var process = FindOwnedCoreProcess(core);
                changedService = true;
                service.Stop(); service.WaitForStatus(ServiceControllerStatus.Stopped, TimeSpan.FromSeconds(30));
                await process.WaitForExitAsync(cancellation);
            }
            var restored = await WorkerAsync(core, config, restore, cancellation);
            Check(restored.ExitCode == 0 && restored.Result.Outcome == BackupRecoveryContract.Restored, "cold-restore-rejected");
            StartService();
            stage = "post-restore-health";
            await WaitHealthyAsync(http, cancellation);
            bearer = await LoginAsync();
            var recovered = await StatusAsync(bearer);
            Check(recovered.CoreInstallationId == status.CoreInstallationId && recovered.OrganizationId == status.OrganizationId &&
                  !recovered.Policy.Enabled, "restored-identity-or-schedule-changed");
            Check(await LanguageAsync() == originalLanguage, "point-in-time-change-not-restored");
            Check(await HeartbeatAsync(originalAgent) == HttpStatusCode.OK, "retained-agent-credential-lost");
            Check(await HeartbeatAsync(laterAgent) == HttpStatusCode.Unauthorized, "post-snapshot-agent-retained");
            using (var response = await http.PostAsJsonAsync("/api/agent/enrollment-check", new { enrollmentToken = unusedToken.Token }, cancellation))
                Check(response.StatusCode == HttpStatusCode.Gone, "old-unused-enrollment-code-revived");
            foreach (var path in protectedFiles)
                Check(SHA256.HashData(File.ReadAllBytes(path)).AsSpan().SequenceEqual(protectedHashes[path]), "protected-installation-metadata-changed");
            foreach (var path in aclPaths) Check(ReadSecurity(path) == protectedAcls[path], "protected-file-or-database-ACL-changed");
            Check(ReadCertificate(config) == certificate, "LAN-certificate-key-or-ACL-changed");

            stage = "commit";
            var committedReply = await WorkerAsync(core, config, new(BackupRecoveryContract.Commit,
                ConfirmedArchiveId: archive.ArchiveId, Confirmation: BackupRecoveryContract.RestoreConfirmation), cancellation);
            Check(committedReply.ExitCode == 0 && committedReply.Result.Outcome == BackupRecoveryContract.Committed, "healthy-restore-not-committed");
            committed = true;
            Check(!File.Exists(Path.Combine(data, "backups", "restore-old.db")) &&
                  !File.Exists(Path.Combine(data, "backups", "restore-journal.json")), "restore-safety-state-not-cleaned");
            Console.WriteLine($"Native backup restore acceptance passed ({checks} checks: encrypted owner key, wrong password/tamper/live-service refusal, cold point-in-time restore, identity, Agent credentials, revoked codes, protected metadata/ACL/certificate and health commit).");
            return 0;
        }
        catch
        {
            Console.Error.WriteLine("Native backup restore acceptance failed at " + stage + ".");
            return 1;
        }
        finally
        {
            if (!committed && changedService && core is not null && config is not null)
            {
                try
                {
                    using var recoveryDeadline = new CancellationTokenSource(TimeSpan.FromMinutes(2));
                    using (var service = new ServiceController("SentinelAICore"))
                    {
                        service.Refresh();
                        if (service.Status != ServiceControllerStatus.Stopped)
                        { service.Stop(); service.WaitForStatus(ServiceControllerStatus.Stopped, TimeSpan.FromSeconds(30)); }
                    }
                    var state = await WorkerAsync(core, config, new(BackupRecoveryContract.Status), recoveryDeadline.Token);
                    if (state.Result.PendingArchiveId is { } pendingId)
                        _ = await WorkerAsync(core, config, new(BackupRecoveryContract.Rollback, ConfirmedArchiveId: pendingId,
                            Confirmation: BackupRecoveryContract.RestoreConfirmation), recoveryDeadline.Token);
                    if (initiallyRunning) StartService();
                }
                catch { }
            }
            if (key is not null) CryptographicOperations.ZeroMemory(key);
            if (inputBytes is not null) CryptographicOperations.ZeroMemory(inputBytes);
        }
    }

    [SupportedOSPlatform("windows")]
    private static string ReadSecurity(string path) => new FileInfo(path).GetAccessControl(AccessControlSections.Owner |
        AccessControlSections.Group | AccessControlSections.Access).GetSecurityDescriptorSddlForm(AccessControlSections.Owner |
        AccessControlSections.Group | AccessControlSections.Access);

    private sealed record CertificateState(string Pin, string KeyName, CngExportPolicies ExportPolicy, string Descriptor);
    [SupportedOSPlatform("windows")]
    private static CertificateState? ReadCertificate(string configuration)
    {
        using var json = JsonDocument.Parse(File.ReadAllBytes(configuration));
        if (!json.RootElement.GetProperty("SentinelAI").TryGetProperty("LocalNetworkCertificateSha256", out var value)) return null;
        var pin = value.GetString() ?? throw new InvalidDataException();
        using var certificate = LocalNetworkCertificate.FindInMachineStore(pin) ?? throw new InvalidDataException();
        using var signer = certificate.GetECDsaPrivateKey();
        if (signer is not ECDsaCng cng || cng.Key.ExportPolicy != CngExportPolicies.None) throw new InvalidDataException();
        var descriptor = cng.Key.GetProperty("Security Descr", (CngPropertyOptions)4).GetValue();
        if (descriptor is null) throw new InvalidDataException();
        var keyName = cng.Key.UniqueName;
        if (string.IsNullOrWhiteSpace(keyName)) throw new InvalidDataException();
        return new(pin, keyName, cng.Key.ExportPolicy, Convert.ToBase64String(descriptor));
    }

    [SupportedOSPlatform("windows")]
    private static Process FindOwnedCoreProcess(string executable)
    {
        var matches = new List<Process>();
        foreach (var process in Process.GetProcessesByName("SentinelAI.Core"))
        {
            try
            {
                if (string.Equals(process.MainModule?.FileName, executable, StringComparison.OrdinalIgnoreCase)) { matches.Add(process); continue; }
            }
            catch { }
            process.Dispose();
        }
        if (matches.Count == 1) return matches[0];
        foreach (var process in matches) process.Dispose();
        throw new InvalidOperationException("owned-Core-process");
    }

    [SupportedOSPlatform("windows")]
    private static void StartService()
    {
        using var service = new ServiceController("SentinelAICore");
        service.Refresh();
        if (service.Status == ServiceControllerStatus.Stopped) service.Start();
        service.WaitForStatus(ServiceControllerStatus.Running, TimeSpan.FromSeconds(30));
    }

    private static async Task WaitHealthyAsync(HttpClient http, CancellationToken cancellation)
    {
        var elapsed = Stopwatch.StartNew();
        while (elapsed.Elapsed < TimeSpan.FromSeconds(30))
        {
            try { using var response = await http.GetAsync("/api/health", cancellation); if (response.IsSuccessStatusCode) return; }
            catch (HttpRequestException) { }
            await Task.Delay(100, cancellation);
        }
        throw new InvalidOperationException("restored-Core-health");
    }

    private static async Task<WorkerReply> WorkerAsync(string executable, string configuration, BackupRecoveryRequest request,
        CancellationToken cancellation)
    {
        var start = new ProcessStartInfo(executable)
        { UseShellExecute = false, CreateNoWindow = true, RedirectStandardInput = true, RedirectStandardOutput = true, RedirectStandardError = true,
            StandardInputEncoding = new System.Text.UTF8Encoding(false) };
        start.ArgumentList.Add(BackupRecoveryContract.Command); start.ArgumentList.Add("--config"); start.ArgumentList.Add(configuration);
        start.Environment.Remove("SENTINELAI_BOOTSTRAP_USERNAME"); start.Environment.Remove("SENTINELAI_BOOTSTRAP_PASSWORD");
        using var process = Process.Start(start) ?? throw new InvalidOperationException("recovery-worker-start");
        var stdout = ReadBoundedAsync(process.StandardOutput.BaseStream, BackupRecoveryContract.MaximumOutputBytes, cancellation);
        var stderr = ReadBoundedAsync(process.StandardError.BaseStream, 8192, cancellation);
        var body = JsonSerializer.SerializeToUtf8Bytes(request, Json);
        try
        {
            await process.StandardInput.BaseStream.WriteAsync(body, cancellation);
            await process.StandardInput.BaseStream.FlushAsync(cancellation);
            process.StandardInput.Close();
            await process.WaitForExitAsync(cancellation);
            var bytes = await stdout;
            try { return new(process.ExitCode, JsonSerializer.Deserialize<BackupRecoveryResult>(bytes, Json) ?? throw new InvalidDataException()); }
            finally { CryptographicOperations.ZeroMemory(bytes); }
        }
        finally
        {
            CryptographicOperations.ZeroMemory(body);
            if (!process.HasExited) { process.Kill(entireProcessTree: true); await process.WaitForExitAsync(CancellationToken.None); }
            try { CryptographicOperations.ZeroMemory(await stderr); } catch { }
        }
    }

    private static async Task<byte[]> ReadBoundedAsync(Stream source, int maximum, CancellationToken cancellation)
    {
        using var output = new MemoryStream();
        var buffer = new byte[4096];
        while (true)
        {
            var read = await source.ReadAsync(buffer, cancellation);
            if (read == 0) return output.ToArray();
            if (output.Length + read > maximum) throw new InvalidDataException();
            output.Write(buffer, 0, read);
        }
    }
}
