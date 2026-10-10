using System.IO.Compression;
using System.Buffers.Binary;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using SentinelAI.Desktop.Foundation;
using SentinelAI.Setup.Foundation;

var assertions = 0;
void Ensure(bool condition, string context) { assertions++; if (!condition) throw new InvalidOperationException(context); }
async Task Reject(Func<Task> action, string context)
{
    assertions++;
    try { await action(); } catch (InvalidDataException) { return; }
    throw new InvalidOperationException(context);
}
SetupMetadata Metadata(byte[] payload) => new("dev-setup-tests", "1.0.0", "pilot", Convert.ToHexStringLower(SHA256.HashData(payload)), payload.Length);
byte[] Archive(params (string Path, string Content, int Attributes)[] extra)
{
    using var output = new MemoryStream();
    using (var zip = new ZipArchive(output, ZipArchiveMode.Create, true))
    {
        foreach (var item in new[] { ("setup/SetupWorker.ps1", "synthetic worker", 0), ("desktop/SentinelAI.Desktop.exe", "synthetic desktop", 0), ("bundle/installer/Install-SentinelAIPilot.ps1", "synthetic installer", 0) }.Concat(extra))
        {
            var entry = zip.CreateEntry(item.Item1); entry.ExternalAttributes = item.Item3;
            using var writer = new StreamWriter(entry.Open(), new UTF8Encoding(false)); writer.Write(item.Item2);
        }
    }
    return output.ToArray();
}
byte[] WithClaimedSizes(byte[] archive, uint size)
{
    var result = archive.ToArray();
    for (var index = 0; index < result.Length - 46; index++)
        if (BinaryPrimitives.ReadUInt32LittleEndian(result.AsSpan(index, 4)) == 0x02014b50)
            BinaryPrimitives.WriteUInt32LittleEndian(result.AsSpan(index + 24, 4), size);
    return result;
}

var valid = Archive(("bundle/core/core.manifest.json", "synthetic signed package fixture", 0));
var metadata = Metadata(valid);
var json = JsonSerializer.SerializeToUtf8Bytes(new { keyId = metadata.KeyId, version = metadata.Version, channel = metadata.Channel, environment = "development", payloadSha256 = metadata.PayloadSha256, payloadLength = metadata.PayloadLength });
Ensure(SetupMetadata.Parse(json) == metadata, "Valid exact metadata");
foreach (var malformed in new[]
{
    "null", "[]", "{}", Encoding.UTF8.GetString(json).Replace("\"development\"", "\"production\""),
    Encoding.UTF8.GetString(json).Replace("\"pilot\"", "\"other\""),
    Encoding.UTF8.GetString(json).Replace("\"keyId\":", "\"keyId\":\"duplicate\",\"keyId\":"),
    Encoding.UTF8.GetString(json).Replace("\"version\":\"1.0.0\"", "\"version\":\"1.0.0\",\"privateKey\":\"never\""),
    Encoding.UTF8.GetString(json).Replace("\"keyId\":\"dev-setup-tests\"", "\"keyId\":\"bad\\nkey\""),
    Encoding.UTF8.GetString(json).Replace("\"version\":\"1.0.0\"", "\"version\":\"latest\""),
    Encoding.UTF8.GetString(json).Replace($"\"payloadLength\":{valid.Length}", "\"payloadLength\":\"wrong\""),
    Encoding.UTF8.GetString(json).Replace($"\"payloadLength\":{valid.Length}", "\"payloadLength\":0"),
    Encoding.UTF8.GetString(json).Replace($"\"payloadSha256\":\"{metadata.PayloadSha256}\"", "\"payloadSha256\":\"short\"")
}) await Reject(() => { _ = SetupMetadata.Parse(Encoding.UTF8.GetBytes(malformed)); return Task.CompletedTask; }, "Reject ambiguous or unsupported metadata");
await Reject(() => { _ = SetupMetadata.Parse(new byte[4097]); return Task.CompletedTask; }, "Metadata bounded before parse");

using (var stream = new MemoryStream(valid)) await SetupPayload.VerifyAsync(stream, metadata, CancellationToken.None);
Ensure(true, "Verified complete payload");
await Reject(() => SetupPayload.VerifyAsync(new MemoryStream(valid), metadata with { PayloadLength = valid.Length + 1 }, CancellationToken.None), "Reject length mismatch");
await Reject(() => SetupPayload.VerifyAsync(new MemoryStream(valid), metadata with { PayloadSha256 = new string('0', 64) }, CancellationToken.None), "Reject payload corruption");
foreach (var path in new[] { "../escape", "/escape", "desktop/../escape", "desktop//file", "desktop/file.", "desktop/file ", "desktop/CON.txt", "desktop/con .txt", "desktop/COM¹.txt", "desktop/NUL", "desktop/file:stream", "desktop/back\\slash", "desktop/tab\tfile", "other/file", "Desktop/case-root", "desktop/question?", "desktop/pipe|", "desktop/quote\"", "desktop/." })
{
    var bytes = Archive((path, "unsafe synthetic file", 0));
    await Reject(() => SetupPayload.VerifyAsync(new MemoryStream(bytes), Metadata(bytes), CancellationToken.None), "Reject Windows alias/traversal/unsupported path");
}
foreach (var extra in new[]
{
    new[] { ("desktop/SentinelAI.Desktop.EXE", "case duplicate", 0) },
    new[] { ("desktop/link", "target", 0xa000 << 16) },
    new[] { ("desktop/reparse", "target", 0x400) },
    new[] { ("desktop/fifo", "target", 0x1000 << 16) },
    new[] { ("desktop/collision", "file", 0), ("desktop/collision/child", "file", 0) },
    new[] { ("desktop/directory/", "nonempty directory", 0) }
})
{
    var bytes = Archive(extra);
    await Reject(() => SetupPayload.VerifyAsync(new MemoryStream(bytes), Metadata(bytes), CancellationToken.None), "Reject duplicate/link/type/collision archive");
}
var tooMany = Archive(Enumerable.Range(0, SetupPayload.MaximumEntries).Select(index => ($"desktop/entry-{index}", "", 0)).ToArray());
await Reject(() => SetupPayload.VerifyAsync(new MemoryStream(tooMany), Metadata(tooMany), CancellationToken.None), "Entry count bounded");
var oversizedFile = WithClaimedSizes(Archive(), checked((uint)SetupPayload.MaximumFileBytes + 1));
await Reject(() => SetupPayload.VerifyAsync(new MemoryStream(oversizedFile), Metadata(oversizedFile), CancellationToken.None), "Forged expanded file size rejected before extraction");
var oversizedTotal = WithClaimedSizes(Archive(), 400 * 1024 * 1024);
await Reject(() => SetupPayload.VerifyAsync(new MemoryStream(oversizedTotal), Metadata(oversizedTotal), CancellationToken.None), "Forged aggregate expanded size rejected before extraction");
using (var incomplete = new MemoryStream())
{
    using (var zip = new ZipArchive(incomplete, ZipArchiveMode.Create, true)) { var entry = zip.CreateEntry("desktop/SentinelAI.Desktop.exe"); using var writer = new StreamWriter(entry.Open()); writer.Write("synthetic"); }
    var bytes = incomplete.ToArray();
    await Reject(() => SetupPayload.VerifyAsync(new MemoryStream(bytes), Metadata(bytes), CancellationToken.None), "Missing bootstrap files refused");
}
using (var cancel = new CancellationTokenSource())
{
    cancel.Cancel();
    try { await SetupPayload.VerifyAsync(new MemoryStream(valid), metadata, cancel.Token); throw new InvalidOperationException("Canceled verification accepted"); }
    catch (OperationCanceledException) { assertions++; }
}
var temporary = Path.Combine(Path.GetTempPath(), "sentinelai-setup-fixture-" + Guid.NewGuid().ToString("N")); Directory.CreateDirectory(temporary);
try
{
    var unsafeArchive = Archive(("desktop/../escape", "unsafe", 0));
    await Reject(() => SetupPayload.ExtractAsync(new MemoryStream(unsafeArchive), temporary, CancellationToken.None), "Extraction validates entire archive before writing");
    Ensure(!Directory.EnumerateFileSystemEntries(temporary).Any(), "Unsafe trailing ZIP entry cannot leave earlier extracted files");
    await SetupPayload.ExtractAsync(new MemoryStream(valid), temporary, CancellationToken.None);
    Ensure(File.ReadAllText(Path.Combine(temporary, "setup", "SetupWorker.ps1")) == "synthetic worker", "Worker copied exactly");
    Ensure(File.Exists(Path.Combine(temporary, "desktop", "SentinelAI.Desktop.exe")), "Desktop payload extracted without manual ZIP step");
    await Reject(() => SetupPayload.ExtractAsync(new MemoryStream(valid), temporary, CancellationToken.None), "Existing destination is refused");
}
finally { Directory.Delete(temporary, true); }

Ensure(SetupWorkflow.ValidCredentials(" operator ", "synthetic-password".AsSpan(), "synthetic-password".AsSpan()), "Valid memory-only credentials");
foreach (var username in new[] { "", " ", "invalid\nname", new string('x', 129) }) Ensure(!SetupWorkflow.ValidCredentials(username, "synthetic-password".AsSpan(), "synthetic-password".AsSpan()), "Reject invalid username");
Ensure(!SetupWorkflow.ValidCredentials("operator", "short".AsSpan(), "short".AsSpan()), "Reject short password");
Ensure(!SetupWorkflow.ValidCredentials("operator", new string('x', 1025).AsSpan(), new string('x', 1025).AsSpan()), "Reject long password");
Ensure(!SetupWorkflow.ValidCredentials("operator", "synthetic-password".AsSpan(), "different-password".AsSpan()), "Reject confirmation mismatch");
var oneUseToken = new string('a', 64);
var buffer = new byte[8192];
try
{
    var count = SetupWorkflow.WriteWorkerRequest(buffer, "complete", "C:\\ProgramData\\SentinelAI-Setup\\0123456789abcdef0123456789abcdef", metadata, oneUseToken.AsSpan());
    Ensure(count <= 8192 && buffer[count - 1] == '\n', "Worker input is one bounded JSON line");
    using var document = JsonDocument.Parse(buffer.AsMemory(0, count - 1));
    Ensure(document.RootElement.EnumerateObject().Select(field => field.Name).SequenceEqual(new[] { "action", "workDirectory", "keyId", "channel", "enrollmentToken", "version", "preserveData" }), "Worker has exact seven fields without administrator credentials");
    Ensure(document.RootElement.EnumerateObject().All(field => field.Value.ValueKind == JsonValueKind.String), "Strict worker grammar uses string values only");
    Ensure(document.RootElement.GetProperty("version").GetString() == metadata.Version && document.RootElement.GetProperty("preserveData").GetString() == "true", "Fresh installation has an explicit candidate version and preserves data");
    Ensure(document.RootElement.GetProperty("enrollmentToken").GetString() == oneUseToken, "Complete uses one-use token only");
    foreach (var action in new[] { "prepare-core", "start-core" })
    {
        count = SetupWorkflow.WriteWorkerRequest(buffer, action, "C:\\ProgramData\\SentinelAI-Setup\\0123456789abcdef0123456789abcdef", metadata, ReadOnlySpan<char>.Empty);
        using var request = JsonDocument.Parse(buffer.AsMemory(0, count - 1));
        Ensure(request.RootElement.GetProperty("action").GetString() == action && request.RootElement.GetProperty("enrollmentToken").ValueKind == JsonValueKind.String && request.RootElement.GetProperty("enrollmentToken").GetString() == "", "Preparing and starting Core use the strict parser's empty credential-free string");
        Ensure(request.RootElement.EnumerateObject().Count() == 7, "All worker actions use the same exact fields");
        await Reject(() => { SetupWorkflow.WriteWorkerRequest(buffer, action, "C:\\safe", metadata, oneUseToken.AsSpan()); return Task.CompletedTask; }, "No premature enrollment token");
    }
    foreach (var invalid in new[] { "", new string('a', 63), new string('a', 65), new string('g', 64), new string('ａ', 64), oneUseToken[..63] + "\n", oneUseToken[..63] + " " })
    {
        Ensure(!SetupWorkflow.ValidEnrollmentToken(invalid.AsSpan()), "Only exact 64 ASCII hex characters form an enrollment token");
        await Reject(() => { SetupWorkflow.WriteWorkerRequest(buffer, "complete", "C:\\safe", metadata, invalid.AsSpan()); return Task.CompletedTask; }, "Malformed token cannot enter a worker request");
    }
    Ensure(SetupWorkflow.ValidEnrollmentToken(new string('F', 64).AsSpan()), "Core hexadecimal token casing is preserved");
    await Reject(() => { SetupWorkflow.WriteWorkerRequest(buffer, "repair", "C:\\wrong", metadata, ReadOnlySpan<char>.Empty); return Task.CompletedTask; }, "No repair action");
    foreach (var path in new[] { "", new string('x', 261) })
        await Reject(() => { SetupWorkflow.WriteWorkerRequest(buffer, "prepare-core", path, metadata, ReadOnlySpan<char>.Empty); return Task.CompletedTask; }, "Worker path length bounded before serialization");
    await Reject(() => { SetupWorkflow.WriteWorkerRequest(new byte[8191], "prepare-core", "C:\\safe", metadata, ReadOnlySpan<char>.Empty); return Task.CompletedTask; }, "Fixed worker buffer bound");
    await Reject(() => { SetupWorkflow.WriteWorkerRequest(buffer, "prepare-core", "C:\\safe", metadata with { KeyId = new string('x', 65) }, ReadOnlySpan<char>.Empty); return Task.CompletedTask; }, "Metadata cannot exceed worker budget");
    foreach (var action in new[] { "inspect", "lifecycle-stop", "lifecycle-start", "lifecycle-health", "lifecycle-context", "lifecycle-cleanup", "uninstall", "lifecycle-reconcile" })
    {
        count = SetupWorkflow.WriteWorkerRequest(buffer, action, "C:\\safe", metadata, ReadOnlySpan<char>.Empty);
        using var request = JsonDocument.Parse(buffer.AsMemory(0, count - 1));
        Ensure(request.RootElement.GetProperty("action").GetString() == action && request.RootElement.GetProperty("enrollmentToken").GetString() == "", "Lifecycle phases are credential-free fixed actions");
        Ensure(request.RootElement.EnumerateObject().Count() == 7 && request.RootElement.EnumerateObject().All(field => field.Value.ValueKind == JsonValueKind.String), "Lifecycle request obeys the exact string-only grammar");
        await Reject(() => { SetupWorkflow.WriteWorkerRequest(buffer, action, "C:\\safe", metadata, oneUseToken.AsSpan()); return Task.CompletedTask; }, "Maintenance never accepts a fresh enrollment token");
        if (action != "uninstall")
            await Reject(() => { SetupWorkflow.WriteWorkerRequest(buffer, action, "C:\\safe", metadata, ReadOnlySpan<char>.Empty, false); return Task.CompletedTask; }, "Only an uninstall request can explicitly remove data");
    }
    count = SetupWorkflow.WriteWorkerRequest(buffer, "uninstall", "C:\\safe", metadata, ReadOnlySpan<char>.Empty, false);
    using var removal = JsonDocument.Parse(buffer.AsMemory(0, count - 1));
    Ensure(removal.RootElement.GetProperty("preserveData").GetString() == "false", "Explicit removal is an exact false string rather than an ambiguous JSON boolean");
    foreach (var version in new[] { "", "1.0", "1.0.0.0", "+1.0.0", "1.0.0\n", "1.0000000000.0", "1.0.beta", "１.0.0", "1.-1.0", "01.0.0", "65536.0.0", "999999999.0.0" })
        await Reject(() => { SetupWorkflow.WriteWorkerRequest(buffer, "inspect", "C:\\safe", metadata with { Version = version }, ReadOnlySpan<char>.Empty); return Task.CompletedTask; }, "Unsupported candidate version never reaches PowerShell");
}
finally { CryptographicOperations.ZeroMemory(buffer); }
foreach (var marker in new[] { "PROGRESS|validate", "PROGRESS|core", "PROGRESS|services", "PROGRESS|agent", "PROGRESS|desktop", "PROGRESS|shortcut" }) Ensure(SetupWorkflow.ProgressFor(marker) is not null, "Fixed progress allowlist");
foreach (var marker in new[] { "secret", "PROGRESS|password", "PROGRESS|core\nsecret", "FAILED|internal exception", "" }) Ensure(SetupWorkflow.ProgressFor(marker) is null, "Unknown output never rendered");
foreach (var name in new[] { "DOTNET_STARTUP_HOOKS", "Dotnet_StartUp_Hooks", "dotnet_additional_deps", "DOTNET_SHARED_STORE", "Dotnet_Bundle_Extract_Base_Dir", "dotnet_root_x64", "CoReClR_Enable_Profiling", "complus_gcstress", "CoR_Profiler_Path_64", "cor_enable_profiling", "SentinelAI_Bootstrap_Password", "SENTINELAI_BOOTSTRAP_USERNAME", "DotNet_Roll_Forward", "DotNet_MultiLevel_Lookup", "DOTNET_DbgEnableMiniDump", "AppDomain_Manager_Type", "devpath", "__compat_layer", "DOTNET_CLI_TELEMETRY_OPTOUT" })
    Ensure(SetupEnvironmentRules.IsExecutionOverride(name), "Execution override is identified independently of Windows environment casing");
foreach (var name in new[] { "TEMP", "TMP", "SystemRoot", "PATH", "PSModulePath", "__PSLockdownPolicy", "HTTPS_PROXY", "PSExecutionPolicyPreference", "psExecutionPolicyPreference" })
    Ensure(!SetupEnvironmentRules.IsExecutionOverride(name), "Protected temp, machine policy and unrelated configuration preserved");

foreach (var (candidate, installed, comparison) in new[] { ("1.0.0", "1.0.0", 0), ("10.0.0", "2.9.9", 1), ("2.10.0", "2.9.99", 1), ("1.2.10", "1.2.9", 1), ("1.0.0", "1.0.1", -1), ("65535.0.0", "2.0.0", 1) })
    Ensure(Math.Sign(SetupWorkflow.CompareVersions(candidate, installed)) == comparison, "Supported versions compare numeric components rather than text");
foreach (var kind in new[] { SetupInstallationKind.Installed, SetupInstallationKind.Retained })
{
    var installation = new SetupInstallation(kind, "2.0.0");
    Ensure(SetupWorkflow.AllowedLifecycleActions(installation, "2.0.0").SequenceEqual(new[] { SetupLifecycleAction.Repair, SetupLifecycleAction.Uninstall }), "Equal version permits repair without resetting identity");
    Ensure(SetupWorkflow.AllowedLifecycleActions(installation, "2.0.1").SequenceEqual(new[] { SetupLifecycleAction.Upgrade, SetupLifecycleAction.Uninstall }), "Newer version permits upgrade");
    Ensure(SetupWorkflow.AllowedLifecycleActions(installation, "1.9.9").SequenceEqual(new[] { SetupLifecycleAction.Uninstall }), "Older setup cannot downgrade or repair with older code");
    Ensure(SetupWorkflow.CanExecuteLifecycle(installation, "2.0.0", SetupLifecycleAction.Uninstall, true, ""), "Uninstall preserves data by default");
    foreach (var confirmation in new[] { "", "delete", " DELETE", "DELETE ", "DELETE\n" })
        Ensure(!SetupWorkflow.CanExecuteLifecycle(installation, "2.0.0", SetupLifecycleAction.Uninstall, false, confirmation), "Accidental or ambiguous destructive selection is refused");
    Ensure(SetupWorkflow.CanExecuteLifecycle(installation, "2.0.0", SetupLifecycleAction.Uninstall, false, "DELETE"), "Data removal requires explicit exact confirmation");
    Ensure(!SetupWorkflow.CanExecuteLifecycle(installation, "2.0.0", SetupLifecycleAction.Repair, false, "DELETE"), "Repair always preserves security data");
    Ensure(!SetupWorkflow.CanExecuteLifecycle(installation, "2.0.1", SetupLifecycleAction.Upgrade, false, "DELETE"), "Upgrade always preserves security data");
}
foreach (var kind in new[] { SetupInstallationKind.Fresh, SetupInstallationKind.Foreign })
    Ensure(SetupWorkflow.AllowedLifecycleActions(new(kind), "2.0.0").Count == 0, "Fresh or foreign state is never adopted as an existing installation");
Ensure(SetupWorkflow.AllowedLifecycleActions(new(SetupInstallationKind.RecoveryPending, "2.0.0"), "1.0.0").SequenceEqual(new[] { SetupLifecycleAction.Repair }), "Recovery restores the previous deployment independently of candidate version and forbids uninstall until recovered");
foreach (var marker in new[] { "STATE|Fresh|", "STATE|Installed|1.0.0", "STATE|Retained|1.0.0", "STATE|Foreign|", "STATE|RecoveryPending|", "STATE|RecoveryPending|1.0.0" })
    Ensure(Enum.IsDefined(SetupWorkflow.ParseInstallationState(marker).Kind), "Only exact fixed state markers are accepted");
foreach (var marker in new[] { "", "STATE|Unknown|", "STATE|fresh|", "STATE|1|1.0.0", "STATE|Fresh|1.0.0", "STATE|Foreign|1.0.0", "STATE|Installed|", "STATE|Retained|latest", "STATE|RecoveryPending|1", "STATE|Installed|01.0.0", "STATE|Installed|65536.0.0", "STATE|Installed|1.0.0|extra", "STATE|Installed|1.0.0\n", new string('x', 129) })
    await Reject(() => { _ = SetupWorkflow.ParseInstallationState(marker); return Task.CompletedTask; }, "Malformed or oversized state output cannot enable operations");
var lifecycle = new FakeLifecycle();
var current = new SetupInstallation(SetupInstallationKind.Installed, "1.0.0");
await SetupWorkflow.ExecuteLifecycleAsync(lifecycle, current, "1.0.0", SetupLifecycleAction.Repair, true, "", CancellationToken.None);
Ensure(lifecycle.Calls == 1 && lifecycle.Action == SetupLifecycleAction.Repair && lifecycle.PreserveData, "Validated lifecycle action reaches the backend without credentials");
foreach (var (installation, candidate, action, preserve, confirmation) in new[]
{
    (new SetupInstallation(SetupInstallationKind.Foreign), "1.0.0", SetupLifecycleAction.Uninstall, false, "DELETE"),
    (current, "0.9.0", SetupLifecycleAction.Upgrade, true, ""),
    (current, "1.0.0", SetupLifecycleAction.Uninstall, false, ""),
    (current, "1.0.0", SetupLifecycleAction.Repair, false, "DELETE"),
    (new SetupInstallation(SetupInstallationKind.RecoveryPending, "1.0.0"), "1.0.0", SetupLifecycleAction.Uninstall, true, "")
})
{
    lifecycle = new FakeLifecycle();
    await Reject(() => SetupWorkflow.ExecuteLifecycleAsync(lifecycle, installation, candidate, action, preserve, confirmation, CancellationToken.None), "Invalid lifecycle selection is refused before mutation");
    Ensure(lifecycle.Calls == 0, "Refused selection cannot reach a privileged backend");
}
using (var cancelLifecycle = new CancellationTokenSource())
{
    cancelLifecycle.Cancel(); lifecycle = new FakeLifecycle();
    try { await SetupWorkflow.ExecuteLifecycleAsync(lifecycle, current, "1.0.0", SetupLifecycleAction.Uninstall, false, "DELETE", cancelLifecycle.Token); throw new InvalidOperationException("Canceled lifecycle accepted"); }
    catch (OperationCanceledException) { assertions++; }
    Ensure(lifecycle.Calls == 0, "Canceled data-removal request never reaches the backend");
}
using (var cancelLifecycle = new CancellationTokenSource())
{
    lifecycle = new FakeLifecycle { AfterExecute = cancelLifecycle.Cancel };
    try { await SetupWorkflow.ExecuteLifecycleAsync(lifecycle, current, "1.0.0", SetupLifecycleAction.Repair, true, "", cancelLifecycle.Token); throw new InvalidOperationException("Canceled lifecycle completion accepted"); }
    catch (OperationCanceledException) { assertions++; }
    Ensure(lifecycle.Calls == 1, "Canceled completion is not rendered as a successful operation");
}

var sequence = new List<string>(); var fake = new FakeWorker(sequence); var administrator = new FakeAdministrator(sequence); var issuer = new FakeIssuer(sequence);
await SetupWorkflow.InstallAsync(fake, administrator, issuer, " operator ", "synthetic-password".AsMemory(), new SilentProgress(), CancellationToken.None);
Ensure(sequence.SequenceEqual(new[] { "prepare", "state", "initialize:operator", "start", "issue:operator", "complete" }), "Administrator bootstrap and Core start precede trusted enrollment issuance and token-only completion");
Ensure(issuer.Password.Span.SequenceEqual("synthetic-password".AsSpan()), "Only the trusted issuer receives the administrator password after Core is running");
Ensure(fake.ReceivedToken == oneUseToken && fake.HeldToken.Span.IndexOfAnyExcept('\0') == -1, "Completion receives exactly the enrollment token and workflow clears its mutable storage");
foreach (var state in Enum.GetValues<AdministratorSetupState>().Where(value => value != AdministratorSetupState.Required))
{
    sequence.Clear(); administrator = new FakeAdministrator(sequence) { State = state };
    await Reject(() => SetupWorkflow.InstallAsync(fake, administrator, issuer, "operator", "synthetic-password".AsMemory(), new SilentProgress(), CancellationToken.None), "Unknown/existing administrator refused");
    Ensure(sequence.SequenceEqual(new[] { "prepare", "state" }), "No overwrite or service completion");
}
foreach (var result in Enum.GetValues<AdministratorSetupResult>().Where(value => value != AdministratorSetupResult.Created))
{
    sequence.Clear(); administrator = new FakeAdministrator(sequence) { Result = result };
    await Reject(() => SetupWorkflow.InstallAsync(fake, administrator, issuer, "operator", "synthetic-password".AsMemory(), new SilentProgress(), CancellationToken.None), "Raced/invalid creation blocks deployment");
    Ensure(sequence.SequenceEqual(new[] { "prepare", "state", "initialize:operator" }), "No service start, credential issuance or completion after bootstrap failure");
}
sequence.Clear();
await Reject(() => SetupWorkflow.InstallAsync(fake, new FakeAdministrator(sequence), issuer, "operator", "short".AsMemory(), new SilentProgress(), CancellationToken.None), "Invalid input rejected before filesystem work");
Ensure(sequence.Count == 0, "No prepare for invalid credentials");
foreach (var failure in new[] { "prepare", "start", "issue", "complete" })
{
    sequence.Clear(); fake = new FakeWorker(sequence) { Failure = failure }; issuer = new FakeIssuer(sequence) { Fail = failure == "issue" };
    await Reject(() => SetupWorkflow.InstallAsync(fake, new FakeAdministrator(sequence), issuer, "operator", "synthetic-password".AsMemory(), new SilentProgress(), CancellationToken.None), "Failed step blocks subsequent deployment");
    var expected = new[] { "prepare", "state", "initialize:operator", "start", "issue:operator", "complete" };
    var last = Array.IndexOf(expected, failure == "issue" ? "issue:operator" : failure);
    Ensure(sequence.SequenceEqual(expected.Take(last + 1)), "A failing stage cannot continue to later stages");
    if (failure == "complete") Ensure(fake.HeldToken.Span.IndexOfAnyExcept('\0') == -1, "Token wiped even if installation fails");
}
foreach (var malformed in new[] { "", new string('g', 64), new string('a', 63), new string('a', 65) })
{
    sequence.Clear(); fake = new FakeWorker(sequence); issuer = new FakeIssuer(sequence) { IssuedToken = malformed };
    await Reject(() => SetupWorkflow.InstallAsync(fake, new FakeAdministrator(sequence), issuer, "operator", "synthetic-password".AsMemory(), new SilentProgress(), CancellationToken.None), "Malformed issuance refuses completion");
    Ensure(sequence.SequenceEqual(new[] { "prepare", "state", "initialize:operator", "start", "issue:operator" }), "Worker never receives malformed enrollment response");
}
foreach (var boundary in new[] { "before", "prepare", "state", "initialize", "start", "issue", "complete" })
{
    using var cancellation = new CancellationTokenSource();
    sequence.Clear();
    fake = new FakeWorker(sequence) { AfterPrepare = boundary == "prepare" ? cancellation.Cancel : null, AfterStart = boundary == "start" ? cancellation.Cancel : null, AfterComplete = boundary == "complete" ? cancellation.Cancel : null };
    administrator = new FakeAdministrator(sequence) { AfterState = boundary == "state" ? cancellation.Cancel : null, AfterInitialize = boundary == "initialize" ? cancellation.Cancel : null };
    issuer = new FakeIssuer(sequence) { AfterIssue = boundary == "issue" ? cancellation.Cancel : null };
    if (boundary == "before") cancellation.Cancel();
    try { await SetupWorkflow.InstallAsync(fake, administrator, issuer, "operator", "synthetic-password".AsMemory(), new SilentProgress(), cancellation.Token); throw new InvalidOperationException("Canceled workflow accepted"); }
    catch (OperationCanceledException) { assertions++; }
    var expected = new[] { "prepare", "state", "initialize:operator", "start", "issue:operator", "complete" };
    var last = boundary switch { "before" => -1, "initialize" => 2, "issue" => 4, _ => Array.IndexOf(expected, boundary) };
    Ensure(sequence.SequenceEqual(expected.Take(last + 1)), "Cancellation at each boundary prevents the next credential or installation operation");
    if (boundary == "complete") Ensure(fake.HeldToken.Span.IndexOfAnyExcept('\0') == -1, "Token wiped even when completion is canceled");
}
assertions += await EnrollmentProtocolTests.RunAsync();
Console.WriteLine($"Setup foundation: {assertions} assertions passed.");

sealed class SilentProgress : IProgress<string> { public void Report(string value) { } }
sealed class FakeLifecycle : ISetupLifecycleBackend
{
    public int Calls { get; private set; }
    public SetupLifecycleAction Action { get; private set; }
    public bool PreserveData { get; private set; }
    public Action? AfterExecute { get; init; }
    public Task<SetupInstallation> InspectAsync(CancellationToken token) => Task.FromResult(new SetupInstallation(SetupInstallationKind.Installed, "1.0.0"));
    public Task<SetupLifecycleResult> ExecuteAsync(SetupLifecycleAction action, bool preserveData, CancellationToken token)
    {
        token.ThrowIfCancellationRequested(); Calls++; Action = action; PreserveData = preserveData; AfterExecute?.Invoke(); return Task.FromResult(new SetupLifecycleResult(true));
    }
}
sealed class FakeWorker(List<string> sequence) : ISetupWorker
{
    public Action? AfterPrepare { get; init; }
    public Action? AfterStart { get; init; }
    public Action? AfterComplete { get; init; }
    public string? Failure { get; init; }
    public ReadOnlyMemory<char> HeldToken { get; private set; }
    public string? ReceivedToken { get; private set; }
    public Task PrepareCoreAsync(CancellationToken token) { token.ThrowIfCancellationRequested(); sequence.Add("prepare"); if (Failure == "prepare") throw new InvalidDataException(); AfterPrepare?.Invoke(); return Task.CompletedTask; }
    public Task StartCoreAsync(CancellationToken token) { token.ThrowIfCancellationRequested(); sequence.Add("start"); if (Failure == "start") throw new InvalidDataException(); AfterStart?.Invoke(); return Task.CompletedTask; }
    public Task CompleteAsync(ReadOnlyMemory<char> enrollmentToken, CancellationToken token)
    {
        token.ThrowIfCancellationRequested(); sequence.Add("complete"); HeldToken = enrollmentToken; ReceivedToken = new string(enrollmentToken.Span);
        if (Failure == "complete") throw new InvalidDataException(); AfterComplete?.Invoke(); return Task.CompletedTask;
    }
}
sealed class FakeAdministrator(List<string> sequence) : IAdministratorSetupClient
{
    public AdministratorSetupState State { get; init; } = AdministratorSetupState.Required;
    public AdministratorSetupResult Result { get; init; } = AdministratorSetupResult.Created;
    public Action? AfterState { get; init; }
    public Action? AfterInitialize { get; init; }
    public Task<AdministratorSetupState> GetStateAsync(CancellationToken token) { token.ThrowIfCancellationRequested(); sequence.Add("state"); AfterState?.Invoke(); return Task.FromResult(State); }
    public Task<AdministratorSetupResult> InitializeAsync(string username, ReadOnlyMemory<char> password, CancellationToken token) { token.ThrowIfCancellationRequested(); sequence.Add("initialize:" + username); AfterInitialize?.Invoke(); return Task.FromResult(Result); }
    public void Dispose() { }
}
sealed class FakeIssuer(List<string> sequence) : ISetupEnrollmentIssuer
{
    public string IssuedToken { get; init; } = new string('a', 64);
    public bool Fail { get; init; }
    public Action? AfterIssue { get; init; }
    public ReadOnlyMemory<char> Password { get; private set; }
    public Task<string> IssueAsync(string username, ReadOnlyMemory<char> password, CancellationToken token)
    {
        token.ThrowIfCancellationRequested(); sequence.Add("issue:" + username); Password = password;
        if (Fail) throw new InvalidDataException(); AfterIssue?.Invoke(); return Task.FromResult(IssuedToken);
    }
}
