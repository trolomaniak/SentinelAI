using System.Globalization;
using System.Text;
using System.Threading.Channels;
using SentinelAI.Desktop.Foundation;

internal static class ReportsViewModelTests
{
    private static readonly TimeSpan Deadline = TimeSpan.FromSeconds(5);
    private static readonly DateTimeOffset Now = new(2026, 10, 4, 12, 0, 0, TimeSpan.Zero);
    private static int assertions;

    public static async Task<int> RunAsync()
    {
        assertions = 0;
        await DefaultsAndDateValidationAsync();
        await GenerationAndMetadataAsync();
        await GenerationFailuresAsync();
        await SavingAndSharedOwnershipAsync();
        await ObsoleteGenerationAsync();
        await ClearCancelsSaveAndErasesContentAsync();
        await ObsoleteSaveCannotAffectNewGenerationAsync();
        await CurrentExpiryAsync();
        Console.WriteLine($"Desktop reports: {assertions} assertions passed.");
        return assertions;
    }

    private static async Task DefaultsAndDateValidationAsync()
    {
        foreach (var (now, from, to) in new[]
                 {
                     (Now, new DateTime(2026, 9, 1), new DateTime(2026, 9, 30)),
                     (new DateTimeOffset(2024, 3, 1, 0, 0, 0, TimeSpan.Zero), new DateTime(2024, 2, 1), new DateTime(2024, 2, 29)),
                     (new DateTimeOffset(2025, 3, 1, 0, 0, 0, TimeSpan.Zero), new DateTime(2025, 2, 1), new DateTime(2025, 2, 28)),
                     (new DateTimeOffset(2025, 1, 1, 0, 0, 0, TimeSpan.Zero), new DateTime(2024, 12, 1), new DateTime(2024, 12, 31)),
                     // The provider's displayed local date is January, but UTC is
                     // still December: the previous complete UTC month is November.
                     (new DateTimeOffset(2026, 1, 1, 0, 0, 0, TimeSpan.FromHours(14)), new DateTime(2025, 11, 1), new DateTime(2025, 11, 30)),
                     (DateTimeOffset.MaxValue, new DateTime(9999, 11, 1), new DateTime(9999, 11, 30))
                 })
        {
            var service = new ControlledServices();
            using var vm = new ReportsViewModel(service, service, new Clock(now));
            Check(vm.FromDate == from && vm.ToDate == to && vm.FromDate.Value.Kind == DateTimeKind.Unspecified &&
                  vm.ToDate.Value.Kind == DateTimeKind.Unspecified,
                "Reports did not default to the previous complete UTC month across a calendar boundary.");
            Check(vm.CanGenerate && !vm.CanSave && !vm.HasReport && vm.State == ReportState.NotGenerated &&
                  service.GenerateCalls == 0 && service.SaveCalls == 0,
                "Reports generated or saved automatically when the workspace opened.");
        }
        var client = new ControlledServices();
        using var minimum = new ReportsViewModel(client, client, new Clock(DateTimeOffset.MinValue));
        Check(minimum.FromDate is null && minimum.ToDate is null && !minimum.CanGenerate && minimum.ValidationText.Length > 0,
            "The earliest representable month invented a previous period or overflowed its defaults.");
        var clock = new Clock(Now);
        using var model = new ReportsViewModel(client, client, clock);
        foreach (var (from, to, valid) in new (DateTime?, DateTime?, bool)[]
                 {
                     (null, new DateTime(2024, 1, 1), false),
                     (new DateTime(2024, 1, 1), null, false),
                     (new DateTime(2024, 1, 2), new DateTime(2024, 1, 1), false),
                     (new DateTime(2024, 1, 1), new DateTime(2024, 12, 31), true),
                     (new DateTime(2024, 1, 1), new DateTime(2025, 1, 1), false),
                     (new DateTime(2023, 3, 1), new DateTime(2024, 2, 29), true),
                     (new DateTime(2023, 3, 1), new DateTime(2024, 3, 1), false),
                     (DateTime.MinValue, DateTime.MinValue, true),
                     (new DateTime(9999, 12, 30), new DateTime(9999, 12, 30), true),
                     (DateTime.MaxValue, DateTime.MaxValue, false)
                 })
        {
            model.FromDate = from;
            model.ToDate = to;
            Check(model.CanGenerate == valid && (model.ValidationText.Length == 0) == valid,
                "Report date validation disagreed with the inclusive 366-day Core boundary.");
            if (!valid)
            {
                await Done(model.GenerateAsync());
                Check(model.ErrorText.Length > 0 && !model.HasReport,
                    "An invalid period attempted generation or hid its validation error.");
            }
        }
        Check(client.GenerateCalls == 0 && client.SaveCalls == 0,
            "Date edits or an invalid period caused a report request or export.");
        model.FromDate = new DateTime(2024, 2, 29, 18, 30, 0, DateTimeKind.Local);
        model.ToDate = new DateTime(2024, 2, 29, 23, 59, 0, DateTimeKind.Utc);
        var generating = model.GenerateAsync();
        var request = await client.TakeGenerateAsync();
        Check(request.Period == new ReportDateRange(new DateOnly(2024, 2, 29), new DateOnly(2024, 2, 29)),
            "DatePicker dates were converted through local timezone or retained their time component.");
        request.Completion.SetResult(new(ReportOutcome.Unavailable));
        await Done(generating);
        clock.UtcNow = new DateTimeOffset(2026, 11, 1, 0, 0, 0, TimeSpan.Zero);
        model.Clear();
        Check(model.FromDate == new DateTime(2026, 10, 1) && model.ToDate == new DateTime(2026, 10, 31),
            "A fresh report session retained old dates instead of refreshing UTC-month defaults.");
        Throws<ArgumentNullException>(() => _ = new ReportsViewModel(null!, client), "A missing report client was accepted.");
        Throws<ArgumentNullException>(() => _ = new ReportsViewModel(client, null!), "A missing report saver was accepted.");
    }

    private static async Task GenerationAndMetadataAsync()
    {
        var client = new ControlledServices();
        using var vm = new ReportsViewModel(client, client, new Clock(Now));
        var changes = new HashSet<string?>();
        vm.PropertyChanged += (_, args) => changes.Add(args.PropertyName);
        var generating = vm.GenerateAsync();
        var request = await client.TakeGenerateAsync();
        Check(vm.State == ReportState.Generating && vm.IsGenerating && vm.IsBusy && !vm.CanGenerate && !vm.CanSave &&
              !vm.HasReport && vm.ByteCount == 0, "Report generation did not expose a bounded explicit busy state.");
        Check(ReferenceEquals(generating, vm.GenerateAsync()) && client.GenerateCalls == 1,
            "Concurrent Generate actions sent duplicate report requests.");
        await Done(vm.SaveAsync());
        Check(client.SaveCalls == 0, "A report was saved before generation completed.");
        var content = Encoding.UTF8.GetBytes("<html><script>synthetic-report-body</script></html>");
        var report = new SecurityReportDocument(request.Period, content);
        Array.Clear(content);
        request.Completion.SetResult(new(ReportOutcome.Success, report));
        await Done(generating);
        var copy = report.CopyContent();
        try { Check(Encoding.UTF8.GetString(copy).Contains("synthetic-report-body", StringComparison.Ordinal), "The document retained caller-owned transport bytes instead of its own copy."); }
        finally { Array.Clear(copy); }
        Check(vm.State == ReportState.Ready && vm.HasReport && vm.CanGenerate && vm.CanSave && !vm.IsBusy &&
              vm.ByteCount == report.ByteCount && vm.PeriodText == request.Period.DisplayText && vm.SuggestedFileName == request.Period.SuggestedFileName,
            "A generated report lost its safe period, filename, size or explicit save action.");
        Check(!string.Join('|', vm.PeriodText, vm.SuggestedFileName, vm.ReportSizeText, vm.StatusText, vm.ErrorText)
                  .Contains("synthetic-report-body", StringComparison.Ordinal) &&
              !typeof(ReportsViewModel).GetProperties().Any(property => property.PropertyType == typeof(SecurityReportDocument) || property.PropertyType == typeof(byte[])),
            "The report workspace exposed HTML content instead of metadata only.");
        Check(changes.Contains(nameof(vm.HasReport)) && changes.Contains(nameof(vm.CanSave)) && changes.Contains(nameof(vm.State)),
            "Report completion omitted binding notifications for its metadata or actions.");
        vm.FromDate = vm.FromDate!.Value.AddHours(17);
        vm.ToDate = DateTime.SpecifyKind(vm.ToDate!.Value, DateTimeKind.Utc);
        Check(vm.HasReport && report.ByteCount > 0 && client.GenerateCalls == 1,
            "A DatePicker's unchanged calendar date invalidated the completed report.");

        var regenerate = vm.GenerateAsync();
        var next = await client.TakeGenerateAsync();
        Check(report.ByteCount == 0 && !vm.HasReport && vm.PeriodText.Length == 0 && vm.SuggestedFileName.Length == 0,
            "Explicit regeneration retained the previous HTML or successful metadata.");
        Throws<ObjectDisposedException>(() => report.CopyContent(), "An obsolete generated report remained readable.");
        var previousCulture = CultureInfo.CurrentCulture;
        try
        {
            CultureInfo.CurrentCulture = CultureInfo.GetCultureInfo("pl-PL");
            var bytes = new byte[1024];
            next.Completion.SetResult(new(ReportOutcome.Success, new SecurityReportDocument(next.Period, bytes)));
            await Done(regenerate);
            Check(vm.ReportSizeText == "1,024 bytes", "Report byte-size metadata depended on machine culture.");
        }
        finally { CultureInfo.CurrentCulture = previousCulture; }
        Check(client.SaveCalls == 0, "Generating or regenerating a report exported it automatically.");
    }

    private static async Task GenerationFailuresAsync()
    {
        var client = new ControlledServices();
        using var vm = new ReportsViewModel(client, client, new Clock(Now));
        foreach (var outcome in new[]
                 {
                     ReportOutcome.Unavailable, ReportOutcome.UntrustedConnection, ReportOutcome.InvalidResponse,
                     ReportOutcome.InvalidPeriod, ReportOutcome.CapacityExceeded, ReportOutcome.TooLarge, (ReportOutcome)999
                 })
        {
            var generating = vm.GenerateAsync();
            var request = await client.TakeGenerateAsync();
            var unwanted = Document(request.Period);
            request.Completion.SetResult(new(outcome, unwanted));
            await Done(generating);
            Check(vm.State == ReportState.Unavailable && !vm.HasReport && vm.CanGenerate && !vm.CanSave &&
                  vm.ErrorText.Length > 0 && vm.ByteCount == 0, "A failed report response retained content or disabled explicit recovery.");
            Check(unwanted.ByteCount == 0, "A document accompanying a failed report response was not disposed.");
            if (outcome == ReportOutcome.CapacityExceeded)
                Check(vm.ErrorText.Contains("capacity", StringComparison.Ordinal) && vm.ErrorText.Contains("dataset", StringComparison.Ordinal),
                    "Core's report-capacity rejection was not explained explicitly.");
            if (outcome == ReportOutcome.TooLarge)
                Check(vm.ErrorText.Contains("size", StringComparison.Ordinal), "An oversized report failure was silently hidden.");
        }
        foreach (var malformed in new[] { "missing", "mismatched", "disposed" })
        {
            var generating = vm.GenerateAsync();
            var request = await client.TakeGenerateAsync();
            SecurityReportDocument? document = malformed == "missing" ? null : Document(malformed == "mismatched"
                ? new ReportDateRange(request.Period.From.AddDays(1), request.Period.To) : request.Period);
            if (malformed == "disposed") document!.Dispose();
            request.Completion.SetResult(new(ReportOutcome.Success, document));
            await Done(generating);
            Check(vm.State == ReportState.Unavailable && vm.ErrorText.Contains("invalid", StringComparison.Ordinal) &&
                  !vm.HasReport && (document is null || document.ByteCount == 0),
                "A success response with missing, mismatched or disposed content became exportable.");
        }
        var failed = vm.GenerateAsync();
        (await client.TakeGenerateAsync()).Completion.SetException(new IOException("synthetic-private-server-error"));
        await Done(failed);
        Check(vm.State == ReportState.Unavailable && !vm.ErrorText.Contains("private", StringComparison.Ordinal),
            "An unexpected report exception escaped or exposed its private diagnostic.");
        var recovered = await ReadyAsync(vm, client);
        Check(vm.CanSave && vm.ErrorText.Length == 0 && recovered.ByteCount > 0 && client.SaveCalls == 0,
            "Explicit generation could not recover from a report failure or saved automatically.");
    }

    private static async Task SavingAndSharedOwnershipAsync()
    {
        var client = new ControlledServices();
        var vm = new ReportsViewModel(client, client, new Clock(Now));
        var report = await ReadyAsync(vm, client);
        var saving = vm.SaveAsync();
        var request = await client.TakeSaveAsync();
        Check(ReferenceEquals(request.Document, report) && report.ByteCount > 0 && vm.IsSaving && vm.IsBusy &&
              !vm.IsGenerating && !vm.CanSave && !vm.CanGenerate,
            "Saving copied HTML before destination selection or failed to gate conflicting actions.");
        Check(ReferenceEquals(saving, vm.SaveAsync()) && client.SaveCalls == 1,
            "Concurrent Save actions opened duplicate exports.");
        await Done(vm.GenerateAsync());
        Check(client.GenerateCalls == 1, "Generate replaced a report while its destination dialog was pending.");
        const string literalFileName = "<Run>literal & report.html";
        request.Completion.SetResult(new(ReportSaveOutcome.Saved, literalFileName));
        await Done(saving);
        Check(vm.SaveStatusText.Contains(literalFileName, StringComparison.Ordinal) && vm.CanSave && vm.HasReport &&
              !vm.IsBusy && vm.ErrorText.Length == 0,
            "The saved filename was interpreted as content or the retained report could not be explicitly saved again.");
        foreach (var outcome in new[] { ReportSaveOutcome.Cancelled, ReportSaveOutcome.Failed, (ReportSaveOutcome)999 })
        {
            saving = vm.SaveAsync();
            request = await client.TakeSaveAsync();
            request.Completion.SetResult(new(outcome, "synthetic-private-failure-filename"));
            await Done(saving);
            Check(vm.HasReport && vm.CanSave && report.ByteCount > 0 && !vm.IsBusy,
                "A cancelled or failed destination selection destroyed the generated report or prevented explicit retry.");
            Check(!vm.SaveStatusText.Contains("private", StringComparison.Ordinal) && !vm.ErrorText.Contains("private", StringComparison.Ordinal),
                "A failed export disclosed an unconfirmed filename or diagnostic.");
            Check((vm.ErrorText.Length == 0) == (outcome == ReportSaveOutcome.Cancelled),
                "A user-cancelled save was reported as failure or an actual failure had no safe error.");
        }
        saving = vm.SaveAsync();
        (await client.TakeSaveAsync()).Completion.SetException(new IOException("synthetic-private-filesystem-error"));
        await Done(saving);
        Check(vm.CanSave && vm.ErrorText.Length > 0 && !vm.ErrorText.Contains("private", StringComparison.Ordinal),
            "A save exception escaped, leaked diagnostics or prevented explicit recovery.");
        saving = vm.SaveAsync();
        (await client.TakeSaveAsync()).Completion.SetResult(new(ReportSaveOutcome.Saved));
        await Done(saving);
        Check(vm.ErrorText.Length == 0 && vm.SaveStatusText == "Report saved." && client.GenerateCalls == 1,
            "Explicit export retry retained an old failure or regenerated the report automatically.");
        vm.Dispose();
        vm.Dispose();
        CheckCleared(vm, disposed: true);
        Check(report.ByteCount == 0 && client.DisposeCalls == 0,
            "Disposing Reports failed to erase retained HTML or disposed its shared client/saver.");
    }

    private static async Task ObsoleteGenerationAsync()
    {
        foreach (var reset in new[] { "edit", "clear", "dispose" })
        foreach (var outcome in new[] { ReportOutcome.Success, ReportOutcome.Unauthenticated })
        {
            var client = new ControlledServices();
            using var vm = new ReportsViewModel(client, client, new Clock(Now));
            var expired = 0;
            vm.SessionExpired += (_, _) => expired++;
            var oldTask = vm.GenerateAsync();
            var old = await client.TakeGenerateAsync();
            Reset(vm, reset);
            await old.CancellationObserved.Task.WaitAsync(Deadline);
            CheckCleared(vm, reset == "dispose");
            Task? newTask = null;
            GenerateRequest? current = null;
            if (reset != "dispose")
            {
                newTask = vm.GenerateAsync();
                current = await client.TakeGenerateAsync();
            }
            var stale = Document(old.Period);
            old.Completion.SetResult(new(outcome, stale));
            await Done(oldTask);
            Check(stale.ByteCount == 0 && expired == 0,
                "An obsolete report response retained HTML or expired a replacement session.");
            if (reset == "dispose") CheckCleared(vm, disposed: true);
            else
            {
                Check(vm.IsGenerating && vm.State == ReportState.Generating && !vm.HasReport && !vm.CanGenerate &&
                      vm.SaveStatusText.Length == 0, "An obsolete response overwrote or released the replacement generation.");
                var fresh = Document(current!.Period);
                current.Completion.SetResult(new(ReportOutcome.Success, fresh));
                await Done(newTask!);
                Check(vm.State == ReportState.Ready && vm.PeriodText == current.Period.DisplayText && vm.CanSave && expired == 0,
                    "A replacement generation could not complete after a stale success or 401.");
            }
            Check(client.SaveCalls == 0 && client.DisposeCalls == 0,
                "Canceling generation exported content or disposed shared services.");
        }
    }

    private static async Task ClearCancelsSaveAndErasesContentAsync()
    {
        foreach (var reset in new[] { "edit", "clear", "dispose" })
        {
            var client = new ControlledServices();
            using var vm = new ReportsViewModel(client, client, new Clock(Now));
            var report = await ReadyAsync(vm, client);
            var saving = vm.SaveAsync();
            var request = await client.TakeSaveAsync();
            Reset(vm, reset);
            await request.CancellationObserved.Task.WaitAsync(Deadline);
            CheckCleared(vm, reset == "dispose");
            Check(ReferenceEquals(request.Document, report) && request.Document.ByteCount == 0,
                "Clearing Reports left a saver's pending-dialog document readable.");
            Throws<OperationCanceledException>(() => request.Token.ThrowIfCancellationRequested(),
                "A destination dialog returning after clear could export old-session content.");
            Throws<ObjectDisposedException>(() => request.Document.CopyContent(),
                "A saver ignoring cancellation could still copy an erased report after destination selection.");
            request.Completion.SetResult(new(ReportSaveOutcome.Saved, "stale-save.html"));
            await Done(saving);
            CheckCleared(vm, reset == "dispose");
            Check(client.GenerateCalls == 1 && client.SaveCalls == 1 && client.DisposeCalls == 0,
                "A late save result regenerated content, retried export or disposed shared services.");
        }
    }

    private static async Task ObsoleteSaveCannotAffectNewGenerationAsync()
    {
        foreach (var outcome in new[] { ReportSaveOutcome.Saved, ReportSaveOutcome.Failed })
        {
            var client = new ControlledServices();
            using var vm = new ReportsViewModel(client, client, new Clock(Now));
            var oldDocument = await ReadyAsync(vm, client);
            var saving = vm.SaveAsync();
            var old = await client.TakeSaveAsync();
            vm.Clear();
            await old.CancellationObserved.Task.WaitAsync(Deadline);
            var generating = vm.GenerateAsync();
            var current = await client.TakeGenerateAsync();
            old.Completion.SetResult(new(outcome, "old-session.html"));
            await Done(saving);
            Check(oldDocument.ByteCount == 0 && vm.IsGenerating && !vm.IsSaving && !vm.HasReport &&
                  vm.ErrorText.Length == 0 && vm.SaveStatusText.Length == 0,
                "A late previous-session export result released, populated or contaminated the new generation.");
            current.Completion.SetResult(new(ReportOutcome.Success, Document(current.Period)));
            await Done(generating);
            Check(vm.CanSave && vm.State == ReportState.Ready && vm.SaveStatusText.Length == 0 && client.SaveCalls == 1,
                "The replacement report retained an old export confirmation or automatically saved.");
        }
    }

    private static async Task CurrentExpiryAsync()
    {
        var client = new ControlledServices();
        using var vm = new ReportsViewModel(client, client, new Clock(Now));
        var expired = 0;
        vm.SessionExpired += (_, _) => expired++;
        var previous = await ReadyAsync(vm, client);
        vm.FromDate = new DateTime(2024, 2, 1);
        vm.ToDate = new DateTime(2024, 2, 29);
        Check(previous.ByteCount == 0, "Editing dates retained the prior administrator's generated HTML.");
        var generating = vm.GenerateAsync();
        var request = await client.TakeGenerateAsync();
        var unwanted = Document(request.Period);
        request.Completion.SetResult(new(ReportOutcome.Unauthenticated, unwanted));
        await Done(generating);
        CheckCleared(vm);
        Check(expired == 1 && unwanted.ByteCount == 0 && vm.FromDate == new DateTime(2026, 9, 1),
            "A current authentication failure did not expire once, erase content and restore fresh-session defaults.");
        vm.Dispose();
        var from = vm.FromDate;
        vm.FromDate = DateTime.MinValue;
        await Done(vm.GenerateAsync());
        await Done(vm.SaveAsync());
        Check(vm.FromDate == from && client.GenerateCalls == 2 && client.SaveCalls == 0 && expired == 1 && client.DisposeCalls == 0,
            "A disposed report workspace accepted new operations or disposed shared services.");
    }

    private static async Task<SecurityReportDocument> ReadyAsync(ReportsViewModel vm, ControlledServices client)
    {
        var generating = vm.GenerateAsync();
        var request = await client.TakeGenerateAsync();
        var report = Document(request.Period);
        request.Completion.SetResult(new(ReportOutcome.Success, report));
        await Done(generating);
        return report;
    }
    private static SecurityReportDocument Document(ReportDateRange period) =>
        new(period, Encoding.UTF8.GetBytes("<!doctype html><p>Synthetic report</p>"));
    private static void Reset(ReportsViewModel vm, string reset)
    {
        if (reset == "dispose") vm.Dispose();
        else if (reset == "clear") vm.Clear();
        else vm.ToDate = vm.ToDate!.Value.AddDays(-1);
    }
    private static void CheckCleared(ReportsViewModel vm, bool disposed = false)
    {
        Check(vm.State == ReportState.NotGenerated && !vm.HasReport && vm.ByteCount == 0 &&
              vm.PeriodText.Length == 0 && vm.SuggestedFileName.Length == 0 && vm.ReportSizeText.Length == 0,
            "Cleared Reports retained HTML or generated-document metadata.");
        Check(!vm.IsBusy && !vm.IsGenerating && !vm.IsSaving && !vm.CanSave && vm.CanGenerate == !disposed &&
              vm.ErrorText.Length == 0 && vm.SaveStatusText.Length == 0,
            "Cleared Reports retained busy state, export feedback or obsolete actions.");
    }
    private static Task Done(Task task) => task.WaitAsync(Deadline);
    private static void Check(bool condition, string message)
    {
        assertions++;
        if (!condition) throw new InvalidOperationException(message);
    }
    private static void Throws<T>(Action action, string message) where T : Exception
    {
        try { action(); }
        catch (T) { assertions++; return; }
        throw new InvalidOperationException(message);
    }
    private sealed class Clock(DateTimeOffset utcNow) : TimeProvider
    {
        public DateTimeOffset UtcNow { get; set; } = utcNow;
        public override DateTimeOffset GetUtcNow() => UtcNow;
    }
    // Cancellation is observable, but responses deliberately finish regardless:
    // late Core or dialog completions must not depend on cooperative I/O.
    private class Request<T>
    {
        public Request(CancellationToken token)
        {
            Token = token;
            token.Register(() => CancellationObserved.TrySetResult());
        }
        public CancellationToken Token { get; }
        public TaskCompletionSource CancellationObserved { get; } = new(TaskCreationOptions.RunContinuationsAsynchronously);
        public TaskCompletionSource<T> Completion { get; } = new(TaskCreationOptions.RunContinuationsAsynchronously);
    }
    private sealed class GenerateRequest(ReportDateRange period, CancellationToken token) : Request<SecurityReportResult>(token)
    {
        public ReportDateRange Period { get; } = period;
    }
    private sealed class SaveRequest(SecurityReportDocument document, CancellationToken token) : Request<ReportSaveResult>(token)
    {
        public SecurityReportDocument Document { get; } = document;
    }
    private sealed class ControlledServices : IReportsClient, IReportSaveService, IDisposable
    {
        private readonly Channel<GenerateRequest> generations = Channel.CreateUnbounded<GenerateRequest>();
        private readonly Channel<SaveRequest> saves = Channel.CreateUnbounded<SaveRequest>();
        private int generateCalls, saveCalls, disposeCalls;
        public int GenerateCalls => Volatile.Read(ref generateCalls);
        public int SaveCalls => Volatile.Read(ref saveCalls);
        public int DisposeCalls => Volatile.Read(ref disposeCalls);
        public Task<GenerateRequest> TakeGenerateAsync() => generations.Reader.ReadAsync().AsTask().WaitAsync(Deadline);
        public Task<SaveRequest> TakeSaveAsync() => saves.Reader.ReadAsync().AsTask().WaitAsync(Deadline);
        public Task<SecurityReportResult> GenerateSecurityReportAsync(ReportDateRange period, CancellationToken cancellationToken)
        {
            var request = new GenerateRequest(period, cancellationToken);
            Interlocked.Increment(ref generateCalls);
            generations.Writer.TryWrite(request);
            return request.Completion.Task;
        }
        public Task<ReportSaveResult> SaveAsync(SecurityReportDocument document, CancellationToken cancellationToken)
        {
            var request = new SaveRequest(document, cancellationToken);
            Interlocked.Increment(ref saveCalls);
            saves.Writer.TryWrite(request);
            return request.Completion.Task;
        }
        public void Dispose() => Interlocked.Increment(ref disposeCalls);
    }
}
