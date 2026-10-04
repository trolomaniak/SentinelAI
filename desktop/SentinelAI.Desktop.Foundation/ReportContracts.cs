using System.Globalization;
using System.Security.Cryptography;

namespace SentinelAI.Desktop.Foundation;

public sealed record ReportDateRange(DateOnly From, DateOnly To)
{
    public bool IsValid => From <= To && To < DateOnly.MaxValue && To.DayNumber - From.DayNumber < 366;
    public string SuggestedFileName => FormattableString.Invariant(
        $"SentinelAI-security-report-{From:yyyy-MM-dd}-{To:yyyy-MM-dd}.html");
    public string DisplayText => From.ToString("yyyy-MM-dd", CultureInfo.InvariantCulture) + " through " +
        To.ToString("yyyy-MM-dd", CultureInfo.InvariantCulture) + " (inclusive UTC dates)";
}

/// <summary>Owned Core HTML bytes for explicit saving; never rendered by Desktop.</summary>
public sealed class SecurityReportDocument : IDisposable
{
    public const int MaximumBytes = 8 * 1024 * 1024;
    private readonly object _gate = new();
    private byte[]? _content;
    public ReportDateRange Period { get; }
    public string SuggestedFileName => Period.SuggestedFileName;
    public int ByteCount { get { lock (_gate) return _content?.Length ?? 0; } }

    public SecurityReportDocument(ReportDateRange period, ReadOnlySpan<byte> content)
    {
        ArgumentNullException.ThrowIfNull(period);
        if (!period.IsValid || content.Length is < 1 or > MaximumBytes)
            throw new ArgumentException("A valid bounded report is required.");
        Period = period;
        _content = content.ToArray();
    }

    // A saver takes a temporary owned copy only after destination confirmation,
    // checks cancellation and erases that copy after its write completes.
    public byte[] CopyContent()
    {
        lock (_gate)
        {
            ObjectDisposedException.ThrowIf(_content is null, this);
            return _content!.ToArray();
        }
    }
    public void Dispose()
    {
        lock (_gate)
        {
            if (_content is null) return;
            CryptographicOperations.ZeroMemory(_content);
            _content = null;
        }
    }
}

public enum ReportOutcome
{
    Success, Unauthenticated, Unavailable, UntrustedConnection, InvalidResponse, InvalidPeriod, CapacityExceeded, TooLarge
}
public sealed record SecurityReportResult(ReportOutcome Outcome, SecurityReportDocument? Document = null);
public interface IReportsClient
{
    Task<SecurityReportResult> GenerateSecurityReportAsync(ReportDateRange period, CancellationToken cancellationToken);
}
public enum ReportSaveOutcome { Saved, Cancelled, Failed }
public sealed record ReportSaveResult(ReportSaveOutcome Outcome, string? FileName = null);
public interface IReportSaveService
{
    Task<ReportSaveResult> SaveAsync(SecurityReportDocument document, CancellationToken cancellationToken);
}
