namespace SentinelAI.Desktop.Foundation;

public enum CoreHealth
{
    Unavailable,
    Available
}

/// <summary>A local Core boundary; authentication and application data are added in later tasks.</summary>
public interface ICoreClient : IDisposable
{
    Task<CoreHealth> CheckHealthAsync(CancellationToken cancellationToken);
}
