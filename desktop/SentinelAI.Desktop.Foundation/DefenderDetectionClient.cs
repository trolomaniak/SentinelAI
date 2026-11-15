using SentinelAI.Contracts.DefenderDetections;

namespace SentinelAI.Desktop.Foundation;

/// <summary>Read-only, retained Microsoft Defender events from the selected endpoint.</summary>
public interface IDefenderDetectionsClient
{
    Task<DeviceReadResult<DefenderDetectionsView>> GetDefenderDetectionsAsync(Guid endpointId, int offset, int limit, CancellationToken cancellationToken);
}
