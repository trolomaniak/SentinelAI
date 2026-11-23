using SentinelAI.Contracts.Monitoring;

namespace SentinelAI.Desktop.Foundation;

public interface IMonitoringCoverageClient
{
    Task<DeviceReadResult<MonitoringEndpointPage>> GetMonitoringEndpointsAsync(int offset, int limit, bool issuesOnly, CancellationToken cancellationToken);
    Task<DeviceReadResult<MonitoringEndpointDetail>> GetMonitoringEndpointAsync(Guid endpointId, CancellationToken cancellationToken);
    Task<DeviceReadResult<MonitoringGapPage>> GetMonitoringGapsAsync(Guid endpointId, int offset, int limit, CancellationToken cancellationToken);
}
