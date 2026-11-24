using SentinelAI.Contracts.Overview;

namespace SentinelAI.Desktop.Foundation;

public interface IOperationsOverviewClient
{
    Task<DeviceReadResult<OperationsOverviewSnapshot>> GetOperationsOverviewAsync(CancellationToken cancellationToken);
}
