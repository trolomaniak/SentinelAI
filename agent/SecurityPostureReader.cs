using SentinelAI.Contracts.Inventory;

namespace SentinelAI.Agent;

/// <summary>Reads the bounded security posture allowlist used by inventory and posture monitoring.</summary>
public interface ISecurityPostureReader
{
    SecurityPostureInventory Read();
}

public sealed class SecurityPostureReader : ISecurityPostureReader
{
    public SecurityPostureInventory Read() => OperatingSystem.IsWindows()
        ? WindowsSecurityConfigurationCollector.CollectPosture()
        : new SecurityPostureInventory(null, null, null);
}
