using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using Microsoft.Win32;
using SentinelAI.Contracts.Inventory;

namespace SentinelAI.Agent;

public sealed class InventoryCollector
{
    private const int MaximumDisks = 16;

    public InventoryReport Collect(Guid endpointId)
    {
        if (endpointId == Guid.Empty)
        {
            throw new ArgumentException("An endpoint ID is required.", nameof(endpointId));
        }

        var isWindows = OperatingSystem.IsWindows();
        var windowsOs = isWindows ? WindowsOperatingSystemCollector.Collect() : null;
        return new InventoryReport(
            endpointId,
            DateTimeOffset.UtcNow,
            typeof(InventoryCollector).Assembly.GetName().Version?.ToString() ?? "0.0.0.0",
            Environment.MachineName,
            windowsOs?.Name ?? RuntimeInformation.OSDescription,
            windowsOs?.Version ?? Environment.OSVersion.Version.ToString(),
            RuntimeInformation.OSArchitecture.ToString(),
            new CpuInventory(isWindows ? ReadCpuModel() : null, Environment.ProcessorCount),
            isWindows ? ReadInstalledRamBytes() : null,
            isWindows ? ReadFixedDisks() : [],
            isWindows
                ? WindowsSecurityConfigurationCollector.CollectPosture()
                : new SecurityPostureInventory(null, null, null),
            windowsOs?.DisplayVersion,
            windowsOs?.InstallationType);
    }

    [SupportedOSPlatform("windows")]
    private static string? ReadCpuModel()
    {
        try
        {
            using var processor = Registry.LocalMachine.OpenSubKey(
                @"HARDWARE\DESCRIPTION\System\CentralProcessor\0");
            var model = (processor?.GetValue("ProcessorNameString") as string)?.Trim();
            return string.IsNullOrWhiteSpace(model) ? null : model[..Math.Min(model.Length, 256)];
        }
        catch (Exception exception) when (IsUnavailable(exception))
        {
            return null;
        }
    }

    [SupportedOSPlatform("windows")]
    private static long? ReadInstalledRamBytes()
    {
        try
        {
            var status = new MemoryStatus { Length = (uint)Marshal.SizeOf<MemoryStatus>() };
            return GlobalMemoryStatusEx(ref status) && status.TotalPhysical is > 0 and <= long.MaxValue
                ? (long)status.TotalPhysical
                : null;
        }
        catch (Exception exception) when (IsUnavailable(exception))
        {
            return null;
        }
    }

    [SupportedOSPlatform("windows")]
    private static IReadOnlyList<DiskInventory> ReadFixedDisks()
    {
        DriveInfo[] drives;
        try
        {
            drives = DriveInfo.GetDrives();
        }
        catch (Exception exception) when (IsUnavailable(exception))
        {
            return [];
        }

        var disks = new List<DiskInventory>();
        // Windows exposes at most 26 drive letters. Examine those entries, but
        // include no more than 16 fixed drives in the report.
        foreach (var drive in drives.Take(26))
        {
            if (disks.Count == MaximumDisks)
            {
                break;
            }

            try
            {
                if (drive.DriveType != DriveType.Fixed || !drive.IsReady)
                {
                    continue;
                }

                var totalBytes = drive.TotalSize;
                var availableBytes = drive.AvailableFreeSpace;
                if (totalBytes > 0 && availableBytes >= 0 && availableBytes <= totalBytes)
                {
                    disks.Add(new DiskInventory(drive.Name, totalBytes, availableBytes));
                }
            }
            catch (Exception exception) when (IsUnavailable(exception))
            {
                // A missing or inaccessible drive does not prevent collecting other drives.
            }
        }

        return disks;
    }

    private static bool IsUnavailable(Exception exception) =>
        exception is IOException or UnauthorizedAccessException or System.Security.SecurityException or
            System.ComponentModel.Win32Exception or ExternalException or PlatformNotSupportedException or
            DllNotFoundException or EntryPointNotFoundException;

    [StructLayout(LayoutKind.Sequential)]
    private struct MemoryStatus
    {
        public uint Length;
        public uint MemoryLoad;
        public ulong TotalPhysical;
        public ulong AvailablePhysical;
        public ulong TotalPageFile;
        public ulong AvailablePageFile;
        public ulong TotalVirtual;
        public ulong AvailableVirtual;
        public ulong AvailableExtendedVirtual;
    }

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool GlobalMemoryStatusEx(ref MemoryStatus status);
}
