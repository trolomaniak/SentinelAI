using System.ComponentModel;
using System.IO;
using System.Net;
using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;

namespace SentinelAI.Desktop.Services;

internal static class WindowsNativeCore
{
    internal sealed record ServiceRecord(string Image, string Account, uint State, int ProcessId);
    internal sealed record TcpRecord(uint State, IPAddress Address, int Port, IPAddress RemoteAddress, int RemotePort, int ProcessId);
    [StructLayout(LayoutKind.Sequential)] private struct ServiceConfiguration
    {
        public uint Type, Start, Error;
        public IntPtr Image, Group;
        public uint Tag;
        public IntPtr Dependencies, Account, DisplayName;
    }
    [StructLayout(LayoutKind.Sequential)] private struct ServiceStatus
    {
        public uint Type, State, Controls, ExitCode, SpecificExitCode, Checkpoint, WaitHint, ProcessId, Flags;
    }
    [StructLayout(LayoutKind.Sequential)] private struct TcpRow
    {
        public uint State, Address, Port, RemoteAddress, RemotePort, ProcessId;
    }
    [StructLayout(LayoutKind.Sequential)] private struct FileInformation
    {
        public uint Attributes, CreationLow, CreationHigh, AccessLow, AccessHigh, WriteLow, WriteHigh,
            Volume, SizeHigh, SizeLow, Links, IndexHigh, IndexLow;
    }
    [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)] private static extern IntPtr OpenSCManager(string? machine, string? database, uint access);
    [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)] private static extern IntPtr OpenService(IntPtr manager, string name, uint access);
    [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)] private static extern bool QueryServiceConfig(IntPtr service, IntPtr buffer, uint size, out uint required);
    [DllImport("advapi32.dll", SetLastError = true)] private static extern bool QueryServiceStatusEx(IntPtr service, int level, out ServiceStatus status, uint size, out uint required);
    [DllImport("advapi32.dll")] private static extern bool CloseServiceHandle(IntPtr handle);
    [DllImport("iphlpapi.dll")] private static extern uint GetExtendedTcpTable(IntPtr table, ref int size, bool ordered, int family, int tableClass, uint reserved);
    [DllImport("kernel32.dll", SetLastError = true)] private static extern SafeProcessHandle OpenProcess(uint access, bool inherit, int id);
    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)] private static extern bool QueryFullProcessImageName(SafeProcessHandle process, uint flags, System.Text.StringBuilder name, ref uint size);
    [DllImport("kernel32.dll", SetLastError = true)] private static extern bool GetExitCodeProcess(SafeProcessHandle process, out uint code);
    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)] private static extern SafeFileHandle CreateFile(string name, uint access, uint share, IntPtr security, uint creation, uint flags, IntPtr template);
    [DllImport("kernel32.dll", SetLastError = true)] private static extern bool GetFileInformationByHandle(SafeFileHandle file, out FileInformation information);
    [DllImport("shell32.dll", CharSet = CharSet.Unicode, SetLastError = true)] private static extern IntPtr CommandLineToArgvW(string command, out int count);
    [DllImport("kernel32.dll")] private static extern IntPtr LocalFree(IntPtr memory);
    [DllImport("ntdll.dll")] private static extern int NtQueryInformationProcess(SafeProcessHandle process, int informationClass, IntPtr information, int length, out int required);

    internal static ServiceRecord? ReadService()
    {
        var manager = OpenSCManager(null, null, 1);
        if (manager == IntPtr.Zero) throw new Win32Exception(Marshal.GetLastWin32Error());
        try
        {
            var service = OpenService(manager, "SentinelAICore", 5);
            if (service == IntPtr.Zero)
            {
                var error = Marshal.GetLastWin32Error();
                if (error == 1060) return null;
                throw new Win32Exception(error);
            }
            try
            {
                QueryServiceConfig(service, IntPtr.Zero, 0, out var required);
                if (required is 0 or > 65536) throw new InvalidDataException();
                var buffer = Marshal.AllocHGlobal(checked((int)required));
                try
                {
                    if (!QueryServiceConfig(service, buffer, required, out _) ||
                        !QueryServiceStatusEx(service, 0, out var status, (uint)Marshal.SizeOf<ServiceStatus>(), out _))
                        throw new Win32Exception(Marshal.GetLastWin32Error());
                    var configuration = Marshal.PtrToStructure<ServiceConfiguration>(buffer);
                    return new ServiceRecord(Marshal.PtrToStringUni(configuration.Image) ?? "", Marshal.PtrToStringUni(configuration.Account) ?? "", status.State, checked((int)status.ProcessId));
                }
                finally { Marshal.FreeHGlobal(buffer); }
            }
            finally { CloseServiceHandle(service); }
        }
        finally { CloseServiceHandle(manager); }
    }

    internal static IReadOnlyList<TcpRecord> TcpConnections()
    {
        var length = 0;
        var result = GetExtendedTcpTable(IntPtr.Zero, ref length, false, 2, 5, 0);
        if (result != 122 || length is < 4 or > 8 * 1024 * 1024) throw new InvalidDataException();
        for (var attempt = 0; attempt < 3; attempt++)
        {
            var buffer = Marshal.AllocHGlobal(length);
            try
            {
                result = GetExtendedTcpTable(buffer, ref length, false, 2, 5, 0);
                if (result == 122 && length <= 8 * 1024 * 1024) continue;
                if (result != 0) throw new Win32Exception(checked((int)result));
                var count = Marshal.ReadInt32(buffer);
                var stride = Marshal.SizeOf<TcpRow>();
                if (count < 0 || count > 100000 || 4L + count * (long)stride > length) throw new InvalidDataException();
                var rows = new List<TcpRecord>(count);
                for (var index = 0; index < count; index++)
                {
                    var row = Marshal.PtrToStructure<TcpRow>(IntPtr.Add(buffer, 4 + index * stride));
                    rows.Add(new TcpRecord(row.State, new IPAddress(BitConverter.GetBytes(row.Address)), Port(row.Port), new IPAddress(BitConverter.GetBytes(row.RemoteAddress)), Port(row.RemotePort), checked((int)row.ProcessId)));
                }
                return rows;
            }
            finally { Marshal.FreeHGlobal(buffer); }
        }
        throw new IOException("Core connection ownership could not be inspected.");
    }
    private static int Port(uint value) => (int)(((value & 255) << 8) | ((value >> 8) & 255));

    internal static SafeProcessHandle HoldCoreProcess(int processId)
    {
        var process = OpenProcess(0x1000, false, processId);
        try
        {
            if (process.IsInvalid) throw new Win32Exception(Marshal.GetLastWin32Error());
            if (!GetExitCodeProcess(process, out var code) || code != 259) throw new InvalidDataException();
            var name = new System.Text.StringBuilder(32768);
            var size = (uint)name.Capacity;
            if (!QueryFullProcessImageName(process, 0, name, ref size) ||
                !string.Equals(name.ToString(), WindowsInstallationTrust.ExecutablePath, StringComparison.OrdinalIgnoreCase)) throw new InvalidDataException();
            return process;
        }
        catch { process.Dispose(); throw; }
    }
    internal static bool IsRunning(SafeProcessHandle process) => !process.IsInvalid && !process.IsClosed && GetExitCodeProcess(process, out var code) && code == 259;
    internal static bool MatchesImageCommand(string command)
    {
        var arguments = SplitCommand(command);
        return arguments.Length == 3 && string.Equals(arguments[0], WindowsInstallationTrust.ExecutablePath, StringComparison.OrdinalIgnoreCase) &&
               arguments[1] == "--config" && string.Equals(arguments[2], WindowsInstallationTrust.ConfigurationPath, StringComparison.OrdinalIgnoreCase);
    }
    internal static bool MatchesConsoleCommand(SafeProcessHandle process)
    {
        const int capacity = 65536;
        var buffer = Marshal.AllocHGlobal(capacity);
        try
        {
            if (NtQueryInformationProcess(process, 60, buffer, capacity, out _) != 0) return false;
            var length = (ushort)Marshal.ReadInt16(buffer);
            var text = Marshal.ReadIntPtr(buffer, IntPtr.Size == 8 ? 8 : 4);
            var offset = text.ToInt64() - buffer.ToInt64();
            if (length == 0 || length % 2 != 0 || offset < 0 || offset + length > capacity) return false;
            return MatchesImageCommand(Marshal.PtrToStringUni(text, length / 2) ?? "");
        }
        finally { Marshal.FreeHGlobal(buffer); }
    }
    private static string[] SplitCommand(string command)
    {
        var memory = CommandLineToArgvW(command, out var count);
        if (memory == IntPtr.Zero) throw new InvalidDataException();
        try
        {
            if (count is < 1 or > 8) return [];
            return Enumerable.Range(0, count).Select(index => Marshal.PtrToStringUni(Marshal.ReadIntPtr(memory, index * IntPtr.Size)) ?? "").ToArray();
        }
        finally { LocalFree(memory); }
    }
    internal static uint GetHardLinkCount(string path)
    {
        using var file = CreateFile(path, 0, 7, IntPtr.Zero, 3, 0, IntPtr.Zero);
        if (file.IsInvalid || !GetFileInformationByHandle(file, out var information)) throw new Win32Exception(Marshal.GetLastWin32Error());
        return information.Links;
    }
}
