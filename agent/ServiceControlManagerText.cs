using System.Collections.Frozen;
using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using SentinelAI.Contracts.SecurityEvents;

namespace SentinelAI.Agent;

/// <summary>
/// The Service Control Manager writes the service type and start type of System 7045 and 7040 as text in the
/// system's display language. Each text is a string of services.exe, so reading those strings from the
/// services.exe.mui of every installed display language recognizes them on Windows in any language. English is
/// always recognized, and a text that means two different values in the loaded languages is not recognized at all.
/// </summary>
public sealed class ServiceControlManagerText
{
    /// <summary>
    /// String IDs in services.exe; the Windows Agent test checks each against its en-US text. "file system
    /// driver" is not among services.exe's strings, so it is recognized in English only (ID 0).
    /// </summary>
    public static readonly IReadOnlyList<Message> Messages =
    [
        new(0x135, "user mode service", false, ServiceTypes.UserModeService),
        new(0x134, "kernel mode driver", false, ServiceTypes.KernelDriver),
        new(0, "file system driver", false, ServiceTypes.FileSystemDriver),
        new(0x41, "boot start", true, ServiceStartTypes.Boot),
        new(0x42, "system start", true, ServiceStartTypes.System),
        new(0x43, "auto start", true, ServiceStartTypes.Auto),
        new(0x44, "demand start", true, ServiceStartTypes.Demand),
        new(0x45, "disabled", true, ServiceStartTypes.Disabled)
    ];

    public static ServiceControlManagerText English { get; } =
        new(Messages.Select(message => (message.English, message.StartType, message.Value)));

    private readonly FrozenDictionary<string, string> _serviceTypes;
    private readonly FrozenDictionary<string, string> _startTypes;

    public ServiceControlManagerText(IEnumerable<(string Text, bool StartType, string Value)> texts)
    {
        var serviceTypes = new Dictionary<string, string?>(StringComparer.Ordinal);
        var startTypes = new Dictionary<string, string?>(StringComparer.Ordinal);
        foreach (var (text, startType, value) in texts.Concat(
                     Messages.Select(message => (message.English, message.StartType, message.Value))))
        {
            var key = Key(text);
            if (key.Length == 0) continue;
            var map = startType ? startTypes : serviceTypes;
            // An ambiguous text stays in the map as null, so it is never recognized.
            map[key] = map.TryGetValue(key, out var existing) && existing != value ? null : value;
        }

        _serviceTypes = Known(serviceTypes);
        _startTypes = Known(startTypes);
    }

    public int Count => _serviceTypes.Count + _startTypes.Count;

    public string? ServiceType(string text) => _serviceTypes.GetValueOrDefault(Key(text));

    public string? StartType(string text) => _startTypes.GetValueOrDefault(Key(text));

    /// <summary>English plus each installed display language's text; English alone when reading them fails.</summary>
    public static ServiceControlManagerText Load()
    {
        if (!OperatingSystem.IsWindows()) return English;
        try
        {
            return new ServiceControlManagerText(LoadInstalledLanguages());
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException or ExternalException or
                                              DllNotFoundException or EntryPointNotFoundException)
        {
            return English;
        }
    }

    public static string Key(string text)
    {
        var trimmed = text.AsSpan().Trim();
        // A message may end in %0, which only suppresses its trailing line break.
        if (trimmed.EndsWith("%0", StringComparison.Ordinal)) trimmed = trimmed[..^2].TrimEnd();
        return trimmed.ToString().ToUpperInvariant();
    }

    /// <summary>The services.exe strings with the given IDs in one resource file's language.</summary>
    [SupportedOSPlatform("windows")]
    public static Dictionary<uint, string> ReadStrings(string path, ushort language, IEnumerable<uint> ids)
    {
        var strings = new Dictionary<uint, string>();
        var module = LoadLibraryExW(path, IntPtr.Zero, LoadLibraryAsDatafile | LoadLibraryAsImageResource);
        if (module == IntPtr.Zero) return strings;
        try
        {
            // RT_STRING stores strings in blocks of 16: block n holds IDs (n - 1) * 16 to n * 16 - 1.
            foreach (var block in ids.Where(id => id != 0).GroupBy(id => id / 16 + 1))
            {
                var resource = FindResourceExW(module, (IntPtr)StringTable, (IntPtr)block.Key, language);
                if (resource == IntPtr.Zero) continue;
                var size = (int)SizeofResource(module, resource);
                var data = LockResource(LoadResource(module, resource));
                if (data == IntPtr.Zero || size <= 0) continue;
                var bytes = new byte[size];
                Marshal.Copy(data, bytes, 0, size);
                var offset = 0;
                for (var index = 0u; index < 16 && offset + 2 <= bytes.Length; index++)
                {
                    var length = BitConverter.ToUInt16(bytes, offset);
                    offset += 2;
                    if (offset + length * 2 > bytes.Length) break;
                    var id = (block.Key - 1) * 16 + index;
                    if (length > 0 && block.Contains(id))
                        strings[id] = System.Text.Encoding.Unicode.GetString(bytes, offset, length * 2);
                    offset += length * 2;
                }
            }
        }
        finally
        {
            FreeLibrary(module);
        }

        return strings;
    }

    private static FrozenDictionary<string, string> Known(Dictionary<string, string?> map) =>
        map.Where(entry => entry.Value is not null)
            .ToFrozenDictionary(entry => entry.Key, entry => entry.Value!, StringComparer.Ordinal);

    /// <summary>Every System32\&lt;language&gt;\services.exe.mui, read in that directory's language.</summary>
    [SupportedOSPlatform("windows")]
    private static List<(string Text, bool StartType, string Value)> LoadInstalledLanguages()
    {
        var texts = new List<(string Text, bool StartType, string Value)>();
        var ids = Messages.Select(message => message.Id).ToArray();
        foreach (var directory in Directory.EnumerateDirectories(Environment.SystemDirectory).Take(1024))
        {
            var file = Path.Combine(directory, "services.exe.mui");
            var language = LocaleNameToLCID(Path.GetFileName(directory), 0);
            if (language is 0 or > 0xFFFF || !File.Exists(file)) continue;
            var strings = ReadStrings(file, (ushort)language, ids);
            foreach (var message in Messages)
            {
                if (strings.TryGetValue(message.Id, out var text)) texts.Add((text, message.StartType, message.Value));
            }
        }

        return texts;
    }

    public sealed record Message(uint Id, string English, bool StartType, string Value);

    private const uint LoadLibraryAsDatafile = 0x2;
    private const uint LoadLibraryAsImageResource = 0x20;
    private const int StringTable = 6;

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    private static extern IntPtr LoadLibraryExW(string path, IntPtr file, uint flags);

    [DllImport("kernel32.dll", SetLastError = true)]
    [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    private static extern bool FreeLibrary(IntPtr module);

    [DllImport("kernel32.dll", SetLastError = true)]
    [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    private static extern IntPtr FindResourceExW(IntPtr module, IntPtr type, IntPtr name, ushort language);

    [DllImport("kernel32.dll", SetLastError = true)]
    [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    private static extern IntPtr LoadResource(IntPtr module, IntPtr resource);

    [DllImport("kernel32.dll")]
    [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    private static extern IntPtr LockResource(IntPtr data);

    [DllImport("kernel32.dll", SetLastError = true)]
    [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    private static extern uint SizeofResource(IntPtr module, IntPtr resource);

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode)]
    [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    private static extern int LocaleNameToLCID(string name, uint flags);
}
