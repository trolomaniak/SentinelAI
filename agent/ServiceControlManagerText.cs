using System.Collections.Frozen;
using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using SentinelAI.Contracts.SecurityEvents;

namespace SentinelAI.Agent;

/// <summary>
/// The Service Control Manager writes the service type and start type of System 7045 and 7040 as text in the
/// system's display language. Each text is a message of services.exe, so loading those messages for every
/// installed display language recognizes them on Windows in any language. English is always recognized, and a
/// text that means two different values in the loaded languages is not recognized at all.
/// </summary>
public sealed class ServiceControlManagerText
{
    /// <summary>Message IDs in services.exe; the Windows Agent test checks each against its English text.</summary>
    public static readonly IReadOnlyList<Message> Messages =
    [
        new(0, "user mode service", false, ServiceTypes.UserModeService),
        new(0, "kernel mode driver", false, ServiceTypes.KernelDriver),
        new(0, "file system driver", false, ServiceTypes.FileSystemDriver),
        new(0, "boot start", true, ServiceStartTypes.Boot),
        new(0, "system start", true, ServiceStartTypes.System),
        new(0, "auto start", true, ServiceStartTypes.Auto),
        new(0, "demand start", true, ServiceStartTypes.Demand),
        new(0, "disabled", true, ServiceStartTypes.Disabled)
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

    /// <summary>English plus each installed display language's text; English alone when any of it fails.</summary>
    public static ServiceControlManagerText Load()
    {
        if (!OperatingSystem.IsWindows()) return English;
        try
        {
            return new ServiceControlManagerText(LoadInstalledLanguages());
        }
        catch (Exception exception) when (exception is ExternalException or DllNotFoundException or
                                              EntryPointNotFoundException or InvalidOperationException)
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

    private static FrozenDictionary<string, string> Known(Dictionary<string, string?> map) =>
        map.Where(entry => entry.Value is not null)
            .ToFrozenDictionary(entry => entry.Key, entry => entry.Value!, StringComparer.Ordinal);

    [SupportedOSPlatform("windows")]
    private static List<(string Text, bool StartType, string Value)> LoadInstalledLanguages()
    {
        var texts = new List<(string Text, bool StartType, string Value)>();
        var module = LoadLibraryExW(Path.Combine(Environment.SystemDirectory, "services.exe"), IntPtr.Zero,
            LoadLibraryAsDatafile | LoadLibraryAsImageResource);
        if (module == IntPtr.Zero) return texts;
        try
        {
            foreach (var language in InstalledLanguages())
            {
                foreach (var message in Messages)
                {
                    if (Format(module, message.Id, language) is { } text)
                        texts.Add((text, message.StartType, message.Value));
                }
            }
        }
        finally
        {
            FreeLibrary(module);
        }

        return texts;
    }

    [SupportedOSPlatform("windows")]
    public static string? Format(IntPtr module, uint id, ushort language)
    {
        if (id == 0) return null;
        var buffer = new char[256];
        // MAX_WIDTH_MASK drops the message's own line breaks; inserts are never expanded.
        var length = FormatMessageW(FormatFromModule | FormatIgnoreInserts | FormatMaxWidthMask, module, id, language,
            buffer, buffer.Length, IntPtr.Zero);
        return length > 0 ? new string(buffer, 0, length) : null;
    }

    [SupportedOSPlatform("windows")]
    private static List<ushort> InstalledLanguages()
    {
        var languages = new List<ushort>();
        EnumUiLanguagesProc callback = (name, _) =>
        {
            if (Marshal.PtrToStringUni(name) is { } hex &&
                ushort.TryParse(hex, System.Globalization.NumberStyles.HexNumber,
                    System.Globalization.CultureInfo.InvariantCulture, out var language) &&
                !languages.Contains(language))
            {
                languages.Add(language);
            }

            return languages.Count < 64;
        };
        EnumUILanguagesW(callback, MuiLanguageId, IntPtr.Zero);
        GC.KeepAlive(callback);
        return languages;
    }

    public sealed record Message(uint Id, string English, bool StartType, string Value);

    private const uint LoadLibraryAsDatafile = 0x2;
    private const uint LoadLibraryAsImageResource = 0x20;
    private const uint FormatFromModule = 0x800;
    private const uint FormatIgnoreInserts = 0x200;
    private const uint FormatMaxWidthMask = 0xFF;
    private const uint MuiLanguageId = 0x4;

    private delegate bool EnumUiLanguagesProc(IntPtr language, IntPtr parameter);

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    private static extern IntPtr LoadLibraryExW(string path, IntPtr file, uint flags);

    [DllImport("kernel32.dll", SetLastError = true)]
    [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    private static extern bool FreeLibrary(IntPtr module);

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    private static extern int FormatMessageW(uint flags, IntPtr source, uint id, uint language, [Out] char[] buffer,
        int size, IntPtr arguments);

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    private static extern bool EnumUILanguagesW(EnumUiLanguagesProc callback, uint flags, IntPtr parameter);
}
