using System.IO;
using System.Runtime.InteropServices;
using System.Text;
using Microsoft.Win32;
using Microsoft.Win32.SafeHandles;
using SentinelAI.Desktop.Foundation;

namespace SentinelAI.Desktop.Services;

/// <summary>Fixed, bounded nonsecret preferences and current-user Desktop auto-start only.</summary>
public sealed class WindowsDesktopPreferences : IDesktopPreferencesStore
{
    private readonly OwnedDesktopPreferencesStore? _store;

    public WindowsDesktopPreferences()
    {
        try
        {
            var executable = Path.GetFullPath(Path.Combine(AppContext.BaseDirectory, "SentinelAI.Desktop.exe"));
            if (!OperatingSystem.IsWindows() || executable.Length > 258 || executable.Contains('"') || executable.Any(char.IsControl) || !File.Exists(executable)) return;
            _store = new(new CurrentUserStorage(), '"' + executable + '"');
        }
        catch { /* Expose a fixed unavailable result, without executable paths or exceptions. */ }
    }

    public DesktopPreferencesResult Read() => _store?.Read() ?? new(DesktopPreferenceOutcome.Unavailable, new());
    public DesktopPreferencesResult Save(DesktopPreferences preferences) => _store?.Save(preferences) ?? new(DesktopPreferenceOutcome.Unavailable, new());

    private sealed class CurrentUserStorage : IDesktopPreferenceStorage
    {
        private const string IntegrationKey = @"Software\SentinelAI\Desktop";
        private const string RunKey = @"Software\Microsoft\Windows\CurrentVersion\Run";
        private static readonly Encoding StrictUnicode = new UnicodeEncoding(false, false, true);
        [DllImport("advapi32.dll", CharSet = CharSet.Unicode, EntryPoint = "RegQueryValueExW")]
        private static extern int QueryValue(SafeRegistryHandle key, string name, IntPtr reserved, out uint type, byte[]? data, ref uint size);
        private static (string Key, string Value) Destination(DesktopPreferenceSlot slot) => slot switch
        {
            DesktopPreferenceSlot.Integration => (IntegrationKey, "Integration"),
            DesktopPreferenceSlot.AutoStart => (RunKey, "SentinelAI.Desktop"),
            _ => throw new ArgumentOutOfRangeException(nameof(slot))
        };

        public DesktopPreferenceValue Read(DesktopPreferenceSlot slot)
        {
            var destination = Destination(slot);
            using var key = Registry.CurrentUser.OpenSubKey(destination.Key, writable: false);
            if (key is null) return DesktopPreferenceValue.Missing;
            uint size = 0;
            var result = QueryValue(key.Handle, destination.Value, IntPtr.Zero, out var kind, null, ref size);
            if (result == 2) return DesktopPreferenceValue.Missing;
            if (result != 0) throw new IOException("Desktop preferences are unavailable.");
            // Inspect native type/size before allocation, never expand environment variables.
            if (slot == DesktopPreferenceSlot.Integration && (kind != 4 || size != 4) ||
                slot == DesktopPreferenceSlot.AutoStart && (kind != 1 || size is < 2 or > 522 || size % 2 != 0))
                return new(DesktopPreferenceValueKind.Unsupported);
            var data = new byte[size];
            var expectedKind = kind;
            var expectedSize = size;
            result = QueryValue(key.Handle, destination.Value, IntPtr.Zero, out kind, data, ref size);
            if (result != 0 || kind != expectedKind || size != expectedSize) return new(DesktopPreferenceValueKind.Unsupported);
            if (slot == DesktopPreferenceSlot.Integration) return new(DesktopPreferenceValueKind.Integer, BitConverter.ToInt32(data));
            if (data[^1] != 0 || data[^2] != 0) return new(DesktopPreferenceValueKind.Unsupported);
            return new(DesktopPreferenceValueKind.String, Text: StrictUnicode.GetString(data, 0, data.Length - 2));
        }

        public void Write(DesktopPreferenceSlot slot, DesktopPreferenceValue value)
        {
            var destination = Destination(slot);
            using var key = Registry.CurrentUser.CreateSubKey(destination.Key, writable: true);
            if (slot == DesktopPreferenceSlot.Integration && value.Kind == DesktopPreferenceValueKind.Integer && value.Integer is 0 or 1 or 3)
                key.SetValue(destination.Value, value.Integer, RegistryValueKind.DWord);
            else if (slot == DesktopPreferenceSlot.AutoStart && value.Kind == DesktopPreferenceValueKind.String && value.Text is { Length: <= 260 })
                key.SetValue(destination.Value, value.Text, RegistryValueKind.String);
            else throw new InvalidOperationException("Unsupported Desktop preference value.");
            key.Flush();
        }

        public void Delete(DesktopPreferenceSlot slot)
        {
            if (slot != DesktopPreferenceSlot.AutoStart) throw new InvalidOperationException("Only the owned Desktop startup entry can be removed.");
            var destination = Destination(slot);
            using var key = Registry.CurrentUser.OpenSubKey(destination.Key, writable: true);
            key?.DeleteValue(destination.Value, throwOnMissingValue: false);
            key?.Flush();
        }
    }
}
