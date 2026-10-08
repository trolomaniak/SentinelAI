namespace SentinelAI.Desktop.Foundation;

/// <summary>Nonsecret current-user Desktop choices; monitoring never depends on them.</summary>
public sealed record DesktopPreferences(bool TrayEnabled = false, bool NotificationsEnabled = false, bool AutoStartEnabled = false);

public enum DesktopPreferenceOutcome { Success, Unavailable, OwnershipConflict, InvalidData }
public sealed record DesktopPreferencesResult(DesktopPreferenceOutcome Outcome, DesktopPreferences Preferences);

public interface IDesktopPreferencesStore
{
    DesktopPreferencesResult Read();
    DesktopPreferencesResult Save(DesktopPreferences preferences);
}

// Fixed slots keep platform adapters from accepting destinations from views.
public enum DesktopPreferenceSlot { Integration, AutoStart }
public enum DesktopPreferenceValueKind { Missing, Integer, String, Unsupported }
public sealed record DesktopPreferenceValue(DesktopPreferenceValueKind Kind, int Integer = 0, string? Text = null)
{
    public static DesktopPreferenceValue Missing { get; } = new(DesktopPreferenceValueKind.Missing);
}

public interface IDesktopPreferenceStorage
{
    DesktopPreferenceValue Read(DesktopPreferenceSlot slot);
    void Write(DesktopPreferenceSlot slot, DesktopPreferenceValue value);
    void Delete(DesktopPreferenceSlot slot);
}
