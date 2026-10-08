using System.ComponentModel;

namespace SentinelAI.Desktop.Foundation;

/// <summary>Local opt-ins only. Contains no session, credentials or Core/Agent controls.</summary>
public sealed class DesktopIntegrationViewModel : INotifyPropertyChanged
{
    private readonly IDesktopPreferencesStore _store;
    private DesktopPreferences _preferences = new();
    private DesktopPreferenceOutcome _outcome = DesktopPreferenceOutcome.Unavailable;

    public DesktopIntegrationViewModel(IDesktopPreferencesStore store)
    {
        ArgumentNullException.ThrowIfNull(store);
        _store = store;
        RefreshPreferences();
    }

    public event PropertyChangedEventHandler? PropertyChanged;
    public bool TrayEnabled { get => _preferences.TrayEnabled; set => Save(_preferences with { TrayEnabled = value, NotificationsEnabled = value && _preferences.NotificationsEnabled }); }
    public bool NotificationsEnabled { get => _preferences.NotificationsEnabled; set => Save(_preferences with { NotificationsEnabled = _preferences.TrayEnabled && value }); }
    public bool AutoStartEnabled { get => _preferences.AutoStartEnabled; set => Save(_preferences with { AutoStartEnabled = value }); }
    public bool PreferencesAvailable => _outcome == DesktopPreferenceOutcome.Success;
    public bool CanConfigureNotifications => PreferencesAvailable && TrayEnabled;
    public string StatusText => "Desktop preferences apply only to this Windows user. Closing Desktop leaves Core and Agent protection running.";
    public string ErrorText => _outcome switch
    {
        DesktopPreferenceOutcome.Success => string.Empty,
        DesktopPreferenceOutcome.OwnershipConflict => "Desktop preferences cannot be changed because its startup entry is owned by another command. The existing entry was preserved.",
        DesktopPreferenceOutcome.InvalidData => "Desktop preferences contain an unsupported value. The existing value was preserved.",
        _ => "Desktop preferences are unavailable. Check current-user access, then refresh preferences."
    };

    public void RefreshPreferences()
    {
        try { Apply(_store.Read()); }
        catch { Apply(new(DesktopPreferenceOutcome.Unavailable, new())); }
    }

    private void Save(DesktopPreferences preferences)
    {
        if (!PreferencesAvailable || preferences == _preferences) return;
        try { Apply(_store.Save(preferences)); }
        catch { Apply(new(DesktopPreferenceOutcome.Unavailable, _preferences)); }
    }

    private void Apply(DesktopPreferencesResult result)
    {
        _preferences = result.Preferences with { NotificationsEnabled = result.Preferences.TrayEnabled && result.Preferences.NotificationsEnabled };
        _outcome = result.Outcome;
        foreach (var property in new[] { nameof(TrayEnabled), nameof(NotificationsEnabled), nameof(AutoStartEnabled), nameof(PreferencesAvailable), nameof(CanConfigureNotifications), nameof(ErrorText) })
            PropertyChanged?.Invoke(this, new(property));
    }
}
