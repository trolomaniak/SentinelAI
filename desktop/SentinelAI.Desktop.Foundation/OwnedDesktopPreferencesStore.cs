namespace SentinelAI.Desktop.Foundation;

/// <summary>Owns two bounded Desktop values and never replaces another startup command.</summary>
public sealed class OwnedDesktopPreferencesStore : IDesktopPreferencesStore
{
    private readonly IDesktopPreferenceStorage _storage;
    private readonly string _ownedCommand;
    private readonly object _gate = new();

    public OwnedDesktopPreferencesStore(IDesktopPreferenceStorage storage, string ownedCommand)
    {
        ArgumentNullException.ThrowIfNull(storage);
        if (string.IsNullOrEmpty(ownedCommand) || ownedCommand.Length is < 3 or > 260 || ownedCommand[0] != '"' ||
            ownedCommand[^1] != '"' || ownedCommand.Count(character => character == '"') != 2 || ownedCommand.Any(char.IsControl))
            throw new ArgumentException("A single quoted Desktop application path is required.", nameof(ownedCommand));
        _storage = storage;
        _ownedCommand = ownedCommand;
    }

    public DesktopPreferencesResult Read()
    {
        lock (_gate) return ReadSafely();
    }

    public DesktopPreferencesResult Save(DesktopPreferences preferences)
    {
        ArgumentNullException.ThrowIfNull(preferences);
        lock (_gate)
        {
            var before = ReadSafely();
            if (before.Outcome != DesktopPreferenceOutcome.Success) return before;
            var desired = preferences with { NotificationsEnabled = preferences.TrayEnabled && preferences.NotificationsEnabled };
            try
            {
                if (desired.AutoStartEnabled != before.Preferences.AutoStartEnabled)
                {
                    // Recheck immediately before mutation, including removal. Never "repair"
                    // an entry that an operator or another application changed.
                    var current = _storage.Read(DesktopPreferenceSlot.AutoStart);
                    if (!IsOwnedOrMissing(current)) return ReadSafely() with { Outcome = DesktopPreferenceOutcome.OwnershipConflict };
                    if (desired.AutoStartEnabled)
                        _storage.Write(DesktopPreferenceSlot.AutoStart, new(DesktopPreferenceValueKind.String, Text: _ownedCommand));
                    else if (current.Kind != DesktopPreferenceValueKind.Missing)
                        _storage.Delete(DesktopPreferenceSlot.AutoStart);
                }
                if (desired.TrayEnabled != before.Preferences.TrayEnabled || desired.NotificationsEnabled != before.Preferences.NotificationsEnabled)
                {
                    var current = _storage.Read(DesktopPreferenceSlot.Integration);
                    if (!ValidIntegration(current)) return ReadSafely() with { Outcome = DesktopPreferenceOutcome.InvalidData };
                    var flags = (desired.TrayEnabled ? 1 : 0) | (desired.NotificationsEnabled ? 2 : 0);
                    _storage.Write(DesktopPreferenceSlot.Integration, new(DesktopPreferenceValueKind.Integer, flags));
                }
                var after = ReadSafely();
                // Registry writes can fail or be changed externally. Bind only read-back facts.
                return after.Outcome == DesktopPreferenceOutcome.Success && after.Preferences != desired
                    ? after with { Outcome = DesktopPreferenceOutcome.Unavailable }
                    : after;
            }
            catch
            {
                // A partial successful write remains visible; no unsafe rollback or retry.
                return ReadSafely() with { Outcome = DesktopPreferenceOutcome.Unavailable };
            }
        }
    }

    private DesktopPreferencesResult ReadSafely()
    {
        try
        {
            var integration = _storage.Read(DesktopPreferenceSlot.Integration);
            var startup = _storage.Read(DesktopPreferenceSlot.AutoStart);
            var validIntegration = ValidIntegration(integration);
            var flags = validIntegration && integration.Kind == DesktopPreferenceValueKind.Integer ? integration.Integer : 0;
            var preferences = new DesktopPreferences((flags & 1) != 0, (flags & 2) != 0,
                startup.Kind == DesktopPreferenceValueKind.String && startup.Text == _ownedCommand);
            return new(!validIntegration ? DesktopPreferenceOutcome.InvalidData :
                !IsOwnedOrMissing(startup) ? DesktopPreferenceOutcome.OwnershipConflict : DesktopPreferenceOutcome.Success, preferences);
        }
        catch { return new(DesktopPreferenceOutcome.Unavailable, new()); }
    }

    private bool IsOwnedOrMissing(DesktopPreferenceValue value) => value.Kind == DesktopPreferenceValueKind.Missing ||
        value.Kind == DesktopPreferenceValueKind.String && value.Text == _ownedCommand;
    private static bool ValidIntegration(DesktopPreferenceValue value) => value.Kind == DesktopPreferenceValueKind.Missing ||
        value.Kind == DesktopPreferenceValueKind.Integer && value.Integer is 0 or 1 or 3;
}
