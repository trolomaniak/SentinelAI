using SentinelAI.Desktop.Foundation;

internal static class DesktopIntegrationTests
{
    private static int _assertions;
    private const string Command = "\"C:\\SentinelAI Development\\SentinelAI.Desktop.exe\"";

    internal static Task<int> RunAsync()
    {
        DefaultsAndIndependentChoices();
        OwnershipAndStrictValues();
        MutationFailuresAndReadBack();
        ViewModelChoicesAndFailures();
        Console.WriteLine($"Desktop integration preferences: {_assertions} assertions passed.");
        return Task.FromResult(_assertions);
    }

    private static void DefaultsAndIndependentChoices()
    {
        var storage = new Storage();
        var store = new OwnedDesktopPreferencesStore(storage, Command);
        Check(store.Read() == new DesktopPreferencesResult(DesktopPreferenceOutcome.Success, new()), "Missing preferences must default to all opt-ins off.");
        Check(storage.Writes == 0 && storage.Deletes == 0, "Reading preferences changed current-user state.");
        var result = store.Save(new(true, true, false));
        Check(result.Preferences == new DesktopPreferences(true, true, false) && result.Outcome == DesktopPreferenceOutcome.Success,
            "Explicit tray and notification opt-ins were not stored together.");
        Check(storage.Integration == new DesktopPreferenceValue(DesktopPreferenceValueKind.Integer, 3) && storage.Startup.Kind == DesktopPreferenceValueKind.Missing,
            "Tray opt-ins created an auto-start command.");
        var integrationWrites = storage.IntegrationWrites;
        result = store.Save(new(true, true, true));
        Check(result.Preferences.AutoStartEnabled && storage.Startup.Text == Command && storage.IntegrationWrites == integrationWrites,
            "Auto-start was not exactly quoted or changed independent tray settings.");
        result = store.Save(new(false, true, true));
        Check(result.Preferences == new DesktopPreferences(false, false, true) && storage.Integration.Integer == 0,
            "Disabling tray left notifications enabled or disabled independent auto-start.");
        result = store.Save(new(false, false, false));
        Check(result.Preferences == new DesktopPreferences() && storage.Startup.Kind == DesktopPreferenceValueKind.Missing && storage.Deletes == 1,
            "Disabling owned auto-start did not remove only its value.");
        var changes = storage.Writes + storage.Deletes;
        store.Save(new());
        Check(storage.Writes + storage.Deletes == changes, "Saving identical preferences mutated the registry again.");
        store.Save(new(false, true, false));
        Check(storage.Writes + storage.Deletes == changes && !store.Read().Preferences.NotificationsEnabled,
            "Notifications became active without tray opt-in.");
        var longestCommand = "\"" + new string('x', 258) + "\"";
        var longestStorage = new Storage();
        var longestStore = new OwnedDesktopPreferencesStore(longestStorage, longestCommand);
        Check(longestCommand.Length == 260 && longestStore.Save(new(false, false, true)).Outcome == DesktopPreferenceOutcome.Success &&
            longestStorage.Startup.Text == longestCommand, "The supported 260-character Run command boundary was rejected or changed.");
        foreach (var bad in new[] { "", "\"\"", "C:\\Desktop.exe", Command + " --setup-administrator", "\"C:\\bad\npath.exe\"", "\"" + new string('x', 259) + "\"", "\"" + new string('x', 2047) + "\"" })
        {
            var rejected = false;
            try { _ = new OwnedDesktopPreferencesStore(storage, bad); }
            catch (ArgumentException) { rejected = true; }
            Check(rejected, "The owned startup command accepted arguments, controls or unsupported bounds.");
        }
    }

    private static void OwnershipAndStrictValues()
    {
        foreach (var value in new[]
        {
            new DesktopPreferenceValue(DesktopPreferenceValueKind.String, Text: "\"C:\\Other\\SentinelAI.Desktop.exe\""),
            new DesktopPreferenceValue(DesktopPreferenceValueKind.String, Text: Command + " --setup-administrator"),
            new DesktopPreferenceValue(DesktopPreferenceValueKind.String, Text: "%USERPROFILE%\\SentinelAI.Desktop.exe"),
            new DesktopPreferenceValue(DesktopPreferenceValueKind.Unsupported),
            new DesktopPreferenceValue(DesktopPreferenceValueKind.Integer, 1)
        })
        {
            var storage = new Storage { Startup = value };
            var store = new OwnedDesktopPreferencesStore(storage, Command);
            Check(store.Read().Outcome == DesktopPreferenceOutcome.OwnershipConflict && !store.Read().Preferences.AutoStartEnabled,
                "An unrelated startup value was treated as the owned Desktop command.");
            foreach (var enabled in new[] { false, true })
            {
                Check(store.Save(new(true, true, enabled)).Outcome == DesktopPreferenceOutcome.OwnershipConflict,
                    "An unrelated startup entry allowed writes or deletion.");
                Check(storage.Startup == value && storage.Writes == 0 && storage.Deletes == 0,
                    "An unrelated startup command or other preference was overwritten.");
            }
        }
        foreach (var value in new[]
        {
            new DesktopPreferenceValue(DesktopPreferenceValueKind.Integer, 2),
            new DesktopPreferenceValue(DesktopPreferenceValueKind.Integer, 4),
            new DesktopPreferenceValue(DesktopPreferenceValueKind.Integer, -1),
            new DesktopPreferenceValue(DesktopPreferenceValueKind.String, Text: "synthetic-private-value"),
            new DesktopPreferenceValue(DesktopPreferenceValueKind.Unsupported)
        })
        {
            var storage = new Storage { Integration = value };
            var store = new OwnedDesktopPreferencesStore(storage, Command);
            Check(store.Read().Outcome == DesktopPreferenceOutcome.InvalidData, "Malformed current-user preferences were accepted.");
            Check(store.Save(new(true, true, true)).Outcome == DesktopPreferenceOutcome.InvalidData && storage.Integration == value && storage.Writes == 0,
                "Malformed preferences were repaired destructively or permitted auto-start writes.");
        }
    }

    private static void MutationFailuresAndReadBack()
    {
        var storage = new Storage { ThrowRead = true };
        var store = new OwnedDesktopPreferencesStore(storage, Command);
        Check(store.Read().Outcome == DesktopPreferenceOutcome.Unavailable && store.Save(new(true, true, true)).Outcome == DesktopPreferenceOutcome.Unavailable && storage.Writes == 0,
            "Access-denied reads allowed unsafe changes.");
        storage.ThrowRead = false;
        storage.ThrowWriteIntegration = true;
        var result = store.Save(new(true, true, true));
        Check(result.Outcome == DesktopPreferenceOutcome.Unavailable && result.Preferences == new DesktopPreferences(false, false, true),
            "A partial write did not reflect actual auto-start read-back.");
        Check(storage.Startup.Text == Command && storage.Deletes == 0, "Failure triggered an automatic destructive rollback.");
        storage.ThrowWriteIntegration = false;
        storage.IgnoreWrites = true;
        result = store.Save(new(true, true, true));
        Check(result.Outcome == DesktopPreferenceOutcome.Unavailable && !result.Preferences.TrayEnabled,
            "A silently rejected write was reported successful.");
        storage.IgnoreWrites = false;
        storage.ThrowDelete = true;
        result = store.Save(new(false, false, false));
        Check(result.Outcome == DesktopPreferenceOutcome.Unavailable && result.Preferences.AutoStartEnabled && storage.Startup.Text == Command,
            "A failed delete optimistically hid an existing startup entry.");

        foreach (var initiallyEnabled in new[] { false, true })
        {
            storage = new Storage { Startup = initiallyEnabled ? new(DesktopPreferenceValueKind.String, Text: Command) : DesktopPreferenceValue.Missing };
            var startupReads = 0;
            storage.OnRead = slot =>
            {
                if (slot == DesktopPreferenceSlot.AutoStart && ++startupReads == 2)
                    storage.Startup = new(DesktopPreferenceValueKind.String, Text: "\"C:\\Other\\unrelated.exe\"");
            };
            store = new(storage, Command);
            result = store.Save(new(false, false, !initiallyEnabled));
            Check(result.Outcome == DesktopPreferenceOutcome.OwnershipConflict && storage.Writes == 0 && storage.Deletes == 0,
                "A startup value changed before mutation was overwritten or removed.");
        }
    }

    private static void ViewModelChoicesAndFailures()
    {
        var storage = new Storage();
        var store = new OwnedDesktopPreferencesStore(storage, Command);
        var vm = new DesktopIntegrationViewModel(store);
        Check(vm.PreferencesAvailable && !vm.TrayEnabled && !vm.NotificationsEnabled && !vm.AutoStartEnabled && !vm.CanConfigureNotifications,
            "Desktop preferences did not start with explicit opt-ins off.");
        vm.NotificationsEnabled = true;
        Check(storage.Writes == 0 && !vm.NotificationsEnabled, "The VM enabled notifications before opting into tray.");
        var changes = new List<string?>();
        vm.PropertyChanged += (_, args) => changes.Add(args.PropertyName);
        vm.TrayEnabled = true;
        vm.NotificationsEnabled = true;
        vm.AutoStartEnabled = true;
        Check(vm.TrayEnabled && vm.NotificationsEnabled && vm.AutoStartEnabled && vm.CanConfigureNotifications && changes.Contains(nameof(vm.TrayEnabled)),
            "Binding changes did not commit opt-ins and notify the tray consumer.");
        vm.TrayEnabled = false;
        Check(!vm.NotificationsEnabled && !vm.CanConfigureNotifications && vm.AutoStartEnabled,
            "Tray shutdown did not clear notifications independently from Desktop auto-start.");
        var reopened = new DesktopIntegrationViewModel(store);
        Check(!reopened.TrayEnabled && !reopened.NotificationsEnabled && reopened.AutoStartEnabled,
            "Reopening Desktop did not load current-user choices independently of authentication.");
        storage.Startup = new(DesktopPreferenceValueKind.String, Text: "synthetic-private-other-command");
        reopened.RefreshPreferences();
        Check(!reopened.PreferencesAvailable && !reopened.AutoStartEnabled && reopened.ErrorText.Contains("preserved", StringComparison.Ordinal) &&
            !reopened.ErrorText.Contains("synthetic-private", StringComparison.Ordinal), "Ownership conflict exposed the unrelated startup command.");
        var writes = storage.Writes;
        reopened.TrayEnabled = true;
        reopened.AutoStartEnabled = true;
        Check(storage.Writes == writes, "Unavailable preferences accepted actions through bindings.");
        storage.Startup = DesktopPreferenceValue.Missing;
        reopened.RefreshPreferences();
        Check(reopened.PreferencesAvailable && reopened.ErrorText.Length == 0, "Explicit refresh did not recover repaired current-user access.");
        storage.ThrowWriteIntegration = true;
        reopened.TrayEnabled = true;
        Check(!reopened.PreferencesAvailable && !reopened.TrayEnabled && !reopened.ErrorText.Contains("synthetic-private", StringComparison.Ordinal),
            "Failed registry writes enabled tray optimistically or exposed exception details.");
        storage.ThrowWriteIntegration = false;
        reopened.RefreshPreferences();
        reopened.TrayEnabled = true;
        Check(reopened.PreferencesAvailable && reopened.TrayEnabled, "Explicit preferences refresh did not permit a later user action.");

        var throwingVm = new DesktopIntegrationViewModel(new ThrowingStore());
        Check(!throwingVm.PreferencesAvailable && !throwingVm.ErrorText.Contains("synthetic-private", StringComparison.Ordinal),
            "An adapter exception escaped preferences construction or reached the UI.");
    }

    private static void Check(bool condition, string message)
    {
        _assertions++;
        if (!condition) throw new InvalidOperationException(message);
    }

    private sealed class ThrowingStore : IDesktopPreferencesStore
    {
        public DesktopPreferencesResult Read() => throw new IOException("synthetic-private-storage-path");
        public DesktopPreferencesResult Save(DesktopPreferences preferences) => throw new IOException("synthetic-private-storage-path");
    }

    private sealed class Storage : IDesktopPreferenceStorage
    {
        internal DesktopPreferenceValue Integration { get; set; } = DesktopPreferenceValue.Missing;
        internal DesktopPreferenceValue Startup { get; set; } = DesktopPreferenceValue.Missing;
        internal bool ThrowRead { get; set; }
        internal bool ThrowWriteIntegration { get; set; }
        internal bool ThrowDelete { get; set; }
        internal bool IgnoreWrites { get; set; }
        internal Action<DesktopPreferenceSlot>? OnRead { get; set; }
        internal int Writes { get; private set; }
        internal int IntegrationWrites { get; private set; }
        internal int Deletes { get; private set; }
        public DesktopPreferenceValue Read(DesktopPreferenceSlot slot)
        {
            if (ThrowRead) throw new UnauthorizedAccessException("synthetic-private-storage-path");
            OnRead?.Invoke(slot);
            return slot == DesktopPreferenceSlot.Integration ? Integration : Startup;
        }
        public void Write(DesktopPreferenceSlot slot, DesktopPreferenceValue value)
        {
            if (slot == DesktopPreferenceSlot.Integration && ThrowWriteIntegration) throw new IOException("synthetic-private-write-details");
            Writes++;
            if (IgnoreWrites) return;
            if (slot == DesktopPreferenceSlot.Integration) { Integration = value; IntegrationWrites++; }
            else Startup = value;
        }
        public void Delete(DesktopPreferenceSlot slot)
        {
            if (ThrowDelete) throw new IOException("synthetic-private-delete-details");
            Check(slot == DesktopPreferenceSlot.AutoStart, "The store removed another preference slot.");
            Deletes++;
            Startup = DesktopPreferenceValue.Missing;
        }
    }
}
