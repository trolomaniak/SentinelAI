using System.ComponentModel;
using System.Globalization;
using SentinelAI.Localization;
using static SentinelAI.Localization.Localizer;

namespace SentinelAI.Desktop.Foundation;

public enum LanguageRequestOutcome { Success, Unauthenticated, Unavailable, UntrustedConnection, InvalidResponse, Rejected }

/// <summary>Changes the installation language in Core (administrators only).</summary>
public interface ILanguageSettingsClient
{
    Task<(LanguageRequestOutcome Outcome, UiLanguage? Language)> SetInstallationLanguageAsync(UiLanguage language, CancellationToken cancellationToken);
}

/// <summary>The last installation language this Windows user saw, for starts while Core does not answer.</summary>
public interface ILanguageCache
{
    UiLanguage? Read();
    void Save(UiLanguage language);
}

public static class DesktopLanguage
{
    /// <summary>
    /// The language Desktop starts in: the installation language Core reports, else the last one seen by this Windows
    /// user, else Polish when Windows is shown in Polish and English otherwise.
    /// </summary>
    public static async Task<UiLanguage> ResolveAsync(Func<CancellationToken, Task<UiLanguage?>> core, ILanguageCache? cache, CultureInfo windowsCulture,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(core);
        ArgumentNullException.ThrowIfNull(windowsCulture);
        UiLanguage? reported = null;
        try { reported = await core(cancellationToken).ConfigureAwait(false); }
        catch (Exception exception) when (exception is not OperationCanceledException) { }
        if (reported is { } language)
        {
            cache?.Save(language);
            return language;
        }

        return cache?.Read() ?? (windowsCulture.TwoLetterISOLanguageName == "pl" ? UiLanguage.Polish : UiLanguage.English);
    }
}

public sealed record LanguageOption(UiLanguage Language, string Text);

/// <summary>
/// Settings → Language: the installation language for Desktop and Core's reports. Desktop is shown in it from its next
/// start; the choice is saved in Core and applies to every administrator.
/// </summary>
public sealed class LanguageSettingsViewModel : INotifyPropertyChanged
{
    private readonly ILanguageSettingsClient _client;
    private readonly ILanguageCache? _cache;
    private UiLanguage _saved;
    private UiLanguage _selected;
    private bool _saving;
    private string _statusText = string.Empty;

    public LanguageSettingsViewModel(ILanguageSettingsClient client, ILanguageCache? cache, UiLanguage current)
    {
        ArgumentNullException.ThrowIfNull(client);
        _client = client;
        _cache = cache;
        Running = current;
        _saved = current;
        _selected = current;
    }

    public event PropertyChangedEventHandler? PropertyChanged;
    public event EventHandler? SessionExpired;

    /// <summary>Each language named in itself.</summary>
    public static IReadOnlyList<LanguageOption> Options { get; } = [new(UiLanguage.English, "English"), new(UiLanguage.Polish, "Polski")];

    /// <summary>The language this Desktop process is shown in.</summary>
    public UiLanguage Running { get; }

    public UiLanguage Selected
    {
        get => _selected;
        set
        {
            if (_selected == value) return;
            _selected = value;
            _statusText = string.Empty;
            Notify();
        }
    }

    public bool CanSave => !_saving && _selected != _saved;
    public string StatusText => _statusText;

    public async Task SaveAsync()
    {
        if (!CanSave) return;
        _saving = true;
        _statusText = T("Saving…");
        Notify();
        (LanguageRequestOutcome Outcome, UiLanguage? Language) result;
        try { result = await _client.SetInstallationLanguageAsync(_selected, CancellationToken.None); }
        finally { _saving = false; }
        switch (result)
        {
            case (LanguageRequestOutcome.Success, { } language):
                _saved = language;
                _selected = language;
                _cache?.Save(language);
                _statusText = language == Running
                    ? T("Saved. SentinelAI is already shown in this language.")
                    : T("Saved. Close and reopen SentinelAI to show it in the chosen language; reports use it from now on.");
                break;
            case (LanguageRequestOutcome.Unauthenticated, _):
                _statusText = string.Empty;
                Notify();
                SessionExpired?.Invoke(this, EventArgs.Empty);
                return;
            default:
                _statusText = T("Local Core is unavailable. The language was not changed.");
                break;
        }

        Notify();
    }

    private void Notify() => PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(string.Empty));
}
