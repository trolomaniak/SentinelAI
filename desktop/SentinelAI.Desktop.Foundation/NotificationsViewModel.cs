using System.ComponentModel;
using System.Globalization;
using System.Text;
using SentinelAI.Contracts.Notifications;
using static SentinelAI.Localization.Localizer;

namespace SentinelAI.Desktop.Foundation;

public sealed record NotificationRow(Guid NotificationId, bool IsUnread, string Title, string Endpoint, string Occurrences, string Time, string ReadState);
public sealed record NotificationDeliveryRow(string Summary, string Time, string Result);

/// <summary>Local notifications remain usable when external delivery or its policy is unavailable.</summary>
public sealed class NotificationsViewModel(INotificationsClient client) : INotifyPropertyChanged, IDisposable
{
    public const int PageSize = 25;
    public static IReadOnlyList<int> OfflineOptions { get; } = Enumerable.Range(5, 116).ToArray();
    public static IReadOnlyList<int> GroupOptions { get; } = Enumerable.Range(1, 60).ToArray();
    private readonly object _gate = new();
    private CancellationTokenSource? _operation;
    private long _generation;
    private bool _disposed, _needsRefresh, _unreadOnly, _appliedUnreadOnly;
    private NotificationPage? _page;
    private NotificationDeliveryPage? _deliveryPage;
    private Guid? _deliveryNotificationId;
    private NotificationPolicy? _policy;
    private IReadOnlyList<NotificationRow> _rows = [];
    private IReadOnlyList<NotificationDeliveryRow> _deliveryRows = [];
    private NotificationRow? _selected;
    private string _listText = T("Notifications have not been read."), _deliveryText = "", _policyText = "", _message = "";
    private bool _criticalAlerts = true, _monitoringChanges = true, _webhookEnabled, _emailEnabled;
    private bool _clearWebhookDestination, _clearWebhookSecret, _clearSmtpPassword;
    private int _offlineMinutes = 15, _groupMinutes = 5;
    private string _smtpHost = "", _smtpUsername = "", _emailFrom = "", _emailTo = "";

    public event PropertyChangedEventHandler? PropertyChanged;
    public event EventHandler? SessionExpired;
    public bool IsBusy { get { lock (_gate) return _operation is not null; } }
    public bool CanRefresh { get { lock (_gate) return !_disposed && _operation is null; } }
    public bool CanEditPolicy { get { lock (_gate) return CanRefresh && _policy is not null && !_needsRefresh; } }
    public bool CanSavePolicy => CanEditPolicy;
    public bool NeedsRefresh { get { lock (_gate) return _needsRefresh; } }
    public bool CanMarkRead { get { lock (_gate) return CanRefresh && _selected is { IsUnread: true }; } }
    public bool CanShowSelectedDeliveries { get { lock (_gate) return CanRefresh && _selected is not null; } }
    public bool CanPreviousPage { get { lock (_gate) return CanRefresh && _page is { Offset: > 0 }; } }
    public bool CanNextPage { get { lock (_gate) return CanRefresh && _page is { } p && p.Offset + p.Items.Count < p.Total; } }
    public bool CanPreviousDeliveryPage { get { lock (_gate) return CanRefresh && _deliveryPage is { Offset: > 0 }; } }
    public bool CanNextDeliveryPage { get { lock (_gate) return CanRefresh && _deliveryPage is { } p && p.Offset + p.Items.Count < p.Total; } }
    public IReadOnlyList<NotificationRow> Rows { get { lock (_gate) return _rows; } }
    public IReadOnlyList<NotificationDeliveryRow> DeliveryRows { get { lock (_gate) return _deliveryRows; } }
    public NotificationPolicy? Policy { get { lock (_gate) return _policy; } }
    public NotificationRow? SelectedNotification
    {
        get { lock (_gate) return _selected; }
        set { lock (_gate) _selected = value is not null && _rows.Contains(value) ? value : null; NotifyAll(); }
    }
    public string ListText { get { lock (_gate) return _listText; } }
    public string DeliveryText { get { lock (_gate) return _deliveryText; } }
    public string PolicyText { get { lock (_gate) return _policyText; } }
    public string Message { get { lock (_gate) return IsBusy ? T("Reading or saving notifications…") : _message; } }
    public string PageText { get { lock (_gate) return _page is { } p ? F("Notifications {0}–{1} of {2}; unread: {3}", p.Items.Count == 0 ? 0 : p.Offset + 1, p.Offset + p.Items.Count, p.Total, p.Unread) : ""; } }
    public string DeliveryPageText { get { lock (_gate) return _deliveryPage is { } p ? F("Deliveries {0}–{1} of {2}", p.Items.Count == 0 ? 0 : p.Offset + 1, p.Offset + p.Items.Count, p.Total) : ""; } }
    public string DeliveryScopeText { get { lock (_gate) return _deliveryNotificationId is null ? T("Delivery history for all notifications") : T("Delivery history for the selected notification"); } }
    public string ProtectedValuesText
    {
        get
        {
            lock (_gate) return _policy is not { } p ? "" : F("Saved webhook origin: {0}; destination: {1}; webhook secret: {2}; SMTP password: {3}.",
                p.WebhookOrigin ?? T("None"), Saved(p.HasWebhookDestination), Saved(p.HasWebhookSecret), Saved(p.HasSmtpPassword));
        }
    }
    public string CredentialText { get { lock (_gate) return _policy?.CredentialAvailability == "unavailable" ? T("Protected credentials are unavailable. External sending stays disabled until Core can protect and read them.") : ""; } }
    public bool UnreadOnly { get { lock (_gate) return _unreadOnly; } set => Set(ref _unreadOnly, value, nameof(UnreadOnly)); }
    public bool CriticalAlerts { get { lock (_gate) return _criticalAlerts; } set => Set(ref _criticalAlerts, value, nameof(CriticalAlerts)); }
    public bool MonitoringChanges { get { lock (_gate) return _monitoringChanges; } set => Set(ref _monitoringChanges, value, nameof(MonitoringChanges)); }
    public int OfflineMinutes { get { lock (_gate) return _offlineMinutes; } set => Set(ref _offlineMinutes, value, nameof(OfflineMinutes)); }
    public int GroupMinutes { get { lock (_gate) return _groupMinutes; } set => Set(ref _groupMinutes, value, nameof(GroupMinutes)); }
    public bool WebhookEnabled { get { lock (_gate) return _webhookEnabled; } set => Set(ref _webhookEnabled, value, nameof(WebhookEnabled)); }
    public bool EmailEnabled { get { lock (_gate) return _emailEnabled; } set => Set(ref _emailEnabled, value, nameof(EmailEnabled)); }
    public bool ClearWebhookDestination { get { lock (_gate) return _clearWebhookDestination; } set => Set(ref _clearWebhookDestination, value, nameof(ClearWebhookDestination)); }
    public bool ClearWebhookSecret { get { lock (_gate) return _clearWebhookSecret; } set => Set(ref _clearWebhookSecret, value, nameof(ClearWebhookSecret)); }
    public bool ClearSmtpPassword { get { lock (_gate) return _clearSmtpPassword; } set => Set(ref _clearSmtpPassword, value, nameof(ClearSmtpPassword)); }
    public string SmtpHost { get { lock (_gate) return _smtpHost; } set => Set(ref _smtpHost, value ?? "", nameof(SmtpHost)); }
    public string SmtpUsername { get { lock (_gate) return _smtpUsername; } set => Set(ref _smtpUsername, value ?? "", nameof(SmtpUsername)); }
    public string EmailFrom { get { lock (_gate) return _emailFrom; } set => Set(ref _emailFrom, value ?? "", nameof(EmailFrom)); }
    public string EmailTo { get { lock (_gate) return _emailTo; } set => Set(ref _emailTo, value ?? "", nameof(EmailTo)); }

    public async Task RefreshAsync()
    {
        if (!Begin(out var operation, out var generation)) return;
        bool unread;
        lock (_gate) unread = _unreadOnly;
        NotifyAll();
        var listTask = Safe(() => client.GetNotificationsAsync(0, PageSize, unread, operation.Token));
        var deliveryTask = Safe(() => client.GetNotificationDeliveriesAsync(0, PageSize, null, operation.Token));
        var policyTask = Safe(() => client.GetNotificationPolicyAsync(operation.Token));
        var list = await listTask;
        var deliveries = await deliveryTask;
        var policy = await policyTask;
        bool expired;
        lock (_gate)
        {
            if (!End(operation, generation)) return;
            expired = Expire(list.Outcome, deliveries.Outcome, policy.Outcome);
            if (!expired)
            {
                ApplyList(list, 0, unread);
                ApplyDeliveries(deliveries, 0, null);
                _policy = policy.Outcome == NotificationRequestOutcome.Success ? policy.Value : null;
                _policyText = _policy is null ? T("Notification settings are unavailable. The local center works independently.") : "";
                _needsRefresh = _policy is null;
                if (_policy is not null) ApplyPolicy(_policy);
            }
        }
        NotifyAll();
        if (expired) SessionExpired?.Invoke(this, EventArgs.Empty);
    }

    public Task ApplyFilterAsync() => LoadListAsync(0, UnreadOnly);
    public Task PreviousPageAsync() { lock (_gate) return CanPreviousPage ? LoadListAsync(Math.Max(0, _page!.Offset - PageSize), _appliedUnreadOnly) : Task.CompletedTask; }
    public Task NextPageAsync() { lock (_gate) return CanNextPage ? LoadListAsync(_page!.Offset + PageSize, _appliedUnreadOnly) : Task.CompletedTask; }
    private async Task LoadListAsync(int offset, bool unread)
    {
        if (!Begin(out var operation, out var generation)) return;
        NotifyAll();
        var result = await Safe(() => client.GetNotificationsAsync(offset, PageSize, unread, operation.Token));
        bool expired;
        lock (_gate)
        {
            if (!End(operation, generation)) return;
            expired = Expire(result.Outcome);
            if (!expired) ApplyList(result, offset, unread);
        }
        NotifyAll();
        if (expired) SessionExpired?.Invoke(this, EventArgs.Empty);
    }

    public async Task MarkSelectedReadAsync()
    {
        Guid id;
        bool unread;
        CancellationTokenSource operation;
        long generation;
        lock (_gate)
        {
            if (!CanMarkRead) return;
            id = _selected!.NotificationId; unread = _appliedUnreadOnly;
            if (!Begin(out operation, out generation)) return;
        }
        NotifyAll();
        var result = await Safe(() => client.MarkNotificationReadAsync(id, operation.Token));
        NotificationResult<NotificationPage>? list = null;
        if (result.Outcome == NotificationRequestOutcome.Success)
            list = await Safe(() => client.GetNotificationsAsync(0, PageSize, unread, operation.Token));
        bool expired;
        lock (_gate)
        {
            if (!End(operation, generation)) return;
            expired = Expire(result.Outcome, list?.Outcome ?? NotificationRequestOutcome.Success);
            if (!expired)
            {
                if (list is not null) ApplyList(list, 0, unread);
                _message = result.Outcome == NotificationRequestOutcome.Success ? T("The notification was marked as read.") : T("The read state could not be saved. Refresh to check it.");
                // An uncertain write is never replayed automatically.
                if (result.Outcome != NotificationRequestOutcome.Success) { _selected = null; _rows = []; _page = null; }
            }
        }
        NotifyAll();
        if (expired) SessionExpired?.Invoke(this, EventArgs.Empty);
    }

    public Task ShowSelectedDeliveriesAsync() { lock (_gate) return CanShowSelectedDeliveries ? LoadDeliveriesAsync(0, _selected!.NotificationId) : Task.CompletedTask; }
    public Task ShowAllDeliveriesAsync() => LoadDeliveriesAsync(0, null);
    public Task PreviousDeliveryPageAsync() { lock (_gate) return CanPreviousDeliveryPage ? LoadDeliveriesAsync(Math.Max(0, _deliveryPage!.Offset - PageSize), _deliveryNotificationId) : Task.CompletedTask; }
    public Task NextDeliveryPageAsync() { lock (_gate) return CanNextDeliveryPage ? LoadDeliveriesAsync(_deliveryPage!.Offset + PageSize, _deliveryNotificationId) : Task.CompletedTask; }
    private async Task LoadDeliveriesAsync(int offset, Guid? id)
    {
        if (!Begin(out var operation, out var generation)) return;
        NotifyAll();
        var result = await Safe(() => client.GetNotificationDeliveriesAsync(offset, PageSize, id, operation.Token));
        bool expired;
        lock (_gate)
        {
            if (!End(operation, generation)) return;
            expired = Expire(result.Outcome);
            if (!expired) ApplyDeliveries(result, offset, id);
        }
        NotifyAll();
        if (expired) SessionExpired?.Invoke(this, EventArgs.Empty);
    }

    public async Task SavePolicyAsync(ReadOnlyMemory<char> webhookUrl, ReadOnlyMemory<char> webhookSecret, ReadOnlyMemory<char> smtpPassword)
    {
        NotificationPolicyWrite request;
        CancellationTokenSource operation = null!;
        long generation = 0;
        lock (_gate)
        {
            if (!CanSavePolicy) return;
            if (_offlineMinutes is < 5 or > 120 || _groupMinutes is < 1 or > 60 || webhookUrl.Length > 2048 || !ValidProtectedInput(webhookSecret, 16) || !ValidProtectedInput(smtpPassword, 8) ||
                _clearWebhookDestination && !webhookUrl.IsEmpty || _clearWebhookSecret && !webhookSecret.IsEmpty || _clearSmtpPassword && !smtpPassword.IsEmpty ||
                _webhookEnabled && (_clearWebhookDestination || webhookUrl.IsEmpty && !_policy!.HasWebhookDestination) ||
                _smtpHost.Length > 253 || _smtpUsername.Length > 254 || _emailFrom.Length > 254 || _emailTo.Length > 254)
            { _message = T("Notification settings are invalid. Check the ranges, destinations and clear choices."); request = null!; }
            else request = new(_policy!.Version, _criticalAlerts, _monitoringChanges, _offlineMinutes, _groupMinutes, _webhookEnabled, null, null,
                _clearWebhookSecret, _clearWebhookDestination, _emailEnabled, NullIfBlank(_smtpHost), 587, NullIfBlank(_smtpUsername), null,
                _clearSmtpPassword, NullIfBlank(_emailFrom), NullIfBlank(_emailTo));
            if (request is not null && !Begin(out operation, out generation)) return;
        }
        if (request is null) { NotifyAll(); return; }
        NotifyAll();
        var result = await Safe(() => client.SetNotificationPolicyAsync(request, webhookUrl, webhookSecret, smtpPassword, operation.Token));
        bool expired;
        lock (_gate)
        {
            if (!End(operation, generation)) return;
            expired = Expire(result.Outcome);
            if (!expired)
            {
                if (result is { Outcome: NotificationRequestOutcome.Success, Value: { } value })
                { _policy = value; ApplyPolicy(value); _needsRefresh = false; _message = T("Notification settings saved. No test message was sent."); }
                else
                {
                    _needsRefresh = true;
                    _message = result.Outcome switch
                    {
                        NotificationRequestOutcome.Conflict => T("Notification settings changed elsewhere. Refresh and review them before saving again."),
                        NotificationRequestOutcome.InvalidPolicy => T("Core rejected these notification settings. Refresh and check the public destination and protected credentials."),
                        _ => T("The save result is uncertain. Refresh and review the current settings before saving again.")
                    };
                }
            }
        }
        NotifyAll();
        if (expired) SessionExpired?.Invoke(this, EventArgs.Empty);
    }

    private void ApplyList(NotificationResult<NotificationPage> result, int offset, bool unread)
    {
        _page = result is { Outcome: NotificationRequestOutcome.Success, Value: { } p } && p.Offset == offset && p.Limit == PageSize ? p : null;
        _appliedUnreadOnly = unread;
        _selected = null;
        _rows = _page?.Items.Select(n => new NotificationRow(n.NotificationId, n.ReadUtc is null, Kind(n.Kind), n.EndpointName,
            F("Grouped occurrences: {0}", n.Occurrences), F("Created: {0}; last observed: {1}", Date(n.CreatedUtc), Date(n.LastObservedUtc)), n.ReadUtc is null ? T("Unread") : T("Read"))).ToArray() ?? [];
        _listText = _page is null ? T("Notifications are unavailable. Refresh to try again.") : _rows.Count == 0 ? T("No notifications match this view.") : T("Local security notifications, newest first.");
    }

    private void ApplyDeliveries(NotificationResult<NotificationDeliveryPage> result, int offset, Guid? id)
    {
        _deliveryPage = result is { Outcome: NotificationRequestOutcome.Success, Value: { } p } && p.Offset == offset && p.Limit == PageSize ? p : null;
        _deliveryNotificationId = id;
        _deliveryRows = _deliveryPage?.Items.Select(d => new NotificationDeliveryRow(
            F("{0}: {1}; attempts: {2}", d.Channel == "webhook" ? T("Webhook") : T("Email"), DeliveryState(d.State), d.Attempts),
            F("Created: {0}; last attempt: {1}; next attempt: {2}", Date(d.CreatedUtc), Date(d.LastAttemptUtc), Date(d.NextAttemptUtc)),
            F("Result: {0}; notification: {1}", d.ResultCode ?? T("None"), d.NotificationId.ToString("D")))).ToArray() ?? [];
        _deliveryText = _deliveryPage is null ? T("Delivery history is unavailable. Refresh to try again.") : _deliveryRows.Count == 0 ? T("No external deliveries are recorded for this view.") : T("A retry can deliver a message more than once. Recipients can deduplicate by notification ID.");
    }

    private void ApplyPolicy(NotificationPolicy p)
    {
        _criticalAlerts = p.CriticalAlerts; _monitoringChanges = p.MonitoringChanges; _offlineMinutes = p.OfflineMinutes; _groupMinutes = p.GroupMinutes;
        _webhookEnabled = p.WebhookEnabled; _emailEnabled = p.EmailEnabled; _smtpHost = p.SmtpHost ?? ""; _smtpUsername = p.SmtpUsername ?? "";
        _emailFrom = p.EmailFrom ?? ""; _emailTo = p.EmailTo ?? "";
        _clearWebhookDestination = _clearWebhookSecret = _clearSmtpPassword = false;
    }

    private bool Begin(out CancellationTokenSource operation, out long generation)
    {
        lock (_gate)
        {
            operation = null!; generation = 0;
            if (!CanRefresh) return false;
            operation = _operation = new CancellationTokenSource(); generation = ++_generation; _message = "";
            return true;
        }
    }
    private bool End(CancellationTokenSource operation, long generation)
    { operation.Dispose(); if (_disposed || generation != _generation) return false; _operation = null; return true; }
    private bool Expire(params NotificationRequestOutcome[] outcomes)
    { if (!outcomes.Any(x => x is NotificationRequestOutcome.Unauthenticated or NotificationRequestOutcome.UntrustedConnection)) return false; ClearLocked(); return true; }
    private static async Task<NotificationResult<T>> Safe<T>(Func<Task<NotificationResult<T>>> action)
    { try { return await action(); } catch (Exception) { return new(NotificationRequestOutcome.Unavailable); } }
    public void Clear() { lock (_gate) { if (_disposed) return; ClearLocked(); } NotifyAll(); }
    private void ClearLocked()
    {
        ++_generation; _operation?.Cancel(); _operation = null; _page = null; _deliveryPage = null; _policy = null; _selected = null;
        _rows = []; _deliveryRows = []; _deliveryNotificationId = null; _needsRefresh = false; _unreadOnly = _appliedUnreadOnly = false;
        _listText = T("Notifications have not been read."); _deliveryText = _policyText = _message = "";
        _criticalAlerts = _monitoringChanges = true; _offlineMinutes = 15; _groupMinutes = 5; _webhookEnabled = _emailEnabled = false;
        _clearWebhookDestination = _clearWebhookSecret = _clearSmtpPassword = false; _smtpHost = _smtpUsername = _emailFrom = _emailTo = "";
    }
    public void Dispose() { lock (_gate) { if (_disposed) return; ClearLocked(); _disposed = true; } }
    private void Set<T>(ref T field, T value, string name) { lock (_gate) { if (_disposed || EqualityComparer<T>.Default.Equals(field, value)) return; field = value; } PropertyChanged?.Invoke(this, new(name)); }
    private void NotifyAll() => PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(string.Empty));
    private static bool ValidProtectedInput(ReadOnlyMemory<char> value, int minimum)
    {
        if (value.IsEmpty) return true;
        try
        {
            var count = new UTF8Encoding(false, true).GetByteCount(value.Span);
            if (count < minimum || count > 512) return false;
            foreach (var c in value.Span) if (char.IsControl(c)) return false;
            return true;
        }
        catch (EncoderFallbackException) { return false; }
    }
    private static string? NullIfBlank(string value) => string.IsNullOrWhiteSpace(value) ? null : value.Trim();
    private static string Saved(bool value) => value ? T("Saved") : T("None");
    private static string Date(DateTimeOffset? value) => value?.ToUniversalTime().ToString("yyyy-MM-dd HH:mm:ss 'UTC'", CultureInfo.InvariantCulture) ?? T("None");
    internal static string Kind(string value) => value switch
    {
        "criticalAlertNew" => T("New critical alert"), "criticalAlertReopened" => T("Critical alert reopened"), "criticalAlertEscalated" => T("Alert escalated to critical"),
        "monitoringOffline" => T("Endpoint monitoring lost"), "monitoringRecovered" => T("Endpoint monitoring recovered"), _ => T("Unknown")
    };
    private static string DeliveryState(string value) => value switch
    {
        "pending" => T("Pending"), "sending" => T("Sending"), "retry" => T("Retry scheduled"), "succeeded" => T("Delivered"), "failed" => T("Failed"), "cancelled" => T("Cancelled"), _ => T("Unknown")
    };
}
