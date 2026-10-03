using System.Net;
using System.Text;
using SentinelAI.Desktop.Foundation;

var assertions = 0;
NavigationTests();
await ShellLifecycleTestsAsync();
await HealthResponseTestsAsync();
await HealthCancellationTestsAsync();
Console.WriteLine($"Desktop foundation: {assertions} assertions passed.");

void Ensure(bool condition, string message)
{
    assertions++;
    if (!condition)
        throw new InvalidOperationException(message);
}

void Throws<TException>(Action action, string message) where TException : Exception
{
    assertions++;
    try { action(); }
    catch (TException) { return; }
    throw new InvalidOperationException(message);
}

async Task<TException> ThrowsAsync<TException>(Func<Task> action, string message) where TException : Exception
{
    assertions++;
    try { await action().WaitAsync(TimeSpan.FromSeconds(6)); }
    catch (TException exception) { return exception; }
    throw new InvalidOperationException(message);
}

void NavigationTests()
{
    using var client = new ControlledCoreClient();
    using var shell = new ShellViewModel(client, "1.2.3-test");
    Ensure(shell.Title == "SentinelAI" && shell.Version == "1.2.3-test", "The shell lost the application title or supplied version.");
    Ensure(shell.Pages.Select(page => page.Id).SequenceEqual(Enum.GetValues<PageId>()), "Navigation must contain each assigned page exactly once in order.");
    Ensure(shell.CurrentPage.Id == PageId.Overview, "Startup must select Overview.");
    Ensure(shell.Pages.All(page => !string.IsNullOrWhiteSpace(page.Title) && !string.IsNullOrWhiteSpace(page.Description)), "All placeholder pages need a title and explanation.");
    Ensure(((ICollection<NavigationPage>)shell.Pages).IsReadOnly, "A caller can mutate the navigation collection.");
    Throws<NotSupportedException>(() => ((IList<NavigationPage>)shell.Pages)[0] = new NavigationPage(PageId.Settings, "Injected", "Injected"), "Navigation was mutable.");
    Ensure(client.Calls == 0 && !shell.IsCheckingCore && shell.RefreshCoreCommand.CanExecute(null), "Constructing the shell must not block on a network request.");

    var changes = new List<string?>();
    shell.PropertyChanged += (_, args) => changes.Add(args.PropertyName);
    foreach (var page in shell.Pages.Skip(1))
    {
        shell.CurrentPage = page;
        Ensure(ReferenceEquals(shell.CurrentPage, page), "Navigation failed to select its placeholder.");
    }
    Ensure(changes.Count == 5 && changes.All(name => name == nameof(shell.CurrentPage)), "Navigation must notify only actual page changes.");
    shell.CurrentPage = shell.CurrentPage;
    Ensure(changes.Count == 5, "Selecting the current page created an unnecessary notification.");
    var selected = shell.CurrentPage;
    Throws<ArgumentException>(() => shell.CurrentPage = selected with { Title = "Injected" }, "A copied or injected page entered the shell.");
    Throws<ArgumentException>(() => shell.CurrentPage = new NavigationPage((PageId)99, "Injected", "Injected"), "An undefined page entered the shell.");
    Throws<ArgumentNullException>(() => shell.CurrentPage = null!, "A null page entered the shell.");
    Ensure(ReferenceEquals(shell.CurrentPage, selected) && changes.Count == 5, "Rejected navigation changed selection or raised notifications.");
    Throws<ArgumentNullException>(() => _ = new ShellViewModel(null!, "1.0"), "A null service was accepted.");
    Throws<ArgumentException>(() => _ = new ShellViewModel(client, " "), "An empty application version was accepted.");
}

async Task ShellLifecycleTestsAsync()
{
    using (var client = new ControlledCoreClient())
    using (var shell = new ShellViewModel(client, "1.0"))
    {
        var properties = new List<string?>();
        var commandNotifications = 0;
        shell.PropertyChanged += (_, args) => properties.Add(args.PropertyName);
        shell.RefreshCoreCommand.CanExecuteChanged += (_, _) => commandNotifications++;
        var initialization = shell.InitializeAsync();
        Ensure(!initialization.IsCompleted && shell.IsCheckingCore && client.Calls == 1, "Startup did not remain asynchronous while Core was pending.");
        Ensure(!shell.RefreshCoreCommand.CanExecute(null), "Refresh remained enabled during a pending request.");
        var refresh = shell.RefreshCoreStatusAsync();
        Ensure(ReferenceEquals(initialization, refresh), "Concurrent refresh did not join the existing request.");
        shell.RefreshCoreCommand.Execute(null);
        Ensure(client.Calls == 1, "Executing a disabled refresh created another request.");
        client.Complete(CoreHealth.Available);
        await initialization.WaitAsync(TimeSpan.FromSeconds(2));
        Ensure(!shell.IsCheckingCore && shell.CoreStatusText == "Local Core available", "Healthy Core was not displayed.");
        Ensure(shell.RefreshCoreCommand.CanExecute(null), "Refresh was not enabled after completion.");
        Ensure(properties.Count(name => name == nameof(shell.IsCheckingCore)) == 2 && properties.Count(name => name == nameof(shell.CoreStatusText)) == 2, "Core availability state changes did not notify bindings.");
        Ensure(commandNotifications == 2, "The refresh command did not notify its busy state.");
        var unavailable = shell.RefreshCoreStatusAsync();
        client.Complete(CoreHealth.Unavailable);
        await unavailable.WaitAsync(TimeSpan.FromSeconds(2));
        Ensure(shell.CoreStatusText == "Local Core unavailable" && !shell.IsCheckingCore && client.Calls == 2, "Explicit refresh failed to display Core unavailability.");
        var failure = shell.RefreshCoreStatusAsync();
        client.Fail(new HttpRequestException("synthetic-private-details"));
        await failure.WaitAsync(TimeSpan.FromSeconds(2));
        Ensure(shell.CoreStatusText == "Local Core unavailable" && !shell.CoreStatusText.Contains("private", StringComparison.Ordinal), "A service failure leaked exception text or escaped the shell.");
        Ensure(shell.RefreshCoreCommand.CanExecute(null), "A service failure left the shell unable to retry.");
    }

    using (var client = new ControlledCoreClient())
    using (var shell = new ShellViewModel(client, "1.0"))
    {
        Parallel.For(0, 32, _ => shell.RefreshCoreCommand.Execute(null));
        var pending = shell.RefreshCoreStatusAsync();
        Ensure(client.Calls == 1, "Simultaneous refresh commands created duplicate network calls.");
        client.Complete(CoreHealth.Available);
        await pending.WaitAsync(TimeSpan.FromSeconds(2));
        Ensure(shell.CoreStatusText == "Local Core available" && !shell.IsCheckingCore, "Concurrent refresh completion was inconsistent.");
    }

    using (var client = new ControlledCoreClient(ignoreCancellation: true))
    {
        var shell = new ShellViewModel(client, "1.0");
        var pending = shell.InitializeAsync();
        var observedToken = client.LastToken;
        shell.Dispose();
        var disposedStatus = shell.CoreStatusText;
        var notificationsAfterDisposal = 0;
        shell.PropertyChanged += (_, _) => notificationsAfterDisposal++;
        Ensure(observedToken.IsCancellationRequested && client.DisposeCalls == 1, "Shutdown did not cancel the pending check and dispose its service.");
        Ensure(!shell.IsCheckingCore && !shell.RefreshCoreCommand.CanExecute(null), "Shutdown left a refresh active or enabled.");
        shell.Dispose();
        await shell.RefreshCoreStatusAsync();
        await shell.InitializeAsync();
        shell.RefreshCoreCommand.Execute(null);
        Ensure(client.Calls == 1 && client.DisposeCalls == 1, "Repeated shutdown or refresh after shutdown affected the disposed client.");
        client.Complete(CoreHealth.Available);
        await pending.WaitAsync(TimeSpan.FromSeconds(2));
        Ensure(shell.CoreStatusText == disposedStatus && notificationsAfterDisposal == 0, "A stale successful response changed the disposed shell.");
        Throws<ObjectDisposedException>(() => shell.CurrentPage = shell.Pages[1], "Disposed navigation accepted further changes.");
    }

    using (var client = new ControlledCoreClient())
    {
        var shell = new ShellViewModel(client, "1.0");
        var pending = shell.InitializeAsync();
        shell.Dispose();
        await pending.WaitAsync(TimeSpan.FromSeconds(2));
        Ensure(!pending.IsFaulted && !pending.IsCanceled && client.LastToken.IsCancellationRequested, "Owned shutdown cancellation escaped as an unhandled refresh failure.");
    }

    using (var client = new ImmediateCoreClient())
    using (var shell = new ShellViewModel(client, "1.0"))
    {
        await shell.InitializeAsync();
        Ensure(shell.CoreStatusText == "Local Core available" && !shell.IsCheckingCore, "An immediately completed service caused a stuck refresh.");
        await shell.RefreshCoreStatusAsync();
        Ensure(client.Calls == 2, "A completed synchronous request was retained as a pending request.");
    }

    using (var client = new ControlledCoreClient())
    using (var shell = new ShellViewModel(client, "1.0"))
    {
        Task? second = null;
        shell.PropertyChanged += (_, args) =>
        {
            if (args.PropertyName == nameof(shell.CoreStatusText) && shell.CoreStatusText == "Local Core available" && second is null)
                second = shell.RefreshCoreStatusAsync();
        };
        var first = shell.InitializeAsync();
        client.Complete(CoreHealth.Available);
        await first.WaitAsync(TimeSpan.FromSeconds(2));
        Ensure(second is not null && !second.IsCompleted && shell.IsCheckingCore && client.Calls == 2, "A binding-triggered refresh was overwritten by the previous completion.");
        client.Complete(CoreHealth.Unavailable);
        await second!.WaitAsync(TimeSpan.FromSeconds(2));
        Ensure(!shell.IsCheckingCore && shell.CoreStatusText == "Local Core unavailable", "A refresh requested during notification failed to settle.");
    }
}

async Task HealthResponseTestsAsync()
{
    using (var handler = new ResponseHandler((request, _) => Task.FromResult(JsonResponse("{\"status\":\"healthy\"}"))))
    using (var client = new HttpCoreClient(handler))
    {
        Ensure(await client.CheckHealthAsync(default) == CoreHealth.Available, "The existing Core health response was not accepted.");
        Ensure(handler.Requests == 1 && handler.LastUri == new Uri("http://127.0.0.1:5000/api/health"), "The Core destination was not the fixed loopback health route.");
        Ensure(handler.LastMethod == HttpMethod.Get && !handler.HadAuthorization && !handler.HadCookies, "The public health check sent credentials or used the wrong method.");
        Ensure(handler.AcceptsJson, "The health request did not request JSON.");
    }

    string[] invalidBodies =
    [
        "", "<html>failure</html>", "null", "[]", "{}", "{\"status\":true}",
        "{\"status\":\"unhealthy\"}", "{\"status\":\"Healthy\"}", "{\"status\":\"healthy\",\"extra\":true}",
        "{\"status\":\"healthy\",\"status\":\"healthy\"}", "{\"STATUS\":\"healthy\"}", "{\"status\":\"healthy\",}",
        "{\"status\":{\"nested\":{\"nested\":{\"nested\":{\"nested\":true}}}}}"
    ];
    foreach (var body in invalidBodies)
    {
        using var handler = new ResponseHandler((_, _) => Task.FromResult(JsonResponse(body)));
        using var client = new HttpCoreClient(handler);
        Ensure(await client.CheckHealthAsync(default) == CoreHealth.Unavailable, "A malformed or ambiguous health response was accepted.");
    }

    foreach (var status in new[] { HttpStatusCode.NoContent, HttpStatusCode.Redirect, HttpStatusCode.TemporaryRedirect, HttpStatusCode.Unauthorized, HttpStatusCode.InternalServerError })
    {
        using var handler = new ResponseHandler((_, _) =>
        {
            var response = JsonResponse("{\"status\":\"healthy\"}");
            response.StatusCode = status;
            response.Headers.Location = new Uri("https://untrusted.example/api/health");
            return Task.FromResult(response);
        });
        using var client = new HttpCoreClient(handler);
        Ensure(await client.CheckHealthAsync(default) == CoreHealth.Unavailable && handler.Requests == 1, "An unsuccessful response or redirect was accepted or retried.");
    }

    using (var handler = new ResponseHandler((_, _) => Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK) { Content = new StringContent("{\"status\":\"healthy\"}", Encoding.UTF8, "text/html") })))
    using (var client = new HttpCoreClient(handler))
        Ensure(await client.CheckHealthAsync(default) == CoreHealth.Unavailable, "A non-JSON media type was accepted.");

    var healthyBody = "{\"status\":\"healthy\"}";
    foreach (var length in new[] { 4096, 4097, 65536 })
    {
        var bytes = Encoding.UTF8.GetBytes(healthyBody.PadRight(length));
        using var stream = new NonSeekableStream(bytes);
        using var handler = new ResponseHandler((_, _) =>
        {
            var response = new HttpResponseMessage(HttpStatusCode.OK) { Content = new StreamContent(stream) };
            response.Content.Headers.ContentType = new("application/json");
            return Task.FromResult(response);
        });
        using var client = new HttpCoreClient(handler);
        Ensure(await client.CheckHealthAsync(default) == (length == 4096 ? CoreHealth.Available : CoreHealth.Unavailable), "The streamed health response bound was not enforced correctly.");
        Ensure(stream.BytesRead <= 4097, "An unknown-length response was read beyond the fixed bound.");
    }

    using (var stream = new ReadFailureStream())
    using (var handler = new ResponseHandler((_, _) =>
    {
        var response = new HttpResponseMessage(HttpStatusCode.OK) { Content = new StreamContent(stream) };
        response.Content.Headers.ContentType = new("application/json");
        response.Content.Headers.ContentLength = 4097;
        return Task.FromResult(response);
    }))
    using (var client = new HttpCoreClient(handler))
    {
        Ensure(await client.CheckHealthAsync(default) == CoreHealth.Unavailable && stream.ReadCalls == 0, "A declared oversized response was read before rejection.");
    }

    using (var stream = new ReadFailureStream())
    using (var handler = new ResponseHandler((_, _) =>
    {
        var response = new HttpResponseMessage(HttpStatusCode.OK) { Content = new StreamContent(stream) };
        response.Content.Headers.ContentType = new("application/json");
        return Task.FromResult(response);
    }))
    using (var client = new HttpCoreClient(handler))
        Ensure(await client.CheckHealthAsync(default) == CoreHealth.Unavailable, "A response stream failure escaped the availability boundary.");

    using (var handler = new ResponseHandler((_, _) => Task.FromException<HttpResponseMessage>(new HttpRequestException("synthetic-private-details"))))
    using (var client = new HttpCoreClient(handler))
        Ensure(await client.CheckHealthAsync(default) == CoreHealth.Unavailable, "A network error escaped the availability boundary.");

    using (var handler = new HttpClientHandler { AllowAutoRedirect = true, UseProxy = true, UseCookies = true, Credentials = new NetworkCredential("test-only", "test-only") })
    using (var client = new HttpCoreClient(handler))
        Ensure(!handler.AllowAutoRedirect && !handler.UseProxy && !handler.UseCookies && !handler.UseDefaultCredentials && handler.Credentials is null, "A supplied transport retained redirects, ambient proxy or credentials.");

    using (var handler = new SocketsHttpHandler { AllowAutoRedirect = true, UseProxy = true, UseCookies = true, Credentials = CredentialCache.DefaultCredentials })
    using (var client = new HttpCoreClient(handler))
        Ensure(!handler.AllowAutoRedirect && !handler.UseProxy && !handler.UseCookies && handler.Credentials is null, "A supplied sockets transport retained redirects, ambient proxy or credentials.");
}

async Task HealthCancellationTestsAsync()
{
    using (var cancellation = new CancellationTokenSource())
    using (var handler = new ResponseHandler((_, _) => Task.FromResult(JsonResponse("{\"status\":\"healthy\"}"))))
    using (var client = new HttpCoreClient(handler))
    {
        cancellation.Cancel();
        var exception = await ThrowsAsync<OperationCanceledException>(() => client.CheckHealthAsync(cancellation.Token), "Pre-canceled health requests were converted to unavailability.");
        Ensure(exception.CancellationToken == cancellation.Token && handler.Requests == 0, "Pre-cancellation did not preserve caller cancellation before HTTP.");
    }

    using (var cancellation = new CancellationTokenSource())
    using (var handler = new ResponseHandler(async (_, token) =>
    {
        await Task.Delay(Timeout.InfiniteTimeSpan, token);
        return JsonResponse("{\"status\":\"healthy\"}");
    }))
    using (var client = new HttpCoreClient(handler))
    {
        var pending = client.CheckHealthAsync(cancellation.Token);
        cancellation.Cancel();
        var exception = await ThrowsAsync<OperationCanceledException>(() => pending, "In-flight caller cancellation was swallowed.");
        Ensure(exception.CancellationToken == cancellation.Token, "In-flight cancellation lost the caller token.");
    }

    using (var handler = new ResponseHandler(async (_, token) =>
    {
        await Task.Delay(Timeout.InfiniteTimeSpan, token);
        return JsonResponse("{\"status\":\"healthy\"}");
    }))
    using (var client = new HttpCoreClient(handler))
        Ensure(await client.CheckHealthAsync(default).WaitAsync(TimeSpan.FromSeconds(6)) == CoreHealth.Unavailable, "The fixed request deadline did not produce generic unavailability.");

    using (var stream = new PendingReadStream())
    using (var handler = new ResponseHandler((_, _) => Task.FromResult(StreamResponse(stream))))
    using (var client = new HttpCoreClient(handler))
    {
        Ensure(await client.CheckHealthAsync(default).WaitAsync(TimeSpan.FromSeconds(6)) == CoreHealth.Unavailable && stream.ReadCalls == 1, "The health response body did not share the bounded request deadline.");
    }

    using (var cancellation = new CancellationTokenSource())
    using (var stream = new PendingReadStream())
    using (var handler = new ResponseHandler((_, _) => Task.FromResult(StreamResponse(stream))))
    using (var client = new HttpCoreClient(handler))
    {
        var pending = client.CheckHealthAsync(cancellation.Token);
        Ensure(stream.ReadCalls == 1, "The cancellation test did not reach the health response body.");
        cancellation.Cancel();
        var exception = await ThrowsAsync<OperationCanceledException>(() => pending, "Caller cancellation while reading the body was swallowed.");
        Ensure(exception.CancellationToken == cancellation.Token, "Body cancellation lost the caller token.");
    }

    using (var handler = new ResponseHandler((_, _) => Task.FromResult(JsonResponse("{\"status\":\"healthy\"}"))))
    {
        var client = new HttpCoreClient(handler);
        client.Dispose();
        client.Dispose();
        await ThrowsAsync<ObjectDisposedException>(() => client.CheckHealthAsync(default), "A disposed HTTP client accepted new requests.");
        Ensure(handler.DisposeCalls == 1, "HTTP transport was disposed more than once.");
    }
}

static HttpResponseMessage JsonResponse(string body) => new(HttpStatusCode.OK)
{
    Content = new StringContent(body, Encoding.UTF8, "application/json")
};

static HttpResponseMessage StreamResponse(Stream stream)
{
    var response = new HttpResponseMessage(HttpStatusCode.OK) { Content = new StreamContent(stream) };
    response.Content.Headers.ContentType = new("application/json");
    return response;
}

sealed class ControlledCoreClient(bool ignoreCancellation = false) : ICoreClient
{
    private TaskCompletionSource<CoreHealth>? _pending;
    private int _calls;
    public int Calls => Volatile.Read(ref _calls);
    public int DisposeCalls { get; private set; }
    public CancellationToken LastToken { get; private set; }

    public Task<CoreHealth> CheckHealthAsync(CancellationToken cancellationToken)
    {
        Interlocked.Increment(ref _calls);
        LastToken = cancellationToken;
        var completion = new TaskCompletionSource<CoreHealth>(TaskCreationOptions.RunContinuationsAsynchronously);
        _pending = completion;
        if (!ignoreCancellation)
            cancellationToken.Register(() => completion.TrySetCanceled(cancellationToken));
        return completion.Task;
    }

    public void Complete(CoreHealth health) => _pending!.TrySetResult(health);
    public void Fail(Exception exception) => _pending!.TrySetException(exception);
    public void Dispose() => DisposeCalls++;
}

sealed class ImmediateCoreClient : ICoreClient
{
    public int Calls { get; private set; }
    public Task<CoreHealth> CheckHealthAsync(CancellationToken cancellationToken)
    {
        Calls++;
        return Task.FromResult(CoreHealth.Available);
    }
    public void Dispose() { }
}

sealed class ResponseHandler(Func<HttpRequestMessage, CancellationToken, Task<HttpResponseMessage>> response) : HttpMessageHandler
{
    public int Requests { get; private set; }
    public int DisposeCalls { get; private set; }
    public Uri? LastUri { get; private set; }
    public HttpMethod? LastMethod { get; private set; }
    public bool HadAuthorization { get; private set; }
    public bool HadCookies { get; private set; }
    public bool AcceptsJson { get; private set; }

    protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
    {
        Requests++;
        LastUri = request.RequestUri;
        LastMethod = request.Method;
        HadAuthorization = request.Headers.Authorization is not null;
        HadCookies = request.Headers.Contains("Cookie");
        AcceptsJson = request.Headers.Accept.Any(value => value.MediaType == "application/json");
        return response(request, cancellationToken);
    }

    protected override void Dispose(bool disposing)
    {
        if (disposing) DisposeCalls++;
        base.Dispose(disposing);
    }
}

sealed class NonSeekableStream(byte[] bytes) : MemoryStream(bytes)
{
    public override bool CanSeek => false;
    public int BytesRead { get; private set; }
    public override async ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken cancellationToken = default)
    {
        var count = await base.ReadAsync(buffer, cancellationToken);
        BytesRead += count;
        return count;
    }
}

sealed class ReadFailureStream : Stream
{
    public int ReadCalls { get; private set; }
    public override bool CanRead => true;
    public override bool CanSeek => false;
    public override bool CanWrite => false;
    public override long Length => throw new NotSupportedException();
    public override long Position { get => throw new NotSupportedException(); set => throw new NotSupportedException(); }
    public override ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken cancellationToken = default)
    {
        ReadCalls++;
        throw new IOException("synthetic-private-details");
    }
    public override int Read(byte[] buffer, int offset, int count) => throw new IOException("synthetic-private-details");
    public override void Flush() => throw new NotSupportedException();
    public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();
    public override void SetLength(long value) => throw new NotSupportedException();
    public override void Write(byte[] buffer, int offset, int count) => throw new NotSupportedException();
}

sealed class PendingReadStream : Stream
{
    public int ReadCalls { get; private set; }
    public override bool CanRead => true;
    public override bool CanSeek => false;
    public override bool CanWrite => false;
    public override long Length => throw new NotSupportedException();
    public override long Position { get => throw new NotSupportedException(); set => throw new NotSupportedException(); }
    public override async ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken cancellationToken = default)
    {
        ReadCalls++;
        await Task.Delay(Timeout.InfiniteTimeSpan, cancellationToken);
        return 0;
    }
    public override int Read(byte[] buffer, int offset, int count) => throw new NotSupportedException();
    public override void Flush() => throw new NotSupportedException();
    public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();
    public override void SetLength(long value) => throw new NotSupportedException();
    public override void Write(byte[] buffer, int offset, int count) => throw new NotSupportedException();
}
