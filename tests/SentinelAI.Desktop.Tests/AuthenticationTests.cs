using System.Net;
using System.Net.Http.Headers;
using System.Text;
using SentinelAI.Desktop.Foundation;

internal static class AuthenticationTests
{
    private static int _assertions;
    private const string Password = "synthetic-password-12345";
    private const string AccessToken = "synthetic.access-token_123";
    private const string RefreshToken = "synthetic.refresh-token_456";

    public static async Task<int> RunAsync()
    {
        _assertions = 0;
        await AuthenticationTransportAsync();
        await AuthenticationFailuresAsync();
        await AuthenticationLifetimeAsync();
        await ViewModelSetupAsync();
        await ViewModelSessionsAsync();
        await ViewModelStaleCompletionsAsync();
        return _assertions;
    }

    private static void Ensure(bool condition, string message)
    {
        _assertions++;
        if (!condition) throw new InvalidOperationException(message);
    }

    private static void Throws<TException>(Action action, string message) where TException : Exception
    {
        _assertions++;
        try { action(); }
        catch (TException) { return; }
        throw new InvalidOperationException(message);
    }

    private static async Task<TException> ThrowsAsync<TException>(Func<Task> action, string message) where TException : Exception
    {
        _assertions++;
        try { await action().WaitAsync(TimeSpan.FromSeconds(5)); }
        catch (TException exception) { return exception; }
        throw new InvalidOperationException(message);
    }

    private static HttpResponseMessage Json(HttpStatusCode status, string body) => new(status)
    {
        Content = new StringContent(body, Encoding.UTF8, "application/json")
    };

    private static HttpResponseMessage LoginResponse() => Json(HttpStatusCode.OK,
        "{\"tokenType\":\"Bearer\",\"accessToken\":\"" + AccessToken + "\",\"expiresIn\":900,\"refreshToken\":\"" + RefreshToken + "\"}");

    private static HttpResponseMessage AdministratorResponse() => Json(HttpStatusCode.OK,
        "{\"username\":\"admin\",\"role\":\"administrator\"}");

    private static async Task AuthenticationTransportAsync()
    {
        var trust = new TestTrust();
        using (var handler = new AuthenticationHandler((request, _) => Task.FromResult(
                   request.RequestUri!.AbsolutePath == "/api/auth/login" ? LoginResponse() : AdministratorResponse())))
        using (var client = new HttpAuthenticationClient(trust, handler))
        {
            var password = Password.ToCharArray();
            var result = await client.SignInAsync(" admin ", password.AsMemory(), default);
            Ensure(result.Outcome == AuthenticationOutcome.Authenticated && result.Username == "admin", "Core's existing login and administrator identity were not accepted.");
            Ensure(handler.Requests.Count >= 1 && handler.Requests[0].Method == HttpMethod.Post &&
                   handler.Requests[0].Uri == new Uri("http://127.0.0.1:5000/api/auth/login"), "Sign-in did not use Core's fixed local POST route.");
            Ensure(handler.Requests[0].Body is not null && handler.Requests[0].Body!.Contains("\"username\":\"admin\"", StringComparison.Ordinal) &&
                   handler.Requests[0].Body!.Contains("\"password\":\"" + Password + "\"", StringComparison.Ordinal), "Core's authoritative username/password payload changed.");
            Ensure(handler.Requests.All(request => !request.Uri.ToString().Contains(Password, StringComparison.Ordinal) &&
                   !request.Headers.Contains(Password, StringComparison.Ordinal)), "A password entered a URI or HTTP header.");
            Ensure(handler.Requests.Skip(1).All(request => request.Body is null || !request.Body.Contains(Password, StringComparison.Ordinal)), "A password was sent outside the login POST body.");
            Ensure(!result.ToString().Contains(Password, StringComparison.Ordinal) && !result.ToString().Contains(AccessToken, StringComparison.Ordinal) &&
                   !result.ToString().Contains(RefreshToken, StringComparison.Ordinal), "A public authentication result disclosed session or credential material.");
            Ensure(!typeof(HttpAuthenticationClient).GetProperties().Any(property => property.PropertyType == typeof(string) &&
                   property.Name.Contains("Token", StringComparison.OrdinalIgnoreCase)), "The HTTP client exposed a token property.");
            Ensure(trust.Calls >= 1 && trust.Origins.All(origin => origin == new Uri("http://127.0.0.1:5000/")), "Credential requests skipped destination trust verification.");
            Array.Clear(password);
        }

        var deniedTrust = new TestTrust { IsTrusted = false };
        using (var handler = new AuthenticationHandler((_, _) => Task.FromResult(LoginResponse())))
        using (var client = new HttpAuthenticationClient(deniedTrust, handler))
        {
            var result = await client.SignInAsync("admin", Password.AsMemory(), default);
            Ensure(result.Outcome == AuthenticationOutcome.UntrustedConnection && handler.Requests.Count == 0, "A denied Core destination received a password.");
        }

        Throws<ArgumentException>(() => new HttpAuthenticationClient(new TestTrust(), new HttpClientHandler(), new Uri("http://192.0.2.1:5000/")),
            "Remote plaintext authentication was accepted.");
        Throws<ArgumentException>(() => new HttpAuthenticationClient(new TestTrust(), new HttpClientHandler(), new Uri("http://127.0.0.1:5000/untrusted")),
            "An origin with a path was accepted as the fixed Core destination.");

        using (var handler = new HttpClientHandler
               {
                   AllowAutoRedirect = true, UseProxy = true, UseCookies = true,
                   UseDefaultCredentials = true, Credentials = CredentialCache.DefaultCredentials
               })
        using (var client = new HttpAuthenticationClient(new TestTrust(), handler))
            Ensure(!handler.AllowAutoRedirect && !handler.UseProxy && !handler.UseCookies &&
                   !handler.UseDefaultCredentials && handler.Credentials is null, "The authentication transport retained redirects, ambient proxy, cookies or credentials.");

        using (var handler = new SocketsHttpHandler
               {
                   AllowAutoRedirect = true, UseProxy = true, UseCookies = true,
                   Credentials = CredentialCache.DefaultCredentials
               })
        using (var client = new HttpAuthenticationClient(new TestTrust(), handler))
            Ensure(!handler.AllowAutoRedirect && !handler.UseProxy && !handler.UseCookies && handler.Credentials is null,
                "The socket transport retained redirects, ambient proxy, cookies or credentials.");
    }

    private static async Task AuthenticationFailuresAsync()
    {
        foreach (var (status, expected) in new[]
                 {
                     (HttpStatusCode.Unauthorized, AuthenticationOutcome.InvalidCredentials),
                     (HttpStatusCode.TooManyRequests, AuthenticationOutcome.Throttled),
                     (HttpStatusCode.ServiceUnavailable, AuthenticationOutcome.Unavailable)
                 })
        {
            using var handler = new AuthenticationHandler((_, _) => Task.FromResult(Json(status, "{\"error\":\"private-server-detail\"}")));
            using var client = new HttpAuthenticationClient(new TestTrust(), handler);
            var result = await client.SignInAsync("unknown-user", Password.AsMemory(), default);
            Ensure(result.Outcome == expected, "A Core login status was mapped incorrectly.");
            Ensure(!result.ToString().Contains("private-server-detail", StringComparison.Ordinal), "A server error detail entered the public result.");
        }

        foreach (var body in new[]
                 {
                     "", "{}", "<html>failure</html>",
                     "{\"accessToken\":\"\",\"expiresIn\":900}",
                     "{\"tokenType\":\"Bearer\",\"accessToken\":\"" + AccessToken + "\",\"expiresIn\":0}"
                 })
        {
            using var handler = new AuthenticationHandler((_, _) => Task.FromResult(Json(HttpStatusCode.OK, body)));
            using var client = new HttpAuthenticationClient(new TestTrust(), handler);
            var result = await client.SignInAsync("admin", Password.AsMemory(), default);
            Ensure(result.Outcome != AuthenticationOutcome.Authenticated, "Malformed or expired Core login material created a session.");
        }

        using (var handler = new AuthenticationHandler((_, _) => Task.FromResult(new HttpResponseMessage(HttpStatusCode.Redirect)
               { Headers = { Location = new Uri("https://untrusted.example/api/auth/login") } })))
        using (var client = new HttpAuthenticationClient(new TestTrust(), handler))
        {
            var result = await client.SignInAsync("admin", Password.AsMemory(), default);
            Ensure(result.Outcome != AuthenticationOutcome.Authenticated && handler.Requests.Count == 1, "Core login followed or accepted a redirect.");
        }

        using (var handler = new AuthenticationHandler((_, _) => Task.FromResult(Json(HttpStatusCode.OK, new string('x', 65537)))))
        using (var client = new HttpAuthenticationClient(new TestTrust(), handler))
            Ensure((await client.SignInAsync("admin", Password.AsMemory(), default)).Outcome != AuthenticationOutcome.Authenticated,
                "An oversized login response was accepted.");

        using (var body = new CountedReadStream(Encoding.UTF8.GetBytes(new string('x', 1024 * 1024))))
        using (var handler = new AuthenticationHandler((_, _) =>
               {
                   var response = new HttpResponseMessage(HttpStatusCode.OK) { Content = new StreamContent(body) };
                   response.Content.Headers.ContentType = new MediaTypeHeaderValue("application/json");
                   return Task.FromResult(response);
               }))
        using (var client = new HttpAuthenticationClient(new TestTrust(), handler))
        {
            Ensure((await client.SignInAsync("admin", Password.AsMemory(), default)).Outcome != AuthenticationOutcome.Authenticated,
                "An oversized unknown-length login response was accepted.");
            Ensure(body.BytesRead <= 65537, "The authentication client read beyond its 64 KiB response bound.");
        }

        using (var handler = new AuthenticationHandler((_, _) => Task.FromException<HttpResponseMessage>(new HttpRequestException("private-network-detail"))))
        using (var client = new HttpAuthenticationClient(new TestTrust(), handler))
        {
            var result = await client.SignInAsync("admin", Password.AsMemory(), default);
            Ensure(result.Outcome == AuthenticationOutcome.Unavailable && !result.ToString().Contains("private-network-detail", StringComparison.Ordinal),
                "Network failures escaped the generic authentication boundary.");
        }

        using (var cancellation = new CancellationTokenSource())
        using (var handler = new AuthenticationHandler(async (_, token) =>
               {
                   await Task.Delay(Timeout.InfiniteTimeSpan, token);
                   return LoginResponse();
               }))
        using (var client = new HttpAuthenticationClient(new TestTrust(), handler))
        {
            var pending = client.SignInAsync("admin", Password.AsMemory(), cancellation.Token);
            cancellation.Cancel();
            await ThrowsAsync<OperationCanceledException>(async () => await pending, "Caller cancellation did not stop pending authentication.");
        }

        using (var handler = new AuthenticationHandler(async (request, token) =>
               {
                   if (request.RequestUri!.AbsolutePath == "/api/auth/login") return LoginResponse();
                   await Task.Delay(Timeout.InfiniteTimeSpan, token);
                   return AdministratorResponse();
               }))
        using (var client = new HttpAuthenticationClient(new TestTrust(), handler))
        {
            var watch = System.Diagnostics.Stopwatch.StartNew();
            var result = await client.SignInAsync("admin", Password.AsMemory(), default).WaitAsync(TimeSpan.FromSeconds(6));
            Ensure(result.Outcome != AuthenticationOutcome.Authenticated && watch.Elapsed < TimeSpan.FromSeconds(5),
                "A stalled Core administrator check exceeded its bounded request deadline.");
        }
    }

    private static async Task AuthenticationLifetimeAsync()
    {
        var clock = new ManualTimeProvider();
        using (var handler = new AuthenticationHandler((request, _) => Task.FromResult(
                   request.RequestUri!.AbsolutePath == "/api/auth/login" ? LoginResponse() : AdministratorResponse())))
        using (var client = new HttpAuthenticationClient(new TestTrust(), handler, timeProvider: clock))
        {
            Ensure((await client.SignInAsync("admin", Password.AsMemory(), default)).Outcome == AuthenticationOutcome.Authenticated,
                "The initial session was not established.");
            var authenticated = await client.ValidateSessionAsync(default);
            Ensure(authenticated.Status == SessionStatus.Authenticated, "A valid local session was not recognized.");
            Ensure(handler.Requests.Any(request => request.Uri.AbsolutePath == "/api/admin/me" &&
                   request.Authorization == "Bearer " + AccessToken), "Session validation did not use Core's bearer verification route.");
            Ensure(handler.Requests.All(request => !request.Headers.Contains(RefreshToken, StringComparison.Ordinal)),
                "The refresh token was sent to Core by the desktop client.");

            clock.Advance(TimeSpan.FromSeconds(901));
            var beforeExpiryCheck = handler.Requests.Count;
            var expired = await client.ValidateSessionAsync(default);
            Ensure(expired.Status is SessionStatus.Expired or SessionStatus.SignedOut, "A 15-minute Core token remained active after expiry.");
            Ensure(handler.Requests.Count == beforeExpiryCheck, "An expired bearer token was sent over HTTP.");
            client.SignOut();
            Ensure((await client.ValidateSessionAsync(default)).Status == SessionStatus.SignedOut, "Sign-out retained a usable bearer session.");
        }

        var rejectMe = false;
        using (var handler = new AuthenticationHandler((request, _) => Task.FromResult(
                   request.RequestUri!.AbsolutePath == "/api/auth/login" ? LoginResponse() :
                   rejectMe ? Json(HttpStatusCode.Unauthorized, "{}") : AdministratorResponse())))
        using (var client = new HttpAuthenticationClient(new TestTrust(), handler))
        {
            Ensure((await client.SignInAsync("admin", Password.AsMemory(), default)).Outcome == AuthenticationOutcome.Authenticated,
                "The pre-restart session was not established.");
            rejectMe = true;
            Ensure((await client.ValidateSessionAsync(default)).Status == SessionStatus.Expired, "Core's 401 did not invalidate its old desktop session.");
            var requests = handler.Requests.Count;
            Ensure((await client.ValidateSessionAsync(default)).Status == SessionStatus.SignedOut && handler.Requests.Count == requests,
                "A session invalidated by Core restart was reused.");
        }

        var revokedTrust = new TestTrust();
        using (var handler = new AuthenticationHandler((request, _) => Task.FromResult(
                   request.RequestUri!.AbsolutePath == "/api/auth/login" ? LoginResponse() : AdministratorResponse())))
        using (var client = new HttpAuthenticationClient(revokedTrust, handler))
        {
            Ensure((await client.SignInAsync("admin", Password.AsMemory(), default)).Outcome == AuthenticationOutcome.Authenticated,
                "The session for trust-revocation verification was not established.");
            revokedTrust.IsTrusted = false;
            var requests = handler.Requests.Count;
            Ensure((await client.ValidateSessionAsync(default)).Status == SessionStatus.UntrustedConnection &&
                   handler.Requests.Count == requests, "A bearer token was sent after Core trust was revoked.");
            Ensure((await client.ValidateSessionAsync(default)).Status == SessionStatus.SignedOut,
                "A trust failure retained a reusable bearer token.");
        }

        var completion = new TaskCompletionSource<HttpResponseMessage>(TaskCreationOptions.RunContinuationsAsynchronously);
        using (var handler = new AuthenticationHandler((_, _) => completion.Task))
        using (var client = new HttpAuthenticationClient(new TestTrust(), handler))
        {
            var pending = client.SignInAsync("admin", Password.AsMemory(), default);
            client.SignOut();
            completion.SetResult(LoginResponse());
            var result = await pending.WaitAsync(TimeSpan.FromSeconds(3));
            Ensure(result.Outcome != AuthenticationOutcome.Authenticated, "A sign-out during login was reversed by a stale response.");
            Ensure((await client.ValidateSessionAsync(default)).Status == SessionStatus.SignedOut, "A stale login response restored bearer material.");
        }
    }

    private static async Task ViewModelSetupAsync()
    {
        var cases = new[]
        {
            (AdministratorSetupState.Required, AuthenticationState.SetupRequired),
            (AdministratorSetupState.Initialized, AuthenticationState.SignedOut),
            (AdministratorSetupState.Unavailable, AuthenticationState.Unavailable),
            (AdministratorSetupState.PermissionRequired, AuthenticationState.PermissionRequired),
            (AdministratorSetupState.UntrustedInstallation, AuthenticationState.UntrustedInstallation)
        };
        foreach (var (setupState, expected) in cases)
        {
            var auth = new ControlledAuthenticationClient();
            var setup = new ControlledSetupClient { State = setupState };
            using var model = new AuthenticationViewModel(auth, setup);
            await model.InitializeAsync();
            Ensure(model.State == expected, "Setup state was not represented distinctly: " + setupState);
            model.Username = "admin";
            Ensure(model.CanCreateAdministrator == (expected == AuthenticationState.SetupRequired), "Setup creation was enabled in the wrong state.");
            Ensure(auth.SignInCalls == 0, "Setup detection attempted a credential login.");
        }

        using (var model = new AuthenticationViewModel(new ControlledAuthenticationClient(),
                   new ControlledSetupClient { State = AdministratorSetupState.Required, Result = AdministratorSetupResult.Created }))
        {
            await model.InitializeAsync();
            model.Username = "admin";
            await model.CreateAdministratorAsync(Password.AsMemory());
            Ensure(model.State == AuthenticationState.SignedOut && !model.IsSignedIn,
                "Successful administrator creation silently authenticated instead of requiring Core sign-in.");
        }

        var existingAuth = new ControlledAuthenticationClient();
        var existingSetup = new ControlledSetupClient { State = AdministratorSetupState.Required, Result = AdministratorSetupResult.AlreadyInitialized };
        using (var model = new AuthenticationViewModel(existingAuth, existingSetup))
        {
            await model.InitializeAsync();
            model.Username = "admin";
            await model.CreateAdministratorAsync(Password.AsMemory());
            Ensure(model.State == AuthenticationState.SignedOut && existingAuth.SignInCalls == 0,
                "A concurrent existing administrator was overwritten or logged in automatically.");
        }

        Ensure(!typeof(AuthenticationViewModel).GetProperties().Any(property =>
                   property.Name.Contains("password", StringComparison.OrdinalIgnoreCase) ||
                   property.Name.Contains("token", StringComparison.OrdinalIgnoreCase)),
            "A password or bearer value was exposed as a bindable view-model property.");
    }

    private static async Task ViewModelSessionsAsync()
    {
        var auth = new ControlledAuthenticationClient
        {
            SignInResult = new(AuthenticationOutcome.Authenticated, "authoritative-admin"),
            SessionResult = new(SessionStatus.Authenticated, "authoritative-admin")
        };
        using (var model = new AuthenticationViewModel(auth,
                   new ControlledSetupClient { State = AdministratorSetupState.Initialized }))
        {
            await model.InitializeAsync();
            model.Username = "typed-admin";
            Ensure(model.State == AuthenticationState.SignedOut && model.CanSignIn, "An existing installation did not offer sign-in.");
            await model.SignInAsync(Password.AsMemory());
            Ensure(model.State == AuthenticationState.SignedIn && model.IsSignedIn && model.DisplayName == "authoritative-admin",
                "Sign-in did not use Core's authoritative administrator identity.");
            Ensure(auth.SignInCalls == 1 && auth.LastUsername == "typed-admin" && auth.LastPasswordLength == Password.Length,
                "The sign-in form did not pass only its transient credential to the client.");
            await model.CheckSessionAsync();
            Ensure(model.State == AuthenticationState.SignedIn && auth.ValidationCalls == 1, "A valid session did not survive Core revalidation.");
            auth.SessionResult = new(SessionStatus.Expired);
            await model.CheckSessionAsync();
            Ensure(model.State == AuthenticationState.SignedOut && !model.IsSignedIn && string.IsNullOrEmpty(model.DisplayName),
                "An expired session did not return to safe signed-out state.");
            Ensure(auth.SignOutCalls > 0, "Expired Core session material was not cleared.");
            model.SignOut();
            Ensure(string.IsNullOrEmpty(model.Username) && string.IsNullOrEmpty(model.DisplayName) && !model.IsSignedIn,
                "Explicit sign-out kept desktop identity data.");
        }

        foreach (var outcome in new[]
                 {
                     AuthenticationOutcome.InvalidCredentials,
                     AuthenticationOutcome.Throttled,
                     AuthenticationOutcome.Unavailable,
                     AuthenticationOutcome.UntrustedConnection,
                     AuthenticationOutcome.InvalidResponse
                 })
        {
            var failedAuth = new ControlledAuthenticationClient { SignInResult = new(outcome) };
            using var model = new AuthenticationViewModel(failedAuth,
                new ControlledSetupClient { State = AdministratorSetupState.Initialized });
            await model.InitializeAsync();
            model.Username = "unknown-user";
            await model.SignInAsync(Password.AsMemory());
            Ensure(!model.IsSignedIn && model.State != AuthenticationState.SetupRequired &&
                   !string.IsNullOrWhiteSpace(model.ErrorText), "An authentication failure became silent, signed-in, or setup-required: " + outcome);
            Ensure(!model.ErrorText.Contains(Password, StringComparison.Ordinal) &&
                   !model.ErrorText.Contains("private", StringComparison.OrdinalIgnoreCase), "An authentication error disclosed sensitive detail.");
        }

        var reconnectAuth = new ControlledAuthenticationClient { SignInResult = new(AuthenticationOutcome.Unavailable) };
        using (var model = new AuthenticationViewModel(reconnectAuth,
                   new ControlledSetupClient { State = AdministratorSetupState.Initialized }))
        {
            await model.InitializeAsync();
            model.Username = "admin";
            await model.SignInAsync(Password.AsMemory());
            Ensure(model.CanSignIn, "A temporary Core outage prevented explicit reconnect.");
            reconnectAuth.SignInResult = new(AuthenticationOutcome.Authenticated, "admin");
            await model.SignInAsync(Password.AsMemory());
            Ensure(model.IsSignedIn && reconnectAuth.SignInCalls == 2, "Reconnect did not allow a fresh Core login.");
            model.SignOut();
            Ensure(!model.IsSignedIn && reconnectAuth.SignOutCalls > 0, "Explicit sign-out did not clear the client session.");
        }
    }

    private static async Task ViewModelStaleCompletionsAsync()
    {
        var lateLogin = new TaskCompletionSource<AuthenticationResult>(TaskCreationOptions.RunContinuationsAsynchronously);
        var auth = new ControlledAuthenticationClient { SignInOperation = (_, _, _) => lateLogin.Task };
        using (var model = new AuthenticationViewModel(auth,
                   new ControlledSetupClient { State = AdministratorSetupState.Initialized }))
        {
            await model.InitializeAsync();
            model.Username = "admin";
            var pending = model.SignInAsync(Password.AsMemory());
            Ensure(model.IsBusy, "Pending authentication did not advertise busy state.");
            model.SignOut();
            lateLogin.SetResult(new(AuthenticationOutcome.Authenticated, "stale-admin"));
            await pending.WaitAsync(TimeSpan.FromSeconds(3));
            Ensure(!model.IsSignedIn && string.IsNullOrEmpty(model.DisplayName), "A late login completion undid sign-out.");
        }

        var shutdownLogin = new TaskCompletionSource<AuthenticationResult>(TaskCreationOptions.RunContinuationsAsynchronously);
        var shutdownAuth = new ControlledAuthenticationClient { SignInOperation = (_, _, _) => shutdownLogin.Task };
        var shutdownSetup = new ControlledSetupClient { State = AdministratorSetupState.Initialized };
        var shutdownModel = new AuthenticationViewModel(shutdownAuth, shutdownSetup);
        await shutdownModel.InitializeAsync();
        shutdownModel.Username = "admin";
        var inFlight = shutdownModel.SignInAsync(Password.AsMemory());
        shutdownModel.Dispose();
        Ensure(shutdownAuth.LastCancellation.IsCancellationRequested && shutdownAuth.DisposeCalls == 1 && shutdownSetup.DisposeCalls == 1,
            "Desktop shutdown failed to cancel authentication and release both clients.");
        shutdownLogin.SetResult(new(AuthenticationOutcome.Authenticated, "late-admin"));
        await inFlight.WaitAsync(TimeSpan.FromSeconds(3));
        Ensure(!shutdownModel.IsSignedIn, "A completion after desktop shutdown restored an authenticated view.");
    }

    private sealed class TestTrust : ICoreEndpointTrust
    {
        public bool IsTrusted { get; set; } = true;
        public int Calls { get; private set; }
        public List<Uri> Origins { get; } = [];
        public Task<bool> IsTrustedAsync(Uri origin, CancellationToken cancellationToken)
        {
            Calls++;
            Origins.Add(origin);
            cancellationToken.ThrowIfCancellationRequested();
            return Task.FromResult(IsTrusted);
        }
    }

    private sealed record CapturedRequest(Uri Uri, HttpMethod Method, string? Body, string Headers, string? Authorization);

    private sealed class AuthenticationHandler(Func<HttpRequestMessage, CancellationToken, Task<HttpResponseMessage>> answer) : HttpMessageHandler
    {
        public List<CapturedRequest> Requests { get; } = [];
        protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            var body = request.Content is null ? null : await request.Content.ReadAsStringAsync(cancellationToken);
            Requests.Add(new(request.RequestUri!, request.Method, body, request.Headers.ToString(),
                request.Headers.Authorization?.ToString()));
            return await answer(request, cancellationToken);
        }
    }

    private sealed class ManualTimeProvider : TimeProvider
    {
        private DateTimeOffset _utcNow = new(2026, 10, 3, 12, 0, 0, TimeSpan.Zero);
        public override DateTimeOffset GetUtcNow() => _utcNow;
        public void Advance(TimeSpan duration) => _utcNow += duration;
    }

    private sealed class CountedReadStream(byte[] bytes) : MemoryStream(bytes)
    {
        public override bool CanSeek => false;
        public int BytesRead { get; private set; }
        public override async ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken cancellationToken = default)
        {
            var count = await base.ReadAsync(buffer, cancellationToken);
            BytesRead += count;
            return count;
        }
        public override async Task<int> ReadAsync(byte[] buffer, int offset, int count, CancellationToken cancellationToken)
        {
            var read = await base.ReadAsync(buffer, offset, count, cancellationToken);
            BytesRead += read;
            return read;
        }
    }

    private sealed class ControlledAuthenticationClient : IAuthenticationClient
    {
        public AuthenticationResult SignInResult { get; set; } = new(AuthenticationOutcome.InvalidCredentials);
        public SessionResult SessionResult { get; set; } = new(SessionStatus.SignedOut);
        public Func<string, ReadOnlyMemory<char>, CancellationToken, Task<AuthenticationResult>>? SignInOperation { get; set; }
        public int SignInCalls { get; private set; }
        public int ValidationCalls { get; private set; }
        public int SignOutCalls { get; private set; }
        public int DisposeCalls { get; private set; }
        public string? LastUsername { get; private set; }
        public int LastPasswordLength { get; private set; }
        public CancellationToken LastCancellation { get; private set; }
        public Task<AuthenticationResult> SignInAsync(string username, ReadOnlyMemory<char> password, CancellationToken cancellationToken)
        {
            SignInCalls++;
            LastUsername = username;
            LastPasswordLength = password.Length;
            LastCancellation = cancellationToken;
            return SignInOperation?.Invoke(username, password, cancellationToken) ?? Task.FromResult(SignInResult);
        }
        public Task<SessionResult> ValidateSessionAsync(CancellationToken cancellationToken)
        {
            ValidationCalls++;
            LastCancellation = cancellationToken;
            return Task.FromResult(SessionResult);
        }
        public void SignOut() => SignOutCalls++;
        public void Dispose() => DisposeCalls++;
    }

    private sealed class ControlledSetupClient : IAdministratorSetupClient
    {
        public AdministratorSetupState State { get; set; } = AdministratorSetupState.Initialized;
        public AdministratorSetupResult Result { get; set; } = AdministratorSetupResult.Created;
        public int InitializeCalls { get; private set; }
        public int DisposeCalls { get; private set; }
        public Task<AdministratorSetupState> GetStateAsync(CancellationToken cancellationToken) => Task.FromResult(State);
        public Task<AdministratorSetupResult> InitializeAsync(string username, ReadOnlyMemory<char> password, CancellationToken cancellationToken)
        {
            InitializeCalls++;
            return Task.FromResult(Result);
        }
        public void Dispose() => DisposeCalls++;
    }
}
