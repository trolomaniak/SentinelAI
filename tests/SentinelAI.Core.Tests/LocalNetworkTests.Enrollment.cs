using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.Json;
using Microsoft.Data.Sqlite;
using SentinelAI.Contracts.Enrollment;
using SentinelAI.Contracts.Heartbeat;
using SentinelAI.Enrollment;
using SentinelAI.Hosting;

// MVP-2: enrollment codes (format, batch issuance, unused codes, revocation, expiry) and "Remove computer".
internal static partial class LocalNetworkTests
{
    private const string SyntheticPin = "0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF";
    private const string SyntheticToken = "FEDCBA9876543210FEDCBA9876543210FEDCBA9876543210FEDCBA9876543210";

    private static void VerifyEnrollmentCodeFormat()
    {
        foreach (var address in new[] { "192.168.1.20", "central-pc", "central-pc.corp.example", "xn--ksigowo-c5a1nq1a", "a_b" })
        {
            var expected = new EnrollmentCode(address, 5443, SyntheticPin, SyntheticToken);
            var text = expected.Encode();
            var parsed = EnrollmentCode.TryParse(text, out var decoded) ? decoded : null;
            Check(text.StartsWith("SAI1-", StringComparison.Ordinal) && text.Length <= EnrollmentCode.MaximumTextLength && parsed == expected,
                "An enrollment code did not round-trip.");
            var pasted = "  " + text.ToLowerInvariant().Replace("-", " - ").Insert(20, "\r\n") + "\n";
            Check(EnrollmentCode.TryParse(pasted, out var relaxed) && relaxed == parsed, "A pasted code with spacing or line breaks was refused.");
            Check(EnrollmentCode.TryParseFile(Encoding.UTF8.GetPreamble().Concat(Encoding.UTF8.GetBytes(text + "\r\n")).ToArray(), out var fromFile) &&
                  fromFile == parsed, "A code file with a byte-order mark was refused.");

            // Every single changed symbol is caught by the checksum or the structure checks.
            var symbols = text["SAI1-".Length..];
            for (var index = 0; index < symbols.Length; index++)
            {
                if (symbols[index] == '-') continue;
                var changed = symbols[index] == 'Z' ? 'Y' : 'Z';
                Check(!EnrollmentCode.TryParse("SAI1-" + symbols[..index] + changed + symbols[(index + 1)..], out _),
                    "A code with a changed character was accepted.");
            }

            Check(!EnrollmentCode.TryParse("SAI2-" + symbols, out _) && !EnrollmentCode.TryParse(symbols, out _) &&
                  !EnrollmentCode.TryParse(text[..^1], out _) && !EnrollmentCode.TryParse(text + "0", out _) &&
                  !EnrollmentCode.TryParse(text + "U", out _),
                "A code with another version, no prefix, a missing or extra character, or a foreign symbol was accepted.");
        }

        var plain = new EnrollmentCode("host", 1, SyntheticPin, SyntheticToken).Encode();
        Check(EnrollmentCode.TryParse("SAI1-" + plain[5..].Replace('0', 'O').Replace('1', 'L'), out var crockford) &&
              crockford!.Address == "host" && crockford.Port == 1, "Crockford's O and L were not read as 0 and 1.");
        foreach (var (address, port, pin, token) in new (string, int, string, string)[]
                 {
                     ("", 5443, SyntheticPin, SyntheticToken), ("bad name", 5443, SyntheticPin, SyntheticToken),
                     ("::1", 5443, SyntheticPin, SyntheticToken), ("192.168.001.020", 5443, SyntheticPin, SyntheticToken),
                     ("-lead", 5443, SyntheticPin, SyntheticToken), (new string('a', 64), 5443, SyntheticPin, SyntheticToken),
                     ("host", 0, SyntheticPin, SyntheticToken), ("host", 65536, SyntheticPin, SyntheticToken),
                     ("host", 5443, SyntheticPin.ToLowerInvariant(), SyntheticToken), ("host", 5443, SyntheticPin, SyntheticToken[..62])
                 })
        {
            Reject(() => new EnrollmentCode(address, port, pin, token).Encode(), "An enrollment code with invalid values was encoded.");
        }

        Check(!EnrollmentCode.TryParse(null, out _) && !EnrollmentCode.TryParse("SAI1-" + new string('0', EnrollmentCode.MaximumTextLength), out _) &&
              !EnrollmentCode.TryParseFile(new byte[EnrollmentCode.MaximumFileBytes + 1], out _) && !EnrollmentCode.TryParseFile([0xFF, 0xFE], out _),
            "An oversized or malformed code was accepted.");
        // The longest address still gives a code that parses as pasted text and as a file with a line break.
        var longest = new string('a', 63) + "." + new string('b', 63) + "." + new string('c', EnrollmentCode.MaximumAddressLength - 128);
        var longestCode = new EnrollmentCode(longest, 65535, SyntheticPin, SyntheticToken);
        var longestText = longestCode.Encode();
        Check(longest.Length == EnrollmentCode.MaximumAddressLength && longestText.Length + 2 <= EnrollmentCode.MaximumTextLength &&
              EnrollmentCode.TryParseFile(Encoding.UTF8.GetPreamble().Concat(Encoding.UTF8.GetBytes(longestText + "\r\n")).ToArray(), out var longestParsed) &&
              longestParsed == longestCode && !EnrollmentCode.IsAddress(longest + "d"),
            "The longest address did not give a parseable code, or a longer one was accepted.");
        Reject(() => new EnrollmentCode(longest + "d", 5443, SyntheticPin, SyntheticToken).Encode(), "An address too long for a code was encoded.");
        var code = new EnrollmentCode("192.168.1.20", 5443, SyntheticPin, SyntheticToken);
        Check(code.CoreUrl == new Uri("https://192.168.1.20:5443") && !code.ToString().Contains(SyntheticToken, StringComparison.Ordinal),
            "The code did not name Core's HTTPS origin, or its text form exposed the token.");
    }

    private static async Task VerifyEnrollmentCodesAsync(string directory, X509Certificate2 certificate, string username, string password)
    {
        var pin = LocalNetworkCertificate.Sha256(certificate);
        var port = FreePort();
        await using var app = BuildCore(directory, port, pin, new FixedSource(certificate));
        await app.StartAsync();
        var loopback = new Uri(app.Urls.Single(url => url.StartsWith("http://", StringComparison.Ordinal)));
        using var local = new HttpClient(new HttpClientHandler { UseProxy = false }) { BaseAddress = loopback, Timeout = TimeSpan.FromSeconds(10) };
        using var network = PinnedClient(new Uri($"https://127.0.0.1:{port}/"), pin);
        var token = await LoginAsync(local, username, password);

        using var optionsResponse = await GetAsync(local, "/api/admin/enrollment-options", token);
        using var options = JsonDocument.Parse(await optionsResponse.Content.ReadAsStringAsync());
        var addresses = options.RootElement.GetProperty("addresses").EnumerateArray().Select(item => item.GetProperty("value").GetString()!).ToArray();
        var recommended = options.RootElement.GetProperty("recommendedAddress").GetString();
        Check(options.RootElement.GetProperty("available").GetBoolean() && options.RootElement.GetProperty("port").GetInt32() == port &&
              addresses.Length > 0 && recommended is not null && addresses.Contains(recommended) && addresses.All(EnrollmentCode.IsAddress),
            "Core did not offer the addresses an enrollment code may carry.");

        // Bounds: 1 to 50 codes, 1 hour to 7 days, one of Core's own addresses.
        foreach (var body in new object[]
                 {
                     new { count = 0, validityHours = 24, address = recommended }, new { count = 51, validityHours = 24, address = recommended },
                     new { count = 1, validityHours = 0, address = recommended }, new { count = 1, validityHours = 169, address = recommended },
                     new { count = 1, validityHours = 24, address = "attacker.example" }, new { count = 1, validityHours = 24, address = (string?)null }
                 })
        {
            using var refused = await SendAsync(local, HttpMethod.Post, "/api/admin/enrollment-codes", token, body);
            Check(refused.StatusCode == HttpStatusCode.BadRequest, "Core issued codes outside the count, validity or address bounds.");
        }

        using (var anonymous = await local.PostAsJsonAsync("/api/admin/enrollment-codes", new { count = 1, validityHours = 24, address = recommended }))
            Check(anonymous.StatusCode == HttpStatusCode.Unauthorized, "Core issued codes without an administrator session.");
        using (var overNetwork = await SendAsync(network, HttpMethod.Post, "/api/admin/enrollment-codes", token, new { count = 1, validityHours = 24, address = recommended }))
            Check(overNetwork.StatusCode == HttpStatusCode.NotFound, "Core issued codes over the local-network listener.");

        var issuedAt = DateTimeOffset.UtcNow;
        using var batchResponse = await SendAsync(local, HttpMethod.Post, "/api/admin/enrollment-codes", token, new { count = 4, validityHours = 24, address = recommended });
        Check(batchResponse.StatusCode == HttpStatusCode.OK && batchResponse.Headers.CacheControl?.NoStore == true, "Core did not issue a batch of codes.");
        using var batch = JsonDocument.Parse(await batchResponse.Content.ReadAsStringAsync());
        var issued = batch.RootElement.GetProperty("codes").EnumerateArray()
            .Select(item => (Id: item.GetProperty("id").GetGuid(), Text: item.GetProperty("code").GetString()!, Expires: item.GetProperty("expiresUtc").GetDateTimeOffset()))
            .ToArray();
        var codes = issued.Select(item => EnrollmentCode.TryParse(item.Text, out var parsed) ? parsed! : null).ToArray();
        Check(issued.Length == 4 && codes.All(code => code is not null && code.Address == recommended && code.Port == port && code.CertificateSha256 == pin) &&
              codes.Select(code => code!.EnrollmentToken).Distinct().Count() == 4 && issued.Select(item => item.Id).Distinct().Count() == 4 &&
              issued.All(item => Math.Abs((item.Expires - issuedAt.AddHours(24)).TotalMinutes) < 2),
            "The batch did not hold four distinct codes for Core's address, port and pin, valid for 24 hours.");

        Check((await UnusedCodesAsync(local, token)).OrderBy(id => id).SequenceEqual(issued.Select(item => item.Id).OrderBy(id => id)),
            "Core did not list the unused codes.");
        foreach (var code in codes)
            Check(await CheckCodeAsync(network, code!) == HttpStatusCode.NoContent, "Core refused an unused code before installation.");

        // Revoked: listed no more, refused by the check and by enrollment.
        using (var revoked = await SendAsync(local, HttpMethod.Delete, $"/api/admin/enrollment-codes/{issued[0].Id:D}", token))
            Check(revoked.StatusCode == HttpStatusCode.NoContent, "Core did not revoke an unused code.");
        using (var again = await SendAsync(local, HttpMethod.Delete, $"/api/admin/enrollment-codes/{issued[0].Id:D}", token))
            Check(again.StatusCode == HttpStatusCode.NotFound, "Core revoked a code twice.");
        Check(await CheckCodeAsync(network, codes[0]!) == HttpStatusCode.Gone && await EnrollAsync(network, codes[0]!) == HttpStatusCode.Unauthorized &&
              !(await UnusedCodesAsync(local, token)).Contains(issued[0].Id), "A revoked code was still usable or listed.");

        // Used: one computer only.
        var installationId = Guid.NewGuid();
        using var enrolled = await network.PostAsJsonAsync("/api/agent/enroll", new EnrollmentRequest(installationId, codes[1]!.EnrollmentToken));
        Check(enrolled.StatusCode == HttpStatusCode.OK, "A code could not enroll a computer.");
        var identity = (await enrolled.Content.ReadFromJsonAsync<EnrollmentResponse>())!;
        Check(await CheckCodeAsync(network, codes[1]!) == HttpStatusCode.Gone && await EnrollAsync(network, codes[1]!) == HttpStatusCode.Unauthorized &&
              !(await UnusedCodesAsync(local, token)).Contains(issued[1].Id), "A used code was usable for a second computer.");
        using (var usedRevoke = await SendAsync(local, HttpMethod.Delete, $"/api/admin/enrollment-codes/{issued[1].Id:D}", token))
            Check(usedRevoke.StatusCode == HttpStatusCode.NotFound, "Core revoked a code that was already used.");

        // Expired: refused although never used.
        using (var connection = new SqliteConnection(new SqliteConnectionStringBuilder { DataSource = Path.Combine(directory, "sentinelai.db") }.ToString()))
        {
            await connection.OpenAsync();
            await using var expire = connection.CreateCommand();
            expire.CommandText = "UPDATE EnrollmentTokens SET ExpiresUtcTicks = $past WHERE TokenId = $id;";
            expire.Parameters.AddWithValue("$past", DateTimeOffset.UtcNow.AddMinutes(-1).UtcDateTime.Ticks);
            expire.Parameters.AddWithValue("$id", issued[2].Id.ToString("D"));
            Check(await expire.ExecuteNonQueryAsync() == 1, "The synthetic expiry could not be applied.");
        }

        Check(await CheckCodeAsync(network, codes[2]!) == HttpStatusCode.Gone && await EnrollAsync(network, codes[2]!) == HttpStatusCode.Unauthorized &&
              (await UnusedCodesAsync(local, token)).SequenceEqual([issued[3].Id]), "An expired code was still usable or listed.");
        using (var malformed = await network.PostAsJsonAsync("/api/agent/enrollment-check", new { enrollmentToken = "short" }))
            Check(malformed.StatusCode == HttpStatusCode.BadRequest, "Core accepted a malformed enrollment check.");

        // Remove computer: the credential stops working and the endpoint disappears; its history is kept.
        async Task<HttpStatusCode> HeartbeatAsync()
        {
            using var heartbeat = new HttpRequestMessage(HttpMethod.Post, "/api/agent/heartbeat") { Content = JsonContent.Create(new HeartbeatRequest(installationId)) };
            heartbeat.Headers.Authorization = new AuthenticationHeaderValue("SentinelAgent", $"{identity.EndpointId:D}.{identity.AgentCredential}");
            using var response = await network.SendAsync(heartbeat);
            return response.StatusCode;
        }

        Check(await HeartbeatAsync() == HttpStatusCode.OK, "The enrolled computer could not report.");
        using (var listed = await GetAsync(local, "/api/admin/devices", token))
            Check((await listed.Content.ReadAsStringAsync()).Contains(identity.EndpointId.ToString("D"), StringComparison.OrdinalIgnoreCase),
                "The enrolled computer was not listed.");
        using (var removed = await SendAsync(local, HttpMethod.Delete, $"/api/admin/devices/{identity.EndpointId:D}", token))
            Check(removed.StatusCode == HttpStatusCode.NoContent, "Core did not remove the computer.");
        using (var again = await SendAsync(local, HttpMethod.Delete, $"/api/admin/devices/{identity.EndpointId:D}", token))
            Check(again.StatusCode == HttpStatusCode.NotFound, "Core removed a computer twice.");
        using (var unknown = await SendAsync(local, HttpMethod.Delete, $"/api/admin/devices/{Guid.NewGuid():D}", token))
            Check(unknown.StatusCode == HttpStatusCode.NotFound, "Core removed an unknown computer.");
        using (var overNetwork = await SendAsync(network, HttpMethod.Delete, $"/api/admin/devices/{identity.EndpointId:D}", token))
            Check(overNetwork.StatusCode == HttpStatusCode.NotFound, "Core served Remove computer over the local-network listener.");
        Check(await HeartbeatAsync() == HttpStatusCode.Unauthorized, "A removed computer could still report.");

        // The central computer's own Agent enrolls over loopback: it can never be removed, so it keeps reporting.
        var localInstallation = Guid.NewGuid();
        using (var localEnrolled = await local.PostAsJsonAsync("/api/agent/enroll", new EnrollmentRequest(localInstallation, codes[3]!.EnrollmentToken)))
        {
            Check(localEnrolled.StatusCode == HttpStatusCode.OK, "The central computer's Agent could not enroll over loopback.");
            var localIdentity = (await localEnrolled.Content.ReadFromJsonAsync<EnrollmentResponse>())!;
            using (var refused = await SendAsync(local, HttpMethod.Delete, $"/api/admin/devices/{localIdentity.EndpointId:D}", token))
                Check(refused.StatusCode == HttpStatusCode.Conflict, "Core removed the central computer's own Agent.");
            using var heartbeat = new HttpRequestMessage(HttpMethod.Post, "/api/agent/heartbeat") { Content = JsonContent.Create(new HeartbeatRequest(localInstallation)) };
            heartbeat.Headers.Authorization = new AuthenticationHeaderValue("SentinelAgent", $"{localIdentity.EndpointId:D}.{localIdentity.AgentCredential}");
            using var reported = await local.SendAsync(heartbeat);
            Check(reported.StatusCode == HttpStatusCode.OK, "Refusing to remove the central computer's Agent stopped its reports.");
        }
        using (var listed = await GetAsync(local, "/api/admin/devices", token))
            Check(!(await listed.Content.ReadAsStringAsync()).Contains(identity.EndpointId.ToString("D"), StringComparison.OrdinalIgnoreCase),
                "A removed computer was still listed.");
        using (var detail = await GetAsync(local, $"/api/admin/devices/{identity.EndpointId:D}", token))
            Check(detail.StatusCode == HttpStatusCode.NotFound, "A removed computer's details were still shown.");
        using (var risk = await GetAsync(local, "/api/admin/risk", token))
            Check(!(await risk.Content.ReadAsStringAsync()).Contains(identity.EndpointId.ToString("D"), StringComparison.OrdinalIgnoreCase),
                "A removed computer still counted in the risk overview.");
        await app.StopAsync();

        using (var connection = new SqliteConnection(new SqliteConnectionStringBuilder { DataSource = Path.Combine(directory, "sentinelai.db") }.ToString()))
        {
            await connection.OpenAsync();
            await using var kept = connection.CreateCommand();
            kept.CommandText = "SELECT COUNT(*) FROM EndpointEnrollments WHERE EndpointId = $id AND RemovedUtcTicks IS NOT NULL;";
            kept.Parameters.AddWithValue("$id", identity.EndpointId.ToString("D"));
            Check((long)(await kept.ExecuteScalarAsync())! == 1, "Removing a computer deleted its history.");
        }

        SqliteConnection.ClearAllPools();
    }

    private static async Task VerifyLocalOnlyEnrollmentCodesAsync(HttpClient local, string token)
    {
        using var optionsResponse = await GetAsync(local, "/api/admin/enrollment-options", token);
        using var options = JsonDocument.Parse(await optionsResponse.Content.ReadAsStringAsync());
        Check(!options.RootElement.GetProperty("available").GetBoolean() && options.RootElement.GetProperty("addresses").GetArrayLength() == 0,
            "A local-only Core offered enrollment code addresses.");
        using var refused = await SendAsync(local, HttpMethod.Post, "/api/admin/enrollment-codes", token, new { count = 1, validityHours = 24, address = "127.0.0.1" });
        Check(refused.StatusCode == HttpStatusCode.Conflict, "A local-only Core issued enrollment codes.");
    }

    private static async Task<Guid[]> UnusedCodesAsync(HttpClient local, string token)
    {
        using var response = await GetAsync(local, "/api/admin/enrollment-codes", token);
        var body = await response.Content.ReadAsStringAsync();
        Check(response.StatusCode == HttpStatusCode.OK && !body.Contains("code\"", StringComparison.Ordinal) && !body.Contains("token", StringComparison.OrdinalIgnoreCase),
            "The unused code list was unavailable or exposed a code.");
        using var json = JsonDocument.Parse(body);
        return json.RootElement.GetProperty("codes").EnumerateArray().Select(item => item.GetProperty("id").GetGuid()).ToArray();
    }

    private static async Task<HttpStatusCode> CheckCodeAsync(HttpClient network, EnrollmentCode code)
    {
        using var response = await network.PostAsJsonAsync("/api/agent/enrollment-check", new { enrollmentToken = code.EnrollmentToken });
        return response.StatusCode;
    }

    private static async Task<HttpStatusCode> EnrollAsync(HttpClient network, EnrollmentCode code)
    {
        using var response = await network.PostAsJsonAsync("/api/agent/enroll", new EnrollmentRequest(Guid.NewGuid(), code.EnrollmentToken));
        return response.StatusCode;
    }

    private static async Task<HttpResponseMessage> SendAsync(HttpClient client, HttpMethod method, string path, string token, object? body = null)
    {
        using var request = new HttpRequestMessage(method, path) { Content = body is null ? null : JsonContent.Create(body) };
        request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", token);
        return await client.SendAsync(request);
    }
}
