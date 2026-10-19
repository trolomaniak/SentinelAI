using System.Text.Json;
using SentinelAI.Desktop.Foundation;

// Desktop and Setup trust only the fixed Core configuration: local-only, or central with Core's
// local-network port and certificate pin (MVP-1).
internal static class InstalledCoreConfigurationTests
{
    private const string Origin = "http://127.0.0.1:5000";
    private const string Data = @"C:\ProgramData\SentinelAI\Core";
    private static readonly string Pin = new('A', 64);
    private static int _assertions;

    internal static Task<int> RunAsync()
    {
        _assertions = 0;
        Ensure(IsExpected(Configuration(Core())), "Desktop rejected the local-only Core configuration.");
        Ensure(IsExpected(Configuration(Core(("LocalNetworkPort", "5443"), ("LocalNetworkCertificateSha256", Pin)))),
            "Desktop rejected the central Core configuration with its local-network port and certificate pin.");
        Ensure(IsExpected(Configuration(Core()).Replace(Data.Replace(@"\", @"\\"), Data.ToLowerInvariant().Replace(@"\", @"\\"))),
            "Desktop compared the data directory case-sensitively.");

        foreach (var (json, reason) in new (string, string)[]
        {
            (Configuration(Core(("LocalNetworkPort", "5443"))), "a local-network port without its certificate pin"),
            (Configuration(Core(("LocalNetworkCertificateSha256", Pin))), "a certificate pin without its port"),
            (Configuration(Core(("LocalNetworkPort", "5444"), ("LocalNetworkCertificateSha256", Pin))), "another local-network port"),
            (Configuration(Core(("LocalNetworkPort", "05443"), ("LocalNetworkCertificateSha256", Pin))), "a non-canonical port"),
            (Configuration(Core(("LocalNetworkPort", "5443"), ("LocalNetworkCertificateSha256", Pin.ToLowerInvariant()))), "a lowercase pin"),
            (Configuration(Core(("LocalNetworkPort", "5443"), ("LocalNetworkCertificateSha256", Pin[..63]))), "a short pin"),
            (Configuration(Core(("LocalNetworkPort", "5443"), ("LocalNetworkCertificateSha256", Pin), ("Extra", "x"))), "an extra Core setting"),
            (Configuration(Core(("localnetworkport", "5443"), ("LocalNetworkCertificateSha256", Pin))), "a differently cased setting name"),
            (Configuration(Core(("Extra", "x"))), "an unknown Core setting"),
            (Configuration(Core()).Replace(Origin, "http://localhost:5000"), "another origin"),
            (Configuration(Core()).Replace(Data.Replace(@"\", @"\\"), @"C:\\Other"), "another data directory"),
            ("{\"urls\":\"" + Origin + "\",\"SentinelAI\":{\"DataDirectory\":\"" + Data.Replace(@"\", @"\\") + "\",\"LocalNetworkPort\":5443,\"LocalNetworkCertificateSha256\":\"" + Pin + "\"}}", "a numeric port"),
            ("{\"urls\":\"" + Origin + "\",\"SentinelAI\":{\"DataDirectory\":\"" + Data.Replace(@"\", @"\\") + "\",\"DataDirectory\":\"" + Data.Replace(@"\", @"\\") + "\"}}", "a duplicate setting"),
            ("{\"urls\":\"" + Origin + "\"}", "a missing Core section"),
            ("{\"urls\":\"" + Origin + "\",\"SentinelAI\":{\"DataDirectory\":\"" + Data.Replace(@"\", @"\\") + "\"},\"Kestrel\":{}}", "an extra root setting"),
            ("[]", "a non-object document")
        })
        {
            Ensure(!IsExpected(json), "Desktop trusted a Core configuration with " + reason + ".");
        }

        Console.WriteLine($"Desktop installed Core configuration: {_assertions} assertions passed.");
        return Task.FromResult(_assertions);
    }

    private static (string Name, string Value)[] Core(params (string Name, string Value)[] extra) => [("DataDirectory", Data), .. extra];

    private static string Configuration((string Name, string Value)[] core) =>
        "{\"urls\":\"" + Origin + "\",\"SentinelAI\":{" +
        string.Join(",", core.Select(setting => JsonSerializer.Serialize(setting.Name) + ":" + JsonSerializer.Serialize(setting.Value))) + "}}";

    private static bool IsExpected(string json)
    {
        using var document = JsonDocument.Parse(json);
        return InstalledCoreConfiguration.IsExpected(document.RootElement, Origin, Data);
    }

    private static void Ensure(bool condition, string message) { if (!condition) throw new InvalidOperationException(message); _assertions++; }
}
