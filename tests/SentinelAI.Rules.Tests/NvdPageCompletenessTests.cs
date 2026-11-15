using System.Text.Json;
using SentinelAI.Rules.Vulnerabilities;

internal static class NvdPageCompletenessTests
{
    public static int Run()
    {
        var checks = 0;
        static string Page(int start, int total, params string[] ids) => JsonSerializer.Serialize(new
        {
            format = "NVD_CVE", version = "2.0", startIndex = start, resultsPerPage = ids.Length, totalResults = total,
            vulnerabilities = ids.Select(id => new { cve = new { id } })
        });
        void Verify(bool valid, params string[] pages)
        {
            var documents = pages.Select(page => JsonDocument.Parse(page)).ToArray();
            try
            {
                var accepted = true;
                try { VulnerabilityNvdPages.ValidateComplete(documents.Select(page => page.RootElement).ToArray()); }
                catch (InvalidDataException) { accepted = false; }
                if (accepted != valid) throw new InvalidOperationException("NVD completeness validation accepted an incomplete/inconsistent query or rejected a complete one.");
                checks++;
            }
            finally { foreach (var document in documents) document.Dispose(); }
        }

        Verify(true, Page(0, 3, "CVE-2099-1001", "CVE-2099-1002"), Page(2, 3, "CVE-2099-1003"));
        Verify(true, Page(2, 3, "CVE-2099-1003"), Page(0, 3, "CVE-2099-1001", "CVE-2099-1002"));
        Verify(true, Page(0, 0));
        Verify(false);
        Verify(false, Page(0, 3, "CVE-2099-1001", "CVE-2099-1002")); // Missing last page.
        Verify(false, Page(1, 2, "CVE-2099-1002")); // Missing first page.
        Verify(false, Page(0, 3, "CVE-2099-1001"), Page(2, 3, "CVE-2099-1003")); // Gap.
        Verify(false, Page(0, 3, "CVE-2099-1001", "CVE-2099-1002"), Page(1, 3, "CVE-2099-1003", "CVE-2099-1004"));
        Verify(false, Page(0, 2, "CVE-2099-1001"), Page(0, 2, "CVE-2099-1002")); // Duplicate index.
        Verify(false, Page(0, 2, "CVE-2099-1001"), Page(1, 3, "CVE-2099-1002")); // Changed total.
        Verify(false, Page(0, 2, "CVE-2099-1001"), Page(1, 2, "CVE-2099-1001")); // Duplicate CVE across pages.
        Verify(false, Page(0, 1, "CVE-2099-1001").Replace("\"resultsPerPage\":1", "\"resultsPerPage\":2", StringComparison.Ordinal));
        Verify(false, Page(0, 1, "CVE-2099-1001").Replace("\"startIndex\":0", "\"startIndex\":-1", StringComparison.Ordinal));
        Verify(false, Page(0, 1, "CVE-2099-1001").Replace("\"totalResults\":1", "\"totalResults\":2147483648", StringComparison.Ordinal));
        Verify(false, "{\"vulnerabilities\":[]}");
        Verify(false, Page(0, 0).Replace("\"2.0\"", "\"1.0\"", StringComparison.Ordinal));
        Verify(false, Page(0, 0), Page(0, 0));
        Verify(false, Page(0, 1, ""));
        return checks;
    }
}
