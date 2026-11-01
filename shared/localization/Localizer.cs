using System.Globalization;
using System.Text.Json;
using System.Text.RegularExpressions;

namespace SentinelAI.Localization;

/// <summary>The languages SentinelAI is shown in. English is the source language of every text.</summary>
public enum UiLanguage { English, Polish }

public static class UiLanguages
{
    public static string Code(UiLanguage language) => language == UiLanguage.Polish ? "pl" : "en";

    public static bool TryParse(string? code, out UiLanguage language)
    {
        language = code switch { "pl" => UiLanguage.Polish, _ => UiLanguage.English };
        return code is "en" or "pl";
    }
}

/// <summary>
/// Translations keyed by the exact English text. A text without a translation stays in English, so a changed English
/// text is never shown with an outdated translation.
/// </summary>
public sealed partial class TextCatalog
{
    private readonly Dictionary<string, string> _entries;

    private TextCatalog(Dictionary<string, string> entries) => _entries = entries;

    /// <summary>The Polish catalog embedded in this assembly.</summary>
    public static TextCatalog Polish { get; } = Load("SentinelAI.Localization.pl.json");

    public IReadOnlyDictionary<string, string> Entries => _entries;

    public string Translate(string english) => _entries.TryGetValue(english, out var translated) ? translated : english;

    /// <summary>The numbered placeholders of a format, such as {0} and {1:0.0}.</summary>
    public static IReadOnlyList<int> Placeholders(string format) =>
        Placeholder().Matches(format).Select(match => int.Parse(match.Groups[1].Value, CultureInfo.InvariantCulture)).Order().ToArray();

    /// <summary>Reads a catalog: one JSON object of nonempty strings, no duplicate keys, placeholders kept.</summary>
    public static TextCatalog Parse(ReadOnlySpan<byte> json)
    {
        var reader = new Utf8JsonReader(json, new JsonReaderOptions { CommentHandling = JsonCommentHandling.Disallow, MaxDepth = 2 });
        using var document = JsonDocument.ParseValue(ref reader);
        if (document.RootElement.ValueKind != JsonValueKind.Object) throw new InvalidDataException("A catalog is one JSON object.");
        var entries = new Dictionary<string, string>(StringComparer.Ordinal);
        foreach (var property in document.RootElement.EnumerateObject())
        {
            if (property.Value.ValueKind != JsonValueKind.String || property.Value.GetString() is not { Length: > 0 } value || property.Name.Length == 0)
                throw new InvalidDataException("Catalog entries are nonempty strings.");
            if (!entries.TryAdd(property.Name, value)) throw new InvalidDataException("A catalog key appears twice: " + property.Name);
            if (!Placeholders(property.Name).SequenceEqual(Placeholders(value)))
                throw new InvalidDataException("A translation changes the placeholders of: " + property.Name);
        }

        return new TextCatalog(entries);
    }

    private static TextCatalog Load(string resource)
    {
        using var stream = typeof(TextCatalog).Assembly.GetManifestResourceStream(resource)
                           ?? throw new InvalidOperationException("The catalog " + resource + " is missing.");
        using var buffer = new MemoryStream();
        stream.CopyTo(buffer);
        return Parse(buffer.ToArray());
    }

    [GeneratedRegex(@"(?<!\{)\{([0-9]+)(?:[,:][^}]*)?\}(?!\})", RegexOptions.CultureInvariant)]
    private static partial Regex Placeholder();
}

/// <summary>
/// The language of this process (Desktop and Setup choose it once at start). Core renders per request with
/// <see cref="Translate(string, UiLanguage)"/> instead, because its installation language can change while it runs.
/// </summary>
public static class Localizer
{
    private static volatile int _current;

    public static UiLanguage Current => (UiLanguage)_current;

    public static void Use(UiLanguage language) => _current = (int)language;

    /// <summary>The text in the current language.</summary>
    public static string T(string english) => Translate(english, Current);

    /// <summary>A format in the current language with invariant numbers, such as F("{0} of {1}", 1, 2).</summary>
    public static string F(string englishFormat, params object?[] arguments) => Format(englishFormat, Current, arguments);

    public static string Translate(string english, UiLanguage language) =>
        language == UiLanguage.Polish ? TextCatalog.Polish.Translate(english) : english;

    public static string Format(string englishFormat, UiLanguage language, params object?[] arguments) =>
        string.Format(CultureInfo.InvariantCulture, Translate(englishFormat, language), arguments);
}
