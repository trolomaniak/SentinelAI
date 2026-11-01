using System.Globalization;
using Microsoft.Data.Sqlite;
using SentinelAI.Core.Persistence;
using SentinelAI.Localization;

namespace SentinelAI.Core;

/// <summary>
/// The language of the installation (English or Polish): chosen in Setup (<c>SentinelAI:Language</c>) and changeable by
/// an administrator in Desktop. Desktop shows itself in it and Core writes its reports in it.
/// </summary>
public sealed record InstallationLanguageOptions(UiLanguage Default)
{
    public static InstallationLanguageOptions Load(IConfiguration configuration)
    {
        var configured = configuration["SentinelAI:Language"];
        if (configured is null) return new InstallationLanguageOptions(UiLanguage.English);
        if (!UiLanguages.TryParse(configured, out var language)) throw new InvalidOperationException("SentinelAI:Language must be en or pl.");
        return new InstallationLanguageOptions(language);
    }
}

public sealed record InstallationLanguageView(string Language);

public sealed record InstallationLanguageRequest(string? Language);

public sealed class InstallationLanguageStore(AdminStore admins, InstallationLanguageOptions options)
{
    private volatile int _current = (int)options.Default;

    public UiLanguage Current => (UiLanguage)_current;

    public async Task InitializeAsync(CancellationToken cancellationToken = default)
    {
        await using var connection = await OpenAsync(cancellationToken);
        await using var command = connection.CreateCommand();
        command.CommandText = """
            CREATE TABLE IF NOT EXISTS InstallationSettings (Key TEXT NOT NULL PRIMARY KEY, Value TEXT NOT NULL);
            SELECT Value FROM InstallationSettings WHERE Key = 'language';
            """;
        // A language an administrator chose in Desktop outlasts the one Setup configured.
        if (await command.ExecuteScalarAsync(cancellationToken) is string stored && UiLanguages.TryParse(stored, out var language)) _current = (int)language;
    }

    public async Task SetAsync(UiLanguage language, CancellationToken cancellationToken = default)
    {
        await using var connection = await OpenAsync(cancellationToken);
        await using var command = connection.CreateCommand();
        command.CommandText = """
            INSERT INTO InstallationSettings (Key, Value) VALUES ('language', $value)
            ON CONFLICT (Key) DO UPDATE SET Value = excluded.Value;
            """;
        command.Parameters.AddWithValue("$value", UiLanguages.Code(language));
        await command.ExecuteNonQueryAsync(cancellationToken);
        _current = (int)language;
    }

    private async Task<SqliteConnection> OpenAsync(CancellationToken cancellationToken)
    {
        var connection = new SqliteConnection(new SqliteConnectionStringBuilder
        {
            DataSource = admins.DatabasePath, Mode = SqliteOpenMode.ReadWrite, DefaultTimeout = 30
        }.ToString());
        await connection.OpenAsync(cancellationToken);
        return connection;
    }
}
