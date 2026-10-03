using Microsoft.AspNetCore.Identity;
using Microsoft.Data.Sqlite;

namespace SentinelAI.Core.Persistence;

public sealed record AdminRecord(string Username, string PasswordHash);

internal enum AdministratorInitializationResult { Created, AlreadyInitialized }
internal enum AdministratorSetupState { Required, Initialized }

public sealed class AdminStore
{
    internal const int PasswordHashIterations = 310_000;
    private const string BootstrapUsernameVariable = "SENTINELAI_BOOTSTRAP_USERNAME";
    private const string BootstrapPasswordVariable = "SENTINELAI_BOOTSTRAP_PASSWORD";
    private const string DatabaseFileName = "sentinelai.db";
    private const UnixFileMode DirectoryMode = UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute;
    private const UnixFileMode FileMode = UnixFileMode.UserRead | UnixFileMode.UserWrite;

    private readonly IPasswordHasher<AdminRecord> _passwordHasher;
    private readonly ILogger<AdminStore> _logger;
    private readonly string _dataDirectory;

    public AdminStore(
        IConfiguration configuration,
        IPasswordHasher<AdminRecord> passwordHasher,
        ILogger<AdminStore> logger)
    {
        _passwordHasher = passwordHasher;
        _logger = logger;

        var configuredDirectory = configuration["SentinelAI:DataDirectory"];
        if (string.IsNullOrWhiteSpace(configuredDirectory))
        {
            var localData = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
            if (string.IsNullOrWhiteSpace(localData))
            {
                throw new InvalidOperationException(
                    "The local application data directory is unavailable. Configure SentinelAI:DataDirectory.");
            }

            configuredDirectory = Path.Combine(localData, "SentinelAI", "Core");
        }

        _dataDirectory = Path.GetFullPath(configuredDirectory);
        DatabasePath = Path.Combine(_dataDirectory, DatabaseFileName);
    }

    public string DatabasePath { get; }

    public Task InitializeAsync(CancellationToken cancellationToken = default) =>
        InitializeAsync(allowBootstrap: true, cancellationToken);

    internal async Task InitializeAsync(bool allowBootstrap, CancellationToken cancellationToken = default)
        => _ = await InitializeCoreAsync(allowBootstrap,
            () => (Environment.GetEnvironmentVariable(BootstrapUsernameVariable)?.Trim(),
                Environment.GetEnvironmentVariable(BootstrapPasswordVariable)), cancellationToken);

    internal Task<AdministratorInitializationResult> InitializeWithCredentialsAsync(
        string username, string password, CancellationToken cancellationToken = default) =>
        InitializeCoreAsync(allowBootstrap: true, () => (username, password), cancellationToken);

    private async Task<AdministratorInitializationResult> InitializeCoreAsync(
        bool allowBootstrap, Func<(string? Username, string? Password)> credentials,
        CancellationToken cancellationToken)
    {
        if (!allowBootstrap && !File.Exists(DatabasePath))
            throw SetupRequired();
        EnsurePrivateStorage();

        await using var connection = CreateConnection(SqliteOpenMode.ReadWriteCreate);
        await connection.OpenAsync(cancellationToken);

        // Acquiring the write lock before checking the table keeps concurrent
        // first starts from creating more than one administrator.
        using var transaction = connection.BeginTransaction(deferred: false);
        await using (var create = connection.CreateCommand())
        {
            create.Transaction = transaction;
            create.CommandText = """
                CREATE TABLE IF NOT EXISTS Administrators (
                    Username TEXT PRIMARY KEY COLLATE NOCASE,
                    PasswordHash TEXT NOT NULL
                );
                """;
            await create.ExecuteNonQueryAsync(cancellationToken);
        }

        long administratorCount;
        await using (var count = connection.CreateCommand())
        {
            count.Transaction = transaction;
            count.CommandText = "SELECT COUNT(*) FROM Administrators;";
            administratorCount = (long)(await count.ExecuteScalarAsync(cancellationToken) ?? 0L);
        }

        var createdAdministrator = administratorCount == 0;
        if (createdAdministrator)
        {
            if (!allowBootstrap)
                throw SetupRequired();
            var (username, password) = credentials();
            if (string.IsNullOrWhiteSpace(username) || password is null || password.Length < 12)
            {
                throw new InvalidOperationException(
                    $"First-run administrator setup requires {BootstrapUsernameVariable} and " +
                    $"{BootstrapPasswordVariable} (at least 12 characters).");
            }

            var administrator = new AdminRecord(username, string.Empty);
            var passwordHash = _passwordHasher.HashPassword(administrator, password);

            await using var insert = connection.CreateCommand();
            insert.Transaction = transaction;
            insert.CommandText = """
                INSERT INTO Administrators (Username, PasswordHash)
                VALUES ($username, $passwordHash);
                """;
            insert.Parameters.AddWithValue("$username", username);
            insert.Parameters.AddWithValue("$passwordHash", passwordHash);
            await insert.ExecuteNonQueryAsync(cancellationToken);
        }

        transaction.Commit();

        if (createdAdministrator)
        {
            _logger.LogInformation("Created the local administrator account.");
        }

        if (!OperatingSystem.IsWindows())
        {
            File.SetUnixFileMode(DatabasePath, FileMode);
        }

        return createdAdministrator ? AdministratorInitializationResult.Created :
            AdministratorInitializationResult.AlreadyInitialized;
    }

    /// <summary>Observe first-run state without creating a directory, SQLite file, or table.</summary>
    internal async Task<AdministratorSetupState> ReadSetupStateAsync(CancellationToken cancellationToken = default)
    {
        try
        {
            var dataAttributes = File.GetAttributes(_dataDirectory);
            if ((dataAttributes & (FileAttributes.Directory | FileAttributes.ReparsePoint)) != FileAttributes.Directory ||
                new DirectoryInfo(_dataDirectory).LinkTarget is not null)
                throw new InvalidOperationException("Administrator storage is unavailable.");
        }
        catch (DirectoryNotFoundException)
        {
            return AdministratorSetupState.Required;
        }
        catch (FileNotFoundException)
        {
            return AdministratorSetupState.Required;
        }

        if (!OperatingSystem.IsWindows() && HasSharedAccess(File.GetUnixFileMode(_dataDirectory)))
            throw new InvalidOperationException("Administrator storage is unavailable.");

        try
        {
            var databaseAttributes = File.GetAttributes(DatabasePath);
            if ((databaseAttributes & (FileAttributes.Directory | FileAttributes.ReparsePoint)) != 0 ||
                new FileInfo(DatabasePath).LinkTarget is not null)
                throw new InvalidOperationException("Administrator storage is unavailable.");
        }
        catch (FileNotFoundException)
        {
            return AdministratorSetupState.Required;
        }

        if (!OperatingSystem.IsWindows() && HasSharedAccess(File.GetUnixFileMode(DatabasePath)))
            throw new InvalidOperationException("Administrator storage is unavailable.");

        await using var connection = CreateConnection(SqliteOpenMode.ReadOnly);
        await connection.OpenAsync(cancellationToken);
        await using var table = connection.CreateCommand();
        table.CommandText = "SELECT COUNT(*) FROM sqlite_master WHERE type = 'table' AND name = 'Administrators';";
        if (Convert.ToInt64(await table.ExecuteScalarAsync(cancellationToken)) == 0)
            return AdministratorSetupState.Required;

        await using var count = connection.CreateCommand();
        count.CommandText = "SELECT COUNT(*) FROM Administrators;";
        return Convert.ToInt64(await count.ExecuteScalarAsync(cancellationToken)) > 0 ?
            AdministratorSetupState.Initialized : AdministratorSetupState.Required;
    }

    private static bool HasSharedAccess(UnixFileMode mode) =>
        (mode & (UnixFileMode.GroupRead | UnixFileMode.GroupWrite | UnixFileMode.GroupExecute |
                 UnixFileMode.OtherRead | UnixFileMode.OtherWrite | UnixFileMode.OtherExecute)) != 0;

    private static InvalidOperationException SetupRequired() =>
        new("Core service startup requires an existing local administrator. Complete local setup before starting the service.");

    public async Task<AdminRecord?> FindByUsernameAsync(
        string username,
        CancellationToken cancellationToken = default)
    {
        if (string.IsNullOrWhiteSpace(username))
        {
            return null;
        }

        await using var connection = CreateConnection(SqliteOpenMode.ReadWrite);
        await connection.OpenAsync(cancellationToken);
        await using var query = connection.CreateCommand();
        query.CommandText = """
            SELECT Username, PasswordHash
            FROM Administrators
            WHERE Username = $username
            LIMIT 1;
            """;
        query.Parameters.AddWithValue("$username", username.Trim());

        await using var reader = await query.ExecuteReaderAsync(cancellationToken);
        if (!await reader.ReadAsync(cancellationToken))
        {
            return null;
        }

        return new AdminRecord(reader.GetString(0), reader.GetString(1));
    }

    private SqliteConnection CreateConnection(SqliteOpenMode mode)
    {
        var connectionString = new SqliteConnectionStringBuilder
        {
            DataSource = DatabasePath,
            Mode = mode,
            DefaultTimeout = 30
        };
        return new SqliteConnection(connectionString.ToString());
    }

    private void EnsurePrivateStorage()
    {
        if (OperatingSystem.IsWindows())
        {
            Directory.CreateDirectory(_dataDirectory);
            return;
        }

        Directory.CreateDirectory(_dataDirectory, DirectoryMode);
        if (new DirectoryInfo(_dataDirectory).LinkTarget is not null)
        {
            throw new InvalidOperationException("The SentinelAI data directory cannot be a symbolic link.");
        }

        File.SetUnixFileMode(_dataDirectory, DirectoryMode);
        if (new FileInfo(DatabasePath).LinkTarget is not null)
        {
            throw new InvalidOperationException("The SentinelAI database cannot be a symbolic link.");
        }

        // Create the file privately before SQLite opens it. A pre-existing file
        // is also restricted before its contents can be read or changed.
        using (new FileStream(DatabasePath, new FileStreamOptions
        {
            Mode = System.IO.FileMode.OpenOrCreate,
            Access = FileAccess.ReadWrite,
            Share = FileShare.ReadWrite,
            UnixCreateMode = FileMode
        }))
        {
        }

        File.SetUnixFileMode(DatabasePath, FileMode);
    }
}
