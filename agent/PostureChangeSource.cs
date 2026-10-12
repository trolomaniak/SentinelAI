using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using Microsoft.Win32;
using Microsoft.Win32.SafeHandles;

namespace SentinelAI.Agent;

/// <summary>
/// Signals that monitored posture settings may have changed. A signal carries no data;
/// the monitor always re-reads the bounded allowlist.
/// </summary>
public interface IPostureChangeSource : IDisposable
{
    /// <summary>
    /// Replaces all previous registrations. Returns false when any monitored location could
    /// not be watched; periodic verification then remains the only detection for it.
    /// <paramref name="onChange"/> may run on any thread and must not block.
    /// </summary>
    bool Arm(Action onChange);
}

public sealed class NoPostureChangeSource : IPostureChangeSource
{
    public bool Arm(Action onChange) => false;

    public void Dispose()
    {
    }
}

/// <summary>
/// One-shot registry change notifications for a fixed list of keys. An absent key is
/// covered by watching its nearest existing ancestor subtree, so creation is noticed; the
/// hive root and top-level keys are never watched.
/// </summary>
[SupportedOSPlatform("windows")]
public sealed class RegistryPostureChangeSource : IPostureChangeSource
{
    private const int NotifyChangeName = 0x1;
    private const int NotifyChangeLastSet = 0x4;
    // Keeps the registration valid after the arming thread-pool thread exits.
    private const int NotifyThreadAgnostic = 0x10000000;
    private const int MinimumAncestorDepth = 2;

    private readonly RegistryHive _hive;
    private readonly RegistryView _view;
    private readonly string[] _keyPaths;
    private readonly object _gate = new();
    private readonly List<Watch> _watches = [];
    private long _generation;
    private bool _disposed;

    public RegistryPostureChangeSource(RegistryHive hive, RegistryView view, IEnumerable<string> keyPaths)
    {
        ArgumentNullException.ThrowIfNull(keyPaths);
        _hive = hive;
        _view = view;
        _keyPaths = keyPaths.Distinct(StringComparer.OrdinalIgnoreCase).ToArray();
        if (_keyPaths.Length is 0 or > 64 || _keyPaths.Any(path =>
                string.IsNullOrWhiteSpace(path) || path.StartsWith('\\') || path.EndsWith('\\')))
        {
            throw new ArgumentException("Between one and 64 relative registry key paths are required.", nameof(keyPaths));
        }
    }

    public static RegistryPostureChangeSource ForSecurityConfiguration() => new(
        RegistryHive.LocalMachine, RegistryView.Registry64, WindowsSecurityConfigurationCollector.ConfigurationKeyPaths);

    public bool Arm(Action onChange)
    {
        ArgumentNullException.ThrowIfNull(onChange);
        lock (_gate)
        {
            ObjectDisposedException.ThrowIf(_disposed, this);
            // Callbacks from earlier registrations, including those raised by closing their
            // keys, are ignored; only this generation may signal.
            var generation = Interlocked.Increment(ref _generation);
            ReleaseWatches();

            var complete = true;
            var watched = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            using var root = RegistryKey.OpenBaseKey(_hive, _view);
            foreach (var keyPath in _keyPaths)
            {
                try
                {
                    var (key, subtree) = OpenNearest(root, keyPath);
                    if (key is null)
                    {
                        complete = false;
                        continue;
                    }

                    if (!watched.Add((subtree ? "subtree:" : "key:") + key.Name))
                    {
                        key.Dispose();
                        continue;
                    }

                    _watches.Add(Watch.Start(key, subtree, () =>
                    {
                        if (Interlocked.Read(ref _generation) == generation)
                        {
                            onChange();
                        }
                    }));
                }
                catch (Exception exception) when (exception is IOException or UnauthorizedAccessException or
                                                   System.Security.SecurityException or Win32Exception)
                {
                    complete = false;
                }
            }

            return complete;
        }
    }

    public void Dispose()
    {
        lock (_gate)
        {
            if (_disposed)
            {
                return;
            }

            _disposed = true;
            Interlocked.Increment(ref _generation);
            ReleaseWatches();
        }
    }

    private void ReleaseWatches()
    {
        foreach (var watch in _watches)
        {
            watch.Dispose();
        }

        _watches.Clear();
    }

    private static (RegistryKey? Key, bool Subtree) OpenNearest(RegistryKey root, string keyPath)
    {
        var path = keyPath;
        var subtree = false;
        while (true)
        {
            var key = root.OpenSubKey(path);
            if (key is not null)
            {
                return (key, subtree);
            }

            var separator = path.LastIndexOf('\\');
            if (separator < 0 || path.AsSpan(0, separator).Count('\\') + 1 < MinimumAncestorDepth)
            {
                return (null, false);
            }

            path = path[..separator];
            subtree = true;
        }
    }

    private sealed class Watch : IDisposable
    {
        private readonly RegistryKey _key;
        private readonly AutoResetEvent _signal;
        private readonly RegisteredWaitHandle _registration;

        private Watch(RegistryKey key, AutoResetEvent signal, RegisteredWaitHandle registration)
        {
            _key = key;
            _signal = signal;
            _registration = registration;
        }

        public static Watch Start(RegistryKey key, bool subtree, Action onChange)
        {
            var signal = new AutoResetEvent(false);
            try
            {
                var result = RegNotifyChangeKeyValue(key.Handle, subtree,
                    NotifyChangeName | NotifyChangeLastSet | NotifyThreadAgnostic, signal.SafeWaitHandle, true);
                if (result != 0)
                {
                    throw new Win32Exception(result);
                }

                var registration = ThreadPool.RegisterWaitForSingleObject(signal,
                    static (state, _) => ((Action)state!)(), onChange, Timeout.Infinite, executeOnlyOnce: true);
                return new Watch(key, signal, registration);
            }
            catch
            {
                signal.Dispose();
                key.Dispose();
                throw;
            }
        }

        public void Dispose()
        {
            // Unregister before closing the key: closing signals any pending notification.
            _registration.Unregister(null);
            _key.Dispose();
            _signal.Dispose();
        }
    }

    [DllImport("advapi32.dll", ExactSpelling = true)]
    [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    private static extern int RegNotifyChangeKeyValue(
        SafeRegistryHandle key,
        [MarshalAs(UnmanagedType.Bool)] bool watchSubtree,
        int notifyFilter,
        SafeWaitHandle eventHandle,
        [MarshalAs(UnmanagedType.Bool)] bool asynchronous);
}
