using System.Diagnostics;
using System.Globalization;
using System.IO;
using System.IO.Pipes;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Security.Principal;
using System.Text;
using Microsoft.Win32.SafeHandles;

[assembly: InternalsVisibleTo("SentinelAI.Desktop.Windows.Tests")]

namespace SentinelAI.Desktop.Services;

/// <summary>
/// Elects one normal Desktop per Windows user and interactive session. The only
/// IPC operation is to show that owner's window; authentication never crosses it.
/// The primary owner must be acquired and disposed on the same (UI) thread.
/// </summary>
internal sealed class WindowsDesktopInstance : IDisposable
{
    internal static ReadOnlyMemory<byte> OpenRequest => "SentinelAI.Open.1\n"u8.ToArray();
    internal static ReadOnlyMemory<byte> OpenResponse => "SentinelAI.Opened.1\n"u8.ToArray();

    private readonly Mutex _mutex;
    private readonly CancellationTokenSource _lifetime = new();
    private readonly object _serverGate = new();
    private readonly int _ownerThread;
    private NamedPipeServerStream? _server;
    private Task? _listener;
    private bool _disposed;

    private WindowsDesktopInstance(Mutex mutex, bool primary, string pipeName)
    {
        _mutex = mutex;
        IsPrimary = primary;
        PipeName = pipeName;
        _ownerThread = Environment.CurrentManagedThreadId;
    }

    public bool IsPrimary { get; }
    internal string PipeName { get; }

    public static WindowsDesktopInstance AcquireForCurrentSession()
    {
        if (!OperatingSystem.IsWindows()) throw new PlatformNotSupportedException();
        using var identity = WindowsIdentity.GetCurrent();
        var sid = identity.User?.Value ?? throw new InvalidOperationException();
        var user = Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(sid)));
        using var process = Process.GetCurrentProcess();
        var session = process.SessionId.ToString(CultureInfo.InvariantCulture);
        var name = "SentinelAI.Desktop.1." + user;
        var pipeName = name + "." + session;
        var mutex = new Mutex(false, name, new NamedWaitHandleOptions
        {
            CurrentUserOnly = true,
            CurrentSessionOnly = true
        });
        try
        {
            bool primary;
            try { primary = mutex.WaitOne(0); }
            catch (AbandonedMutexException) { primary = true; }
            return new WindowsDesktopInstance(mutex, primary, pipeName);
        }
        catch
        {
            mutex.Dispose();
            throw;
        }
    }

    public void StartListening(Action activation)
    {
        ArgumentNullException.ThrowIfNull(activation);
        ObjectDisposedException.ThrowIf(_disposed, this);
        if (!IsPrimary || _listener is not null) throw new InvalidOperationException();
        // Construct the first endpoint synchronously so startup fails safely if
        // its current-user-only pipe cannot be created.
        var first = CreateServer();
        lock (_serverGate) _server = first;
        _listener = ListenAsync(first, activation);
    }

    public async Task<bool> ActivateExistingAsync(CancellationToken cancellationToken = default)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        if (IsPrimary) throw new InvalidOperationException();
        using var deadline = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken, _lifetime.Token);
        deadline.CancelAfter(TimeSpan.FromSeconds(5));
        try
        {
            using var pipe = new NamedPipeClientStream(".", PipeName, PipeDirection.InOut,
                PipeOptions.Asynchronous | PipeOptions.CurrentUserOnly);
            await pipe.ConnectAsync(deadline.Token).ConfigureAwait(false);
            pipe.ReadMode = PipeTransmissionMode.Message;
            // A user-launched duplicate can grant the already-running window
            // foreground permission to honor that explicit activation action.
            if (GetNamedPipeServerProcessId(pipe.SafePipeHandle, out var ownerProcess))
                _ = AllowSetForegroundWindow(ownerProcess);
            await pipe.WriteAsync(OpenRequest, deadline.Token).ConfigureAwait(false);
            await pipe.FlushAsync(deadline.Token).ConfigureAwait(false);
            return await ReadLiteralAsync(pipe, OpenResponse, deadline.Token).ConfigureAwait(false);
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException
            or OperationCanceledException or InvalidOperationException)
        {
            return false;
        }
    }

    private NamedPipeServerStream CreateServer() => new(PipeName, PipeDirection.InOut, 1,
        PipeTransmissionMode.Message, PipeOptions.Asynchronous | PipeOptions.CurrentUserOnly,
        64, 64);

    private async Task ListenAsync(NamedPipeServerStream first, Action activation)
    {
        NamedPipeServerStream? server = first;
        try
        {
            while (!_lifetime.IsCancellationRequested)
            {
                try
                {
                    await server.WaitForConnectionAsync(_lifetime.Token).ConfigureAwait(false);
                    using var deadline = CancellationTokenSource.CreateLinkedTokenSource(_lifetime.Token);
                    deadline.CancelAfter(TimeSpan.FromSeconds(1));
                    if (await ReadLiteralAsync(server, OpenRequest, deadline.Token).ConfigureAwait(false))
                    {
                        activation();
                        await server.WriteAsync(OpenResponse, deadline.Token).ConfigureAwait(false);
                        await server.FlushAsync(deadline.Token).ConfigureAwait(false);
                    }
                }
                catch (Exception exception) when (exception is IOException or UnauthorizedAccessException
                    or OperationCanceledException or ObjectDisposedException or InvalidOperationException)
                {
                    // Malformed/stalled/disconnected local clients carry no
                    // command or diagnostic content into the application.
                }
                finally
                {
                    lock (_serverGate)
                    {
                        if (ReferenceEquals(_server, server)) _server = null;
                        server.Dispose();
                    }
                }
                lock (_serverGate)
                {
                    if (_lifetime.IsCancellationRequested) break;
                    server = CreateServer();
                    _server = server;
                }
            }
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException
            or OperationCanceledException or ObjectDisposedException or InvalidOperationException)
        {
            // If the endpoint becomes unavailable, duplicates fail safely;
            // they never create a second authenticated UI.
        }
        finally
        {
            lock (_serverGate)
            {
                if (ReferenceEquals(_server, server)) _server = null;
                server?.Dispose();
            }
        }
    }

    private static async Task<bool> ReadLiteralAsync(PipeStream pipe, ReadOnlyMemory<byte> expected,
        CancellationToken cancellationToken)
    {
        // One bounded native pipe message, with no trailing payload, paths,
        // process arguments, user text or serialized state accepted.
        var bytes = new byte[expected.Length + 1];
        var count = 0;
        while (count < bytes.Length)
        {
            var read = await pipe.ReadAsync(bytes.AsMemory(count), cancellationToken).ConfigureAwait(false);
            if (read == 0) return false;
            count += read;
            if (pipe.IsMessageComplete)
                return count == expected.Length && bytes.AsSpan(0, count).SequenceEqual(expected.Span);
        }
        return false;
    }

    public void Dispose()
    {
        if (_disposed) return;
        if (IsPrimary && _ownerThread != Environment.CurrentManagedThreadId)
            throw new InvalidOperationException("The Desktop instance must be released by its acquiring thread.");
        _disposed = true;
        _lifetime.Cancel();
        lock (_serverGate)
        {
            _server?.Dispose();
            _server = null;
        }
        if (IsPrimary) _mutex.ReleaseMutex();
        _mutex.Dispose();
        // The listener may be completing cancellation on another thread. Keep
        // its cancellation source alive until that completion.
        if (_listener is null) _lifetime.Dispose();
        else _ = _listener.ContinueWith(_ => _lifetime.Dispose(), CancellationToken.None,
            TaskContinuationOptions.ExecuteSynchronously, TaskScheduler.Default);
    }

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool GetNamedPipeServerProcessId(SafePipeHandle pipe, out uint processId);

    [DllImport("user32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool AllowSetForegroundWindow(uint processId);
}
