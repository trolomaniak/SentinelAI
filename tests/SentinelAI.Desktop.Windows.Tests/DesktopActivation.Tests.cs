using System.Diagnostics;
using System.IO;
using System.IO.Pipes;
using System.Text;
using SentinelAI.Desktop.Services;

internal static partial class Program
{
    private static async Task DesktopActivationAsync()
    {
        // Mutex ownership belongs to the acquiring UI thread. Duplicates are
        // acquired on a worker, since Windows mutex acquisition is recursive
        // when performed a second time by the same owning thread.
        using var primary = WindowsDesktopInstance.AcquireForCurrentSession();
        Ensure(primary.IsPrimary, "The first Desktop did not become the current session's owner.");
        var activations = 0;
        primary.StartListening(() => Interlocked.Increment(ref activations));

        var first = await ActivateDesktopFromWorkerAsync();
        Ensure(!first.IsPrimary && first.PipeName == primary.PipeName,
            "A duplicate Desktop did not select the existing user/session endpoint.");
        Ensure(first.Activated && Volatile.Read(ref activations) == 1,
            "A duplicate Desktop did not acknowledge exactly one Open action.");

        var expectedActivations = 1;
        var invalidRequests = new[]
        {
            Encoding.UTF8.GetBytes("SentinelAI.SignIn.1\n"),
            Encoding.UTF8.GetBytes("SentinelAI.Open.1\nextra"),
            Encoding.UTF8.GetBytes("SentinelAI.Open.1\nSentinelAI.Open.1\n"),
            Enumerable.Repeat((byte)'X', 4096).ToArray(),
            new byte[] { 0xff, 0xfe, 0xfd, 0x0a }
        };
        foreach (var request in invalidRequests)
        {
            await RejectDesktopActivationMessageAsync(primary.PipeName, request);
            Ensure(Volatile.Read(ref activations) == expectedActivations,
                "Malformed Desktop IPC invoked an application action.");
            var recovery = await ActivateDesktopFromWorkerAsync();
            expectedActivations++;
            Ensure(!recovery.IsPrimary && recovery.Activated && Volatile.Read(ref activations) == expectedActivations,
                "Rejected Desktop IPC prevented a subsequent valid Open action.");
        }

        // A client that connects without sending its bounded message must not
        // hold the one local activation endpoint indefinitely.
        using (var stalled = CreateActivationProbe(primary.PipeName))
        using (var deadline = new CancellationTokenSource(TimeSpan.FromSeconds(4)))
        {
            await stalled.ConnectAsync(deadline.Token);
            stalled.ReadMode = PipeTransmissionMode.Message;
            var elapsed = Stopwatch.StartNew();
            var closed = false;
            try
            {
                var count = await stalled.ReadAsync(new byte[1], deadline.Token);
                closed = count == 0;
            }
            catch (IOException)
            {
                closed = true;
            }
            Ensure(closed && elapsed.Elapsed < TimeSpan.FromSeconds(3.5),
                "A stalled Desktop activation client was not disconnected within the server handshake bound.");
        }
        Ensure(Volatile.Read(ref activations) == expectedActivations,
            "A stalled Desktop activation client invoked an application action.");
        var afterStall = await ActivateDesktopFromWorkerAsync();
        expectedActivations++;
        Ensure(afterStall.Activated && Volatile.Read(ref activations) == expectedActivations,
            "Desktop activation did not recover after a stalled client.");

        using (var cancellation = new CancellationTokenSource())
        {
            cancellation.Cancel();
            var elapsed = Stopwatch.StartNew();
            var cancelled = await ActivateDesktopFromWorkerAsync(cancellation.Token);
            Ensure(!cancelled.IsPrimary && !cancelled.Activated && elapsed.Elapsed < TimeSpan.FromSeconds(2),
                "Cancelled Desktop activation sent or acknowledged an Open action.");
            Ensure(Volatile.Read(ref activations) == expectedActivations,
                "Cancelled Desktop activation reached the owner's action.");
        }

        // Dispose and reacquire without an artificial delay: closing Desktop
        // must release both ownership and the endpoint for a normal reopen.
        primary.Dispose();
        using var reopened = WindowsDesktopInstance.AcquireForCurrentSession();
        Ensure(reopened.IsPrimary && reopened.PipeName == primary.PipeName,
            "Closing Desktop did not permit a replacement owner in the same user/session.");
        var reopenActivations = 0;
        reopened.StartListening(() => Interlocked.Increment(ref reopenActivations));
        var replacement = await ActivateDesktopFromWorkerAsync();
        Ensure(!replacement.IsPrimary && replacement.Activated && Volatile.Read(ref reopenActivations) == 1,
            "The reopened Desktop did not accept exactly one duplicate activation.");
        Ensure(Volatile.Read(ref activations) == expectedActivations,
            "A replacement Desktop action reached the disposed owner.");

        // Ownership is authoritative even when its activation listener is not
        // available. A duplicate must time out safely rather than becoming a
        // second authenticated UI beside the existing owner.
        reopened.Dispose();
        using var unreachableOwner = WindowsDesktopInstance.AcquireForCurrentSession();
        Ensure(unreachableOwner.IsPrimary,
            "The unavailable-listener fixture did not acquire Desktop ownership.");
        var unavailableElapsed = Stopwatch.StartNew();
        var unavailable = await ActivateDesktopFromWorkerAsync();
        Ensure(!unavailable.IsPrimary && !unavailable.Activated && unavailableElapsed.Elapsed < TimeSpan.FromSeconds(7),
            "An unavailable existing Desktop listener did not fail within a bounded activation deadline.");
    }

    private static Task<(bool IsPrimary, bool Activated, string PipeName)> ActivateDesktopFromWorkerAsync(
        CancellationToken cancellationToken = default) => Task.Run(async () =>
    {
        using var duplicate = WindowsDesktopInstance.AcquireForCurrentSession();
        if (duplicate.IsPrimary)
            return (IsPrimary: true, Activated: false, duplicate.PipeName);
        var activated = await duplicate.ActivateExistingAsync(cancellationToken).ConfigureAwait(false);
        return (IsPrimary: false, Activated: activated, duplicate.PipeName);
    });

    private static NamedPipeClientStream CreateActivationProbe(string pipeName) => new(
        ".", pipeName, PipeDirection.InOut, PipeOptions.Asynchronous | PipeOptions.CurrentUserOnly);

    private static async Task RejectDesktopActivationMessageAsync(string pipeName, byte[] request)
    {
        using var pipe = CreateActivationProbe(pipeName);
        using var deadline = new CancellationTokenSource(TimeSpan.FromSeconds(4));
        await pipe.ConnectAsync(deadline.Token);
        pipe.ReadMode = PipeTransmissionMode.Message;
        var elapsed = Stopwatch.StartNew();
        var rejected = false;
        try
        {
            // One native message carries the whole request. A valid prefix
            // with trailing bytes must be rejected just like an unknown verb.
            await pipe.WriteAsync(request, deadline.Token);
            await pipe.FlushAsync(deadline.Token);
            rejected = await pipe.ReadAsync(new byte[WindowsDesktopInstance.OpenResponse.Length + 1], deadline.Token) == 0;
        }
        catch (IOException)
        {
            rejected = true;
        }
        Ensure(rejected && elapsed.Elapsed < TimeSpan.FromSeconds(3.5),
            "Malformed or oversized Desktop IPC was acknowledged or left connected.");
    }
}
