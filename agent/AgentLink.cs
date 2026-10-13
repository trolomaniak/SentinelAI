namespace SentinelAI.Agent;

/// <summary>
/// The Agent's link to Core: the enrollment, present only while the Agent is enrolled and
/// Core acknowledged its latest heartbeat. <see cref="HeartbeatWorker"/> publishes it; the
/// security event pipeline stays dormant until it is present.
/// </summary>
public sealed class AgentLink
{
    private readonly object _gate = new();
    private EnrollmentState? _current;
    private TaskCompletionSource _changed = NewSignal();

    public EnrollmentState? Current
    {
        get
        {
            lock (_gate)
            {
                return _current;
            }
        }
    }

    /// <summary>Completes when the link appears, disappears or names a different endpoint.</summary>
    public Task Changed
    {
        get
        {
            lock (_gate)
            {
                return _changed.Task;
            }
        }
    }

    public void Publish(EnrollmentState? linked)
    {
        TaskCompletionSource? signal = null;
        lock (_gate)
        {
            if (_current?.EndpointId != linked?.EndpointId)
            {
                signal = _changed;
                _changed = NewSignal();
            }

            _current = linked;
        }

        signal?.TrySetResult();
    }

    private static TaskCompletionSource NewSignal() => new(TaskCreationOptions.RunContinuationsAsynchronously);
}
