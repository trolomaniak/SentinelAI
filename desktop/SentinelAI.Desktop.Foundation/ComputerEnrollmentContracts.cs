namespace SentinelAI.Desktop.Foundation;

// MVP-2 "Add computers" and "Remove computer". Enrollment codes are secrets: Desktop shows them only after issuing,
// never logs them and forgets them on sign-out.
public sealed record EnrollmentAddressOption(string Value, bool IsName, bool Resolves);
public sealed record ComputerEnrollmentOptions(bool Available, bool Listening, int? Port, string? RecommendedAddress,
    IReadOnlyList<EnrollmentAddressOption> Addresses);
public sealed record IssuedComputerCode(Guid Id, string Code, DateTimeOffset ExpiresUtc)
{
    public override string ToString() => nameof(IssuedComputerCode);
}
public sealed record UnusedComputerCode(Guid Id, DateTimeOffset CreatedUtc, DateTimeOffset ExpiresUtc);

public enum ComputerEnrollmentOutcome { Success, Unauthenticated, Unavailable, UntrustedConnection, InvalidResponse, TooLarge, NotFound, Conflict, Rejected }
public sealed record ComputerEnrollmentResult<T>(ComputerEnrollmentOutcome Outcome, T? Value = default) where T : class;

public interface IComputerEnrollmentClient
{
    Task<ComputerEnrollmentResult<ComputerEnrollmentOptions>> GetEnrollmentOptionsAsync(CancellationToken cancellationToken);
    Task<ComputerEnrollmentResult<IReadOnlyList<IssuedComputerCode>>> IssueCodesAsync(int count, int validityHours, string address, CancellationToken cancellationToken);
    Task<ComputerEnrollmentResult<IReadOnlyList<UnusedComputerCode>>> GetUnusedCodesAsync(CancellationToken cancellationToken);
    Task<ComputerEnrollmentOutcome> RevokeCodeAsync(Guid id, CancellationToken cancellationToken);
    Task<ComputerEnrollmentOutcome> RemoveComputerAsync(Guid endpointId, CancellationToken cancellationToken);
}
