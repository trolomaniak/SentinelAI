using SentinelAI.Contracts.Ai;

namespace SentinelAI.AiGateway;

public interface IAiExplanationProvider
{
    Task<AiExplanation?> ExplainAsync(AiAlertContext context, CancellationToken cancellationToken);
}
