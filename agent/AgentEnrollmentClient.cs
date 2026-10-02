using System.Net.Http.Json;
using SentinelAI.Contracts.Enrollment;

namespace SentinelAI.Agent;

public sealed class AgentEnrollmentClient(AgentOptions options, HttpClient httpClient)
{
    public async Task<(EnrollmentResponse? Response, int StatusCode)> EnrollAsync(
        Guid installationId,
        CancellationToken cancellationToken = default)
    {
        var token = await EnrollmentTokenHandoff.ReadAsync(options, cancellationToken);

        using var response = await httpClient.PostAsJsonAsync(
            options.EnrollmentUrl,
            new EnrollmentRequest(installationId, token),
            cancellationToken);
        if (!response.IsSuccessStatusCode)
        {
            return (null, (int)response.StatusCode);
        }

        var enrollment = await response.Content.ReadFromJsonAsync<EnrollmentResponse>(cancellationToken);
        if (enrollment is null || enrollment.InstallationId != installationId ||
            enrollment.EndpointId == Guid.Empty || enrollment.CoreInstallationId == Guid.Empty ||
            enrollment.OrganizationId == Guid.Empty ||
            enrollment.AgentCredential is not { Length: 64 })
        {
            throw new InvalidDataException("Core returned an invalid enrollment response.");
        }

        return (enrollment, (int)response.StatusCode);
    }
}
