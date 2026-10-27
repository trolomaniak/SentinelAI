using SentinelAI.Updates.Tests;

await ManifestTests.RunAsync();
await UpdaterTests.RunAsync();
await AgentUpdateApplierTests.RunAsync();
await DeploymentUpdaterTests.RunAsync();
await CommandTests.RunAsync();
