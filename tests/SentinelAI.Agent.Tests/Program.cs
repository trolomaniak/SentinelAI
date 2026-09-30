var agentAssembly = typeof(SentinelAI.Agent.Program).Assembly;
if (agentAssembly.GetName().Name != "SentinelAI.Agent")
{
    throw new Exception("The Agent project did not produce the expected assembly.");
}

if (agentAssembly.EntryPoint is null)
{
    throw new Exception("The Agent assembly must be executable.");
}

if (SentinelAI.Agent.Program.Main() != 0)
{
    throw new Exception("The Agent scaffold did not exit successfully.");
}

Console.WriteLine("Agent scaffold tests passed.");
