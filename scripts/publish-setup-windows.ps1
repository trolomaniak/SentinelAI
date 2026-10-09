#requires -Version 5.1
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][ValidatePattern('^(0|[1-9][0-9]{0,4})\.(0|[1-9][0-9]{0,4})\.(0|[1-9][0-9]{0,4})$')][string]$Version,
    [Parameter(Mandatory = $true)][string]$DevelopmentPrivateKey,
    [Parameter(Mandatory = $true)][string]$PublicKeyPath,
    [Parameter(Mandatory = $true)][ValidatePattern('^dev-[A-Za-z0-9_-]{1,48}$')][string]$KeyId,
    [ValidateSet('stable', 'pilot', 'beta')][string]$Channel = 'pilot',
    [string]$OutputDirectory
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
$repo = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..'))
if ([string]::IsNullOrWhiteSpace($OutputDirectory)) { $OutputDirectory = Join-Path $repo ('artifacts/setup/win-x64/' + $Version) }
$OutputDirectory = [IO.Path]::GetFullPath($OutputDirectory)
$work = $null
$complete = $false
$script:SetupNativeCompilerDiagnostic = $null

function Invoke-SetupDotnet {
    param([string[]]$Arguments)
    & dotnet @Arguments
    if ($LASTEXITCODE -ne 0) { throw 'A setup build or package verification command failed.' }
}

function Assert-SetupPath {
    param([string]$Path, [switch]$OutsideRepository)
    if (-not [IO.Path]::IsPathRooted($Path)) { throw 'An absolute path is required.' }
    $full = [IO.Path]::GetFullPath($Path)
    for ($current = $full; $null -ne $current; $current = [IO.Path]::GetDirectoryName($current)) {
        if (Test-Path -LiteralPath $current) {
            if (([IO.File]::GetAttributes($current) -band [IO.FileAttributes]::ReparsePoint) -ne 0) { throw 'Linked build paths are not supported.' }
        }
        if ($OutsideRepository -and ((Test-Path -LiteralPath (Join-Path $current '.git')) -or
            ((Test-Path -LiteralPath (Join-Path $current 'AGENTS.md')) -and (Test-Path -LiteralPath (Join-Path $current 'SentinelAI.sln'))))) {
            throw 'Signing and trust files must be outside every repository.'
        }
    }
    return $full
}

function New-SetupPayload {
    param([string]$Source, [string]$Destination)
    # Keep these bounds aligned with the Setup extractor. Inspect each directory
    # before descending so a link cannot pull arbitrary build-machine data in.
    $maximumEntries = 4096
    $maximumExpandedBytes = 1GB
    $paths = New-Object 'System.Collections.Generic.Stack[string]'
    $paths.Push($Source)
    $entryNames = New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::OrdinalIgnoreCase)
    $total = [long]0
    $count = 0
    $output = [IO.File]::Open($Destination, [IO.FileMode]::CreateNew, [IO.FileAccess]::Write, [IO.FileShare]::None)
    $archive = $null
    try {
        $archive = New-Object IO.Compression.ZipArchive($output, [IO.Compression.ZipArchiveMode]::Create, $true)
        while ($paths.Count -gt 0) {
            $directory = $paths.Pop()
            foreach ($path in [IO.Directory]::EnumerateFileSystemEntries($directory)) {
                $attributes = [IO.File]::GetAttributes($path)
                if (($attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) { throw 'Payload links are not allowed.' }
                if (($attributes -band [IO.FileAttributes]::Directory) -ne 0) { $paths.Push($path); continue }
                # Trust is embedded separately; no PEM/key file belongs in the
                # payload and the development private key is never copied.
                if ([IO.Path]::GetExtension($path) -in @('.pem', '.key')) { throw 'Payload key files are not allowed.' }
                $name = $path.Substring($Source.Length + 1).Replace('\', '/')
                if (-not $entryNames.Add($name) -or ++$count -gt $maximumEntries) { throw 'Payload entry bounds exceeded.' }
                $input = [IO.File]::Open($path, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::Read)
                try {
                    $length = $input.Length
                    if ($length -gt 512MB -or $length -gt $maximumExpandedBytes - $total) { throw 'Expanded payload bounds exceeded.' }
                    $total += $length
                    $entry = $archive.CreateEntry($name, [IO.Compression.CompressionLevel]::Optimal)
                    $entryOutput = $entry.Open()
                    try { $input.CopyTo($entryOutput) } finally { $entryOutput.Dispose() }
                    if ($input.Position -ne $length -or $input.Length -ne $length) { throw 'A payload source changed while packaging.' }
                } finally { $input.Dispose() }
            }
        }
        if ($count -eq 0) { throw 'The setup payload is empty.' }
    } finally {
        if ($null -ne $archive) { $archive.Dispose() }
        $output.Dispose()
    }
    if ((Get-Item -LiteralPath $Destination).Length -gt 512MB) { throw 'Compressed payload bounds exceeded.' }
}

function ConvertTo-SetupCString {
    param([string]$Value)
    if ($Value.IndexOfAny([char[]]@(0, 10, 13)) -ge 0) { throw 'Invalid native resource path.' }
    return $Value.Replace('\', '\\').Replace('"', '\"')
}

function Assert-SetupRelativePath {
    param([string]$Path)
    if ([string]::IsNullOrWhiteSpace($Path) -or $Path.Length -gt 240 -or $Path.StartsWith('/')) { throw 'Invalid native payload path.' }
    foreach ($part in $Path.Split('/')) {
        if ([string]::IsNullOrWhiteSpace($part) -or $part.Length -gt 255 -or $part -in @('.', '..') -or
            $part.TrimEnd(' ', '.') -cne $part -or $part -match '[\x00-\x1f<>:"\\|?*]' -or
            $part.Split('.')[0] -match '^(?i:CON|PRN|AUX|NUL|COM[0-9]|LPT[0-9])$') { throw 'Invalid native payload path.' }
    }
}

function New-SetupNativeResources {
    param([string]$Source, [string]$HeaderPath, [string]$ResourcePath, [string]$ManifestPath)
    $paths = New-Object 'System.Collections.Generic.Stack[string]'
    $paths.Push($Source)
    $files = New-Object 'System.Collections.Generic.SortedDictionary[string,string]' ([StringComparer]::OrdinalIgnoreCase)
    while ($paths.Count -gt 0) {
        foreach ($path in [IO.Directory]::EnumerateFileSystemEntries($paths.Pop())) {
            $attributes = [IO.File]::GetAttributes($path)
            if (($attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) { throw 'Native payload links are not allowed.' }
            if (($attributes -band [IO.FileAttributes]::Directory) -ne 0) { $paths.Push($path); continue }
            if ([IO.Path]::GetExtension($path) -in @('.pem', '.key')) { throw 'Native payload key files are not allowed.' }
            $relative = $path.Substring($Source.Length + 1).Replace('\', '/')
            Assert-SetupRelativePath -Path $relative
            if ($files.ContainsKey($relative) -or $files.Count -ge 4096) { throw 'Native payload entry bounds exceeded.' }
            $files.Add($relative, $path)
        }
    }
    if (-not $files.ContainsKey('SentinelAI.Setup.Host.exe')) { throw 'The private Setup host is missing.' }
    $header = New-Object Text.StringBuilder
    [void]$header.AppendLine('#pragma once')
    [void]$header.AppendLine('#include <windows.h>')
    [void]$header.AppendLine('#include <cstddef>')
    [void]$header.AppendLine('struct SentinelAIEmbeddedFile { WORD resource_id; const wchar_t* relative_path; DWORD expected_length; unsigned char sha256[32]; };')
    [void]$header.AppendLine('static const SentinelAIEmbeddedFile kSentinelAIPayloadFiles[] = {')
    $resource = New-Object Text.StringBuilder
    [void]$resource.AppendLine('#pragma code_page(65001)')
    [void]$resource.AppendLine('1 24 "' + (ConvertTo-SetupCString -Value $ManifestPath) + '"')
    $total = [long]0
    $resourceId = 1000
    foreach ($file in $files.GetEnumerator()) {
        $input = [IO.File]::Open($file.Value, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::Read)
        $sha256 = [Security.Cryptography.SHA256]::Create()
        try {
            $length = $input.Length
            if ($length -lt 0 -or $length -gt 512MB -or $length -gt 2GB - $total) { throw 'Native payload size bounds exceeded.' }
            $hash = $sha256.ComputeHash($input)
            if ($input.Position -ne $length -or $input.Length -ne $length) { throw 'A native payload source changed while hashing.' }
        } finally { $sha256.Dispose(); $input.Dispose() }
        $total += $length
        $hashBytes = @($hash | ForEach-Object { '0x' + $_.ToString('x2') }) -join ','
        [void]$header.AppendLine('    {' + $resourceId + ', L"' + (ConvertTo-SetupCString -Value $file.Key) + '", ' + $length + 'u, {' + $hashBytes + '}},')
        [void]$resource.AppendLine($resourceId.ToString() + ' RCDATA "' + (ConvertTo-SetupCString -Value $file.Value) + '"')
        $resourceId++
    }
    [void]$header.AppendLine('};')
    [void]$header.AppendLine('static const size_t kSentinelAIPayloadFileCount = sizeof(kSentinelAIPayloadFiles) / sizeof(kSentinelAIPayloadFiles[0]);')
    $encoding = New-Object Text.UTF8Encoding($false)
    [IO.File]::WriteAllText($HeaderPath, $header.ToString(), $encoding)
    [IO.File]::WriteAllText($ResourcePath, $resource.ToString(), $encoding)
}

function Get-SetupNativeEnvironment {
    $vswhere = Join-Path ([Environment]::GetFolderPath([Environment+SpecialFolder]::ProgramFilesX86)) 'Microsoft Visual Studio/Installer/vswhere.exe'
    if (-not (Test-Path -LiteralPath $vswhere -PathType Leaf)) { throw 'Visual Studio C++ build tools are required.' }
    $installation = @(& $vswhere -latest -products '*' -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath)
    if ($LASTEXITCODE -ne 0 -or $installation.Count -ne 1) { throw 'Visual Studio C++ build tools are required.' }
    $vsDevCmd = Join-Path $installation[0].Trim() 'Common7/Tools/VsDevCmd.bat'
    if (-not (Test-Path -LiteralPath $vsDevCmd -PathType Leaf) -or $vsDevCmd -match '[%"\r\n]') { throw 'The native build environment path is invalid.' }
    $start = New-Object Diagnostics.ProcessStartInfo
    $start.FileName = Join-Path ([Environment]::GetFolderPath([Environment+SpecialFolder]::System)) 'cmd.exe'
    $start.Arguments = '/d /s /c ""' + $vsDevCmd + '" -no_logo -arch=x64 -host_arch=x64 >nul && set"'
    $start.UseShellExecute = $false
    $start.CreateNoWindow = $true
    $start.RedirectStandardOutput = $true
    $start.RedirectStandardError = $true
    $process = New-Object Diagnostics.Process
    $process.StartInfo = $start
    try {
        if (-not $process.Start()) { throw 'The native build environment could not start.' }
        $outputTask = $process.StandardOutput.ReadToEndAsync()
        $errorTask = $process.StandardError.ReadToEndAsync()
        $process.WaitForExit()
        $environmentOutput = $outputTask.GetAwaiter().GetResult()
        $null = $errorTask.GetAwaiter().GetResult()
        if ($process.ExitCode -ne 0) { throw 'The native build environment could not initialize.' }
    } finally { $process.Dispose() }
    # Capture only into child-process environments; never print the environment
    # or change the caller's SDK/credential variables.
    $result = New-Object 'System.Collections.Generic.Dictionary[string,string]' ([StringComparer]::OrdinalIgnoreCase)
    foreach ($line in $environmentOutput -split "`r?`n") {
        $separator = $line.IndexOf('=')
        if ($separator -gt 0) { $result[$line.Substring(0, $separator)] = $line.Substring($separator + 1) }
    }
    if (-not $result.ContainsKey('PATH')) { throw 'The native build environment is missing its tools.' }
    return ,$result
}

function Invoke-SetupNativeTool {
    param([string]$Tool, [string[]]$Arguments, [Collections.Generic.Dictionary[string,string]]$NativeEnvironment, [string]$WorkingDirectory)
    $executable = $null
    foreach ($directory in $NativeEnvironment['PATH'].Split(';')) {
        if ([string]::IsNullOrWhiteSpace($directory)) { continue }
        $candidate = Join-Path $directory ($Tool + '.exe')
        if (Test-Path -LiteralPath $candidate -PathType Leaf) { $executable = $candidate; break }
    }
    if ($null -eq $executable) { throw 'A required C++ or Windows SDK tool is missing.' }
    $quotedArguments = @($Arguments | ForEach-Object {
        if ($_ -match '["\x00\r\n]' -or $_.EndsWith('\')) { throw 'Invalid native tool argument.' }
        '"' + $_ + '"'
    })
    $start = New-Object Diagnostics.ProcessStartInfo
    $start.FileName = $executable
    $start.Arguments = $quotedArguments -join ' '
    $start.WorkingDirectory = $WorkingDirectory
    $start.UseShellExecute = $false
    $start.CreateNoWindow = $true
    $start.RedirectStandardOutput = $true
    $start.RedirectStandardError = $true
    foreach ($variable in $NativeEnvironment.GetEnumerator()) { $start.EnvironmentVariables[$variable.Key] = $variable.Value }
    $process = New-Object Diagnostics.Process
    $process.StartInfo = $start
    $script:SetupNativeCompilerDiagnostic = $null
    try {
        if (-not $process.Start()) { throw 'A native setup compiler could not start.' }
        # Drain both streams concurrently without accumulating their complete
        # contents. Preserve only a small tail of compiler diagnostic lines;
        # neither the native environment nor signing-key arguments are printed.
        $outputTask = $process.StandardOutput.ReadLineAsync()
        $errorTask = $process.StandardError.ReadLineAsync()
        $diagnostics = New-Object 'System.Collections.Generic.Queue[string]'
        $lastError = $null
        while ($null -ne $outputTask -or $null -ne $errorTask) {
            $pending = New-Object 'System.Collections.Generic.List[System.Threading.Tasks.Task]'
            if ($null -ne $outputTask) { $pending.Add($outputTask) }
            if ($null -ne $errorTask) { $pending.Add($errorTask) }
            $completed = [Threading.Tasks.Task]::WaitAny($pending.ToArray())
            $isOutput = [object]::ReferenceEquals($pending[$completed], $outputTask)
            $line = if ($isOutput) { $outputTask.GetAwaiter().GetResult() } else { $errorTask.GetAwaiter().GetResult() }
            if ($null -ne $line -and $line -match '\b(?:fatal\s+error|error|warning)\s+[A-Za-z]{1,4}\d{3,5}\b') {
                $bounded = $line.Substring(0, [Math]::Min($line.Length, 800)) -replace '[\x00-\x1f\x7f]', ' '
                if ($line -match '\b(?:fatal\s+error|error)\s+[A-Za-z]{1,4}\d{3,5}\b') { $lastError = $bounded }
                if ($diagnostics.Count -eq 6) { $null = $diagnostics.Dequeue() }
                $diagnostics.Enqueue($bounded)
            }
            if ($isOutput) { $outputTask = if ($null -eq $line) { $null } else { $process.StandardOutput.ReadLineAsync() } }
            else { $errorTask = if ($null -eq $line) { $null } else { $process.StandardError.ReadLineAsync() } }
        }
        $process.WaitForExit()
        if ($process.ExitCode -ne 0) {
            # A late-drained warning stream must not push the fatal diagnostic
            # out of the small tail gathered from the other stream.
            if ($null -ne $lastError -and -not $diagnostics.Contains($lastError)) {
                if ($diagnostics.Count -eq 6) { $null = $diagnostics.Dequeue() }
                $diagnostics.Enqueue($lastError)
            }
            $script:SetupNativeCompilerDiagnostic = 'Native ' + $Tool + ' failed with exit code ' + $process.ExitCode + '.'
            if ($diagnostics.Count -gt 0) { $script:SetupNativeCompilerDiagnostic += ' ' + ($diagnostics.ToArray() -join ' | ') }
            throw 'A native setup compiler failed.'
        }
    } finally { $process.Dispose() }
}

try {
    if ([Environment]::OSVersion.Platform -ne [PlatformID]::Win32NT) { throw 'Final Setup packaging requires Windows and Visual Studio C++ build tools.' }
    foreach ($part in $Version.Split('.')) { if ([int]$part -gt 65535) { throw 'Invalid version.' } }
    if ($Version -eq '0.0.0') { throw 'A fresh-install version must be newer than 0.0.0.' }
    $DevelopmentPrivateKey = Assert-SetupPath -Path $DevelopmentPrivateKey -OutsideRepository
    $PublicKeyPath = Assert-SetupPath -Path $PublicKeyPath -OutsideRepository
    $OutputDirectory = Assert-SetupPath -Path $OutputDirectory
    if (-not (Test-Path -LiteralPath $DevelopmentPrivateKey -PathType Leaf) -or
        -not (Test-Path -LiteralPath $PublicKeyPath -PathType Leaf)) { throw 'Separate development signing and public trust files are required.' }
    if (Test-Path -LiteralPath $OutputDirectory) { throw 'The output directory must be new.' }
    $trustLength = (Get-Item -LiteralPath $PublicKeyPath).Length
    if ($trustLength -le 0 -or $trustLength -gt 16384) { throw 'The public trust file is invalid.' }
    $trustBytes = [IO.File]::ReadAllBytes($PublicKeyPath)
    $trustText = [Text.Encoding]::UTF8.GetString($trustBytes)
    if ($trustBytes.Length -le 0 -or $trustBytes.Length -gt 16384 -or $trustText.Contains('PRIVATE KEY') -or
        -not $trustText.Contains('-----BEGIN PUBLIC KEY-----')) { throw 'Only a bounded public trust root can be embedded.' }
    $worker = Join-Path $repo 'installer/setup/SetupWorker.ps1'
    if (-not (Test-Path -LiteralPath $worker -PathType Leaf)) { throw 'The trusted setup worker is missing.' }

    New-Item -ItemType Directory -Path $OutputDirectory | Out-Null
    $work = $OutputDirectory + '.work-' + [Guid]::NewGuid().ToString('N')
    New-Item -ItemType Directory -Path $work | Out-Null
    $payloadSource = Join-Path $work 'payload'
    New-Item -ItemType Directory -Path $payloadSource | Out-Null
    $bundle = Join-Path $payloadSource 'bundle'
    & (Join-Path $PSScriptRoot 'publish-pilot-windows.ps1') -Version $Version -DevelopmentPrivateKey $DevelopmentPrivateKey -KeyId $KeyId -Channel $Channel -OutputDirectory $bundle -DirectoryHosts

    # Pin an immutable copy of the explicitly supplied public root, outside the
    # bundle. Existing public verification checks that it matches both signatures.
    $trust = Join-Path $work 'trust.pem'
    [IO.File]::WriteAllBytes($trust, $trustBytes)
    foreach ($component in @('core', 'agent')) {
        Invoke-SetupDotnet -Arguments @('run', '--project', (Join-Path $repo 'updater/SentinelAI.Updater.csproj'), '--configuration', 'Release', '--', 'verify',
            '--manifest', (Join-Path $bundle ($component + '.manifest.json')), '--package', (Join-Path $bundle ($component + '.zip')),
            '--public-key', $trust, '--key-id', $KeyId, '--environment', 'development', '--channel', $Channel,
            '--artifact-id', ('sentinelai-' + $component + '-win-x64'), '--installed-version', '0.0.0')
    }

    $desktop = Join-Path $payloadSource 'desktop'
    Invoke-SetupDotnet -Arguments @('publish', (Join-Path $repo 'desktop/SentinelAI.Desktop/SentinelAI.Desktop.csproj'), '--configuration', 'Release',
        '--runtime', 'win-x64', '--self-contained', 'true', '-p:PublishSingleFile=false', '-p:PublishTrimmed=false',
        '-p:DebugType=none', '-p:DebugSymbols=false', ('-p:Version=' + $Version), ('-p:AssemblyVersion=' + $Version + '.0'), '--output', $desktop)
    foreach ($required in @('SentinelAI.Desktop.exe', 'SentinelAI.Desktop.dll', 'SentinelAI.Desktop.deps.json', 'SentinelAI.Desktop.runtimeconfig.json', 'PresentationFramework.dll', 'coreclr.dll')) {
        if (-not (Test-Path -LiteralPath (Join-Path $desktop $required) -PathType Leaf)) { throw 'A Desktop runtime file is missing.' }
    }
    $setupSource = Join-Path $payloadSource 'setup'
    New-Item -ItemType Directory -Path $setupSource | Out-Null
    Copy-Item -LiteralPath $worker -Destination (Join-Path $setupSource 'SetupWorker.ps1')
    Add-Type -AssemblyName System.IO.Compression.FileSystem
    $payload = Join-Path $work 'payload.zip'
    New-SetupPayload -Source $payloadSource -Destination $payload
    $input = [IO.File]::OpenRead($payload)
    $sha256 = [Security.Cryptography.SHA256]::Create()
    try { $hash = [BitConverter]::ToString($sha256.ComputeHash($input)).Replace('-', '').ToLowerInvariant() }
    finally { $sha256.Dispose(); $input.Dispose() }
    $metadata = Join-Path $work 'metadata.json'
    $document = [ordered]@{ version = $Version; keyId = $KeyId; channel = $Channel; environment = 'development'; payloadSha256 = $hash; payloadLength = (Get-Item -LiteralPath $payload).Length }
    [IO.File]::WriteAllText($metadata, ($document | ConvertTo-Json -Compress), (New-Object Text.UTF8Encoding($false)))

    # Do not use .NET's single-file extraction cache for an elevated bootstrap.
    # The native wrapper authenticates and privately extracts every runtime file
    # before loading CLR/WPF; no shared or user-writable runtime cache is trusted.
    $host = Join-Path $work 'host'
    Invoke-SetupDotnet -Arguments @('publish', (Join-Path $repo 'installer/SentinelAI.Setup/SentinelAI.Setup.csproj'), '--configuration', 'Release',
        '--runtime', 'win-x64', '--self-contained', 'true', '-p:PublishSingleFile=false', '-p:PublishTrimmed=false',
        '-p:DebugType=none', '-p:DebugSymbols=false',
        ('-p:Version=' + $Version), ('-p:AssemblyVersion=' + $Version + '.0'), ('-p:SetupPayloadPath=' + $payload),
        ('-p:SetupTrustPath=' + $trust), ('-p:SetupMetadataPath=' + $metadata), '--output', $host)
    foreach ($required in @('SentinelAI.Setup.Host.exe', 'SentinelAI.Setup.Host.dll', 'SentinelAI.Setup.Host.deps.json', 'SentinelAI.Setup.Host.runtimeconfig.json', 'PresentationFramework.dll', 'coreclr.dll')) {
        if (-not (Test-Path -LiteralPath (Join-Path $host $required) -PathType Leaf)) { throw 'A private Setup runtime file is missing.' }
    }
    $nativeSource = Join-Path $repo 'installer/setup-native/Bootstrap.cpp'
    $nativeManifest = Join-Path $repo 'installer/setup-native/setup-native.manifest'
    $nativeHeader = Join-Path $work 'NativePayload.h'
    $nativeResource = Join-Path $work 'NativePayload.rc'
    $compiledResource = Join-Path $work 'NativePayload.res'
    New-SetupNativeResources -Source $host -HeaderPath $nativeHeader -ResourcePath $nativeResource -ManifestPath $nativeManifest
    $nativeEnvironment = Get-SetupNativeEnvironment
    Invoke-SetupNativeTool -Tool 'rc' -Arguments @('/nologo', '/fo', $compiledResource, $nativeResource) -NativeEnvironment $nativeEnvironment -WorkingDirectory $work
    Invoke-SetupNativeTool -Tool 'cl' -Arguments @('/nologo', '/std:c++17', '/utf-8', '/W4', '/WX', '/O2', '/MT', '/DUNICODE', '/D_UNICODE', '/EHsc', '/guard:cf',
        ('/I' + $work), ('/Fo' + (Join-Path $work 'Bootstrap.obj')), ('/Fe' + (Join-Path $OutputDirectory 'SentinelAI-Setup.exe')), $nativeSource, $compiledResource,
        '/link', '/SUBSYSTEM:WINDOWS', '/MACHINE:X64', '/DYNAMICBASE', '/NXCOMPAT', '/HIGHENTROPYVA', '/MANIFEST:NO', '/INCREMENTAL:NO',
        'bcrypt.lib', 'advapi32.lib', 'shell32.lib', 'ole32.lib', 'user32.lib') -NativeEnvironment $nativeEnvironment -WorkingDirectory $work
    $outputItems = @(Get-ChildItem -LiteralPath $OutputDirectory -Force)
    if ($outputItems.Count -ne 1 -or $outputItems[0].PSIsContainer -or $outputItems[0].Name -cne 'SentinelAI-Setup.exe' -or $outputItems[0].Length -le 0) {
        throw 'The setup publish must produce exactly SentinelAI-Setup.exe.'
    }
    $complete = $true
    Write-Output ('Development single-EXE setup created: ' + (Join-Path $OutputDirectory 'SentinelAI-Setup.exe'))
} catch {
    $failure = 'Setup packaging failed. Check the version, separate development keys outside source, SDK/package access and fresh output path. Partial artifacts are not a release.'
    if ($script:SetupNativeCompilerDiagnostic) { $failure += ' ' + $script:SetupNativeCompilerDiagnostic }
    throw $failure
} finally {
    if ($null -ne $work -and (Test-Path -LiteralPath $work)) { Remove-Item -LiteralPath $work -Recurse -Force }
    if (-not $complete) { Write-Warning 'Packaging did not finish; inspect and remove only the failed output directory before retrying.' }
}
