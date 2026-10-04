# Native TASK-019 extension of the fresh, installer-owned authentication fixture.
# Dot-source only from Authentication.Acceptance.ps1 -VerifyDevices after sign-in.
# Synthetic enrollment/Agent credentials stay in memory and never enter arguments,
# files, output or the production Desktop. All UI reads use the actual Core API.
#requires -Version 5.1

function Invoke-NativeDevicesAcceptance {
    Add-Type -AssemblyName System.Net.Http
    $handler = [Net.Http.HttpClientHandler]::new()
    $handler.UseProxy = $false; $handler.UseCookies = $false; $handler.AllowAutoRedirect = $false
    $handler.Credentials = $null
    $api = [Net.Http.HttpClient]::new($handler)
    $api.BaseAddress = [Uri]'http://127.0.0.1:5000/'
    $api.Timeout = [TimeSpan]::FromSeconds(10)
    $api.MaxResponseContentBufferSize = 512 * 1024
    function Invoke-DeviceFixtureApi([string]$Path, [object]$Body, [string]$Scheme = '', [string]$Credential = '') {
        $request = [Net.Http.HttpRequestMessage]::new([Net.Http.HttpMethod]::Post, $Path)
        if ($Scheme) { $request.Headers.Authorization = [Net.Http.Headers.AuthenticationHeaderValue]::new($Scheme, $Credential) }
        $request.Content = [Net.Http.StringContent]::new(($Body | ConvertTo-Json -Depth 8 -Compress), [Text.Encoding]::UTF8, 'application/json')
        try {
            $response = $api.SendAsync($request).GetAwaiter().GetResult()
            try {
                Assert-AuthenticationAcceptance $response.IsSuccessStatusCode ('A synthetic native-device fixture API operation failed at ' + $Path + ' with status ' + [int]$response.StatusCode + '.')
                if ($response.StatusCode -eq [Net.HttpStatusCode]::NoContent) { return $null }
                return ($response.Content.ReadAsStringAsync().GetAwaiter().GetResult() | ConvertFrom-Json)
            } finally { $response.Dispose() }
        } finally { $request.Dispose() }
    }
    function Set-DeviceSearch([string]$Text) {
        $search = Find-AuthenticationControl 'DeviceSearchInput'
        ([System.Windows.Automation.ValuePattern]$search.GetCurrentPattern([System.Windows.Automation.ValuePattern]::Pattern)).SetValue($Text)
    }
    function Get-DeviceGridRows {
        $grid = Find-AuthenticationControl 'DevicesGrid'
        if ($null -eq $grid) { return @() }
        $condition = [System.Windows.Automation.PropertyCondition]::new([System.Windows.Automation.AutomationElement]::ControlTypeProperty, [System.Windows.Automation.ControlType]::DataItem)
        return @($grid.FindAll([System.Windows.Automation.TreeScope]::Children, $condition))
    }
    function Select-DeviceRow {
        $rows = @(Get-DeviceGridRows)
        Assert-AuthenticationAcceptance ($rows.Count -eq 1) 'Filtered native device search did not select one endpoint.'
        ([System.Windows.Automation.SelectionItemPattern]$rows[0].GetCurrentPattern([System.Windows.Automation.SelectionItemPattern]::Pattern)).Select()
        Invoke-AuthenticationControl 'OpenDeviceButton'
    }
    function Test-DeviceFact([string]$Text) {
        $condition = [System.Windows.Automation.PropertyCondition]::new([System.Windows.Automation.AutomationElement]::NameProperty, $Text)
        $element = $script:root.FindFirst([System.Windows.Automation.TreeScope]::Descendants, $condition)
        # Long detail panels scroll; values must exist as native text even when
        # below the viewport. The visible detail heading separately proves entry.
        return $null -ne $element
    }
    function Test-DeviceField([string]$Label, [string]$Value) {
        $element = Find-AuthenticationControl ('DeviceFact_' + $Label)
        return $null -ne $element -and $element.Current.Name -ceq $Value
    }
    try {
        $navigation = Find-AuthenticationControl 'NavigationList'
        $name = [System.Windows.Automation.PropertyCondition]::new([System.Windows.Automation.AutomationElement]::NameProperty, 'Devices')
        $item = $navigation.FindFirst([System.Windows.Automation.TreeScope]::Descendants, $name)
        ([System.Windows.Automation.SelectionItemPattern]$item.GetCurrentPattern([System.Windows.Automation.SelectionItemPattern]::Pattern)).Select()
        Wait-AuthenticationAcceptance { $status = Find-AuthenticationControl 'DeviceListStatus'; $null -ne $status -and $status.Current.Name -match '(?i)(no .*enrolled|no devices)' } 'The real empty Core fleet did not show a native no-data state.'
        # The outer fixture holds/verifies this exact installer-owned SCM process.
        $held = Get-OwnedCoreProcess
        try { Assert-AuthenticationAcceptance ($held.Id -eq $script:coreProcess.Id) 'Core changed before synthetic device enrollment.' }
        finally { $held.Dispose() }
        $login = Invoke-DeviceFixtureApi 'api/auth/login' @{ username = $script:username; password = $script:password }
        $bearer = [string]$login.accessToken
        $installation = [Guid]::NewGuid()
        $token = Invoke-DeviceFixtureApi 'api/admin/enrollment-tokens' @{} 'Bearer' $bearer
        $endpoint = Invoke-DeviceFixtureApi 'api/agent/enroll' @{ installationId = $installation; enrollmentToken = $token.token }
        $endpointId = [Guid]$endpoint.endpointId
        $agent = $endpointId.ToString('D') + '.' + [string]$endpoint.agentCredential
        $null = Invoke-DeviceFixtureApi 'api/agent/heartbeat' @{ installationId = $installation } 'SentinelAgent' $agent
        $hostname = 'Native-Device-' + [Guid]::NewGuid().ToString('N').Substring(0, 8)
        $inventoryTime = [DateTimeOffset]::UtcNow.AddSeconds(-1).ToString('O')
        $inventory = @{
            endpointId = $endpointId; collectedUtc = $inventoryTime; agentVersion = '1.0.0-native-test'
            hostname = $hostname; osName = 'Windows 11'; osVersion = '10.0.26200.0'; osDisplayVersion = '26H2'; osInstallationType = 'Client'
            architecture = 'X64'; cpu = @{ model = 'Synthetic native test CPU'; logicalProcessorCount = 8 }
            installedRamBytes = [long]8589934592
            disks = @(@{ name = 'C:'; totalBytes = [long]107374182400; availableBytes = [long]53687091200 })
            securityPosture = @{ domainFirewallEnabled = $true; privateFirewallEnabled = $false; publicFirewallEnabled = $null }
        }
        $null = Invoke-DeviceFixtureApi 'api/agent/inventory' $inventory 'SentinelAgent' $agent
        # A second enrolled endpoint has no heartbeat or inventory at all.
        $unknownToken = Invoke-DeviceFixtureApi 'api/admin/enrollment-tokens' @{} 'Bearer' $bearer
        $unknown = Invoke-DeviceFixtureApi 'api/agent/enroll' @{ installationId = [Guid]::NewGuid(); enrollmentToken = $unknownToken.token }
        $unknownId = [Guid]$unknown.endpointId
        Invoke-AuthenticationControl 'RefreshDevicesButton'
        Wait-AuthenticationAcceptance { Test-AuthenticationControl 'DevicesGrid' } 'The published Desktop did not open native Devices.'
        Wait-AuthenticationAcceptance { @(Get-DeviceGridRows).Count -eq 2 } 'Native Devices did not load the real enrolled endpoints from Core.'
        Set-DeviceSearch $hostname
        Wait-AuthenticationAcceptance { @(Get-DeviceGridRows).Count -eq 1 } 'Native hostname filtering did not isolate its endpoint.'
        Select-DeviceRow
        Wait-AuthenticationAcceptance { $heading = Find-AuthenticationControl 'DeviceDetailHostname'; $null -ne $heading -and -not $heading.Current.IsOffscreen -and $heading.Current.Name -ceq $hostname } 'Native endpoint detail did not show its hostname.'
        Wait-AuthenticationAcceptance { Test-DeviceFact '26H2 10.0.26200.0' } 'Native endpoint detail lost OS release/build information.'
        Assert-AuthenticationAcceptance (Test-DeviceField 'Heartbeat connectivity' 'Healthy') 'Desktop changed Core heartbeat health semantics.'
        Assert-AuthenticationAcceptance (Test-DeviceField 'Configured firewall summary' 'Disabled on one or more profiles') 'Configured firewall posture was conflated with healthy connectivity.'
        Assert-AuthenticationAcceptance (Test-DeviceField 'Configured Private firewall' 'Disabled') 'Native detail changed a disabled firewall observation.'
        Assert-AuthenticationAcceptance (Test-DeviceField 'Configured Public firewall' 'Unknown') 'Native detail inferred an unknown firewall observation.'
        $expectedInventory = [DateTimeOffset]::Parse($inventoryTime).UtcDateTime.ToString('yyyy-MM-dd HH:mm:ss') + ' UTC'
        Assert-AuthenticationAcceptance (Test-DeviceField 'Last inventory' $expectedInventory) 'Native detail omitted the authoritative inventory timestamp.'
        Assert-AuthenticationAcceptance (Test-DeviceFact 'Synthetic native test CPU') 'Native detail omitted existing Core hardware information.'
        Assert-AuthenticationAcceptance (Test-DeviceFact $endpointId.ToString('D')) 'Native detail opened the wrong endpoint.'
        Invoke-AuthenticationControl 'BackToDevicesButton'
        Wait-AuthenticationAcceptance { Test-AuthenticationControl 'DeviceSearchInput' } 'Native detail did not return to its device list.'
        Set-DeviceSearch $unknownId.ToString('D')
        Wait-AuthenticationAcceptance { @(Get-DeviceGridRows).Count -eq 1 } 'Native endpoint identifier filtering failed.'
        Select-DeviceRow
        Wait-AuthenticationAcceptance { Test-DeviceFact $unknownId.ToString('D') } 'Native detail did not open an inventory-free endpoint.'
        Assert-AuthenticationAcceptance (Test-DeviceField 'Heartbeat connectivity' 'Unknown') 'Missing heartbeat/inventory was inferred as healthy or protected.'
        Assert-AuthenticationAcceptance (Test-DeviceField 'Configured firewall summary' 'Unknown') 'Missing firewall inventory was inferred as enabled.'
        $status = Find-AuthenticationControl 'DeviceInventoryStatus'
        Assert-AuthenticationAcceptance ($null -ne $status -and $status.Current.Name -match '(?i)(not received|not reported|no inventory|unknown)') 'Missing inventory was not explicit in native detail.'
        Invoke-AuthenticationControl 'BackToDevicesButton'
        Wait-AuthenticationAcceptance { Test-AuthenticationControl 'DeviceSearchInput' } 'Inventory-free native detail did not return to the list.'
        Set-DeviceSearch ('no-native-match-' + [Guid]::NewGuid().ToString('N'))
        Wait-AuthenticationAcceptance { $status = Find-AuthenticationControl 'DeviceListStatus'; $null -ne $status -and $status.Current.Name -match '(?i)(no .*match|no devices match)' } 'Native Devices did not show an explicit filtered-empty state.'
        Set-DeviceSearch ''
        Wait-AuthenticationAcceptance { @(Get-DeviceGridRows).Count -eq 2 } 'Clearing native search did not restore the fleet.'
        # Clear all enrollment/bearer references; production Desktop never received them.
        $bearer = $null; $agent = $null; $login = $null; $token = $null; $endpoint = $null; $unknownToken = $null
    } finally { $api.Dispose() }
}
