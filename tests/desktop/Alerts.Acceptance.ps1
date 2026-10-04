# TASK-020 extension of the fresh installer-owned native authentication fixture.
# Dot-source from Authentication.Acceptance.ps1 -VerifyAlerts. All credentials
# remain in fixture memory; status changes operate only through public Core APIs.
#requires -Version 5.1

function Invoke-NativeAlertsAcceptance {
    Add-Type -AssemblyName System.Net.Http
    $handler = [Net.Http.HttpClientHandler]::new()
    $handler.UseProxy = $false; $handler.UseCookies = $false; $handler.AllowAutoRedirect = $false
    $handler.Credentials = $null
    $api = [Net.Http.HttpClient]::new($handler)
    $api.BaseAddress = [Uri]'http://127.0.0.1:5000/'
    $api.Timeout = [TimeSpan]::FromSeconds(10)
    $api.MaxResponseContentBufferSize = 512 * 1024
    function Invoke-AlertFixtureApi([string]$Method, [string]$Path, [object]$Body = $null, [string]$Scheme = '', [string]$Credential = '') {
        $request = [Net.Http.HttpRequestMessage]::new([Net.Http.HttpMethod]::new($Method), $Path)
        if ($Scheme) { $request.Headers.Authorization = [Net.Http.Headers.AuthenticationHeaderValue]::new($Scheme, $Credential) }
        if ($null -ne $Body) { $request.Content = [Net.Http.StringContent]::new(($Body | ConvertTo-Json -Depth 8 -Compress), [Text.Encoding]::UTF8, 'application/json') }
        try {
            $response = $api.SendAsync($request).GetAwaiter().GetResult()
            try {
                Assert-AuthenticationAcceptance $response.IsSuccessStatusCode ('A synthetic native-alert API operation failed at ' + $Path + ' with status ' + [int]$response.StatusCode + '.')
                if ($response.StatusCode -eq [Net.HttpStatusCode]::NoContent) { return $null }
                try { return ($response.Content.ReadAsStringAsync().GetAwaiter().GetResult() | ConvertFrom-Json) }
                catch { throw 'A synthetic native-alert API response was invalid.' }
            } finally { $response.Dispose() }
        } finally { $request.Dispose() }
    }
    function Select-AlertOption([string]$Id, [string]$Name) {
        Wait-AuthenticationAcceptance { Test-AuthenticationControl $Id } 'A native alert filter or status choice was unavailable.'
        $control = Find-AuthenticationControl $Id
        $expand = [System.Windows.Automation.ExpandCollapsePattern]$control.GetCurrentPattern([System.Windows.Automation.ExpandCollapsePattern]::Pattern)
        $expand.Expand()
        $nameCondition = [System.Windows.Automation.PropertyCondition]::new([System.Windows.Automation.AutomationElement]::NameProperty, $Name)
        $itemCondition = [System.Windows.Automation.PropertyCondition]::new([System.Windows.Automation.AutomationElement]::ControlTypeProperty, [System.Windows.Automation.ControlType]::ListItem)
        $condition = [System.Windows.Automation.AndCondition]::new($nameCondition, $itemCondition)
        $option = $control.FindFirst([System.Windows.Automation.TreeScope]::Descendants, $condition)
        Assert-AuthenticationAcceptance ($null -ne $option) 'A required native alert choice was missing.'
        ([System.Windows.Automation.SelectionItemPattern]$option.GetCurrentPattern([System.Windows.Automation.SelectionItemPattern]::Pattern)).Select()
        $expand.Collapse()
    }
    function Get-AlertGridRows {
        $grid = Find-AuthenticationControl 'AlertsGrid'
        if ($null -eq $grid) { return @() }
        $condition = [System.Windows.Automation.PropertyCondition]::new([System.Windows.Automation.AutomationElement]::ControlTypeProperty, [System.Windows.Automation.ControlType]::DataItem)
        return @($grid.FindAll([System.Windows.Automation.TreeScope]::Children, $condition))
    }
    function Test-AlertFact([string]$Label, [string]$Value) {
        $control = Find-AuthenticationControl ('AlertFact_' + $Label)
        return $null -ne $control -and $control.Current.Name -ceq $Value
    }
    function Test-AlertText([string]$Id, [string]$Value) {
        $control = Find-AuthenticationControl $Id
        return $null -ne $control -and $control.Current.Name -ceq $Value
    }
    function Select-OnlyNativeAlert {
        Wait-AuthenticationAcceptance { @(Get-AlertGridRows).Count -eq 1 } 'Native alert filters did not select exactly one tracked incident.'
        $row = @(Get-AlertGridRows)[0]
        ([System.Windows.Automation.SelectionItemPattern]$row.GetCurrentPattern([System.Windows.Automation.SelectionItemPattern]::Pattern)).Select()
        Invoke-AuthenticationControl 'OpenAlertButton'
        Wait-AuthenticationAcceptance { Test-AuthenticationControl 'AlertDetailTitle' } 'The published Desktop did not open native alert detail.'
    }
    function Save-NativeAlertStatus([string]$Status) {
        Select-AlertOption 'AlertProposedStatus' $Status
        Invoke-AuthenticationControl 'SaveAlertStatusButton'
        Wait-AuthenticationAcceptance { Test-AlertFact 'Status' $Status } 'The native administrator status change did not complete.'
    }
    try {
        $held = Get-OwnedCoreProcess
        try { Assert-AuthenticationAcceptance ($held.Id -eq $script:coreProcess.Id) 'Core changed before the native alert fixture.' }
        finally { $held.Dispose() }
        $login = Invoke-AlertFixtureApi 'POST' 'api/auth/login' @{ username = $script:username; password = $script:password }
        $bearer = [string]$login.accessToken
        $enrollmentToken = Invoke-AlertFixtureApi 'POST' 'api/admin/enrollment-tokens' @{} 'Bearer' $bearer
        $enrollment = Invoke-AlertFixtureApi 'POST' 'api/agent/enroll' @{ installationId = [Guid]::NewGuid(); enrollmentToken = $enrollmentToken.token }
        $endpointId = [Guid]$enrollment.endpointId
        $agent = $endpointId.ToString('D') + '.' + [string]$enrollment.agentCredential
        $hostname = 'Native-Alert-' + [Guid]::NewGuid().ToString('N').Substring(0, 8)
        $observation = [DateTimeOffset]::UtcNow.AddSeconds(-30)
        $inventory = @{
            endpointId = $endpointId; collectedUtc = $observation.ToString('O'); agentVersion = '1.0.0-native-alert-test'
            hostname = $hostname; osName = 'Windows 11'; osVersion = '10.0.26200.0'; architecture = 'X64'
            cpu = @{ model = 'Synthetic alert test CPU'; logicalProcessorCount = 4 }
            installedRamBytes = [long]4294967296; disks = @()
            securityPosture = @{ domainFirewallEnabled = $false; privateFirewallEnabled = $true; publicFirewallEnabled = $null }
        }
        $null = Invoke-AlertFixtureApi 'POST' 'api/agent/inventory' $inventory 'SentinelAgent' $agent
        $page = Invoke-AlertFixtureApi 'GET' ('api/admin/alerts?endpointId=' + $endpointId.ToString('D')) $null 'Bearer' $bearer
        Assert-AuthenticationAcceptance ($page.total -eq 1 -and $page.alerts.Count -eq 1) 'Core did not create the isolated native tracked alert.'
        $alertId = [Guid]$page.alerts[0].alertId
        $detailPath = 'api/admin/alerts/' + $alertId.ToString('D')
        $initial = Invoke-AlertFixtureApi 'GET' $detailPath $null 'Bearer' $bearer

        $navigation = Find-AuthenticationControl 'NavigationList'
        $name = [System.Windows.Automation.PropertyCondition]::new([System.Windows.Automation.AutomationElement]::NameProperty, 'Alerts')
        $item = $navigation.FindFirst([System.Windows.Automation.TreeScope]::Descendants, $name)
        ([System.Windows.Automation.SelectionItemPattern]$item.GetCurrentPattern([System.Windows.Automation.SelectionItemPattern]::Pattern)).Select()
        Wait-AuthenticationAcceptance { Test-AuthenticationControl 'AlertEndpointFilter' } 'The published Desktop did not open native Alerts.'
        Invoke-AuthenticationControl 'RefreshAlertsButton'
        Wait-AuthenticationAcceptance { Test-AuthenticationControl 'ApplyAlertFiltersButton' } 'Native Alerts did not finish loading endpoint choices.'
        Select-AlertOption 'AlertEndpointFilter' ($hostname + ' (' + $endpointId.ToString('D') + ')')
        Select-AlertOption 'AlertSeverityFilter' 'High'
        Select-AlertOption 'AlertStatusFilter' 'Open'
        Invoke-AuthenticationControl 'ApplyAlertFiltersButton'
        Wait-AuthenticationAcceptance { @(Get-AlertGridRows).Count -eq 1 } 'Endpoint/severity/status filtering did not return the isolated incident.'
        Select-AlertOption 'AlertSeverityFilter' 'Medium'
        Invoke-AuthenticationControl 'ApplyAlertFiltersButton'
        Wait-AuthenticationAcceptance { $status = Find-AuthenticationControl 'AlertListStatus'; $null -ne $status -and $status.Current.Name -match '(?i)(no .*alert|no .*match)' } 'Native severity filtering did not show an explicit empty result.'
        Select-AlertOption 'AlertSeverityFilter' 'High'
        Invoke-AuthenticationControl 'ApplyAlertFiltersButton'
        Select-OnlyNativeAlert
        Assert-AuthenticationAcceptance (Test-AlertFact 'Rule ID' 'SA-FW-001') 'Native alert detail lost the deterministic rule ID.'
        Assert-AuthenticationAcceptance (Test-AlertText 'AlertReason' ([string]$initial.reason)) 'Native alert detail lost the recorded reason.'
        Assert-AuthenticationAcceptance (Test-AlertText 'AlertRecommendation' ([string]$initial.recommendedAction)) 'Native alert detail lost its recommended action.'
        Assert-AuthenticationAcceptance (Test-AlertText 'AlertEvidenceField' 'securityPosture.domainFirewallEnabled') 'Native typed evidence lost its field.'
        Assert-AuthenticationAcceptance (Test-AlertText 'AlertEvidenceType' 'Boolean') 'Native typed evidence lost its Boolean type.'
        Assert-AuthenticationAcceptance (Test-AlertText 'AlertEvidenceValue' 'False') 'Native typed evidence coerced the recorded Boolean value.'
        $firstTime = $observation.UtcDateTime.ToString('yyyy-MM-dd HH:mm:ss') + ' UTC'
        Assert-AuthenticationAcceptance (Test-AlertFact 'First observed' $firstTime) 'Native detail lost the first observation time.'
        Assert-AuthenticationAcceptance (Test-AlertFact 'Last observed' $firstTime) 'Native detail lost the latest observation time.'

        Save-NativeAlertStatus 'Investigating'
        $investigating = Invoke-AlertFixtureApi 'GET' $detailPath $null 'Bearer' $bearer
        Assert-AuthenticationAcceptance ($investigating.status -ceq 'investigating' -and $investigating.version -gt $initial.version -and $investigating.statusHistoryCount -eq 2) 'Native status/history was not persisted by Core.'
        Assert-AuthenticationAcceptance (Test-AlertText 'AlertHistoryChangedBy' 'system') 'Native incident history did not show its initial system entry.'
        $history = Find-AuthenticationControl 'AlertHistoryGrid'
        $actorCondition = [System.Windows.Automation.PropertyCondition]::new([System.Windows.Automation.AutomationElement]::NameProperty, $script:username)
        Assert-AuthenticationAcceptance ($null -ne $history -and $null -ne $history.FindFirst([System.Windows.Automation.TreeScope]::Descendants, $actorCondition)) 'Native incident history did not show the administrator decision.'
        # Another authenticated client changes Core while Desktop holds its reviewed version.
        $accepted = Invoke-AlertFixtureApi 'PUT' ($detailPath + '/status') @{ status = 'accepted'; expectedVersion = $investigating.version } 'Bearer' $bearer
        Select-AlertOption 'AlertProposedStatus' 'Resolved'
        Invoke-AuthenticationControl 'SaveAlertStatusButton'
        Wait-AuthenticationAcceptance { Test-AlertFact 'Status' 'Accepted' } 'A stale Desktop status write did not reload the current tracked incident.'
        Wait-AuthenticationAcceptance { $feedback = Find-AuthenticationControl 'AlertStatusMessage'; $null -ne $feedback -and $feedback.Current.Name -match '(?i)not saved' } 'Native conflict feedback did not explain that the stale decision was rejected.'
        $afterConflict = Invoke-AlertFixtureApi 'GET' $detailPath $null 'Bearer' $bearer
        Assert-AuthenticationAcceptance ($afterConflict.status -ceq 'accepted' -and $afterConflict.version -eq $accepted.version -and $afterConflict.statusHistoryCount -eq 3) 'A stale native write overwrote or retried the concurrent decision.'

        $inventory.collectedUtc = $observation.AddSeconds(1).ToString('O')
        $null = Invoke-AlertFixtureApi 'POST' 'api/agent/inventory' $inventory 'SentinelAgent' $agent
        Invoke-AuthenticationControl 'RefreshAlertDetailButton'
        Wait-AuthenticationAcceptance { Test-AlertFact 'Version' ([string]($accepted.version + 1)) } 'Native detail did not refresh a newer positive observation.'
        Assert-AuthenticationAcceptance (Test-AlertFact 'Status' 'Accepted') 'A positive observation discarded the Accepted operator decision.'
        Save-NativeAlertStatus 'Resolved'
        $resolved = Invoke-AlertFixtureApi 'GET' $detailPath $null 'Bearer' $bearer
        Assert-AuthenticationAcceptance ($resolved.status -ceq 'resolved' -and $resolved.statusHistoryCount -eq 4) 'Native resolution was not persisted with history.'

        $inventory.collectedUtc = $observation.AddSeconds(2).ToString('O')
        $inventory.securityPosture = @{ domainFirewallEnabled = $true; privateFirewallEnabled = $true; publicFirewallEnabled = $true }
        $null = Invoke-AlertFixtureApi 'POST' 'api/agent/inventory' $inventory 'SentinelAgent' $agent
        $inventory.collectedUtc = $observation.AddSeconds(3).ToString('O')
        $inventory.securityPosture = @{ domainFirewallEnabled = $null; privateFirewallEnabled = $null; publicFirewallEnabled = $null }
        $null = Invoke-AlertFixtureApi 'POST' 'api/agent/inventory' $inventory 'SentinelAgent' $agent
        $afterUnknown = Invoke-AlertFixtureApi 'GET' $detailPath $null 'Bearer' $bearer
        Assert-AuthenticationAcceptance ($afterUnknown.status -ceq 'resolved' -and $afterUnknown.version -eq $resolved.version) 'Normal/Unknown telemetry changed the operator lifecycle decision.'
        $inventory.collectedUtc = $observation.AddSeconds(4).ToString('O')
        $inventory.securityPosture = @{ domainFirewallEnabled = $false; privateFirewallEnabled = $true; publicFirewallEnabled = $null }
        $null = Invoke-AlertFixtureApi 'POST' 'api/agent/inventory' $inventory 'SentinelAgent' $agent
        Invoke-AuthenticationControl 'RefreshAlertDetailButton'
        Wait-AuthenticationAcceptance { Test-AlertFact 'Status' 'Open' } 'A newer positive observation did not reopen the resolved native incident.'
        $reopened = Invoke-AlertFixtureApi 'GET' $detailPath $null 'Bearer' $bearer
        Assert-AuthenticationAcceptance ($reopened.statusHistoryCount -eq 5 -and $reopened.statusHistory[-1].changedBy -ceq 'system' -and $reopened.firstObservedUtc -ceq $initial.firstObservedUtc) 'Automatic reopening lost first observation or lifecycle history.'
        Assert-AuthenticationAcceptance (Test-AlertFact 'Last observed' ($observation.AddSeconds(4).UtcDateTime.ToString('yyyy-MM-dd HH:mm:ss') + ' UTC')) 'Native reopened detail lost the latest positive observation.'
        Invoke-AuthenticationControl 'BackToAlertsButton'
        Select-AlertOption 'AlertStatusFilter' 'Resolved'
        Invoke-AuthenticationControl 'ApplyAlertFiltersButton'
        Wait-AuthenticationAcceptance { $status = Find-AuthenticationControl 'AlertListStatus'; $null -ne $status -and $status.Current.Name -match '(?i)(no .*alert|no .*match)' } 'Native filtered-empty alert state was unavailable.'
        Select-AlertOption 'AlertStatusFilter' 'Open'
        Invoke-AuthenticationControl 'ApplyAlertFiltersButton'
        Wait-AuthenticationAcceptance { @(Get-AlertGridRows).Count -eq 1 } 'Native status filtering did not restore the reopened incident.'
        # A new Desktop session must read the persisted workflow, not retained
        # view-model data. Core's existing integration suite also restarts SQLite.
        Invoke-AuthenticationControl 'SignOutButton'
        Wait-AuthenticationAcceptance { Test-AuthenticationControl 'SignInButton' $false } 'Native alert session did not sign out.'
        Assert-SignedOut
        Set-AuthenticationCredential $script:username $script:password
        Invoke-AuthenticationControl 'SignInButton'
        Wait-AuthenticationAcceptance { Test-AuthenticationControl 'SignOutButton' } 'Native alert session could not sign in again.'
        Wait-AuthenticationAcceptance { Test-AuthenticationControl 'ApplyAlertFiltersButton' } 'Native alert workspace did not reload after sign-in.'
        Select-AlertOption 'AlertEndpointFilter' ($hostname + ' (' + $endpointId.ToString('D') + ')')
        Select-AlertOption 'AlertSeverityFilter' 'High'
        Select-AlertOption 'AlertStatusFilter' 'Open'
        Invoke-AuthenticationControl 'ApplyAlertFiltersButton'
        Select-OnlyNativeAlert
        Assert-AuthenticationAcceptance (Test-AlertFact 'Version' ([string]$reopened.version)) 'A new native session lost the persisted incident version.'
        Assert-AuthenticationAcceptance (Test-AlertFact 'First observed' $firstTime) 'A new native session lost the first observation.'
        $history = Find-AuthenticationControl 'AlertHistoryGrid'
        Assert-AuthenticationAcceptance ($null -ne $history -and $null -ne $history.FindFirst([System.Windows.Automation.TreeScope]::Descendants, $actorCondition)) 'A new native session lost persisted operator history.'
    } finally {
        $bearer = $null; $agent = $null; $login = $null; $enrollmentToken = $null; $enrollment = $null
        $api.Dispose()
    }
}
