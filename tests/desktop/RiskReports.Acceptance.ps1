# TASK-021 extension of the fresh, signed installer-owned authentication fixture.
# Dot-source from Authentication.Acceptance.ps1 -VerifyRiskReports. Synthetic
# credentials and Core responses stay in memory; diagnostics use fixed messages.
#requires -Version 5.1

function Invoke-NativeRiskReportsAcceptance {
    # Earlier authentication/device/alert fixtures approach the five-per-minute
    # limit. Restart only the held installer-owned service, then make one explicit
    # native sign-in and one fixture API sign-in. Never retry a password.
    $previousCore = $script:coreProcess
    Invoke-OwnedServiceAction Restart
    Assert-AuthenticationAcceptance ($previousCore.WaitForExit(10000) -and $previousCore.ExitCode -eq 0) 'The owned Core did not exit gracefully before Risk/Reports acceptance.'
    $previousCore.Dispose(); $script:coreProcess = Get-OwnedCoreProcess
    Wait-AuthenticationAcceptance { Test-AuthenticationControl 'SignInButton' } 'Core restart did not clear the prior native session.' 45
    Assert-SignedOut
    Set-AuthenticationCredential $script:username $script:password
    Invoke-AuthenticationControl 'SignInButton'
    Wait-AuthenticationAcceptance { Test-AuthenticationControl 'SignOutButton' } 'The native Risk/Reports fixture could not explicitly sign in.'

    Add-Type -AssemblyName System.Net.Http
    $handler = [Net.Http.HttpClientHandler]::new()
    $handler.UseProxy = $false; $handler.UseCookies = $false; $handler.AllowAutoRedirect = $false; $handler.Credentials = $null
    $api = [Net.Http.HttpClient]::new($handler)
    $api.BaseAddress = [Uri]'http://127.0.0.1:5000/'
    $api.Timeout = [TimeSpan]::FromSeconds(10)
    $api.MaxResponseContentBufferSize = 8 * 1024 * 1024
    $bearer = $null; $agent = $null; $login = $null; $enrollmentToken = $null; $enrollment = $null
    $reportBytes = $null; $saved = $null; $html = $null; $apiHtml = $null; $visibleHtml = $null; $visibleApiHtml = $null

    function Invoke-RiskReportFixtureApi([string]$Method, [string]$Path, [object]$Body = $null, [string]$Scheme = '', [string]$Credential = '', [switch]$Html) {
        $held = Get-OwnedCoreProcess
        try { Assert-AuthenticationAcceptance ($held.Id -eq $script:coreProcess.Id) 'Core changed during the Risk/Reports fixture.' }
        finally { $held.Dispose() }
        $request = [Net.Http.HttpRequestMessage]::new([Net.Http.HttpMethod]::new($Method), $Path)
        if ($Scheme) { $request.Headers.Authorization = [Net.Http.Headers.AuthenticationHeaderValue]::new($Scheme, $Credential) }
        if ($null -ne $Body) { $request.Content = [Net.Http.StringContent]::new(($Body | ConvertTo-Json -Depth 8 -Compress), [Text.Encoding]::UTF8, 'application/json') }
        try {
            $response = $api.SendAsync($request).GetAwaiter().GetResult()
            try {
                Assert-AuthenticationAcceptance $response.IsSuccessStatusCode ('A synthetic Risk/Reports API request failed with status ' + [int]$response.StatusCode + '.')
                if ($response.StatusCode -eq [Net.HttpStatusCode]::NoContent) { return $null }
                if ($Html) {
                    Assert-AuthenticationAcceptance ($response.Content.Headers.ContentType.MediaType -ceq 'text/html') 'Core did not return its HTML report attachment.'
                    Assert-AuthenticationAcceptance ($response.Headers.Contains('Content-Security-Policy') -and
                        @($response.Headers.GetValues('X-Content-Type-Options')) -contains 'nosniff') 'Core report privacy headers were missing.'
                    return [pscustomobject]@{ Bytes = $response.Content.ReadAsByteArrayAsync().GetAwaiter().GetResult() }
                }
                try { return ($response.Content.ReadAsStringAsync().GetAwaiter().GetResult() | ConvertFrom-Json) }
                catch { throw 'A synthetic Risk/Reports JSON response was invalid.' }
            } finally { $response.Dispose() }
        } finally { $request.Headers.Authorization = $null; $request.Dispose() }
    }
    function Select-RiskReportNavigation([string]$Name) {
        $navigation = Find-AuthenticationControl 'NavigationList'
        $condition = [System.Windows.Automation.PropertyCondition]::new([System.Windows.Automation.AutomationElement]::NameProperty, $Name)
        $item = $navigation.FindFirst([System.Windows.Automation.TreeScope]::Descendants, $condition)
        Assert-AuthenticationAcceptance ($null -ne $item) 'Native Risk/Reports navigation was unavailable.'
        ([System.Windows.Automation.SelectionItemPattern]$item.GetCurrentPattern([System.Windows.Automation.SelectionItemPattern]::Pattern)).Select()
    }
    function Get-RiskRows {
        $grid = Find-AuthenticationControl 'RiskGrid'
        if ($null -eq $grid) { return @() }
        $condition = [System.Windows.Automation.PropertyCondition]::new([System.Windows.Automation.AutomationElement]::ControlTypeProperty, [System.Windows.Automation.ControlType]::DataItem)
        return @($grid.FindAll([System.Windows.Automation.TreeScope]::Children, $condition))
    }
    function Risk-Number([object]$Value) { return [Convert]::ToDecimal($Value, [Globalization.CultureInfo]::InvariantCulture).ToString([Globalization.CultureInfo]::InvariantCulture) }
    function Risk-Time([object]$Value) { return [DateTimeOffset]::Parse([string]$Value, [Globalization.CultureInfo]::InvariantCulture).UtcDateTime.ToString('yyyy-MM-dd HH:mm:ss') + ' UTC' }
    function Assert-RiskFact([string]$Prefix, [string]$Label, [string]$Value, [object]$Scope = $null) {
        $condition = [System.Windows.Automation.PropertyCondition]::new([System.Windows.Automation.AutomationElement]::AutomationIdProperty, $Prefix + $Label)
        if ($null -eq $Scope) { $Scope = $script:root }
        $element = $Scope.FindFirst([System.Windows.Automation.TreeScope]::Descendants, $condition)
        Assert-AuthenticationAcceptance ($null -ne $element -and $element.Current.Name -ceq $Value) 'A native risk factor differed from the public Core value.'
    }
    function Set-NativeReportDate([string]$Id, [DateTime]$Date) {
        $control = Find-AuthenticationControl $Id
        Assert-AuthenticationAcceptance ($null -ne $control) 'A native report date picker was missing.'
        $editCondition = [System.Windows.Automation.PropertyCondition]::new([System.Windows.Automation.AutomationElement]::ControlTypeProperty, [System.Windows.Automation.ControlType]::Edit)
        $edit = $control.FindFirst([System.Windows.Automation.TreeScope]::Descendants, $editCondition)
        if ($null -ne $edit -and $edit.Current.IsKeyboardFocusable) { $edit.SetFocus() }
        ([System.Windows.Automation.ValuePattern]$control.GetCurrentPattern([System.Windows.Automation.ValuePattern]::Pattern)).SetValue($Date.ToString('d', [Globalization.CultureInfo]::CurrentCulture))
        (Find-AuthenticationControl 'GenerateReportButton').SetFocus()
    }
    function Find-NativeReportSaveDialog {
        $process = [System.Windows.Automation.PropertyCondition]::new([System.Windows.Automation.AutomationElement]::ProcessIdProperty, $script:desktop.Id)
        $title = [System.Windows.Automation.PropertyCondition]::new([System.Windows.Automation.AutomationElement]::NameProperty, 'Save security report')
        $window = [System.Windows.Automation.PropertyCondition]::new([System.Windows.Automation.AutomationElement]::ControlTypeProperty, [System.Windows.Automation.ControlType]::Window)
        $condition = [System.Windows.Automation.AndCondition]::new([System.Windows.Automation.Condition[]]@($process, $title, $window))
        # Owned common dialogs can appear beneath their owner in the automation
        # tree rather than as direct desktop children. Search only the held app's
        # descendants, with its exact PID/title/window type, before the existing
        # top-level fallback. Never scan other applications' descendant trees.
        $dialog = $script:root.FindFirst([System.Windows.Automation.TreeScope]::Descendants, $condition)
        if ($null -ne $dialog) { return $dialog }
        return [System.Windows.Automation.AutomationElement]::RootElement.FindFirst([System.Windows.Automation.TreeScope]::Children,
            $condition)
    }
    function Get-NativeReportSaveCategory {
        try {
            $script:desktop.Refresh()
            if ($script:desktop.HasExited) { return 'desktop_exited' }
            $status = Find-AuthenticationControl 'ReportSaveStatus'
            if ($null -ne $status) {
                switch ($status.Current.Name) {
                    'Choose a destination for the generated HTML report.' { return 'dialog_waiting' }
                    'The report was not saved.' { return 'save_failed' }
                    'Save cancelled. The generated report remains available.' { return 'save_cancelled' }
                }
            }
            $save = Find-AuthenticationControl 'SaveReportButton'
            if ($null -eq $save -or $save.Current.IsOffscreen) { return 'save_workspace_unavailable' }
            if ($save.Current.IsEnabled) { return 'save_action_idle' }
            return 'save_action_pending'
        } catch { return 'diagnostic_unavailable' }
    }
    function Get-WritableReportFileName([object]$Element) {
        if ($null -eq $Element) { return $null }
        try {
            $pattern = $null
            if ($Element.Current.IsEnabled -and $Element.TryGetCurrentPattern([System.Windows.Automation.ValuePattern]::Pattern, [ref]$pattern) -and
                -not ([System.Windows.Automation.ValuePattern]$pattern).Current.IsReadOnly) {
                return [pscustomobject]@{ Element = $Element; ValuePattern = [System.Windows.Automation.ValuePattern]$pattern }
            }
        } catch [System.Windows.Automation.ElementNotAvailableException] { }
        return $null
    }
    function Find-NativeReportFileName([object]$Dialog) {
        if ($null -eq $Dialog) { return $null }
        $edit = [System.Windows.Automation.PropertyCondition]::new([System.Windows.Automation.AutomationElement]::ControlTypeProperty, [System.Windows.Automation.ControlType]::Edit)
        $combo = [System.Windows.Automation.PropertyCondition]::new([System.Windows.Automation.AutomationElement]::ControlTypeProperty, [System.Windows.Automation.ControlType]::ComboBox)
        $editableType = [System.Windows.Automation.OrCondition]::new($edit, $combo)
        # Modern dialogs can expose ValuePattern directly on the filename host
        # or its ComboBox rather than on a descendant Edit. 1152 is the classic
        # common-dialog edt1 filename ID. Every search stays under a known
        # filename ID, never an arbitrary address/search edit in the dialog.
        foreach ($id in @('FileNameControlHost', '1001', '1148', '1152')) {
            $identity = [System.Windows.Automation.PropertyCondition]::new([System.Windows.Automation.AutomationElement]::AutomationIdProperty, $id)
            $hosts = $Dialog.FindAll([System.Windows.Automation.TreeScope]::Descendants, $identity)
            if ($hosts.Count -gt 16) { throw 'The native report filename host count exceeded its bound.' }
            foreach ($hostControl in $hosts) {
                $writable = Get-WritableReportFileName $hostControl
                if ($null -ne $writable) { return $writable }
                $children = $hostControl.FindAll([System.Windows.Automation.TreeScope]::Descendants, $editableType)
                if ($children.Count -gt 32) { throw 'The native report filename child count exceeded its bound.' }
                foreach ($child in $children) {
                    $writable = Get-WritableReportFileName $child
                    if ($null -ne $writable) { return $writable }
                }
            }
        }
        return $null
    }
    function Get-NativeReportFileNameCategory([object]$Dialog) {
        try {
            $known = 0; $enabled = 0; $focusable = 0; $supported = 0; $readOnly = 0
            foreach ($id in @('FileNameControlHost', '1001', '1148', '1152')) {
                $identity = [System.Windows.Automation.PropertyCondition]::new([System.Windows.Automation.AutomationElement]::AutomationIdProperty, $id)
                $hosts = $Dialog.FindAll([System.Windows.Automation.TreeScope]::Descendants, $identity)
                $limit = [Math]::Min($hosts.Count, 16)
                $known += $limit
                for ($i = 0; $i -lt $limit; $i++) {
                    $hostControl = $hosts[$i]
                    if ($hostControl.Current.IsEnabled) { $enabled++ }
                    if ($hostControl.Current.IsKeyboardFocusable) { $focusable++ }
                    $pattern = $null
                    if ($hostControl.TryGetCurrentPattern([System.Windows.Automation.ValuePattern]::Pattern, [ref]$pattern)) {
                        $supported++
                        if (([System.Windows.Automation.ValuePattern]$pattern).Current.IsReadOnly) { $readOnly++ }
                    }
                }
            }
            return 'known_filename_hosts_' + $known + '_enabled_' + $enabled + '_focusable_' + $focusable + '_value_supported_' + $supported + '_readonly_' + $readOnly
        } catch { return 'filename_metadata_unavailable' }
    }
    function Find-NativeReportKeyboardFileName([object]$Dialog) {
        if ($null -eq $Dialog) { return $null }
        $fallback = $null
        foreach ($id in @('FileNameControlHost', '1001', '1148', '1152')) {
            $identity = [System.Windows.Automation.PropertyCondition]::new([System.Windows.Automation.AutomationElement]::AutomationIdProperty, $id)
            $hosts = $Dialog.FindAll([System.Windows.Automation.TreeScope]::Descendants, $identity)
            if ($hosts.Count -gt 16) { throw 'The native report filename host count exceeded its bound.' }
            foreach ($hostControl in $hosts) {
                if ($null -eq $fallback) { $fallback = $hostControl }
                if (-not $hostControl.Current.IsEnabled) { continue }
                foreach ($type in @([System.Windows.Automation.ControlType]::Edit, [System.Windows.Automation.ControlType]::ComboBox)) {
                    if ($hostControl.Current.ControlType -eq $type -and $hostControl.Current.IsKeyboardFocusable) { return $hostControl }
                    $condition = [System.Windows.Automation.PropertyCondition]::new([System.Windows.Automation.AutomationElement]::ControlTypeProperty, $type)
                    $children = $hostControl.FindAll([System.Windows.Automation.TreeScope]::Descendants, $condition)
                    if ($children.Count -gt 32) { throw 'The native report filename child count exceeded its bound.' }
                    foreach ($child in $children) {
                        if ($child.Current.IsEnabled -and $child.Current.IsKeyboardFocusable) { return $child }
                    }
                }
            }
        }
        # A known host can still identify the filename subtree even when its
        # provider exposes no focusable child; the standard Alt+N path is checked
        # against actual focus under that known subtree before text is entered.
        return $fallback
    }
    function Get-NativeReportFocusCategory([object]$Dialog) {
        $focus = [System.Windows.Automation.AutomationElement]::FocusedElement
        if ($null -eq $focus -or $focus.Current.ProcessId -ne $script:desktop.Id) { return 'unavailable' }
        $known = New-Object 'System.Collections.Generic.HashSet[string]'
        foreach ($id in @('FileNameControlHost', '1001', '1148', '1152')) {
            $identity = [System.Windows.Automation.PropertyCondition]::new([System.Windows.Automation.AutomationElement]::AutomationIdProperty, $id)
            $hosts = $Dialog.FindAll([System.Windows.Automation.TreeScope]::Descendants, $identity)
            if ($hosts.Count -gt 16) { return 'unavailable' }
            foreach ($hostControl in $hosts) { [void]$known.Add((@($hostControl.GetRuntimeId()) -join ',')) }
        }
        $dialogId = @($Dialog.GetRuntimeId()) -join ','
        $filename = $false
        $node = $focus
        for ($depth = 0; $depth -lt 32 -and $null -ne $node; $depth++) {
            $runtimeId = @($node.GetRuntimeId()) -join ','
            if ($known.Contains($runtimeId)) { $filename = $true }
            if ($runtimeId -ceq $dialogId) {
                if ($filename) { return 'filename' }
                return 'other_owned_dialog'
            }
            $node = [System.Windows.Automation.TreeWalker]::RawViewWalker.GetParent($node)
        }
        return 'unavailable'
    }
    function Test-NativeReportFileNameFocus([object]$Dialog) {
        return (Get-NativeReportFocusCategory $Dialog) -ceq 'filename'
    }
    function Enter-NativeReportFileName([object]$Dialog, [string]$Destination) {
        $handle = [IntPtr]$Dialog.Current.NativeWindowHandle
        Assert-AuthenticationAcceptance ($handle -ne [IntPtr]::Zero -and $Dialog.Current.ProcessId -eq $script:desktop.Id) 'The held report dialog had no owned native window.'
        [void][SentinelAIDesktopAuthenticationAcceptance.Native]::SetForegroundWindow($handle)
        Wait-AuthenticationAcceptance { [SentinelAIDesktopAuthenticationAcceptance.Native]::GetForegroundWindow() -eq $handle } 'The held report dialog did not own foreground input.'
        $candidate = Find-NativeReportKeyboardFileName $Dialog
        Assert-AuthenticationAcceptance ($null -ne $candidate) 'The held report dialog had no known filename host.'
        if ($candidate.Current.IsKeyboardFocusable) {
            try { $candidate.SetFocus() } catch [InvalidOperationException] { }
        }
        if (-not (Test-NativeReportFileNameFocus $Dialog)) { [SentinelAIDesktopAuthenticationAcceptance.Native]::FocusFileName($handle) }
        Wait-AuthenticationAcceptance { [SentinelAIDesktopAuthenticationAcceptance.Native]::GetForegroundWindow() -eq $handle -and
            (Test-NativeReportFileNameFocus $Dialog) } 'Native report keyboard focus was outside the known filename input.'
        [SentinelAIDesktopAuthenticationAcceptance.Native]::EnterFileName($Destination, $handle)
        # The queued Tab must leave the known filename subtree before UIA may
        # invoke Save, so native text input cannot be overtaken by the invocation.
        Wait-AuthenticationAcceptance { [SentinelAIDesktopAuthenticationAcceptance.Native]::GetForegroundWindow() -eq $handle -and
            (Get-NativeReportFocusCategory $Dialog) -ceq 'other_owned_dialog' } 'Native report filename input did not finish its owned focus transfer.'
    }
    function Find-NativeReportSaveButton([object]$Dialog, [bool]$RequireEnabled = $true) {
        $identity = [System.Windows.Automation.PropertyCondition]::new([System.Windows.Automation.AutomationElement]::AutomationIdProperty, '1')
        $button = [System.Windows.Automation.PropertyCondition]::new([System.Windows.Automation.AutomationElement]::ControlTypeProperty, [System.Windows.Automation.ControlType]::Button)
        $control = $Dialog.FindFirst([System.Windows.Automation.TreeScope]::Descendants, [System.Windows.Automation.AndCondition]::new($identity, $button))
        if ($null -ne $control -and (-not $RequireEnabled -or $control.Current.IsEnabled)) { return $control }
        return $null
    }
    function Save-NativeSecurityReport([string]$Destination) {
        Assert-AuthenticationAcceptance (-not (Test-Path -LiteralPath $Destination)) 'Native report acceptance must not overwrite an existing destination.'
        Invoke-AuthenticationControl 'SaveReportButton'
        try { Wait-AuthenticationAcceptance { $null -ne (Find-NativeReportSaveDialog) } 'The actual native security-report save dialog did not open.' }
        catch { throw ('The actual native security-report save dialog did not open. Save result: ' + (Get-NativeReportSaveCategory) + '.') }
        $dialog = Find-NativeReportSaveDialog
        try { Wait-AuthenticationAcceptance { $null -ne (Find-NativeReportFileName $dialog) -or
            $null -ne (Find-NativeReportKeyboardFileName $dialog) } 'The native report dialog filename control was unavailable.' }
        catch { throw ('The native report dialog filename control was unavailable. Filename result: ' + (Get-NativeReportFileNameCategory $dialog) + '.') }
        $fileName = Find-NativeReportFileName $dialog
        if ($null -ne $fileName) { $fileName.ValuePattern.SetValue($Destination) }
        else { Enter-NativeReportFileName $dialog $Destination }
        $saveButton = Find-NativeReportSaveButton $dialog $false
        $invoke = $null
        if ($null -ne $saveButton -and $saveButton.Current.IsEnabled -and $saveButton.TryGetCurrentPattern([System.Windows.Automation.InvokePattern]::Pattern, [ref]$invoke)) {
            ([System.Windows.Automation.InvokePattern]$invoke).Invoke()
        } else {
            # Some common-dialog providers omit the Save button entirely. Use
            # its actual keyboard access key once in the held, owned dialog;
            # it cannot enable a disabled action or bypass destination checks.
            $handle = [IntPtr]$dialog.Current.NativeWindowHandle
            Assert-AuthenticationAcceptance ($handle -ne [IntPtr]::Zero -and $dialog.Current.ProcessId -eq $script:desktop.Id) 'Native report Save lost its held process/window ownership.'
            Assert-AuthenticationAcceptance ([SentinelAIDesktopAuthenticationAcceptance.Native]::GetForegroundWindow() -eq $handle -and
                (Get-NativeReportFocusCategory $dialog) -cin @('filename', 'other_owned_dialog')) 'Native report Save did not own the held dialog foreground/focus.'
            [SentinelAIDesktopAuthenticationAcceptance.Native]::SaveFileName($handle)
        }
        try { Wait-AuthenticationAcceptance { $null -eq (Find-NativeReportSaveDialog) -and (Test-Path -LiteralPath $Destination -PathType Leaf) -and
            (Test-AuthenticationControl 'SaveReportButton') } 'The native report save did not finish writing its selected file.' }
        catch { throw ('The native report save did not finish writing its selected file. Save result: ' + (Get-NativeReportSaveCategory) + '.') }
    }
    function Assert-NoNativeReport {
        $save = Find-AuthenticationControl 'SaveReportButton'
        $period = Find-AuthenticationControl 'ReportPeriod'
        $size = Find-AuthenticationControl 'ReportSize'
        Assert-AuthenticationAcceptance ($null -ne $save -and -not $save.Current.IsEnabled -and
            ($null -eq $period -or [string]::IsNullOrEmpty($period.Current.Name)) -and ($null -eq $size -or [string]::IsNullOrEmpty($size.Current.Name))) 'Native Reports retained a prior generated document.'
    }

    try {
        $login = Invoke-RiskReportFixtureApi 'POST' 'api/auth/login' @{ username = $script:username; password = $script:password }
        $bearer = [string]$login.accessToken
        $enrollmentToken = Invoke-RiskReportFixtureApi 'POST' 'api/admin/enrollment-tokens' @{} 'Bearer' $bearer
        $installation = [Guid]::NewGuid()
        $enrollment = Invoke-RiskReportFixtureApi 'POST' 'api/agent/enroll' @{ installationId = $installation; enrollmentToken = $enrollmentToken.token }
        $endpointId = [Guid]$enrollment.endpointId
        $agent = $endpointId.ToString('D') + '.' + [string]$enrollment.agentCredential
        $hostname = 'Native-Risk-' + [Guid]::NewGuid().ToString('N').Substring(0, 8)
        $privateHardware = 'Synthetic-private-report-hardware-' + [Guid]::NewGuid().ToString('N')
        $observation = [DateTimeOffset]::UtcNow.AddSeconds(-1)
        $inventory = @{
            endpointId = $endpointId; collectedUtc = $observation.ToString('O'); agentVersion = '1.0.0-native-risk-test'
            hostname = $hostname; osName = 'Windows 11'; osVersion = '10.0.26200.0'; architecture = 'X64'
            cpu = @{ model = $privateHardware; logicalProcessorCount = 8 }; installedRamBytes = [long]8589934592; disks = @()
            securityPosture = @{ domainFirewallEnabled = $false; privateFirewallEnabled = $true; publicFirewallEnabled = $true; configuration = @{ uacEnabled = $false } }
        }
        $null = Invoke-RiskReportFixtureApi 'POST' 'api/agent/inventory' $inventory 'SentinelAgent' $agent
        $page = Invoke-RiskReportFixtureApi 'GET' 'api/admin/risk?offset=0&limit=50' $null 'Bearer' $bearer
        Select-RiskReportNavigation 'Risk'
        Wait-AuthenticationAcceptance { Test-AuthenticationControl 'RiskGrid' } 'The published Desktop did not open native Risk.'
        Invoke-AuthenticationControl 'RefreshRiskButton'
        Wait-AuthenticationAcceptance { @(Get-RiskRows).Count -eq $page.endpoints.Count } 'Native ranked Risk did not show the real Core endpoint page.'
        $organization = Find-AuthenticationControl 'RiskOrganizationScore'
        Assert-AuthenticationAcceptance ($null -ne $organization -and $organization.Current.Name -ceq ('Score ' + $page.organization.score + ' / 100')) 'Native organization risk differed from Core.'
        $rows = @(Get-RiskRows)
        for ($i = 0; $i -lt $rows.Count; $i++) { Assert-AuthenticationAcceptance ($rows[$i].Current.Name -ceq $page.endpoints[$i].endpointName) 'Native risk endpoint order differed from the Core ranking.' }
        $selected = @($rows | Where-Object { $_.Current.Name -ceq $hostname })
        Assert-AuthenticationAcceptance ($selected.Count -eq 1) 'Native Risk did not contain exactly the isolated endpoint.'
        $path = 'api/admin/devices/' + $endpointId.ToString('D') + '/risk'
        $before = Invoke-RiskReportFixtureApi 'GET' $path $null 'Bearer' $bearer
        ([System.Windows.Automation.SelectionItemPattern]$selected[0].GetCurrentPattern([System.Windows.Automation.SelectionItemPattern]::Pattern)).Select()
        Invoke-AuthenticationControl 'OpenEndpointRiskButton'
        Wait-AuthenticationAcceptance { $name = Find-AuthenticationControl 'RiskDetailName'; $null -ne $name -and $name.Current.Name -ceq $hostname } 'Native Risk did not open the exact endpoint detail.'
        $after = Invoke-RiskReportFixtureApi 'GET' $path $null 'Bearer' $bearer
        foreach ($pair in @(@('Endpoint score', (Risk-Number $before.risk.score)), @('Raw score', (Risk-Number $before.risk.rawScore)),
            @('Saturated', ([bool]$before.risk.saturated).ToString()), @('Asset criticality', $before.risk.context.assetCriticality),
            @('Asset criticality source', $before.risk.context.assetCriticalitySource), @('Asset criticality multiplier', (Risk-Number $before.risk.assetCriticalityMultiplier)),
            @('Declared exposure', $before.risk.context.exposure), @('Exposure source', $before.risk.context.exposureSource),
            @('Exposure multiplier', (Risk-Number $before.risk.exposureMultiplier)), @('Correlation base bonus', (Risk-Number $before.risk.correlationBaseBonus)),
            @('Correlation bonus', (Risk-Number $before.risk.correlationBonus)))) { Assert-RiskFact 'RiskFact_' $pair[0] ([string]$pair[1]) }
        foreach ($pair in @(@('Inventory state', $before.coverage.inventoryState), @('Signal coverage', $before.coverage.signalCoverage),
            @('Known rule signals', (Risk-Number $before.coverage.knownRuleSignals)), @('Total rule signals', (Risk-Number $before.coverage.totalRuleSignals)),
            @('Inventory collected', (Risk-Time $before.inventoryCollectedUtc)), @('Inventory freshness (hours)', (Risk-Number $before.inventoryFreshForHours)))) {
            Assert-RiskFact 'RiskCoverage_' $pair[0] ([string]$pair[1])
        }
        Assert-AuthenticationAcceptance ($before.alerts.Count -eq 2 -and $before.risk.contributions.Count -eq 2) 'The isolated risk fixture did not contain two deterministic findings.'
        foreach ($contribution in $before.risk.contributions) {
            $scope = Find-AuthenticationControl ('RiskContribution_' + $contribution.alertId)
            Assert-AuthenticationAcceptance ($null -ne $scope) 'A native recorded risk contribution was missing.'
            ([System.Windows.Automation.ExpandCollapsePattern]$scope.GetCurrentPattern([System.Windows.Automation.ExpandCollapsePattern]::Pattern)).Expand()
            Wait-AuthenticationAcceptance {
                $id = [System.Windows.Automation.PropertyCondition]::new([System.Windows.Automation.AutomationElement]::AutomationIdProperty, 'RiskFactor_Severity points')
                return $null -ne $scope.FindFirst([System.Windows.Automation.TreeScope]::Descendants, $id)
            } 'Native risk contribution expansion did not expose its factors.'
            foreach ($pair in @(@('Severity', $contribution.severity), @('Status', $contribution.status), @('Age band', $contribution.ageBand),
                @('Severity points', (Risk-Number $contribution.severityPoints)), @('Confidence weight', (Risk-Number $contribution.detectionConfidence)),
                @('Confidence source', $contribution.confidenceSource), @('Asset multiplier', (Risk-Number $contribution.assetCriticalityMultiplier)),
                @('Exposure multiplier', (Risk-Number $contribution.exposureMultiplier)), @('Age multiplier', (Risk-Number $contribution.ageMultiplier)),
                @('Remaining risk multiplier', (Risk-Number $contribution.remainingRiskMultiplier)), @('Points before status effect', (Risk-Number $contribution.pointsBeforeMitigation)),
                @('Status reduction', (Risk-Number $contribution.mitigationReduction)), @('Contribution', (Risk-Number $contribution.contribution)),
                @('Correlation group', $contribution.correlationGroup), @('Latest snapshot confirmed', ([bool]$contribution.latestSnapshotConfirmed).ToString()),
                @('Correlation eligible', ([bool]$contribution.correlationEligible).ToString()), @('Future timestamp clamped', ([bool]$contribution.futureTimestampClamped).ToString()))) {
                Assert-RiskFact 'RiskFactor_' $pair[0] ([string]$pair[1]) $scope
            }
            $ageId = [System.Windows.Automation.PropertyCondition]::new([System.Windows.Automation.AutomationElement]::AutomationIdProperty, 'RiskFactor_Age (days)')
            $age = $scope.FindFirst([System.Windows.Automation.TreeScope]::Descendants, $ageId)
            $displayedAge = [decimal]::Parse($age.Current.Name, [Globalization.CultureInfo]::InvariantCulture)
            $later = @($after.risk.contributions | Where-Object { $_.alertId -ceq $contribution.alertId })[0]
            Assert-AuthenticationAcceptance ($displayedAge -ge [decimal]$contribution.ageDays -and $displayedAge -le [decimal]$later.ageDays) 'Native observation age was outside the bracketing real Core evaluations.'
        }

        $license = Invoke-RiskReportFixtureApi 'GET' 'api/admin/license' $null 'Bearer' $bearer
        Assert-AuthenticationAcceptance ($license.mode -ceq 'SAFE_MODE') 'The native report fixture did not exercise existing Safe Mode.'
        Select-RiskReportNavigation 'Reports'
        Wait-AuthenticationAcceptance { Test-AuthenticationControl 'GenerateReportButton' } 'The published Desktop did not open native Reports.'
        Assert-NoNativeReport
        $date = $observation.UtcDateTime.Date
        $dateText = $date.ToString('yyyy-MM-dd', [Globalization.CultureInfo]::InvariantCulture)
        Set-NativeReportDate 'ReportToDate' $date
        Set-NativeReportDate 'ReportFromDate' $date
        Invoke-AuthenticationControl 'GenerateReportButton'
        Wait-AuthenticationAcceptance { Test-AuthenticationControl 'SaveReportButton' } 'Explicit native report generation did not produce a savable document.'
        $period = Find-AuthenticationControl 'ReportPeriod'
        Assert-AuthenticationAcceptance ($null -ne $period -and $period.Current.Name -ceq ($dateText + ' through ' + $dateText + ' (inclusive UTC dates)')) 'Native report generation used a different selected UTC period.'
        $fileName = Find-AuthenticationControl 'ReportFileName'
        Assert-AuthenticationAcceptance ($null -ne $fileName -and $fileName.Current.Name -ceq ('SentinelAI-security-report-' + $dateText + '-' + $dateText + '.html')) 'Native report metadata lost the Core attachment name.'
        $directory = Join-Path $script:workDirectory 'RiskReports'
        New-PilotDirectoryWithAcl -Path $directory -Kind Container
        Assert-PilotTrustedPath -Path $directory
        $first = Join-Path $directory 'native-security-report-first.html'
        $second = Join-Path $directory 'native-security-report-second.html'
        Save-NativeSecurityReport $first
        Save-NativeSecurityReport $second
        Assert-AuthenticationAcceptance ((Get-FileHash -LiteralPath $first -Algorithm SHA256).Hash -ceq (Get-FileHash -LiteralPath $second -Algorithm SHA256).Hash) 'Two native saves changed the exact retained Core HTML bytes.'
        $saved = [IO.File]::ReadAllBytes($first)
        $size = Find-AuthenticationControl 'ReportSize'
        Assert-AuthenticationAcceptance ($null -ne $size -and $size.Current.Name -ceq ($saved.Length.ToString('N0', [Globalization.CultureInfo]::InvariantCulture) + ' bytes')) 'Native export byte length differed from its Core document metadata.'
        $utf8 = [Text.UTF8Encoding]::new($false, $true)
        $html = $utf8.GetString($saved)
        Assert-AuthenticationAcceptance ($html.StartsWith('<!doctype html>', [StringComparison]::OrdinalIgnoreCase) -and $html.Contains('<html') -and $html.EndsWith('</html>')) 'Native export was not the complete standalone Core HTML attachment.'
        Assert-AuthenticationAcceptance ($html.Contains('Reporting period (inclusive UTC dates)</dt><dd>' + $dateText + ' through ' + $dateText) -and
            $html.Contains($hostname) -and $html.Contains($endpointId.ToString('D')) -and $html.Contains('raw ' + (Risk-Number $before.risk.rawScore))) 'Native report content lost the selected period, real endpoint or authoritative risk points.'
        $report = Invoke-RiskReportFixtureApi 'GET' ('api/admin/reports/security?from=' + $dateText + '&to=' + $dateText) $null 'Bearer' $bearer -Html
        $reportBytes = $report.Bytes; $apiHtml = $utf8.GetString($reportBytes)
        Assert-AuthenticationAcceptance ($apiHtml.Contains($hostname) -and $apiHtml.Contains('raw ' + (Risk-Number $before.risk.rawScore)) -and
            $apiHtml.Contains('Reporting period (inclusive UTC dates)</dt><dd>' + $dateText + ' through ' + $dateText)) 'Real Core report generation disagreed with the native selected-period/risk fixture.'
        # Separate generations contain different evaluation timestamps (and may
        # legitimately cross another endpoint's heartbeat freshness boundary).
        # Exact copying is established by the two native saves and portable byte
        # tests; this real fixture compares selected-period/risk/privacy semantics.
        $visibleHtml = [Net.WebUtility]::HtmlDecode($html); $visibleApiHtml = [Net.WebUtility]::HtmlDecode($apiHtml)
        foreach ($secret in @($script:password, $script:username, $bearer, $agent, [string]$enrollmentToken.token, $privateHardware)) {
            Assert-AuthenticationAcceptance (-not $visibleHtml.Contains($secret) -and -not $visibleApiHtml.Contains($secret)) 'A native/Core report disclosed a fixture credential, actor or raw hardware field.'
        }
        Assert-AuthenticationAcceptance (-not $html.Contains('<script') -and -not $html.Contains('https://') -and -not $html.Contains('http://')) 'Native report introduced executable or external content.'
        [Array]::Clear($saved, 0, $saved.Length); $saved = $null; $html = $null; $apiHtml = $null; $visibleHtml = $null; $visibleApiHtml = $null
        Select-RiskReportNavigation 'Risk'
        Wait-AuthenticationAcceptance { Test-AuthenticationControl 'RiskGrid' } 'Native Reports did not allow leaving the report workspace.'
        Select-RiskReportNavigation 'Reports'
        Wait-AuthenticationAcceptance { Test-AuthenticationControl 'GenerateReportButton' } 'Native Reports did not reopen.'
        Assert-NoNativeReport
        Invoke-AuthenticationControl 'GenerateReportButton'
        Wait-AuthenticationAcceptance { Test-AuthenticationControl 'SaveReportButton' } 'Native Reports could not generate explicitly after clearing.'
        Invoke-AuthenticationControl 'SignOutButton'
        Wait-AuthenticationAcceptance { Test-AuthenticationControl 'SignInButton' $false } 'Native Reports did not sign out.'
        Assert-SignedOut
        foreach ($id in @('RiskGrid', 'RiskDetailName', 'SaveReportButton', 'ReportPeriod', 'ReportSize')) {
            $control = Find-AuthenticationControl $id
            Assert-AuthenticationAcceptance ($null -eq $control -or $control.Current.IsOffscreen) 'Protected risk/report content remained visible after sign-out.'
        }
    } finally {
        if ($null -ne $reportBytes) { [Array]::Clear($reportBytes, 0, $reportBytes.Length) }
        if ($null -ne $saved) { [Array]::Clear($saved, 0, $saved.Length) }
        $bearer = $null; $agent = $null; $login = $null; $enrollmentToken = $null; $enrollment = $null; $html = $null; $apiHtml = $null; $visibleHtml = $null; $visibleApiHtml = $null
        $api.Dispose()
    }
}
