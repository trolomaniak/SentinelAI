# Real published Desktop and installer-owned Core; no external issuer/provider.
# Dot-source after the isolated Risk/Reports fixture has signed out.
#requires -Version 5.1
function Invoke-NativeAiLicenseSettingsAcceptance {
    Assert-SignedOut
    Set-AuthenticationCredential $script:username $script:password
    Invoke-AuthenticationControl 'SignInButton'
    Wait-AuthenticationAcceptance { Test-AuthenticationControl 'SignOutButton' } 'Native Settings could not explicitly sign in.'
    Add-Type -AssemblyName System.Net.Http
    $handler = [Net.Http.HttpClientHandler]::new()
    $handler.UseProxy = $false; $handler.UseCookies = $false; $handler.AllowAutoRedirect = $false; $handler.Credentials = $null
    $api = [Net.Http.HttpClient]::new($handler)
    $api.BaseAddress = [Uri]'http://127.0.0.1:5000/'
    $api.Timeout = [TimeSpan]::FromSeconds(10); $api.MaxResponseContentBufferSize = 65536
    $bearer = $null; $login = $null; $license = $null
    function Invoke-SettingsApi([string]$Path, [object]$Body = $null) {
        $held = Get-OwnedCoreProcess
        try { Assert-AuthenticationAcceptance ($held.Id -eq $script:coreProcess.Id) 'Core changed during Settings acceptance.' }
        finally { $held.Dispose() }
        $method = if ($null -eq $Body) { [Net.Http.HttpMethod]::Get } else { [Net.Http.HttpMethod]::Post }
        $request = [Net.Http.HttpRequestMessage]::new($method, $Path)
        if ($bearer) { $request.Headers.Authorization = [Net.Http.Headers.AuthenticationHeaderValue]::new('Bearer', $bearer) }
        if ($null -ne $Body) { $request.Content = [Net.Http.StringContent]::new(($Body | ConvertTo-Json -Compress), [Text.Encoding]::UTF8, 'application/json') }
        try {
            $response = $api.SendAsync($request).GetAwaiter().GetResult()
            try {
                Assert-AuthenticationAcceptance $response.IsSuccessStatusCode 'A bounded synthetic Settings API request failed.'
                try { return ($response.Content.ReadAsStringAsync().GetAwaiter().GetResult() | ConvertFrom-Json) }
                catch { throw 'A bounded Settings API projection was invalid.' }
            } finally { $response.Dispose() }
        } finally { $request.Headers.Authorization = $null; $request.Dispose() }
    }
    function Select-SettingsNavigation([string]$Name) {
        $navigation = Find-AuthenticationControl 'NavigationList'
        $condition = [System.Windows.Automation.PropertyCondition]::new([System.Windows.Automation.AutomationElement]::NameProperty, $Name)
        $item = $navigation.FindFirst([System.Windows.Automation.TreeScope]::Descendants, $condition)
        Assert-AuthenticationAcceptance ($null -ne $item) 'Native Settings navigation was unavailable.'
        ([System.Windows.Automation.SelectionItemPattern]$item.GetCurrentPattern([System.Windows.Automation.SelectionItemPattern]::Pattern)).Select()
    }
    function Test-SettingsText([string]$Id, [string]$Text) {
        $element = Find-AuthenticationControl $Id
        return $null -ne $element -and $element.Current.Name -ceq $Text
    }
    try {
        $login = Invoke-SettingsApi 'api/auth/login' @{ username = $script:username; password = $script:password }
        $bearer = [string]$login.accessToken; $login = $null
        $license = Invoke-SettingsApi 'api/admin/license'
        Assert-AuthenticationAcceptance ($license.mode -ceq 'SAFE_MODE' -and $license.capabilities.localDetectionRules -and
            $license.capabilities.criticalAlerts -and -not $license.capabilities.premiumFeatures -and @($license.enabledFeatures).Count -eq 0) 'The synthetic Core did not preserve its Safe Mode baseline.'
        Select-SettingsNavigation 'Settings'
        Wait-AuthenticationAcceptance { Test-SettingsText 'LicenseMode' $license.mode } 'Native license state differed from Core.'
        Assert-AuthenticationAcceptance (Test-SettingsText 'LicenseFeatures' 'No optional features permitted.') 'Native license features differed from Core.'
        Assert-AuthenticationAcceptance (Test-SettingsText 'SettingsCoreAddress' 'http://127.0.0.1:5000') 'Settings changed the fixed local Core destination.'
        $preference = Find-AuthenticationControl 'CloudAiRequestsEnabled'
        Assert-AuthenticationAcceptance ($null -ne $preference) 'Native session AI setting was missing.'
        $toggle = [System.Windows.Automation.TogglePattern]$preference.GetCurrentPattern([System.Windows.Automation.TogglePattern]::Pattern)
        Assert-AuthenticationAcceptance ($toggle.Current.ToggleState -eq [System.Windows.Automation.ToggleState]::Off) 'Cloud AI consent was enabled without an operator choice.'
        Invoke-AuthenticationControl 'RenewLicenseButton'
        Wait-AuthenticationAcceptance { Test-SettingsText 'LicenseRenewalStatus' 'License renewal is unavailable. Check Core''s renewal configuration, then refresh license status.' } 'Unconfigured renewal did not produce its fixed safe error.'
        Assert-AuthenticationAcceptance (-not (Test-AuthenticationControl 'RenewLicenseButton')) 'Unavailable renewal retained an unverified renewal action.'
        Invoke-AuthenticationControl 'RefreshLicenseButton'
        Wait-AuthenticationAcceptance { Test-SettingsText 'LicenseMode' 'SAFE_MODE' } 'Explicit native refresh did not reconcile licensing.'
        Invoke-AuthenticationControl 'SettingsCheckCoreButton'
        Wait-AuthenticationAcceptance { Test-SettingsText 'SettingsCoreStatus' 'Local Core available' } 'Settings connection check failed against the held Core.'
        $toggle.Toggle()
        Wait-AuthenticationAcceptance { $toggle.Current.ToggleState -eq [System.Windows.Automation.ToggleState]::On } 'The explicit session AI setting did not change.'
        Select-SettingsNavigation 'Alerts'
        Wait-AuthenticationAcceptance { Test-AuthenticationControl 'AlertsGrid' } 'Renewal failure blocked native local alerts.'
        $grid = Find-AuthenticationControl 'AlertsGrid'
        $rowType = [System.Windows.Automation.PropertyCondition]::new([System.Windows.Automation.AutomationElement]::ControlTypeProperty, [System.Windows.Automation.ControlType]::DataItem)
        Wait-AuthenticationAcceptance { $null -ne $grid.FindFirst([System.Windows.Automation.TreeScope]::Children, $rowType) } 'Native Settings fixture found no stored local alert.'
        $row = $grid.FindFirst([System.Windows.Automation.TreeScope]::Children, $rowType)
        ([System.Windows.Automation.SelectionItemPattern]$row.GetCurrentPattern([System.Windows.Automation.SelectionItemPattern]::Pattern)).Select()
        Invoke-AuthenticationControl 'OpenAlertButton'
        Wait-AuthenticationAcceptance { Test-SettingsText 'AiExplanationStatus' 'Cloud AI is not permitted by the current license. Safe Mode preserves local security functions.' } 'Safe Mode did not explain the native supported-alert AI gate.'
        Assert-AuthenticationAcceptance (-not (Test-AuthenticationControl 'ExplainAlertWithAiButton')) 'Session consent bypassed Core''s Safe Mode entitlement.'
        Assert-AuthenticationAcceptance (Test-AuthenticationControl 'AlertDetailTitle') 'Safe Mode hid local incident details.'
        Select-SettingsNavigation 'Risk'
        Wait-AuthenticationAcceptance { Test-AuthenticationControl 'RiskGrid' } 'Unavailable optional services blocked local Risk.'
        Select-SettingsNavigation 'Reports'
        Wait-AuthenticationAcceptance { Test-AuthenticationControl 'GenerateReportButton' } 'Unavailable optional services blocked local Reports.'
        Select-SettingsNavigation 'Settings'
        Wait-AuthenticationAcceptance { Test-SettingsText 'LicenseMode' 'SAFE_MODE' } 'Native Settings could not reopen after local workflows.'
        $preference = Find-AuthenticationControl 'CloudAiRequestsEnabled'
        $toggle = [System.Windows.Automation.TogglePattern]$preference.GetCurrentPattern([System.Windows.Automation.TogglePattern]::Pattern)
        Assert-AuthenticationAcceptance ($toggle.Current.ToggleState -eq [System.Windows.Automation.ToggleState]::On) 'Navigation lost the explicit session setting.'
        Invoke-AuthenticationControl 'SignOutButton'
        Wait-AuthenticationAcceptance { Test-AuthenticationControl 'SignInButton' $false } 'Native Settings did not sign out.'
        Assert-SignedOut
        foreach ($id in @('LicenseMode', 'LicenseFeatures', 'CloudAiRequestsEnabled', 'AiExplanationText')) {
            $element = Find-AuthenticationControl $id
            Assert-AuthenticationAcceptance ($null -eq $element -or $element.Current.IsOffscreen) 'Sign-out retained protected optional-workflow output.'
        }
    } finally { $bearer = $null; $login = $null; $license = $null; $api.Dispose() }
}
