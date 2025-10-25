<#
.SYNOPSIS
    Checks state of preset security policies

.DESCRIPTION
    Impersonation protection checks SHOULD be used.

.EXAMPLE
    Test-MtCisaImpersonationTip

    Returns true if standard and strict protection is on

.LINK
    https://maester.dev/docs/commands/Test-MtCisaImpersonationTip
#>
function Test-MtCisaImpersonationTip {
    [CmdletBinding()]
    [OutputType([bool])]
    param()

    if (!(Test-MtConnection ExchangeOnline)) {
        Add-MtTestResultDetail -SkippedBecause NotConnectedExchange
        return $null
    } elseif ("P1" -notin (Get-MtLicenseInformation -Product MdoV2)) {
        Add-MtTestResultDetail -SkippedBecause NotLicensedMdoP1
        return $null
    }

    $policies = Get-MtExoThreatPolicyAntiPhish
    $failingPolicies = $policies | Where-Object { `
        $_.Enabled -and `
        -not ($_.EnableSimilarDomainsSafetyTips -and $_.EnableSimilarUsersSafetyTips -and $_.EnableUnusualCharactersSafetyTips)
    }
    $testResult = ($failingPolicies | Measure-Object).Count -eq 0

    $portalLink = "https://security.microsoft.com/antiphishing"
    $passResult = "✅&nbsp;Pass"
    $failResult = "❌&nbsp;Fail"
    $skipResult = "🗄️&nbsp;Skip"

    $result = "| Policy name | Enabled | Enable Similar Domains Safety Tips | Enable Similar Users Safety Tips | Enable Unusual Characters Safety Tips | Result |`n"
    $result += "| --- | --- | --- | --- | --- | --- |`n"
    foreach ($item in $policies) {
        $itemResult = if (-not $item.IsEnabled) {
            $skipResult
        } elseif ($item.EnableSimilarDomainsSafetyTips -and $item.EnableSimilarUsersSafetyTips -and $item.EnableUnusualCharactersSafetyTips) {
            $passResult
        } else {
            $failResult
        }
        $result += "| $($item.Identity) | $($item.IsEnabled) | $($item.EnableSimilarDomainsSafetyTips) | $($item.EnableSimilarUsersSafetyTips) | $($item.EnableUnusualCharactersSafetyTips) | $itemResult |`n"
    }

    if ($testResult) {
        $testResultMarkdown = "Well done. All the enabled anti-phish policies in your tenant have the EnableSimilarDomainsSafetyTips -and EnableSimilarUsersSafetyTips -and EnableUnusualCharactersSafetyTips enabled ($portalLink).`n`n%TestResult%"
    } else {
        $testResultMarkdown = "Your tenant does not have all the enabled anti-phish policies with the EnableSimilarDomainsSafetyTips -and EnableSimilarUsersSafetyTips -and EnableUnusualCharactersSafetyTips enabled ($portalLink).`n`n%TestResult%"
    }

    $testResultMarkdown = $testResultMarkdown -replace "%TestResult%", $result

    Add-MtTestResultDetail -Result $testResultMarkdown

    return $testResult

    # $policies = Get-MtExo -Request AntiPhishPolicy

    # $resultPolicies = $policies | Where-Object { `
    #     $_.Enabled -and `
    #     $_.EnableSimilarDomainsSafetyTips -and `
    #     $_.EnableSimilarUsersSafetyTips -and `
    #     $_.EnableUnusualCharactersSafetyTips
    # }

    # $standard = $policies | Where-Object { `
    #     $_.RecommendedPolicyType -eq "Standard"
    # }

    # $strict = $policies | Where-Object { `
    #     $_.RecommendedPolicyType -eq "Strict"
    # }

    # $testResult = $standard -and $strict -and (($resultPolicies|Measure-Object).Count -ge 1)

    # $portalLink = "https://security.microsoft.com/presetSecurityPolicies"
    # $passResult = "✅ Pass"
    # $failResult = "❌ Fail"

    # if ($testResult) {
    #     $testResultMarkdown = "Well done. Your tenant has [standard and strict preset security policies for the common file filter]($portalLink).`n`n%TestResult%"
    # } else {
    #     $testResultMarkdown = "Your tenant does not have [standard and strict preset security policies enabled]($portalLink).`n`n%TestResult%"
    # }

    # $result = "| Policy | Status |`n"
    # $result += "| --- | --- |`n"
    # if ($standard) {
    #     $result += "| Standard | $passResult |`n"
    # } else {
    #     $result += "| Standard | $failResult |`n"
    # }
    # if ($strict) {
    #     $result += "| Strict | $passResult |`n`n"
    # } else {
    #     $result += "| Strict | $failResult |`n`n"
    # }

    # $result += "| Policy Name | Result |`n"
    # $result += "| --- | --- |`n"
    # foreach($item in $policies | Sort-Object -Property Identity){
    #     if($item.Guid -in $resultPolicies.Guid){
    #         $result += "| $($item.Identity) | $($passResult) |`n"
    #     }else{
    #         $result += "| $($item.Identity) | $($failResult) |`n"
    #     }
    # }

    # $testResultMarkdown = $testResultMarkdown -replace "%TestResult%", $result

    # Add-MtTestResultDetail -Result $testResultMarkdown

    # return $testResult
}