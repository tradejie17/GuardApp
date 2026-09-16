<#
.SYNOPSIS
    Applies browser enterprise policies so the Guard extension is force-installed and the user
    cannot remove or disable it.

.DESCRIPTION
    A force-installed extension is the part of this system that a browser will not let the user
    switch off: it cannot be disabled from chrome://extensions, and the Remove button is gone.

    Force-installing requires the browser to be able to fetch the extension from an update URL:

      * Chrome Web Store (recommended) - publish the extension as Unlisted, then pass its store
        id and leave -UpdateUrl at its default.
      * Self-hosted - serve a packed .crx and an update manifest from a URL the machine can
        reach, and pass that URL.

    Loading the extension unpacked through Developer mode is fine for testing, but such an
    extension CANNOT be force-installed and the user can remove it. Do not treat that as a
    deployed configuration.

.PARAMETER ChromeExtensionId
    The 32-character id of the Chromium build of the extension.

.PARAMETER UpdateUrl
    The update manifest URL. Defaults to the Chrome Web Store.

.PARAMETER FirefoxXpiPath
    Full path to the signed Firefox .xpi. Firefox release builds refuse unsigned add-ons, so
    this must be signed by Mozilla (AMO can sign an add-on for self-distribution).

.PARAMETER LockExtensionsPage
    Also block the browser's own extensions page, so the extension list cannot be inspected or
    tampered with. This blocks the page for every extension, not only Guard.

.EXAMPLE
    .\configure-policies.ps1 -ChromeExtensionId abcdefghijklmnopabcdefghijklmnop
#>
#Requires -RunAsAdministrator
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][ValidatePattern('^[a-p]{32}$')][string] $ChromeExtensionId,
    [string] $UpdateUrl = 'https://clients2.google.com/service/update2/crx',
    [string] $FirefoxExtensionId = 'guard@guard.local',
    [string] $FirefoxXpiPath,
    [switch] $LockExtensionsPage
)

$ErrorActionPreference = 'Stop'

function Set-PolicyValue {
    param([string] $Key, [string] $Name, $Value, [string] $Type = 'String')

    New-Item -Path $Key -Force | Out-Null
    New-ItemProperty -Path $Key -Name $Name -Value $Value -PropertyType $Type -Force | Out-Null
}

# ExtensionSettings is what actually removes the user's ability to turn the extension off:
# force_installed also implies "cannot be disabled or uninstalled by the user".
$extensionSettings = @{
    $ChromeExtensionId = @{
        installation_mode = 'force_installed'
        update_url        = $UpdateUrl
        toolbar_pin       = 'force_pinned'
    }
} | ConvertTo-Json -Depth 5 -Compress

foreach ($browser in @(
    @{ Name = 'Chrome'; Key = 'HKLM:\SOFTWARE\Policies\Google\Chrome' },
    @{ Name = 'Edge';   Key = 'HKLM:\SOFTWARE\Policies\Microsoft\Edge' }
)) {
    Write-Host "Configuring $($browser.Name) policy..."

    $forcelistKey = Join-Path $browser.Key 'ExtensionInstallForcelist'
    New-Item -Path $forcelistKey -Force | Out-Null
    Set-ItemProperty -Path $forcelistKey -Name '1' -Value "$ChromeExtensionId;$UpdateUrl"

    Set-PolicyValue -Key $browser.Key -Name 'ExtensionSettings' -Value $extensionSettings

    if ($LockExtensionsPage) {
        $blocklistKey = Join-Path $browser.Key 'URLBlocklist'
        New-Item -Path $blocklistKey -Force | Out-Null
        Set-ItemProperty -Path $blocklistKey -Name '1' -Value 'chrome://extensions'
        Set-ItemProperty -Path $blocklistKey -Name '2' -Value 'edge://extensions'
        Set-ItemProperty -Path $blocklistKey -Name '3' -Value 'about:addons'
    }
}

# Avast Secure Browser reads Chromium policy from its own vendor key. Verify the path on the
# target machine; Avast has moved it between releases.
$avastKey = 'HKLM:\SOFTWARE\Policies\AVAST Software\Browser'
if (Test-Path 'HKLM:\SOFTWARE\AVAST Software\Browser') {
    Write-Host 'Configuring Avast Secure Browser policy...'
    $avastForcelist = Join-Path $avastKey 'ExtensionInstallForcelist'
    New-Item -Path $avastForcelist -Force | Out-Null
    Set-ItemProperty -Path $avastForcelist -Name '1' -Value "$ChromeExtensionId;$UpdateUrl"
    Set-PolicyValue -Key $avastKey -Name 'ExtensionSettings' -Value $extensionSettings
} else {
    Write-Host 'Avast Secure Browser was not detected; skipping.' -ForegroundColor DarkGray
}

# --- Firefox ----------------------------------------------------------------------------------
# Firefox reads policies.json from a distribution folder next to firefox.exe.
$firefoxDir = @(
    "$env:ProgramFiles\Mozilla Firefox",
    "${env:ProgramFiles(x86)}\Mozilla Firefox"
) | Where-Object { Test-Path (Join-Path $_ 'firefox.exe') } | Select-Object -First 1

if ($firefoxDir) {
    Write-Host 'Configuring Firefox policy...'

    $policies = [ordered]@{
        policies = [ordered]@{
            ExtensionSettings = @{
                $FirefoxExtensionId = [ordered]@{
                    installation_mode = 'force_installed'
                    install_url       = if ($FirefoxXpiPath) { "file:///$($FirefoxXpiPath -replace '\\','/')" } else { '' }
                }
            }
            DisableDeveloperTools = $false
            BlockAboutAddons      = [bool] $LockExtensionsPage
        }
    }

    if (-not $FirefoxXpiPath) {
        Write-Warning 'No -FirefoxXpiPath given: the Firefox policy is written without an install URL and will not install anything. Sign the add-on and re-run with -FirefoxXpiPath.'
    }

    $distribution = Join-Path $firefoxDir 'distribution'
    New-Item -ItemType Directory -Path $distribution -Force | Out-Null
    # Written without a BOM for the same reason as the native messaging manifests: Windows
    # PowerShell 5.1's -Encoding UTF8 adds one, and a policy file the browser cannot parse is
    # silently ignored rather than reported.
    $policiesPath = Join-Path $distribution 'policies.json'
    [System.IO.File]::WriteAllText(
        $policiesPath,
        ($policies | ConvertTo-Json -Depth 8),
        (New-Object System.Text.UTF8Encoding($false)))
} else {
    Write-Host 'Firefox was not detected; skipping.' -ForegroundColor DarkGray
}

Write-Host ''
Write-Host 'Browser policies applied.' -ForegroundColor Green
Write-Host 'Restart each browser, then confirm at chrome://policy that the extension is listed as'
Write-Host 'installed by policy. A force-installed extension shows "Installed by enterprise policy"'
Write-Host 'and has no Remove button.'
