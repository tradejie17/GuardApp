<#
.SYNOPSIS
    Registers Guard.NativeHost as a native messaging host for the installed browsers.

.DESCRIPTION
    A browser will only launch a native host that is named in a manifest referenced from the
    registry, and it will only connect an extension whose id is listed in that manifest. This
    script writes one manifest per browser family and the HKLM registry value that points to it.

    Writing under HKLM (rather than HKCU) is deliberate: a standard user cannot then repoint the
    manifest at a different executable.

.PARAMETER InstallRoot
    Where Guard.NativeHost.exe was installed.

.PARAMETER ChromeExtensionId
    The 32-character extension id of the Chromium build of the Guard extension.

.PARAMETER FirefoxExtensionId
    The Firefox add-on id, which is the one declared in the Firefox manifest.

.EXAMPLE
    .\register-native-host.ps1 -ChromeExtensionId abcdefghijklmnopabcdefghijklmnop
#>
#Requires -RunAsAdministrator
[CmdletBinding()]
param(
    [string] $InstallRoot = "$env:ProgramFiles\Guard",
    [Parameter(Mandatory = $true)][ValidatePattern('^[a-p]{32}$')][string] $ChromeExtensionId,
    [string] $FirefoxExtensionId = 'guard@guard.local'
)

$ErrorActionPreference = 'Stop'

$hostName = 'com.guard.windows'
$hostExe  = Join-Path $InstallRoot 'Guard.NativeHost.exe'
$manifestDir = Join-Path $InstallRoot 'native-hosts'

if (-not (Test-Path $hostExe)) {
    throw "Guard.NativeHost.exe was not found at $hostExe. Run install.ps1 first."
}

New-Item -ItemType Directory -Path $manifestDir -Force | Out-Null

# Chromium browsers identify the caller by extension id; Firefox by add-on id. The two manifest
# shapes differ only in that field.
$chromiumManifest = [ordered]@{
    name            = $hostName
    description     = 'Guard for Windows native messaging host'
    path            = $hostExe
    type            = 'stdio'
    allowed_origins = @("chrome-extension://$ChromeExtensionId/")
}

$firefoxManifest = [ordered]@{
    name               = $hostName
    description        = 'Guard for Windows native messaging host'
    path               = $hostExe
    type               = 'stdio'
    allowed_extensions = @($FirefoxExtensionId)
}

$chromiumPath = Join-Path $manifestDir "$hostName.chromium.json"
$firefoxPath  = Join-Path $manifestDir "$hostName.firefox.json"

$chromiumManifest | ConvertTo-Json -Depth 4 | Set-Content -Path $chromiumPath -Encoding UTF8
$firefoxManifest  | ConvertTo-Json -Depth 4 | Set-Content -Path $firefoxPath  -Encoding UTF8

# Only SYSTEM and Administrators may change a manifest; otherwise the restricted user could
# point the host at a program of their own.
icacls $manifestDir /inheritance:r /grant 'SYSTEM:(OI)(CI)F' 'Administrators:(OI)(CI)F' /T | Out-Null

$targets = @(
    @{ Browser = 'Chrome';                 Key = 'HKLM:\SOFTWARE\Google\Chrome\NativeMessagingHosts';          Manifest = $chromiumPath },
    @{ Browser = 'Edge';                   Key = 'HKLM:\SOFTWARE\Microsoft\Edge\NativeMessagingHosts';         Manifest = $chromiumPath },
    # Avast Secure Browser is Chromium-based but uses its own vendor key. Confirm this path on
    # the target machine if Avast is in scope; it has changed between Avast releases.
    @{ Browser = 'Avast Secure Browser';   Key = 'HKLM:\SOFTWARE\AVAST Software\Browser\NativeMessagingHosts'; Manifest = $chromiumPath },
    @{ Browser = 'Firefox';                Key = 'HKLM:\SOFTWARE\Mozilla\NativeMessagingHosts';                Manifest = $firefoxPath }
)

foreach ($target in $targets) {
    $key = Join-Path $target.Key $hostName
    New-Item -Path $key -Force | Out-Null
    Set-ItemProperty -Path $key -Name '(Default)' -Value $target.Manifest
    Write-Host ("  registered for {0}" -f $target.Browser)
}

Write-Host ''
Write-Host "Native messaging host '$hostName' registered." -ForegroundColor Green
Write-Host "  Chromium manifest : $chromiumPath"
Write-Host "  Firefox manifest  : $firefoxPath"
Write-Host ''
Write-Host 'If you rebuild the extension with a different id, re-run this script with the new id.'
