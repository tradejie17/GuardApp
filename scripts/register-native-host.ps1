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

# The browser launches this executable as the logged-in user, not as an administrator, so it
# needs read-and-execute on it as well as on the manifest.
$hostAcl = icacls $hostExe
if (-not ($hostAcl -match 'BUILTIN\\Users')) {
    Write-Warning "No Users permission on $hostExe; the browser will not be able to launch it."
    Write-Warning "Fix with: icacls '$InstallRoot' /reset /T /C"
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

# Windows PowerShell 5.1 writes a UTF-8 BOM when told -Encoding UTF8, PowerShell 7 does not, and
# Chrome rejects a manifest that starts with one -- surfacing it to the extension as "Specified
# native messaging host not found", which points nowhere near the real cause. Write the bytes
# directly so the result does not depend on which PowerShell ran the script.
$utf8NoBom = New-Object System.Text.UTF8Encoding($false)
[System.IO.File]::WriteAllText($chromiumPath, ($chromiumManifest | ConvertTo-Json -Depth 4), $utf8NoBom)
[System.IO.File]::WriteAllText($firefoxPath,  ($firefoxManifest  | ConvertTo-Json -Depth 4), $utf8NoBom)

foreach ($manifest in @($chromiumPath, $firefoxPath)) {
    $head = [System.IO.File]::ReadAllBytes($manifest)[0..2]
    if ($head[0] -eq 0xEF -and $head[1] -eq 0xBB -and $head[2] -eq 0xBF) {
        throw "$manifest was written with a UTF-8 BOM; the browser will not be able to parse it."
    }
}

# Permissions on the manifests: users must be able to READ them (the browser opens them as the
# logged-in user) but not to CHANGE them (or the restricted user could repoint the host at a
# program of their own). The ACL %ProgramFiles% already hands down is exactly that -- Users
# read-and-execute, Administrators and SYSTEM full control -- so inheritance is restored rather
# than replaced.
#
# An earlier version did this with `/inheritance:r /grant 'Administrators:(OI)(CI)F' /T`. (OI)
# and (CI) are *inheritance* flags: applied to a file they produce an inherit-only ACE that
# grants that file nothing. Combined with /inheritance:r stripping what the file did have, both
# manifests ended up readable by nobody at all -- which the browser reports as "Specified native
# messaging host not found", naming neither permissions nor the file.
icacls $manifestDir /reset /T /C
if ($LASTEXITCODE -ne 0) { throw "icacls failed on $manifestDir with exit code $LASTEXITCODE." }

# Read the effective ACL of a manifest back. Checking the directory would not catch the bug
# above, because there the inheritance flags are valid and the directory looks correct.
$manifestAcl = icacls $chromiumPath
if (-not ($manifestAcl -match 'BUILTIN\\Users')) {
    throw "No Users read permission on $chromiumPath; the browser will not be able to read it. " +
          "Run: icacls '$manifestDir' /reset /T /C"
}

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
