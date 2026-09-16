<#
.SYNOPSIS
    Builds and installs Guard for Windows: the service, the native messaging host and guardctl.

.DESCRIPTION
    Run from an elevated PowerShell prompt. The script:
      1. publishes the three .NET projects into %ProgramFiles%\Guard
      2. creates %ProgramData%\Guard and locks it to SYSTEM and Administrators
      3. registers GuardService to start automatically, running as LocalSystem
      4. configures the service to restart itself if it is killed
      5. sets the administrator password, which every later change requires

    Browser-side setup is separate: run register-native-host.ps1 once the extension is loaded
    and you know its id, and configure-policies.ps1 to force-install the extension.

.PARAMETER InstallRoot
    Installation directory. Defaults to %ProgramFiles%\Guard.

.PARAMETER SkipBuild
    Install from an existing publish output instead of building again.

.EXAMPLE
    .\install.ps1
#>
#Requires -RunAsAdministrator
[CmdletBinding()]
param(
    [string] $InstallRoot = "$env:ProgramFiles\Guard",
    [switch] $SkipBuild
)

$ErrorActionPreference = 'Stop'

$serviceName = 'GuardService'
$repoRoot    = Split-Path -Parent $PSScriptRoot
$dataRoot    = Join-Path $env:ProgramData 'Guard'

Write-Host "Installing Guard for Windows" -ForegroundColor Cyan
Write-Host "  source      : $repoRoot"
Write-Host "  program     : $InstallRoot"
Write-Host "  data        : $dataRoot"
Write-Host ''

# --- 1. stop any previous instance so its files can be replaced ------------------------------
$existing = Get-Service -Name $serviceName -ErrorAction SilentlyContinue
if ($existing -and $existing.Status -ne 'Stopped') {
    Write-Host 'Stopping the running Guard service...'
    Stop-Service -Name $serviceName -Force
    $existing.WaitForStatus('Stopped', '00:00:30')
}

# --- 2. publish ------------------------------------------------------------------------------
if (-not $SkipBuild) {
    foreach ($project in 'Guard.Service', 'Guard.NativeHost', 'Guard.Cli') {
        Write-Host "Publishing $project..."
        & dotnet publish (Join-Path $repoRoot "src\$project\$project.csproj") `
            --configuration Release `
            --runtime win-x64 `
            --self-contained false `
            --output $InstallRoot `
            /p:DebugType=None | Out-Null

        if ($LASTEXITCODE -ne 0) { throw "dotnet publish failed for $project." }
    }
}

# --- 3. data directory, locked down ----------------------------------------------------------
foreach ($sub in 'config', 'secrets', 'logs') {
    New-Item -ItemType Directory -Path (Join-Path $dataRoot $sub) -Force | Out-Null
}

# The whole point of the ACL: the restricted user must not be able to edit the policy, read the
# password verifier, or delete the logs. Inheritance is removed so nothing grants Users access.
Write-Host 'Applying permissions to the data directory...'
icacls $dataRoot /inheritance:r /grant 'SYSTEM:(OI)(CI)F' 'Administrators:(OI)(CI)F' /T /Q | Out-Null

# Program files: everyone may read and execute, only administrators may replace binaries.
icacls $InstallRoot /inheritance:r `
    /grant 'SYSTEM:(OI)(CI)F' 'Administrators:(OI)(CI)F' 'Users:(OI)(CI)RX' /T /Q | Out-Null

# --- 4. register the service -----------------------------------------------------------------
$serviceExe = Join-Path $InstallRoot 'Guard.Service.exe'
if (-not (Test-Path $serviceExe)) { throw "Guard.Service.exe was not found at $serviceExe." }

if ($existing) {
    Write-Host 'Updating the existing service registration...'
    & sc.exe config $serviceName binPath= "`"$serviceExe`"" start= auto obj= LocalSystem | Out-Null
} else {
    Write-Host 'Registering the Guard service...'
    & sc.exe create $serviceName binPath= "`"$serviceExe`"" start= auto obj= LocalSystem `
        DisplayName= 'Guard for Windows' | Out-Null
    if ($LASTEXITCODE -ne 0) { throw 'sc.exe create failed.' }
}

& sc.exe description $serviceName 'Monitors browser navigation for restricted keywords and enforces the configured policy.' | Out-Null

# Restart automatically if the process is killed, and never give up: stopping the service is one
# of the obvious ways to try to switch protection off.
& sc.exe failure $serviceName reset= 0 actions= restart/5000/restart/5000/restart/60000 | Out-Null
& sc.exe failureflag $serviceName 1 | Out-Null

Write-Host 'Starting the service...'
Start-Service -Name $serviceName
(Get-Service -Name $serviceName).WaitForStatus('Running', '00:00:30')

# --- 5. administrator password ----------------------------------------------------------------
$guardctl = Join-Path $InstallRoot 'guardctl.exe'

Write-Host ''
& $guardctl status

$status = & $guardctl status | Out-String
if ($status -match 'Admin password\s*:\s*NOT SET') {
    Write-Host ''
    Write-Host 'Set the administrator password now. It is required to pause protection,' -ForegroundColor Yellow
    Write-Host 'change the rules, or uninstall Guard. There is no recovery if it is lost.' -ForegroundColor Yellow
    Write-Host ''
    & $guardctl set-password
}

Write-Host ''
Write-Host 'Guard service installed and running.' -ForegroundColor Green
Write-Host ''
Write-Host 'Next steps:'
Write-Host '  1. Load or publish the browser extension and note its id'
Write-Host '  2. .\register-native-host.ps1 -ChromeExtensionId <id>'
Write-Host '  3. .\configure-policies.ps1 -ChromeExtensionId <id> -UpdateUrl <url>'
Write-Host ''
Write-Host "  guardctl status      shows protection state"
Write-Host "  guardctl help        lists every command"
