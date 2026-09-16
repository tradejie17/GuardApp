<#
.SYNOPSIS
    Removes Guard for Windows. Requires the administrator password.

.DESCRIPTION
    Uninstalling is gated on the same password that protects the rules, because for a
    self-control tool the person at the keyboard usually is the local administrator: without the
    gate, "uninstall Guard" would be the easy way around every other control.

    The gate is a deliberate obstacle, not a security boundary. Someone with administrator
    rights and enough determination can always remove a service from their own machine; this
    stops the impulsive attempt, which is the behaviour the tool exists to interrupt.

.PARAMETER KeepData
    Leave %ProgramData%\Guard in place, including logs and the policy.

.EXAMPLE
    .\uninstall.ps1
#>
#Requires -RunAsAdministrator
[CmdletBinding()]
param(
    [string] $InstallRoot = "$env:ProgramFiles\Guard",
    [switch] $KeepData
)

$ErrorActionPreference = 'Stop'

$serviceName = 'GuardService'
$dataRoot    = Join-Path $env:ProgramData 'Guard'
$guardctl    = Join-Path $InstallRoot 'guardctl.exe'

# --- password check --------------------------------------------------------------------------
if (Test-Path $guardctl) {
    Write-Host 'Uninstalling Guard requires the administrator password.' -ForegroundColor Yellow
    & $guardctl verify
    if ($LASTEXITCODE -ne 0) {
        Write-Error 'Password check failed. Guard has not been removed.'
        exit 1
    }
} else {
    Write-Warning "guardctl.exe was not found at $guardctl; continuing without a password check."
}

# --- service ----------------------------------------------------------------------------------
$service = Get-Service -Name $serviceName -ErrorAction SilentlyContinue
if ($service) {
    Write-Host 'Stopping and removing the Guard service...'
    # Clear the restart-on-failure actions first, or the SCM will restart it as we stop it.
    & sc.exe failure $serviceName reset= 0 actions= '' | Out-Null
    Stop-Service -Name $serviceName -Force -ErrorAction SilentlyContinue
    & sc.exe delete $serviceName | Out-Null
}

# --- native messaging registration --------------------------------------------------------------
$hostName = 'com.guard.windows'
foreach ($key in @(
    "HKLM:\SOFTWARE\Google\Chrome\NativeMessagingHosts\$hostName",
    "HKLM:\SOFTWARE\Microsoft\Edge\NativeMessagingHosts\$hostName",
    "HKLM:\SOFTWARE\AVAST Software\Browser\NativeMessagingHosts\$hostName",
    "HKLM:\SOFTWARE\Mozilla\NativeMessagingHosts\$hostName"
)) {
    if (Test-Path $key) {
        Remove-Item -Path $key -Recurse -Force
        Write-Host "  removed $key"
    }
}

# --- browser policies ---------------------------------------------------------------------------
foreach ($key in @(
    'HKLM:\SOFTWARE\Policies\Google\Chrome',
    'HKLM:\SOFTWARE\Policies\Microsoft\Edge',
    'HKLM:\SOFTWARE\Policies\AVAST Software\Browser'
)) {
    if (Test-Path $key) {
        Remove-ItemProperty -Path $key -Name 'ExtensionSettings' -ErrorAction SilentlyContinue
        Remove-Item -Path (Join-Path $key 'ExtensionInstallForcelist') -Recurse -Force -ErrorAction SilentlyContinue
        Remove-Item -Path (Join-Path $key 'URLBlocklist') -Recurse -Force -ErrorAction SilentlyContinue
    }
}

foreach ($dir in @("$env:ProgramFiles\Mozilla Firefox", "${env:ProgramFiles(x86)}\Mozilla Firefox")) {
    $policyFile = Join-Path $dir 'distribution\policies.json'
    if (Test-Path $policyFile) {
        Remove-Item -Path $policyFile -Force
        Write-Host "  removed $policyFile"
    }
}

# --- files ----------------------------------------------------------------------------------------
if (Test-Path $InstallRoot) {
    Write-Host 'Removing program files...'
    Remove-Item -Path $InstallRoot -Recurse -Force -ErrorAction SilentlyContinue
}

if ($KeepData) {
    Write-Host "Configuration and logs kept at $dataRoot"
} elseif (Test-Path $dataRoot) {
    Remove-Item -Path $dataRoot -Recurse -Force -ErrorAction SilentlyContinue
    Write-Host "Removed $dataRoot"
}

Write-Host ''
Write-Host 'Guard has been removed. Restart your browsers to clear the enforced policy.' -ForegroundColor Green
