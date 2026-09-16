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

.PARAMETER SelfContained
    Bundle the .NET runtime into the published binaries instead of relying on a machine-wide
    .NET 8 installation. Larger on disk; useful where installing the runtime is not an option.

.EXAMPLE
    .\install.ps1
#>
#Requires -RunAsAdministrator
[CmdletBinding()]
param(
    [string] $InstallRoot = "$env:ProgramFiles\Guard",
    [switch] $SkipBuild,
    [switch] $SelfContained
)

$ErrorActionPreference = 'Stop'

# $ErrorActionPreference does not apply to native commands, so each one is checked by hand and
# its output is left visible. A silenced icacls or sc.exe is how a broken installation gets to
# look like a successful one.
function Invoke-Checked {
    param([string] $What, [scriptblock] $Command)

    & $Command
    if ($LASTEXITCODE -ne 0) {
        throw "$What failed with exit code $LASTEXITCODE."
    }
}

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
    $selfContainedArg = if ($SelfContained) { 'true' } else { 'false' }

    # The first publish on a machine is slow for reasons none of which are this script: a
    # RID-specific NuGet restore, a cold MSBuild and Roslyn, and the virus scanner reading every
    # file written into %ProgramFiles%. Minimal verbosity still shows progress, so a slow run is
    # distinguishable from a stuck one.
    foreach ($project in 'Guard.Service', 'Guard.NativeHost', 'Guard.Cli') {
        Write-Host "Publishing $project..." -ForegroundColor Cyan

        Invoke-Checked "dotnet publish ($project)" {
            & dotnet publish (Join-Path $repoRoot "src\$project\$project.csproj") `
                --configuration Release `
                --runtime win-x64 `
                --self-contained $selfContainedArg `
                --output $InstallRoot `
                --verbosity minimal `
                /p:DebugType=None
        }
    }
}

# --- 3. data directory, locked down ----------------------------------------------------------
foreach ($sub in 'config', 'secrets', 'logs') {
    New-Item -ItemType Directory -Path (Join-Path $dataRoot $sub) -Force | Out-Null
}

# The whole point of this ACL: the restricted user must not be able to edit the policy, read the
# password verifier, or delete the logs. %ProgramData% grants Users write access by default, so
# inheritance genuinely has to come off here -- and the result has to be verified, because an
# /inheritance:r whose /grant did not land leaves a directory nobody can use at all.
# Applied in two passes, and the order matters. (OI) and (CI) are *inheritance* flags: valid on
# a directory, meaningless on a file, where icacls turns them into an inherit-only ACE that
# grants the file nothing. So `/grant 'Administrators:(OI)(CI)F' /T` over a directory that
# already holds files locks those files away from everyone -- invisible on a first install where
# the directory is still empty, and a broken reinstall the moment there is a guard.json.
#
# Instead: let every existing child inherit, then set the inheritable ACEs on the parent alone
# and let Windows propagate them down.
Write-Host 'Locking down the data directory...' -ForegroundColor Cyan
Invoke-Checked 'icacls (data directory, restore inheritance)' {
    icacls $dataRoot /reset /T /C
}
Invoke-Checked 'icacls (data directory, lock down)' {
    icacls $dataRoot /inheritance:r /grant 'SYSTEM:(OI)(CI)F' 'Administrators:(OI)(CI)F'
}

# Verify against a real file rather than the directory: the directory looks correct even in the
# failure mode above, because there the inheritance flags are valid.
$dataAcl = icacls $dataRoot
if ($LASTEXITCODE -ne 0) { throw "icacls could not read the ACL on $dataRoot." }
if (-not ($dataAcl -match 'BUILTIN\\Administrators')) {
    throw "Locking down $dataRoot removed every permission on it. Run: icacls '$dataRoot' /reset /T /C"
}

$probe = Get-ChildItem $dataRoot -Recurse -File -ErrorAction SilentlyContinue | Select-Object -First 1
if ($probe) {
    $probeAcl = icacls $probe.FullName
    if (-not ($probeAcl -match 'BUILTIN\\Administrators')) {
        throw "$($probe.FullName) ended up with no usable permissions. Run: icacls '$dataRoot' /reset /T /C"
    }
}

# %ProgramFiles% needs no such surgery: its default ACL is already SYSTEM and Administrators full
# control plus Users read-and-execute, which is exactly what Guard wants. An earlier version of
# this script stripped inheritance here and re-granted by hand; when that /grant did not fully
# apply it produced binaries not even an administrator could launch, and the service failed to
# start with nothing but 'Access is denied' to go on. The inherited ACL is verified now, not
# replaced.
Write-Host 'Verifying permissions on the program directory...' -ForegroundColor Cyan
$installAcl = icacls $InstallRoot
if ($LASTEXITCODE -ne 0) { throw "icacls could not read the ACL on $InstallRoot." }

if (-not ($installAcl -match 'BUILTIN\\Administrators')) {
    Write-Warning "No Administrators entry on $InstallRoot; restoring inherited permissions."
    Invoke-Checked 'icacls (program directory reset)' { icacls $InstallRoot /reset /T /C }
}

# --- 4. register the service -----------------------------------------------------------------
$serviceExe = Join-Path $InstallRoot 'Guard.Service.exe'
if (-not (Test-Path $serviceExe)) { throw "Guard.Service.exe was not found at $serviceExe." }

if ($existing) {
    Write-Host 'Updating the existing service registration...' -ForegroundColor Cyan
    Invoke-Checked 'sc.exe config' {
        & sc.exe config $serviceName binPath= "`"$serviceExe`"" start= auto obj= LocalSystem
    }
} else {
    Write-Host 'Registering the Guard service...' -ForegroundColor Cyan
    Invoke-Checked 'sc.exe create' {
        & sc.exe create $serviceName binPath= "`"$serviceExe`"" start= auto obj= LocalSystem `
            DisplayName= 'Guard for Windows'
    }
}

Invoke-Checked 'sc.exe description' {
    & sc.exe description $serviceName 'Monitors browser navigation for restricted keywords and enforces the configured policy.'
}

# Restart automatically if the process is killed, and never give up: stopping the service is one
# of the obvious ways to try to switch protection off.
Invoke-Checked 'sc.exe failure' {
    & sc.exe failure $serviceName reset= 0 actions= restart/5000/restart/5000/restart/60000
}
Invoke-Checked 'sc.exe failureflag' { & sc.exe failureflag $serviceName 1 }

Write-Host 'Starting the service...' -ForegroundColor Cyan
try {
    Start-Service -Name $serviceName
    (Get-Service -Name $serviceName).WaitForStatus('Running', '00:00:30')
}
catch {
    # Start-Service reports every failure with the same generic message, which on its own says
    # nothing. Name the four commands that do.
    Write-Host ''
    Write-Warning "The service did not start: $($_.Exception.Message)"
    Write-Host ''
    Write-Host 'Run these from this elevated prompt to find out why:' -ForegroundColor Yellow
    Write-Host "  sc.exe start $serviceName"
    Write-Host '      5 = access denied (ACL or antivirus), 1053 = start timed out, 1067 = the process exited'
    Write-Host "  & '$serviceExe'"
    Write-Host '      runs it in this console, printing the startup error directly'
    Write-Host "  icacls '$serviceExe'"
    Write-Host '      confirm BUILTIN\Administrators and BUILTIN\Users are still on the binary'
    Write-Host "  Get-Content '$dataRoot\logs\guard.log' -Tail 30"
    Write-Host ''
    throw
}

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
