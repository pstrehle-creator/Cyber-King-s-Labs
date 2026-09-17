#Requires -Version 5.1
<#
.SYNOPSIS
    Uses PsExec to reach a remote Windows host, installs Nmap on it, and runs
    a port enumeration scan against a target, then copies the results back.

.DESCRIPTION
    This script is intended for home-lab / CTF use against systems you own or
    have explicit written authorization to test. It:

      1. Opens a PsExec session against -ComputerName using the supplied
         credentials (or the current user's context if none are supplied).
      2. On that remote host, checks whether Nmap is already installed and,
         if not, installs it via Chocolatey (bootstrapping Chocolatey first
         if needed) or, as a fallback, via a direct silent install of the
         official Nmap Windows installer.
      3. Runs Nmap against -TargetScan from the remote host and writes
         normal + XML output to a working directory on the remote machine.
      4. Copies the resulting scan files back to -LocalOutputDir over the
         admin share (\\ComputerName\C$\...).

    PsExec (from Sysinternals) must already be present locally; this script
    does not silently download and run third-party tooling. Get it from
    https://learn.microsoft.com/sysinternals/downloads/psexec and place it
    next to this script, or pass -PsExecPath.

.PARAMETER ComputerName
    The remote host to PsExec into.

.PARAMETER Credential
    Credential with local admin rights on the remote host. If omitted,
    PsExec runs under the current user's context, which must already have
    admin rights on the target.

.PARAMETER TargetScan
    The IP address, hostname, or CIDR range that Nmap should scan, run FROM
    the remote host. Mandatory, so a network is never scanned by accident.

.PARAMETER NmapArguments
    Extra arguments passed to nmap.exe. Defaults to a standard TCP connect
    top-1000 ports scan with service/version detection.

.PARAMETER PsExecPath
    Path to psexec.exe. Defaults to psexec.exe next to this script, falling
    back to whatever is on PATH.

.PARAMETER RemoteWorkDir
    Local (on the remote box) working directory, e.g. C:\Windows\Temp\NmapEnum.

.PARAMETER LocalOutputDir
    Where scan results are copied to on this machine.

.PARAMETER Force
    Skip the interactive authorization confirmation prompt.

.EXAMPLE
    .\Invoke-RemoteNmapEnum.ps1 -ComputerName LAB-DC01 -TargetScan 10.10.10.0/24 -Credential (Get-Credential)

.EXAMPLE
    .\Invoke-RemoteNmapEnum.ps1 -ComputerName 192.168.1.50 -TargetScan 192.168.1.1-254 -NmapArguments '-sS -p1-1024 -T4' -Force

.NOTES
    Run only against hosts and networks you own or are explicitly authorized
    to test. Passing credentials to PsExec exposes the password in the local
    process's command line arguments for the life of that process; prefer
    running this from an already-elevated session in the target's own
    security context where possible.
#>
[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
param(
    [Parameter(Mandatory = $true)]
    [string]$ComputerName,

    [Parameter(Mandatory = $false)]
    [System.Management.Automation.PSCredential]$Credential,

    [Parameter(Mandatory = $true)]
    [string]$TargetScan,

    [Parameter(Mandatory = $false)]
    [string]$NmapArguments = '-sT -sV -T4 --top-ports 1000',

    [Parameter(Mandatory = $false)]
    [string]$PsExecPath = (Join-Path $PSScriptRoot 'psexec.exe'),

    [Parameter(Mandatory = $false)]
    [string]$RemoteWorkDir = 'C:\Windows\Temp\NmapEnum',

    [Parameter(Mandatory = $false)]
    [string]$LocalOutputDir = (Join-Path (Get-Location) 'NmapResults'),

    [switch]$Force
)

function Resolve-PsExec {
    param([string]$Path)

    if (Test-Path -LiteralPath $Path -PathType Leaf) {
        return (Resolve-Path -LiteralPath $Path).Path
    }

    $onPath = Get-Command 'psexec.exe' -ErrorAction SilentlyContinue
    if ($onPath) {
        return $onPath.Source
    }

    throw "psexec.exe not found at '$Path' or on PATH. Download it from " +
          "https://learn.microsoft.com/sysinternals/downloads/psexec and " +
          "place it next to this script, or pass -PsExecPath."
}

function New-RemoteInstallAndScanCommand {
    param(
        [string]$WorkDir,
        [string]$Target,
        [string]$NmapArgs
    )

    # Escape single quotes so the values can't break out of the quoted
    # literals they're substituted into below.
    $WorkDir = $WorkDir -replace "'", "''"
    $Target = $Target -replace "'", "''"
    $NmapArgs = $NmapArgs -replace "'", "''"

    # This is the script block that actually executes ON the remote host.
    $remoteScript = @'
$ErrorActionPreference = 'Stop'
$workDir = '{0}'
$target  = '{1}'
$nmapArgs = '{2}'

New-Item -ItemType Directory -Path $workDir -Force | Out-Null

function Get-NmapExe {{
    $candidates = @(
        "$env:ProgramFiles\Nmap\nmap.exe",
        "${{env:ProgramFiles(x86)}}\Nmap\nmap.exe"
    )
    foreach ($c in $candidates) {{
        if (Test-Path -LiteralPath $c) {{ return $c }}
    }}
    $onPath = Get-Command nmap.exe -ErrorAction SilentlyContinue
    if ($onPath) {{ return $onPath.Source }}
    return $null
}}

$nmapExe = Get-NmapExe
if (-not $nmapExe) {{
    Write-Output '[remote] Nmap not found, installing...'

    $choco = Get-Command choco.exe -ErrorAction SilentlyContinue
    if (-not $choco) {{
        Write-Output '[remote] Chocolatey not found, bootstrapping...'
        Set-ExecutionPolicy Bypass -Scope Process -Force
        [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.SecurityProtocolType]::Tls12
        Invoke-Expression ((New-Object System.Net.WebClient).DownloadString('https://community.chocolatey.org/install.ps1'))
        $choco = Get-Command choco.exe -ErrorAction SilentlyContinue
    }}

    if ($choco) {{
        & $choco.Source install nmap -y --no-progress | Out-Null
    }}

    $nmapExe = Get-NmapExe

    if (-not $nmapExe) {{
        Write-Output '[remote] Chocolatey install unavailable, falling back to direct download...'
        $installer = Join-Path $env:TEMP 'nmap-setup.exe'
        [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.SecurityProtocolType]::Tls12
        Invoke-WebRequest -Uri 'https://nmap.org/dist/nmap-7.95-setup.exe' -OutFile $installer -UseBasicParsing
        Start-Process -FilePath $installer -ArgumentList '/S' -Wait
        $nmapExe = Get-NmapExe
    }}
}}

if (-not $nmapExe) {{
    Write-Output '[remote] ERROR: Nmap installation failed.'
    exit 1
}}

Write-Output "[remote] Using Nmap at $nmapExe"

$stamp = Get-Date -Format 'yyyyMMdd-HHmmss'
$outBase = Join-Path $workDir "scan-$stamp"

$argList = @($nmapArgs -split '\s+') + @('-oN', "$outBase.txt", '-oX', "$outBase.xml", $target)
Write-Output "[remote] Running: $nmapExe $($argList -join ' ')"
& $nmapExe @argList

if ($LASTEXITCODE -ne 0) {{
    Write-Output "[remote] ERROR: nmap exited with code $LASTEXITCODE"
    exit $LASTEXITCODE
}}

Write-Output '[remote] SCAN_COMPLETE'
'@ -f $WorkDir, $Target, $NmapArgs

    return $remoteScript
}

# --- main -------------------------------------------------------------

$resolvedPsExec = Resolve-PsExec -Path $PsExecPath

if (-not $Force) {
    Write-Warning "This will remotely execute code on '$ComputerName' and install software (Nmap) on it."
    Write-Warning "Only proceed if you own this host or have explicit written authorization to test it."
    if (-not $PSCmdlet.ShouldProcess($ComputerName, "Install Nmap and scan '$TargetScan' via PsExec")) {
        Write-Output 'Aborted.'
        return
    }
}

$remoteScript = New-RemoteInstallAndScanCommand -WorkDir $RemoteWorkDir -Target $TargetScan -NmapArgs $NmapArguments

$encodedCommand = [Convert]::ToBase64String([System.Text.Encoding]::Unicode.GetBytes($remoteScript))

$psExecArgs = @("\\$ComputerName", '-accepteula', '-h')

if ($Credential) {
    $networkCred = $Credential.GetNetworkCredential()
    $psExecArgs += @('-u', $networkCred.UserName, '-p', $networkCred.Password)
}

$psExecArgs += @('powershell.exe', '-NoProfile', '-ExecutionPolicy', 'Bypass', '-EncodedCommand', $encodedCommand)

Write-Output "Connecting to \\$ComputerName via PsExec..."
$output = & $resolvedPsExec @psExecArgs 2>&1
$output | ForEach-Object { Write-Output $_ }

if ($output -notmatch 'SCAN_COMPLETE') {
    throw "Remote scan did not report completion. Review the PsExec output above for errors."
}

# Map the remote work dir (assumed to be on C:) to its admin-share UNC path.
$driveLetter = ($RemoteWorkDir -split ':')[0]
$restOfPath = $RemoteWorkDir.Substring(3)
$uncSource = "\\$ComputerName\$driveLetter`$\$restOfPath"

if (-not (Test-Path -LiteralPath $LocalOutputDir)) {
    New-Item -ItemType Directory -Path $LocalOutputDir -Force | Out-Null
}

Write-Output "Copying results from $uncSource to $LocalOutputDir..."
Copy-Item -Path (Join-Path $uncSource '*') -Destination $LocalOutputDir -Recurse -Force

Write-Output "Done. Results saved to: $LocalOutputDir"
Get-ChildItem -Path $LocalOutputDir | Sort-Object LastWriteTime -Descending | Select-Object -First 5 Name, LastWriteTime
