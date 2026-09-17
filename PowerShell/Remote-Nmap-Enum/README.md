# Remote Nmap Enum via PsExec

`Invoke-RemoteNmapEnum.ps1` opens a [PsExec](https://learn.microsoft.com/sysinternals/downloads/psexec)
session against a remote Windows host, makes sure Nmap is installed there
(via Chocolatey, falling back to a direct silent install of the official
Windows installer), runs a port scan from that host against a target you
specify, and copies the scan results back to your machine.

**Only run this against hosts and networks you own or have explicit written
authorization to test** — this is lab/CTF tooling, not something to point at
third-party infrastructure.

## Prerequisites

- PsExec.exe (from Sysinternals) placed next to the script, or on `PATH`,
  or passed via `-PsExecPath`. It isn't bundled here — grab it yourself
  from Microsoft: https://learn.microsoft.com/sysinternals/downloads/psexec
- Local admin rights on the remote host (via `-Credential`, or by already
  running as a user with those rights).
- The remote host needs outbound internet access to install Nmap
  (Chocolatey bootstrap / nmap.org), unless Nmap is already installed.

## Usage

```powershell
# Prompt for creds, scan a /24 from the remote box's vantage point
.\Invoke-RemoteNmapEnum.ps1 -ComputerName LAB-DC01 -TargetScan 10.10.10.0/24 -Credential (Get-Credential)

# Run under the current (already-admin) session, custom nmap flags, skip the confirm prompt
.\Invoke-RemoteNmapEnum.ps1 -ComputerName 192.168.1.50 -TargetScan 192.168.1.1-254 -NmapArguments '-sS -p1-1024 -T4' -Force
```

Results land in `./NmapResults` (or wherever `-LocalOutputDir` points), as
both a plain-text (`-oN`) and XML (`-oX`) Nmap output pair per run.

## How it works

1. Builds a PowerShell script block that installs Nmap (if missing) and
   runs it against `-TargetScan`, base64-encodes it, and hands it to
   `psexec.exe \\ComputerName ... powershell.exe -EncodedCommand ...`.
2. Waits for a `SCAN_COMPLETE` marker in PsExec's output.
3. Copies the remote working directory (default
   `C:\Windows\Temp\NmapEnum`) back over the admin share
   (`\\ComputerName\C$\...`) into `-LocalOutputDir`.

## Notes / caveats

- PsExec receives the remote credential's password as a plaintext command
  line argument for the life of the PsExec process. Prefer running this
  from a session already in an appropriately privileged security context
  when you can, rather than passing `-Credential`.
- The direct-download Nmap fallback pins a specific installer version URL
  in the script; update it if you need a newer release.
