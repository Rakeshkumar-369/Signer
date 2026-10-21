<#
  Silent roll-out of the Signer Agent to a computer (run as administrator, e.g. from SCCM / Intune / GPO startup script).

    powershell -ExecutionPolicy Bypass -File deploy-agent.ps1 -Msi "\\fileserver\signer\Signer Agent-1.0.0.msi" `
        -ServerUrl https://signer.example.gov.in -AllowedOrigins https://eoffice.example.gov.in
#>
param(
    [Parameter(Mandatory = $true)][string]$Msi,
    [Parameter(Mandatory = $true)][string]$ServerUrl,
    [string]$AllowedOrigins = "",
    [int]$Port = 1645
)
$ErrorActionPreference = "Stop"
$log = Join-Path $env:TEMP "signer-agent-install.log"
$p = Start-Process msiexec.exe -ArgumentList "/i `"$Msi`" /qn /norestart /l*v `"$log`"" -Wait -PassThru
if ($p.ExitCode -ne 0 -and $p.ExitCode -ne 3010) { throw "msiexec failed with exit code $($p.ExitCode); see $log" }

$installDir = Join-Path $env:ProgramFiles "Signer Agent"
$config = @"
security.mode=token
security.serverUrl=$ServerUrl
agent.port=$Port
"@
if ($AllowedOrigins) { $config += "`r`nsecurity.allowedOrigins=$AllowedOrigins" }
Set-Content -Path (Join-Path $installDir "agent.properties") -Value $config -Encoding UTF8

$exe = Join-Path $installDir "Signer Agent.exe"
New-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Run" -Name "SignerAgent" -Value "`"$exe`"" -PropertyType String -Force | Out-Null
Write-Host "Signer Agent installed in $installDir and registered to start at logon."
