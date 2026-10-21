<#
  Builds the Signer Agent Windows installer (MSI) with jpackage.
  Requirements: JDK 21+ (with jpackage), Maven, WiX Toolset 3.14 on PATH (candle.exe, light.exe).
  Optional code signing: set SIGN_CERT_PFX (path) and SIGN_CERT_PASSWORD, signtool.exe on PATH.

  Usage:  powershell -ExecutionPolicy Bypass -File packaging\agent\windows\build-msi.ps1 [-Version 1.0.0]
#>
param(
    [string]$Version = "1.0.0",
    [string]$Vendor = "Signer",
    # Keep this GUID constant across releases so new MSIs upgrade old installations.
    [string]$UpgradeUuid = "6f3c2a1e-4b7d-4c38-9a51-2d0e8f7b6c41"
)
$ErrorActionPreference = "Stop"
$root = Resolve-Path "$PSScriptRoot\..\..\.."
Push-Location $root
try {
    mvn -B -q -DskipTests -pl signer-agent -am package
    $input = "target\agent-input"
    $out = "target\installer"
    Remove-Item -Recurse -Force $input, $out -ErrorAction SilentlyContinue
    New-Item -ItemType Directory -Force $input, $out | Out-Null
    Copy-Item signer-agent\target\signer-agent.jar $input\

    $content = "target\agent-content"
    Remove-Item -Recurse -Force $content -ErrorAction SilentlyContinue
    New-Item -ItemType Directory -Force "$content\trust" | Out-Null
    Copy-Item packaging\agent\common\agent.properties $content\
    Copy-Item packaging\agent\windows\autostart-all-users.cmd $content\
    if (Test-Path packaging\agent\common\trust) { Copy-Item packaging\agent\common\trust\* "$content\trust\" }

    jpackage --type msi `
        --name "Signer Agent" `
        --app-version $Version `
        --vendor $Vendor `
        --description "Digital signature agent for USB tokens (DSC)" `
        --input $input `
        --main-jar signer-agent.jar `
        --main-class in.signer.agent.AgentMain `
        --app-content "$content\agent.properties" `
        --app-content "$content\autostart-all-users.cmd" `
        --app-content "$content\trust" `
        --java-options "-Xmx256m" `
        --java-options "-Dfile.encoding=UTF-8" `
        --add-modules java.base,java.desktop,java.logging,java.naming,java.net.http,java.security.jgss,java.sql,jdk.crypto.cryptoki,jdk.crypto.mscapi,jdk.crypto.ec,jdk.httpserver,jdk.unsupported `
        --win-menu --win-menu-group "Signer" `
        --win-shortcut `
        --win-upgrade-uuid $UpgradeUuid `
        --icon packaging\agent\windows\signer.ico `
        --dest $out

    $msi = Get-ChildItem $out\*.msi | Select-Object -First 1
    if ($env:SIGN_CERT_PFX) {
        signtool sign /f $env:SIGN_CERT_PFX /p $env:SIGN_CERT_PASSWORD /fd SHA256 /tr http://timestamp.digicert.com /td SHA256 $msi.FullName
    }
    Write-Host "Installer: $($msi.FullName)"
} finally {
    Pop-Location
}
