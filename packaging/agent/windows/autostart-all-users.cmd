@echo off
rem Starts Signer Agent at logon for every user of this computer. Run once as administrator
rem (or deploy the same registry value with Group Policy / SCCM).
set "APPDIR=%~dp0"
reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\Run" /v SignerAgent /t REG_SZ /d "\"%APPDIR%Signer Agent.exe\"" /f
