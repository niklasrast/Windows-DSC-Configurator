# Desired State Configuration

This repo contains an powershell scripts to deploy an DSC through Powershell to an Windows 10 client.

## Install:
```powershell
PowerShell.exe -ExecutionPolicy Bypass -Command .\W10_BaseClientDSC.ps1 -install
```

## Uninstall:
```powershell
PowerShell.exe -ExecutionPolicy Bypass -Command .\W10_BaseClientDSC.ps1 -uninstall
```

### Parameter definitions:
- -install configures the .mof file on the windows 10 client and activates the dsc
- -uninstall removes the .mof file on the windows 10 client and deactivates the dsc
 
## Logfiles:
The scripts create a logfile with the name of the .ps1 script in the folder C:\Windows\Logs.

## Requirements:
- PowerShell 5.0
- Windows 10

Created by @niklasrast 