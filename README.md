# Desired State Configuration

![GitHub repo size](https://img.shields.io/github/repo-size/niklasrast/Windows-10-DSC-Configurator)

![GitHub issues](https://img.shields.io/github/issues-raw/niklasrast/Windows-10-DSC-Configurator)

![GitHub last commit](https://img.shields.io/github/last-commit/niklasrast/Windows-10-DSC-Configurator)

This repo contains an powershell scripts to deploy an DSC through Powershell to an Windows 10 client.

## Install:
```powershell
C:\Windows\SysNative\WindowsPowershell\v1.0\PowerShell.exe -ExecutionPolicy Bypass -Command .\W10_BaseClientDSC.ps1 -install
```

## Uninstall:
```powershell
C:\Windows\SysNative\WindowsPowershell\v1.0\PowerShell.exe -ExecutionPolicy Bypass -Command .\W10_BaseClientDSC.ps1 -uninstall
```

### Parameter definitions:
- install configures the .mof file on the windows 10 client and activates the dsc
- uninstall removes the .mof file on the windows 10 client and deactivates the dsc
 
## Logfiles:
The scripts create a logfile with the name of the .ps1 script in the folder C:\Windows\Logs.

## Requirements:
- PowerShell 5.0
- Windows 10 or later

# Feature requests
If you have an idea for a new feature in this repo, send me an issue with the subject Feature request and write your suggestion in the text. I will then check the feature and implement it if necessary.

Created by @niklasrast 
