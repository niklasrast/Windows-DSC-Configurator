<#
    .SYNOPSIS 
    Windows 10 Base Client Configuration DSC

    .DESCRIPTION
    Install:   PowerShell.exe -ExecutionPolicy Bypass -Command .\W10_BaseClientDSC.ps1 -install
    Uninstall:   PowerShell.exe -ExecutionPolicy Bypass -Command .\W10_BaseClientDSC.ps1 -uninstall

    .NOTES
    Detection:
    "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\MyCompany"
    "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\MyCompany\Version", "1.0"
    "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\MyCompany\Revision", "001"

    .ENVIRONMENT
    PowerShell 5.0

    .AUTHOR
    Niklas Rast
#>

[CmdletBinding()]
[Alias()]
[OutputType([int])]
Param(
    [Parameter(Mandatory = $true, ParameterSetName = 'install')]
    [switch]$install,
    [Parameter(Mandatory = $true, ParameterSetName = 'uninstall')]
    [switch]$uninstall
)

$ErrorActionPreference="SilentlyContinue"

$logFile = ('{0}\{1}.log' -f "C:\Windows\Logs", [System.IO.Path]::GetFileNameWithoutExtension($MyInvocation.MyCommand.Name))
$dscConfigPath = "C:\Windows\DSC"

if ($install) {
    Start-Transcript -path $logFile

    # Cleanup previous configurations
    if ( Test-Path -Path "$dscConfigPath\*" ) {
        Remove-Item -Path "$dscConfigPath\*" -Recurse -Force
    }

    # Configure local winrm service
    $null = Enable-PSRemoting -Force -SkipNetworkProfileCheck

    # Remove current DSC configuration
    # Remove-DscConfigurationDocument -Stage Current, Pending, Previous -Verbose

    # LCM meta configuration properties
    configuration MetaConfig
    {
        LocalConfigurationManager
        {
            ConfigurationModeFrequencyMins = 60
            #ConfigurationModeFrequencyMins = 15
            ConfigurationMode              = 'ApplyAndAutoCorrect'
            RebootNodeIfNeeded             = $false
        }
    }

    # Apply meta configuration to LCM
    $null = MetaConfig -OutputPath "$dscConfigPath\MetaConfig" -Verbose
    Set-DscLocalConfigurationManager -Path "$dscConfigPath\MetaConfig" -Force -Verbose

    # Base client configuration
    Configuration BaseClientConfig {

        Import-DscResource –ModuleName 'PSDesiredStateConfiguration'

        Node localhost
        {
            Script RemoveProvisionedApps
            {
                GetScript =
                {
                    # Check if the dsc should run
                    $InstalledApps = (Get-AppxPackage -AllUsers -PackageTypeFilter Bundle | Select-Object -Property Name, PackageFullName).Name
                    $AppBlacklist = Get-Content -Path "$env:windir\DSC\BaseClientConfig\appx-blacklist.txt"

                    $compareResult = Compare-Object -ReferenceObject $AppBlacklist -DifferenceObject $InstalledApps -IncludeEqual -ExcludeDifferent

                    # Return results
                    @{
                        Result = @{
                            CompareResult = ( 0 -eq ( $compareResult | Measure-Object ).Count )
                            AppBlacklist  = $compareResult.InputObject
                        }
                    }
                }

                TestScript =
                {
                    [scriptblock]::Create($GetScript).Invoke() | % Result | % CompareResult
                }

                SetScript =
                {
                    # Logging
                    $appxLogFile = "${env:Temp}\RemoveProvisionedApps.log"

                    [scriptblock]::Create($GetScript).Invoke() | % Result | % AppBlacklist | % {

                        $null = Get-AppxPackage -Name $_ -AllUsers -Verbose:$false | Remove-AppxPackage -AllUsers -Verbose:$false
                        $null = Get-AppXProvisionedPackage -Online -Verbose:$false | Where-Object DisplayName -eq $_ | Remove-AppxProvisionedPackage -Online -AllUsers -Verbose:$false

                        $logMessage = ('{0} INFO: Removed Appx- and AppxProvisionedPackage "{1}"' -f $(Get-Date -Format g), $_)

                        # Verbose logging at DSC runtime
                        Write-Verbose -Message $logMessage

                        # Write log to file
                        Write-Output -InputObject $logMessage >> $appxLogFile
                    }
                }

            }
        }
    }

    # Output mof configuration to destination path
    $null = BaseClientConfig -OutputPath "$dscConfigPath\BaseClientConfig" -Verbose

    # Copy blacklist to dsc-folder
    Copy-Item -Path "$PSScriptRoot\appx-blacklist.txt" -Destination "$dscConfigPath\BaseClientConfig"

    # Apply BaseClientConfig to localhost
    Start-DscConfiguration -Path "$dscConfigPath\BaseClientConfig" -Wait -Force -Verbose

    # Set branding
    $null = New-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall" -Name "MyCompany" -Force
    $null = New-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\MyCompany" -Name "Version" -PropertyType "String" -Value "1.0" -Force
    $null = New-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\MyCompany" -Name "Revision" -PropertyType "String" -Value "001" -Force

    Stop-Transcript
 }

 if ($uninstall) {
    Start-Transcript -path $logFile

    # Stop all running configuration jobs
    Stop-DscConfiguration -Force

    # Remove current DSC configuration
    Remove-DscConfigurationDocument -Stage Current, Pending, Previous -Verbose

    # Remove registry branding
    Remove-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\MyCompany" -Force -Recurse

    # Cleanup previous configurations
    if ( Test-Path -Path "$dscConfigPath\*" ) {
        Remove-Item -Path "$dscConfigPath\*" -Recurse -Force
    }

    Stop-Transcript
 }
