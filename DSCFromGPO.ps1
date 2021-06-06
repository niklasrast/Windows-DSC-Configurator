<#
    .SYNOPSIS 
    Windows OpenBIOS Configurator

    .DESCRIPTION
    Install:   PowerShell.exe -ExecutionPolicy Bypass -Command .\BIOSConfigurator.ps1

    .ENVIRONMENT
    PowerShell 5.0

    .AUTHOR
    Niklas Rast
#>

Configuration DSCFromGPO
{

	Import-DSCResource -ModuleName 'GPRegistryPolicyDsc'
	Import-DSCResource -ModuleName 'AuditPolicyDSC'
	Import-DSCResource -ModuleName 'SecurityPolicyDSC'
	Node localhost
	{
         <#RegistryPolicyFile 'Registry(POL): HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\DisallowRun'
         {
              ValueName = 'DisallowRun'
              ValueData = 1
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer'
         }#>

         <#RegistryPolicyFile 'DELVALS_CU:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\DisallowRun'
         {
              ValueName = ''
              Exclusive = $True
              ValueData = ''
              Ensure = 'Present'
              ValueType = 'String'
              TargetType = 'ComputerConfiguration'
              Key = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\DisallowRun'
         }#>

         <#RegistryPolicyFile 'Registry(POL): HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\DisallowRun\1'
         {
              ValueName = '1'
              ValueData = 'cmd.exe'
              ValueType = 'String'
              TargetType = 'ComputerConfiguration'
              Key = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\DisallowRun'
         }#>

         <#RegistryPolicyFile 'Registry(POL): HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\DisallowRun\2'
         {
              ValueName = '2'
              ValueData = 'powershell.exe'
              ValueType = 'String'
              TargetType = 'ComputerConfiguration'
              Key = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\DisallowRun'
         }#>

         <#RegistryPolicyFile 'Registry(POL): HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\DisallowRun\3'
         {
              ValueName = '3'
              ValueData = 'powershell_ise.exe'
              ValueType = 'String'
              TargetType = 'ComputerConfiguration'
              Key = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\DisallowRun'
         }#>

         <#RegistryPolicyFile 'Registry(POL): HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\DisallowRun\4'
         {
              ValueName = '4'
              ValueData = 'reg.exe'
              ValueType = 'String'
              TargetType = 'ComputerConfiguration'
              Key = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\DisallowRun'
         }#>

         <#RegistryPolicyFile 'Registry(POL): HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\DisallowRun\5'
         {
              ValueName = '5'
              ValueData = 'regedit.exe'
              ValueType = 'String'
              TargetType = 'ComputerConfiguration'
              Key = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\DisallowRun'
         }#>

         <#RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\common\qmenable'
         {
              ValueName = 'qmenable'
              ValueData = 0
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKCU:\software\policies\microsoft\office\16.0\common'
         }#>

         <#RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\common\sendcustomerdata'
         {
              ValueName = 'sendcustomerdata'
              ValueData = 0
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKCU:\software\policies\microsoft\office\16.0\common'
         }#>

         <#RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\common\autoorgidgetkey'
         {
              ValueName = 'autoorgidgetkey'
              ValueData = 1
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKCU:\software\policies\microsoft\office\16.0\common'
         }#>

         <#RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\common\feedback\enabled'
         {
              ValueName = 'enabled'
              ValueData = 0
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKCU:\software\policies\microsoft\office\16.0\common\feedback'
         }#>

         <#RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\common\feedback\msoridsurveyenabled'
         {
              ValueName = 'msoridsurveyenabled'
              ValueData = 0
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKCU:\software\policies\microsoft\office\16.0\common\feedback'
         }#>

         <#RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\common\general\disableboottoofficestart'
         {
              ValueName = 'disableboottoofficestart'
              ValueData = 1
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKCU:\software\policies\microsoft\office\16.0\common\general'
         }#>

         <#RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\common\general\optindisable'
         {
              ValueName = 'optindisable'
              ValueData = 1
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKCU:\software\policies\microsoft\office\16.0\common\general'
         }#>

         <#RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\common\general\shownfirstrunoptin'
         {
              ValueName = 'shownfirstrunoptin'
              ValueData = 1
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKCU:\software\policies\microsoft\office\16.0\common\general'
         }#>

         <#RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\common\general\disablehyperlinkstowebtemplates'
         {
              ValueName = 'disablehyperlinkstowebtemplates'
              ValueData = 1
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKCU:\software\policies\microsoft\office\16.0\common\general'
         }#>

         <#RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\common\general\disableofficetemplates'
         {
              ValueName = 'disableofficetemplates'
              ValueData = 1
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKCU:\software\policies\microsoft\office\16.0\common\general'
         }#>

         <#RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\common\general\corporatetemplates'
         {
              ValueName = 'corporatetemplates'
              ValueData = '\\fradc01\myad\cicd\Office_Templates'
              ValueType = 'ExpandString'
              TargetType = 'ComputerConfiguration'
              Key = 'HKCU:\software\policies\microsoft\office\16.0\common\general'
         }#>

         <#RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\common\general\sharedtemplates'
         {
              ValueName = 'sharedtemplates'
              ValueData = '\\fradc01\myad\cicd\Office_Templates'
              ValueType = 'ExpandString'
              TargetType = 'ComputerConfiguration'
              Key = 'HKCU:\software\policies\microsoft\office\16.0\common\general'
         }#>

         <#RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\common\internet\donotcheckifwordisdefaulthtmleditor'
         {
              ValueName = 'donotcheckifwordisdefaulthtmleditor'
              ValueData = 1
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKCU:\software\policies\microsoft\office\16.0\common\internet'
         }#>

         <#RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\common\licensing\hidemanageaccountlink'
         {
              ValueName = 'hidemanageaccountlink'
              ValueData = 1
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKCU:\software\policies\microsoft\office\16.0\common\licensing'
         }#>

         <#RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\common\research\translation\usemt'
         {
              ValueName = 'usemt'
              ValueData = 0
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKCU:\software\policies\microsoft\office\16.0\common\research\translation'
         }#>

         <#RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\common\research\translation\useonline'
         {
              ValueName = 'useonline'
              ValueData = 0
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKCU:\software\policies\microsoft\office\16.0\common\research\translation'
         }#>

         <#RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\common\services\fax\nofax'
         {
              ValueName = 'nofax'
              ValueData = 1
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKCU:\software\policies\microsoft\office\16.0\common\services\fax'
         }#>

         <#RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\common\targetedmessagingservice\disabletargetedmessaging'
         {
              ValueName = 'disabletargetedmessaging'
              ValueData = 1
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKCU:\software\policies\microsoft\office\16.0\common\targetedmessagingservice'
         }#>

         <#RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\excel\options\defsheets'
         {
              ValueName = 'defsheets'
              ValueData = 3
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKCU:\software\policies\microsoft\office\16.0\excel\options'
         }#>

         <#RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\excel\options\defaultformat'
         {
              ValueName = 'defaultformat'
              ValueData = 51
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKCU:\software\policies\microsoft\office\16.0\excel\options'
         }#>

         <#RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\excel\options\disableboottoofficestart'
         {
              ValueName = 'disableboottoofficestart'
              ValueData = 1
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKCU:\software\policies\microsoft\office\16.0\excel\options'
         }#>

         <#RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\excel\options\officestartdefaulttab'
         {
              ValueName = 'officestartdefaulttab'
              ValueData = 1
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKCU:\software\policies\microsoft\office\16.0\excel\options'
         }#>

         <#RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\excel\options\font'
         {
              ValueName = 'font'
              ValueData = 'Arial, 10'
              ValueType = 'String'
              TargetType = 'ComputerConfiguration'
              Key = 'HKCU:\software\policies\microsoft\office\16.0\excel\options'
         }#>

         <#RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\excel\security\vbawarnings'
         {
              ValueName = 'vbawarnings'
              ValueData = 2
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKCU:\software\policies\microsoft\office\16.0\excel\security'
         }#>

         <#RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\excel\security\vbadigsigtrustedpublishers'
         {
              ValueName = 'vbadigsigtrustedpublishers'
              ValueData = 0
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKCU:\software\policies\microsoft\office\16.0\excel\security'
         }#>

         <#RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\excel\security\vbarequirelmtrustedpublisher'
         {
              ValueName = 'vbarequirelmtrustedpublisher'
              ValueData = 0
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKCU:\software\policies\microsoft\office\16.0\excel\security'
         }#>

         <#RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\excel\security\vbarequiredigsigwithcodesigningeku'
         {
              ValueName = 'vbarequiredigsigwithcodesigningeku'
              ValueData = 0
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKCU:\software\policies\microsoft\office\16.0\excel\security'
         }#>

         <#RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\excel\security\blockcontentexecutionfrominternet'
         {
              ValueName = 'blockcontentexecutionfrominternet'
              ValueData = 1
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKCU:\software\policies\microsoft\office\16.0\excel\security'
         }#>

         <#RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\excel\security\protectedview\disableattachmentsinpv'
         {
              ValueName = 'disableattachmentsinpv'
              ValueData = 0
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKCU:\software\policies\microsoft\office\16.0\excel\security\protectedview'
         }#>

         <#RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\excel\security\protectedview\disableunsafelocationsinpv'
         {
              ValueName = 'disableunsafelocationsinpv'
              ValueData = 0
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKCU:\software\policies\microsoft\office\16.0\excel\security\protectedview'
         }#>

         <#RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\excel\security\protectedview\disableinternetfilesinpv'
         {
              ValueName = 'disableinternetfilesinpv'
              ValueData = 0
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKCU:\software\policies\microsoft\office\16.0\excel\security\protectedview'
         }#>

         <#RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\firstrun\disablemovie'
         {
              ValueName = 'disablemovie'
              ValueData = 1
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKCU:\software\policies\microsoft\office\16.0\firstrun'
         }#>

         <#RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\firstrun\bootedrtm'
         {
              ValueName = 'bootedrtm'
              ValueData = 1
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKCU:\software\policies\microsoft\office\16.0\firstrun'
         }#>

         <#RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\osm\enableupload'
         {
              ValueName = 'enableupload'
              ValueData = 0
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKCU:\software\policies\microsoft\office\16.0\osm'
         }#>

         <#RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\osm\enablefileobfuscation'
         {
              ValueName = 'enablefileobfuscation'
              ValueData = 1
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKCU:\software\policies\microsoft\office\16.0\osm'
         }#>

         <#RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\osm\enablelogging'
         {
              ValueName = 'enablelogging'
              ValueData = 0
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKCU:\software\policies\microsoft\office\16.0\osm'
         }#>

         <#RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\powerpoint\options\defaultformat'
         {
              ValueName = 'defaultformat'
              ValueData = 27
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKCU:\software\policies\microsoft\office\16.0\powerpoint\options'
         }#>

         <#RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\powerpoint\security\protectedview\disableinternetfilesinpv'
         {
              ValueName = 'disableinternetfilesinpv'
              ValueData = 0
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKCU:\software\policies\microsoft\office\16.0\powerpoint\security\protectedview'
         }#>

         <#RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\powerpoint\security\protectedview\disableunsafelocationsinpv'
         {
              ValueName = 'disableunsafelocationsinpv'
              ValueData = 0
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKCU:\software\policies\microsoft\office\16.0\powerpoint\security\protectedview'
         }#>

         <#RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\powerpoint\security\protectedview\disableattachmentsinpv'
         {
              ValueName = 'disableattachmentsinpv'
              ValueData = 0
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKCU:\software\policies\microsoft\office\16.0\powerpoint\security\protectedview'
         }#>

         <#RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\wef\trustedcatalogs\disableomexcatalogs'
         {
              ValueName = 'disableomexcatalogs'
              ValueData = 1
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKCU:\software\policies\microsoft\office\16.0\wef\trustedcatalogs'
         }#>

         <#RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\wef\trustedcatalogs\disableallcatalogs'
         {
              ValueName = 'disableallcatalogs'
              ValueData = 1
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKCU:\software\policies\microsoft\office\16.0\wef\trustedcatalogs'
         }#>

         <#RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\word\options\disableboottoofficestart'
         {
              ValueName = 'disableboottoofficestart'
              ValueData = 1
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKCU:\software\policies\microsoft\office\16.0\word\options'
         }#>

         <#RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\word\options\defaultformat'
         {
              ValueName = 'defaultformat'
              ValueData = '
'
              ValueType = 'String'
              TargetType = 'ComputerConfiguration'
              Key = 'HKCU:\software\policies\microsoft\office\16.0\word\options'
         }#>

         <#RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\word\security\vbawarnings'
         {
              ValueName = 'vbawarnings'
              ValueData = 2
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKCU:\software\policies\microsoft\office\16.0\word\security'
         }#>

         <#RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\word\security\vbadigsigtrustedpublishers'
         {
              ValueName = 'vbadigsigtrustedpublishers'
              ValueData = 0
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKCU:\software\policies\microsoft\office\16.0\word\security'
         }#>

         <#RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\word\security\vbarequirelmtrustedpublisher'
         {
              ValueName = 'vbarequirelmtrustedpublisher'
              ValueData = 0
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKCU:\software\policies\microsoft\office\16.0\word\security'
         }#>

         <#RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\word\security\vbarequiredigsigwithcodesigningeku'
         {
              ValueName = 'vbarequiredigsigwithcodesigningeku'
              ValueData = 0
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKCU:\software\policies\microsoft\office\16.0\word\security'
         }#>

         RegistryPolicyFile 'DELETEKEYS_\Software\Policies\Microsoft\Cryptography'
         {
              ValueName = '**DeleteKeys'
              ValueData = 'Software\Policies\Microsoft\Cryptography\PolicyServers'
              Ensure = 'Absent'
              ValueType = 'String'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\Cryptography'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Cryptography\AutoEnrollment\AEPolicy'
         {
              ValueName = 'AEPolicy'
              ValueData = 7
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\Cryptography\AutoEnrollment'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Cryptography\AutoEnrollment\OfflineExpirationPercent'
         {
              ValueName = 'OfflineExpirationPercent'
              ValueData = 10
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\Cryptography\AutoEnrollment'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Cryptography\AutoEnrollment\OfflineExpirationStoreNames'
         {
              ValueName = 'OfflineExpirationStoreNames'
              ValueData = 'MY'
              ValueType = 'String'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\Cryptography\AutoEnrollment'
         }

         <#
         	This MultiString Value has a value of $null, 
          	Some Security Policies require Registry Values to be $null
          	If you believe ' ' is the correct value for this string, you may change it here.
         #>
         RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Cryptography\PolicyServers\'
         {
              ValueName = ''
              ValueType = 'String'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\Cryptography\PolicyServers'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Cryptography\PolicyServers\Flags'
         {
              ValueName = 'Flags'
              ValueData = 0
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\Cryptography\PolicyServers'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Cryptography\PolicyServers\37c9dc30f207f27f61a2f7c3aed598a6e2920b54\URL'
         {
              ValueName = 'URL'
              ValueData = 'LDAP:'
              ValueType = 'String'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\Cryptography\PolicyServers\37c9dc30f207f27f61a2f7c3aed598a6e2920b54'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Cryptography\PolicyServers\37c9dc30f207f27f61a2f7c3aed598a6e2920b54\PolicyID'
         {
              ValueName = 'PolicyID'
              ValueData = '{D1E74DB3-855C-4FAA-818E-4AAC3889B1CC}'
              ValueType = 'String'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\Cryptography\PolicyServers\37c9dc30f207f27f61a2f7c3aed598a6e2920b54'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Cryptography\PolicyServers\37c9dc30f207f27f61a2f7c3aed598a6e2920b54\FriendlyName'
         {
              ValueName = 'FriendlyName'
              ValueData = 'Active Directory Enrollment Policy'
              ValueType = 'String'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\Cryptography\PolicyServers\37c9dc30f207f27f61a2f7c3aed598a6e2920b54'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Cryptography\PolicyServers\37c9dc30f207f27f61a2f7c3aed598a6e2920b54\Flags'
         {
              ValueName = 'Flags'
              ValueData = 16
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\Cryptography\PolicyServers\37c9dc30f207f27f61a2f7c3aed598a6e2920b54'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Cryptography\PolicyServers\37c9dc30f207f27f61a2f7c3aed598a6e2920b54\AuthFlags'
         {
              ValueName = 'AuthFlags'
              ValueData = 2
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\Cryptography\PolicyServers\37c9dc30f207f27f61a2f7c3aed598a6e2920b54'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Cryptography\PolicyServers\37c9dc30f207f27f61a2f7c3aed598a6e2920b54\Cost'
         {
              ValueName = 'Cost'
              ValueData = 2147483645
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\Cryptography\PolicyServers\37c9dc30f207f27f61a2f7c3aed598a6e2920b54'
         }

         <#
         	This MultiString Value has a value of $null, 
          	Some Security Policies require Registry Values to be $null
          	If you believe ' ' is the correct value for this string, you may change it here.
         #>
         RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\SystemCertificates\ACRS\Certificates\'
         {
              ValueName = ''
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\SystemCertificates\ACRS\Certificates'
         }

         <#
         	This MultiString Value has a value of $null, 
          	Some Security Policies require Registry Values to be $null
          	If you believe ' ' is the correct value for this string, you may change it here.
         #>
         RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\SystemCertificates\ACRS\CRLs\'
         {
              ValueName = ''
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\SystemCertificates\ACRS\CRLs'
         }

         <#
         	This MultiString Value has a value of $null, 
          	Some Security Policies require Registry Values to be $null
          	If you believe ' ' is the correct value for this string, you may change it here.
         #>
         RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\SystemCertificates\ACRS\CTLs\'
         {
              ValueName = ''
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\SystemCertificates\ACRS\CTLs'
         }

         <#
         	This MultiString Value has a value of $null, 
          	Some Security Policies require Registry Values to be $null
          	If you believe ' ' is the correct value for this string, you may change it here.
         #>
         RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\SystemCertificates\CA\Certificates\'
         {
              ValueName = ''
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\SystemCertificates\CA\Certificates'
         }

         <#
         	This MultiString Value has a value of $null, 
          	Some Security Policies require Registry Values to be $null
          	If you believe ' ' is the correct value for this string, you may change it here.
         #>
         RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\SystemCertificates\CA\CRLs\'
         {
              ValueName = ''
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\SystemCertificates\CA\CRLs'
         }

         <#
         	This MultiString Value has a value of $null, 
          	Some Security Policies require Registry Values to be $null
          	If you believe ' ' is the correct value for this string, you may change it here.
         #>
         RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\SystemCertificates\CA\CTLs\'
         {
              ValueName = ''
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\SystemCertificates\CA\CTLs'
         }

         <#
         	This MultiString Value has a value of $null, 
          	Some Security Policies require Registry Values to be $null
          	If you believe ' ' is the correct value for this string, you may change it here.
         #>
         RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\SystemCertificates\Disallowed\Certificates\'
         {
              ValueName = ''
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\SystemCertificates\Disallowed\Certificates'
         }

         <#
         	This MultiString Value has a value of $null, 
          	Some Security Policies require Registry Values to be $null
          	If you believe ' ' is the correct value for this string, you may change it here.
         #>
         RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\SystemCertificates\Disallowed\CRLs\'
         {
              ValueName = ''
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\SystemCertificates\Disallowed\CRLs'
         }

         <#
         	This MultiString Value has a value of $null, 
          	Some Security Policies require Registry Values to be $null
          	If you believe ' ' is the correct value for this string, you may change it here.
         #>
         RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\SystemCertificates\Disallowed\CTLs\'
         {
              ValueName = ''
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\SystemCertificates\Disallowed\CTLs'
         }

         <#
         	This MultiString Value has a value of $null, 
          	Some Security Policies require Registry Values to be $null
          	If you believe ' ' is the correct value for this string, you may change it here.
         #>
         RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\SystemCertificates\DPNGRA\Certificates\'
         {
              ValueName = ''
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\SystemCertificates\DPNGRA\Certificates'
         }

         <#
         	This MultiString Value has a value of $null, 
          	Some Security Policies require Registry Values to be $null
          	If you believe ' ' is the correct value for this string, you may change it here.
         #>
         RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\SystemCertificates\DPNGRA\CRLs\'
         {
              ValueName = ''
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\SystemCertificates\DPNGRA\CRLs'
         }

         <#
         	This MultiString Value has a value of $null, 
          	Some Security Policies require Registry Values to be $null
          	If you believe ' ' is the correct value for this string, you may change it here.
         #>
         RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\SystemCertificates\DPNGRA\CTLs\'
         {
              ValueName = ''
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\SystemCertificates\DPNGRA\CTLs'
         }

         <#
         	This MultiString Value has a value of $null, 
          	Some Security Policies require Registry Values to be $null
          	If you believe ' ' is the correct value for this string, you may change it here.
         #>
         RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\SystemCertificates\FVE\Certificates\'
         {
              ValueName = ''
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\SystemCertificates\FVE\Certificates'
         }

         <#
         	This MultiString Value has a value of $null, 
          	Some Security Policies require Registry Values to be $null
          	If you believe ' ' is the correct value for this string, you may change it here.
         #>
         RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\SystemCertificates\FVE\CRLs\'
         {
              ValueName = ''
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\SystemCertificates\FVE\CRLs'
         }

         <#
         	This MultiString Value has a value of $null, 
          	Some Security Policies require Registry Values to be $null
          	If you believe ' ' is the correct value for this string, you may change it here.
         #>
         RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\SystemCertificates\FVE\CTLs\'
         {
              ValueName = ''
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\SystemCertificates\FVE\CTLs'
         }

         <#
         	This MultiString Value has a value of $null, 
          	Some Security Policies require Registry Values to be $null
          	If you believe ' ' is the correct value for this string, you may change it here.
         #>
         RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\SystemCertificates\FVE_NKP\Certificates\'
         {
              ValueName = ''
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\SystemCertificates\FVE_NKP\Certificates'
         }

         <#
         	This MultiString Value has a value of $null, 
          	Some Security Policies require Registry Values to be $null
          	If you believe ' ' is the correct value for this string, you may change it here.
         #>
         RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\SystemCertificates\FVE_NKP\CRLs\'
         {
              ValueName = ''
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\SystemCertificates\FVE_NKP\CRLs'
         }

         <#
         	This MultiString Value has a value of $null, 
          	Some Security Policies require Registry Values to be $null
          	If you believe ' ' is the correct value for this string, you may change it here.
         #>
         RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\SystemCertificates\FVE_NKP\CTLs\'
         {
              ValueName = ''
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\SystemCertificates\FVE_NKP\CTLs'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\SystemCertificates\Root\Certificates\1B305A45D56B550DF3FEFC679A4BB773B8D9FC34\Blob'
         {
              ValueName = 'Blob'
              ValueData = '0400000001000000100000002CC4CE75527A593CFC16B40D48FD6BE10F00000001000000200000000ED2679908F62EEBB9E51F8FA9005D59E9896FA179B08D8A600684004D0816BD1400000001000000140000006CAF800DBF7A151D0DAA85A795EABFDA72556861190000000100000010000000DB325FEB12A40221C69074FD9BDFFBA55C0000000100000004000000000800000300000001000000140000001B305A45D56B550DF3FEFC679A4BB773B8D9FC3420000000010000005D0300003082035930820241A0030201020210666E7290BA6EF98B496D8DAF1E8DC2F9300D06092A864886F70D01010B0500303F31153013060A0992268993F22C6401191605696E74726131143012060A0992268993F22C64011916046D7961643110300E0603550403130746524143413031301E170D3231303431363138303132335A170D3331303431363138313132335A303F31153013060A0992268993F22C6401191605696E74726131143012060A0992268993F22C64011916046D7961643110300E060355040313074652414341303130820122300D06092A864886F70D01010105000382010F003082010A0282010100CE82A5E679F554A420D533CF45A3DB29787FCD6A0D3435C3B90EBE022985680EBC57710E08DD036249542909E4E18DFA79A5340107765869C011641D4461D54931250A710DE19FE4370A1777490928259C1BFCD097C1C674991898D3F7B1C298DD607CDBB796DABBEC27BEF569677D04D6B04C0EE450CF5A931CD368DCEE72DBA382EFF46E7839EC619B18D3DE8390DE7752E55C60ED4728752D0DCBFC5D302E27D7A91254466F235E7A5825ACB2139EFE0FD53443FBE0133538186278C3ADF2D1812716C8ADB2058CFDBDE1C46CFF02E31B7BD512BEE279928A592DF347F9CEDE8F828AF603BB2823D346096DD18B7C4D20870931BA47C7048CE9CAD753B5D10203010001A351304F300B0603551D0F040403020186300F0603551D130101FF040530030101FF301D0603551D0E041604146CAF800DBF7A151D0DAA85A795EABFDA72556861301006092B06010401823715010403020100300D06092A864886F70D01010B05000382010100592F46F21C26DDFA4E46B107E89E83E3449C67AD7AF210EEE0D5622CCE351AA79C2EFF4936014F8466F7A18E7334A451D1E3573E3B512B716A98F580BD92E183C5B5C06BBCE5EC17070420545156EC62F9038B7F7EC6F8A724C497E12EC7094F21733EF225E4E5B95A41C42AD09F0DAA2C01297CEBE382DF85969F0B743D2FDF3EE0188CA6E4E195E29A3A6C1283A971F19430E8DC0BA6C08AE63555C7B79100ED6CB8D62025A2780213E89502BF75948DD45FFED526FAAAAC4165E162B15937C63104E5910396A5FEAED4C02710A5D687B612D58DD7FAA3937F0A2EBF03AC4FF8DDC814431FCA9DB3F46FAE2606E34739C8558FE5C5EC8830A0CB5201B7FC3A'
              ValueType = 'Binary'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\SystemCertificates\Root\Certificates\1B305A45D56B550DF3FEFC679A4BB773B8D9FC34'
         }

         <#
         	This MultiString Value has a value of $null, 
          	Some Security Policies require Registry Values to be $null
          	If you believe ' ' is the correct value for this string, you may change it here.
         #>
         RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\SystemCertificates\Root\CRLs\'
         {
              ValueName = ''
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\SystemCertificates\Root\CRLs'
         }

         <#
         	This MultiString Value has a value of $null, 
          	Some Security Policies require Registry Values to be $null
          	If you believe ' ' is the correct value for this string, you may change it here.
         #>
         RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\SystemCertificates\Root\CTLs\'
         {
              ValueName = ''
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\SystemCertificates\Root\CTLs'
         }

         <#
         	This MultiString Value has a value of $null, 
          	Some Security Policies require Registry Values to be $null
          	If you believe ' ' is the correct value for this string, you may change it here.
         #>
         RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\SystemCertificates\Trust\Certificates\'
         {
              ValueName = ''
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\SystemCertificates\Trust\Certificates'
         }

         <#
         	This MultiString Value has a value of $null, 
          	Some Security Policies require Registry Values to be $null
          	If you believe ' ' is the correct value for this string, you may change it here.
         #>
         RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\SystemCertificates\Trust\CRLs\'
         {
              ValueName = ''
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\SystemCertificates\Trust\CRLs'
         }

         <#
         	This MultiString Value has a value of $null, 
          	Some Security Policies require Registry Values to be $null
          	If you believe ' ' is the correct value for this string, you may change it here.
         #>
         RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\SystemCertificates\Trust\CTLs\'
         {
              ValueName = ''
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\SystemCertificates\Trust\CTLs'
         }

         <#
         	This MultiString Value has a value of $null, 
          	Some Security Policies require Registry Values to be $null
          	If you believe ' ' is the correct value for this string, you may change it here.
         #>
         RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\SystemCertificates\TrustedPeople\Certificates\'
         {
              ValueName = ''
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\SystemCertificates\TrustedPeople\Certificates'
         }

         <#
         	This MultiString Value has a value of $null, 
          	Some Security Policies require Registry Values to be $null
          	If you believe ' ' is the correct value for this string, you may change it here.
         #>
         RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\SystemCertificates\TrustedPeople\CRLs\'
         {
              ValueName = ''
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\SystemCertificates\TrustedPeople\CRLs'
         }

         <#
         	This MultiString Value has a value of $null, 
          	Some Security Policies require Registry Values to be $null
          	If you believe ' ' is the correct value for this string, you may change it here.
         #>
         RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\SystemCertificates\TrustedPeople\CTLs\'
         {
              ValueName = ''
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\SystemCertificates\TrustedPeople\CTLs'
         }

         <#
         	This MultiString Value has a value of $null, 
          	Some Security Policies require Registry Values to be $null
          	If you believe ' ' is the correct value for this string, you may change it here.
         #>
         RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\SystemCertificates\TrustedPublisher\Certificates\'
         {
              ValueName = ''
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\SystemCertificates\TrustedPublisher\Certificates'
         }

         <#
         	This MultiString Value has a value of $null, 
          	Some Security Policies require Registry Values to be $null
          	If you believe ' ' is the correct value for this string, you may change it here.
         #>
         RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\SystemCertificates\TrustedPublisher\CRLs\'
         {
              ValueName = ''
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\SystemCertificates\TrustedPublisher\CRLs'
         }

         <#
         	This MultiString Value has a value of $null, 
          	Some Security Policies require Registry Values to be $null
          	If you believe ' ' is the correct value for this string, you may change it here.
         #>
         RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\SystemCertificates\TrustedPublisher\CTLs\'
         {
              ValueName = ''
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\SystemCertificates\TrustedPublisher\CTLs'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\DataCollection\AllowTelemetry'
         {
              ValueName = 'AllowTelemetry'
              ValueData = 0
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\Windows\DataCollection'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\Explorer\HideRecentlyAddedApps'
         {
              ValueName = 'HideRecentlyAddedApps'
              ValueData = 1
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\Windows\Explorer'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\System\UserPolicyMode'
         {
              ValueName = 'UserPolicyMode'
              ValueData = 1
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\Windows\System'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\Windows Search\AllowCloudSearch'
         {
              ValueName = 'AllowCloudSearch'
              ValueData = 0
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\Windows\Windows Search'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\Windows Search\AllowCortana'
         {
              ValueName = 'AllowCortana'
              ValueData = 0
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\Windows\Windows Search'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\Windows Search\AllowCortanaAboveLock'
         {
              ValueName = 'AllowCortanaAboveLock'
              ValueData = 0
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\Windows\Windows Search'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\Windows Search\DisableWebSearch'
         {
              ValueName = 'DisableWebSearch'
              ValueData = 1
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\Windows\Windows Search'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\Windows Search\ConnectedSearchUseWeb'
         {
              ValueName = 'ConnectedSearchUseWeb'
              ValueData = 0
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\Windows\Windows Search'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\Windows Search\ConnectedSearchUseWebOverMeteredConnections'
         {
              ValueName = 'ConnectedSearchUseWebOverMeteredConnections'
              ValueData = 0
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\Windows\Windows Search'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows NT\Terminal Services\MaxIdleTime'
         {
              ValueName = 'MaxIdleTime'
              ValueData = 7200000
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\Windows NT\Terminal Services'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows NT\Terminal Services\MaxDisconnectionTime'
         {
              ValueName = 'MaxDisconnectionTime'
              ValueData = 10800000
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\Windows NT\Terminal Services'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\Software\FSLogix\Logging\LogDir'
         {
              ValueName = 'LogDir'
              ValueData = 'C:\Windows\Logs'
              ValueType = 'String'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\FSLogix\Logging'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\Software\FSLogix\Logging\LoggingEnabled'
         {
              ValueName = 'LoggingEnabled'
              ValueData = 2
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\FSLogix\Logging'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\Software\FSLogix\Logging\Profile'
         {
              ValueName = 'Profile'
              ValueData = 1
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\FSLogix\Logging'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\Software\FSLogix\Profiles\ProfileType'
         {
              ValueName = 'ProfileType'
              ValueData = 3
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\FSLogix\Profiles'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\Software\FSLogix\Profiles\Enabled'
         {
              ValueName = 'Enabled'
              ValueData = 1
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\FSLogix\Profiles'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\Software\FSLogix\Profiles\DeleteLocalProfileWhenVHDShouldApply'
         {
              ValueName = 'DeleteLocalProfileWhenVHDShouldApply'
              ValueData = 1
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\FSLogix\Profiles'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\Software\FSLogix\Profiles\SizeInMBs'
         {
              ValueName = 'SizeInMBs'
              ValueData = 30000
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\FSLogix\Profiles'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\Software\FSLogix\Profiles\VolumeType'
         {
              ValueName = 'VolumeType'
              ValueData = 'VHDX'
              ValueType = 'String'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\FSLogix\Profiles'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\Software\FSLogix\Profiles\PreventLoginWithFailure'
         {
              ValueName = 'PreventLoginWithFailure'
              ValueData = 1
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\FSLogix\Profiles'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\Software\FSLogix\Profiles\PreventLoginWithTempProfile'
         {
              ValueName = 'PreventLoginWithTempProfile'
              ValueData = 1
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\FSLogix\Profiles'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\Software\FSLogix\Profiles\LockedRetryCount'
         {
              ValueName = 'LockedRetryCount'
              ValueData = 12
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\FSLogix\Profiles'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\Software\FSLogix\Profiles\LockedRetryInterval'
         {
              ValueName = 'LockedRetryInterval'
              ValueData = 12
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\FSLogix\Profiles'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\Software\FSLogix\Profiles\RoamSearch'
         {
              ValueName = 'RoamSearch'
              ValueData = 2
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\FSLogix\Profiles'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\Software\FSLogix\Profiles\SetTempToLocalPath'
         {
              ValueName = 'SetTempToLocalPath'
              ValueData = 3
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\FSLogix\Profiles'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\Software\FSLogix\Profiles\VHDLocations'
         {
              ValueName = 'VHDLocations'
              ValueData = '\\FRADC01\profiles'
              ValueType = 'String'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\FSLogix\Profiles'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\WindowsUpdate\ElevateNonAdmins'
         {
              ValueName = 'ElevateNonAdmins'
              ValueData = 0
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\Windows\WindowsUpdate'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\WindowsUpdate\SetDisablePauseUXAccess'
         {
              ValueName = 'SetDisablePauseUXAccess'
              ValueData = 1
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\Windows\WindowsUpdate'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\WindowsUpdate\SetActiveHoursMaxRange'
         {
              ValueName = 'SetActiveHoursMaxRange'
              ValueData = 1
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\Windows\WindowsUpdate'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\WindowsUpdate\ActiveHoursMaxRange'
         {
              ValueName = 'ActiveHoursMaxRange'
              ValueData = 18
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\Windows\WindowsUpdate'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\WindowsUpdate\SetActiveHours'
         {
              ValueName = 'SetActiveHours'
              ValueData = 1
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\Windows\WindowsUpdate'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\WindowsUpdate\ActiveHoursStart'
         {
              ValueName = 'ActiveHoursStart'
              ValueData = 8
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\Windows\WindowsUpdate'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\WindowsUpdate\ActiveHoursEnd'
         {
              ValueName = 'ActiveHoursEnd'
              ValueData = 18
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\Windows\WindowsUpdate'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\WindowsUpdate\SetAutoRestartNotificationDisable'
         {
              ValueName = 'SetAutoRestartNotificationDisable'
              ValueData = 0
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\Windows\WindowsUpdate'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\WindowsUpdate\ManagePreviewBuilds'
         {
              ValueName = 'ManagePreviewBuilds'
              ValueData = 1
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\Windows\WindowsUpdate'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\WindowsUpdate\ManagePreviewBuildsPolicyValue'
         {
              ValueName = 'ManagePreviewBuildsPolicyValue'
              ValueData = 0
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\Windows\WindowsUpdate'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\WindowsUpdate\DeferFeatureUpdates'
         {
              ValueName = 'DeferFeatureUpdates'
              ValueData = 1
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\Windows\WindowsUpdate'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\WindowsUpdate\BranchReadinessLevel'
         {
              ValueName = 'BranchReadinessLevel'
              ValueData = 32
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\Windows\WindowsUpdate'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\WindowsUpdate\DeferFeatureUpdatesPeriodInDays'
         {
              ValueName = 'DeferFeatureUpdatesPeriodInDays'
              ValueData = 250
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\Windows\WindowsUpdate'
         }

         <#
         	This MultiString Value has a value of $null, 
          	Some Security Policies require Registry Values to be $null
          	If you believe ' ' is the correct value for this string, you may change it here.
         #>
         RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\WindowsUpdate\PauseFeatureUpdatesStartTime'
         {
              ValueName = 'PauseFeatureUpdatesStartTime'
              ValueData = $null
              ValueType = 'String'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\Windows\WindowsUpdate'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\WindowsUpdate\DeferQualityUpdates'
         {
              ValueName = 'DeferQualityUpdates'
              ValueData = 1
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\Windows\WindowsUpdate'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\WindowsUpdate\DeferQualityUpdatesPeriodInDays'
         {
              ValueName = 'DeferQualityUpdatesPeriodInDays'
              ValueData = 21
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\Windows\WindowsUpdate'
         }

         <#
         	This MultiString Value has a value of $null, 
          	Some Security Policies require Registry Values to be $null
          	If you believe ' ' is the correct value for this string, you may change it here.
         #>
         RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\WindowsUpdate\PauseQualityUpdatesStartTime'
         {
              ValueName = 'PauseQualityUpdatesStartTime'
              ValueData = $null
              ValueType = 'String'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\Windows\WindowsUpdate'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\WindowsUpdate\AU\AutoInstallMinorUpdates'
         {
              ValueName = 'AutoInstallMinorUpdates'
              ValueData = 0
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\Windows\WindowsUpdate\AU'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\WindowsUpdate\AU\NoAutoUpdate'
         {
              ValueName = 'NoAutoUpdate'
              ValueData = 1
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\Windows\WindowsUpdate\AU'
         }

         RegistryPolicyFile 'DEL_\Software\Policies\Microsoft\Windows\WindowsUpdate\AU\AUOptions'
         {
              ValueName = 'AUOptions'
              ValueData = ''
              Ensure = 'Absent'
              ValueType = 'String'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\Windows\WindowsUpdate\AU'
         }

         RegistryPolicyFile 'DEL_\Software\Policies\Microsoft\Windows\WindowsUpdate\AU\AutomaticMaintenanceEnabled'
         {
              ValueName = 'AutomaticMaintenanceEnabled'
              ValueData = ''
              Ensure = 'Absent'
              ValueType = 'String'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\Windows\WindowsUpdate\AU'
         }

         RegistryPolicyFile 'DEL_\Software\Policies\Microsoft\Windows\WindowsUpdate\AU\ScheduledInstallDay'
         {
              ValueName = 'ScheduledInstallDay'
              ValueData = ''
              Ensure = 'Absent'
              ValueType = 'String'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\Windows\WindowsUpdate\AU'
         }

         RegistryPolicyFile 'DEL_\Software\Policies\Microsoft\Windows\WindowsUpdate\AU\ScheduledInstallTime'
         {
              ValueName = 'ScheduledInstallTime'
              ValueData = ''
              Ensure = 'Absent'
              ValueType = 'String'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\Windows\WindowsUpdate\AU'
         }

         RegistryPolicyFile 'DEL_\Software\Policies\Microsoft\Windows\WindowsUpdate\AU\ScheduledInstallEveryWeek'
         {
              ValueName = 'ScheduledInstallEveryWeek'
              ValueData = ''
              Ensure = 'Absent'
              ValueType = 'String'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\Windows\WindowsUpdate\AU'
         }

         RegistryPolicyFile 'DEL_\Software\Policies\Microsoft\Windows\WindowsUpdate\AU\ScheduledInstallFirstWeek'
         {
              ValueName = 'ScheduledInstallFirstWeek'
              ValueData = ''
              Ensure = 'Absent'
              ValueType = 'String'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\Windows\WindowsUpdate\AU'
         }

         RegistryPolicyFile 'DEL_\Software\Policies\Microsoft\Windows\WindowsUpdate\AU\ScheduledInstallSecondWeek'
         {
              ValueName = 'ScheduledInstallSecondWeek'
              ValueData = ''
              Ensure = 'Absent'
              ValueType = 'String'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\Windows\WindowsUpdate\AU'
         }

         RegistryPolicyFile 'DEL_\Software\Policies\Microsoft\Windows\WindowsUpdate\AU\ScheduledInstallThirdWeek'
         {
              ValueName = 'ScheduledInstallThirdWeek'
              ValueData = ''
              Ensure = 'Absent'
              ValueType = 'String'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\Windows\WindowsUpdate\AU'
         }

         RegistryPolicyFile 'DEL_\Software\Policies\Microsoft\Windows\WindowsUpdate\AU\ScheduledInstallFourthWeek'
         {
              ValueName = 'ScheduledInstallFourthWeek'
              ValueData = ''
              Ensure = 'Absent'
              ValueType = 'String'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\Windows\WindowsUpdate\AU'
         }

         RegistryPolicyFile 'DEL_\Software\Policies\Microsoft\Windows\WindowsUpdate\AU\AllowMUUpdateService'
         {
              ValueName = 'AllowMUUpdateService'
              ValueData = ''
              Ensure = 'Absent'
              ValueType = 'String'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\Windows\WindowsUpdate\AU'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\WindowsUpdate\AU\IncludeRecommendedUpdates'
         {
              ValueName = 'IncludeRecommendedUpdates'
              ValueData = 1
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\Windows\WindowsUpdate\AU'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\Personalization\LockScreenImage'
         {
              ValueName = 'LockScreenImage'
              ValueData = '\\fradc01\myad\cicd\wallpaper.png'
              ValueType = 'String'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\Windows\Personalization'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\Personalization\LockScreenOverlaysDisabled'
         {
              ValueName = 'LockScreenOverlaysDisabled'
              ValueData = 1
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\Windows\Personalization'
         }

         <#RegistryPolicyFile 'Registry(POL): HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\System\Wallpaper'
         {
              ValueName = 'Wallpaper'
              ValueData = '\\fradc01\myad\cicd\wallpaper.png'
              ValueType = 'String'
              TargetType = 'ComputerConfiguration'
              Key = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\System'
         }#>

         <#RegistryPolicyFile 'Registry(POL): HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\System\WallpaperStyle'
         {
              ValueName = 'WallpaperStyle'
              ValueData = '5'
              ValueType = 'String'
              TargetType = 'ComputerConfiguration'
              Key = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\System'
         }#>

         <#RegistryPolicyFile 'Registry(POL): HKCU:\Software\Policies\Microsoft\Windows\Control Panel\Desktop\ScreenSaveActive'
         {
              ValueName = 'ScreenSaveActive'
              ValueData = '1'
              ValueType = 'String'
              TargetType = 'ComputerConfiguration'
              Key = 'HKCU:\Software\Policies\Microsoft\Windows\Control Panel\Desktop'
         }#>

         <#RegistryPolicyFile 'Registry(POL): HKCU:\Software\Policies\Microsoft\Windows\Control Panel\Desktop\SCRNSAVE.EXE'
         {
              ValueName = 'SCRNSAVE.EXE'
              ValueData = 'Mystify.scr'
              ValueType = 'String'
              TargetType = 'ComputerConfiguration'
              Key = 'HKCU:\Software\Policies\Microsoft\Windows\Control Panel\Desktop'
         }#>

         <#RegistryPolicyFile 'Registry(POL): HKCU:\Software\Policies\Microsoft\Windows\Control Panel\Desktop\ScreenSaverIsSecure'
         {
              ValueName = 'ScreenSaverIsSecure'
              ValueData = '1'
              ValueType = 'String'
              TargetType = 'ComputerConfiguration'
              Key = 'HKCU:\Software\Policies\Microsoft\Windows\Control Panel\Desktop'
         }#>

         <#RegistryPolicyFile 'Registry(POL): HKCU:\Software\Policies\Microsoft\Windows\Control Panel\Desktop\ScreenSaveTimeOut'
         {
              ValueName = 'ScreenSaveTimeOut'
              ValueData = '900'
              ValueType = 'String'
              TargetType = 'ComputerConfiguration'
              Key = 'HKCU:\Software\Policies\Microsoft\Windows\Control Panel\Desktop'
         }#>

         RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Edge\AllowSurfGame'
         {
              ValueName = 'AllowSurfGame'
              ValueData = 0
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\Edge'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Edge\UserFeedbackAllowed'
         {
              ValueName = 'UserFeedbackAllowed'
              ValueData = 0
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\Edge'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Edge\FamilySafetySettingsEnabled'
         {
              ValueName = 'FamilySafetySettingsEnabled'
              ValueData = 0
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\Edge'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Edge\PaymentMethodQueryEnabled'
         {
              ValueName = 'PaymentMethodQueryEnabled'
              ValueData = 0
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\Edge'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Edge\AutofillAddressEnabled'
         {
              ValueName = 'AutofillAddressEnabled'
              ValueData = 0
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\Edge'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Edge\AutofillCreditCardEnabled'
         {
              ValueName = 'AutofillCreditCardEnabled'
              ValueData = 0
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\Edge'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Edge\BrowserGuestModeEnabled'
         {
              ValueName = 'BrowserGuestModeEnabled'
              ValueData = 0
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\Edge'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Edge\SearchSuggestEnabled'
         {
              ValueName = 'SearchSuggestEnabled'
              ValueData = 0
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\Edge'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Edge\TranslateEnabled'
         {
              ValueName = 'TranslateEnabled'
              ValueData = 0
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\Edge'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Edge\FavoritesBarEnabled'
         {
              ValueName = 'FavoritesBarEnabled'
              ValueData = 1
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\Edge'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Edge\ForceGoogleSafeSearch'
         {
              ValueName = 'ForceGoogleSafeSearch'
              ValueData = 1
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\Edge'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Edge\HideFirstRunExperience'
         {
              ValueName = 'HideFirstRunExperience'
              ValueData = 1
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\Edge'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Edge\DefaultSearchProviderSearchURL'
         {
              ValueName = 'DefaultSearchProviderSearchURL'
              ValueData = '{google:baseURL}search?q={searchTerms}&{google:RLZ}{google:originalQueryForSuggestion}{google:assistedQueryStats}{google:searchFieldtrialParameter}{google:searchClient}{google:sourceId}ie={inputEncoding}'
              ValueType = 'String'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\Edge'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Edge\HomepageLocation'
         {
              ValueName = 'HomepageLocation'
              ValueData = 'https://www.google.de'
              ValueType = 'String'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\Edge'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Edge\NewTabPageLocation'
         {
              ValueName = 'NewTabPageLocation'
              ValueData = 'https://www.google.de'
              ValueType = 'String'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\Edge'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Edge\ShowHomeButton'
         {
              ValueName = 'ShowHomeButton'
              ValueData = 0
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\Edge'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Edge\ConfigureDoNotTrack'
         {
              ValueName = 'ConfigureDoNotTrack'
              ValueData = 1
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\Edge'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Edge\InPrivateModeAvailability'
         {
              ValueName = 'InPrivateModeAvailability'
              ValueData = 0
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\Edge'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Edge\SpeechRecognitionEnabled'
         {
              ValueName = 'SpeechRecognitionEnabled'
              ValueData = 0
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\Edge'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Edge\SmartScreenEnabled'
         {
              ValueName = 'SmartScreenEnabled'
              ValueData = 1
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\Edge'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Edge\TrackingPrevention'
         {
              ValueName = 'TrackingPrevention'
              ValueData = 2
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\Edge'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Edge\ImportBrowserSettings'
         {
              ValueName = 'ImportBrowserSettings'
              ValueData = 0
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\Edge'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Edge\ImportExtensions'
         {
              ValueName = 'ImportExtensions'
              ValueData = 0
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\Edge'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Edge\DiagnosticData'
         {
              ValueName = 'DiagnosticData'
              ValueData = 0
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\Edge'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Edge\EditFavoritesEnabled'
         {
              ValueName = 'EditFavoritesEnabled'
              ValueData = 1
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\Edge'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Edge\MetricsReportingEnabled'
         {
              ValueName = 'MetricsReportingEnabled'
              ValueData = 0
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\Edge'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Edge\EdgeShoppingAssistantEnabled'
         {
              ValueName = 'EdgeShoppingAssistantEnabled'
              ValueData = 0
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\Edge'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Edge\DefaultCookiesSetting'
         {
              ValueName = 'DefaultCookiesSetting'
              ValueData = 1
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\Edge'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Edge\BlockThirdPartyCookies'
         {
              ValueName = 'BlockThirdPartyCookies'
              ValueData = 0
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\Edge'
         }

         <#RegistryPolicyFile 'DELVALS_\Software\Policies\Microsoft\Edge\RestoreOnStartupURLs'
         {
              ValueName = ''
              Exclusive = $True
              ValueData = ''
              Ensure = 'Present'
              ValueType = 'String'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\Edge\RestoreOnStartupURLs'
         }#>

         RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Edge\RestoreOnStartupURLs\1'
         {
              ValueName = '1'
              ValueData = 'https://www.google.de'
              ValueType = 'String'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\Edge\RestoreOnStartupURLs'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\EdgeUpdate\Update{56EB18F8-B008-4CBD-B6D2-8C97FE7E9062}'
         {
              ValueName = 'Update{56EB18F8-B008-4CBD-B6D2-8C97FE7E9062}'
              ValueData = 3
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\EdgeUpdate'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\MicrosoftEdge\PhishingFilter\EnabledV9'
         {
              ValueName = 'EnabledV9'
              ValueData = 1
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\MicrosoftEdge\PhishingFilter'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\MicrosoftEdge\PhishingFilter\PreventOverride'
         {
              ValueName = 'PreventOverride'
              ValueData = 1
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\MicrosoftEdge\PhishingFilter'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\SystemCertificates\EFS\EFSBlob'
         {
              ValueName = 'EFSBlob'
              ValueData = '0100010001000000C1030000BD0300001C00000002000000850300003800000000000000000000000105000000000005150000002D1E817A1842409235D12A74F40100003082038130820269A003020102021011D1C8CF4122F9B24D5997DBBBEFF624300D06092A864886F70D01010505003050311630140603550403130D61646D696E6973747261746F72310C300A0603550407130345465331283026060355040B131F4546532046696C6520456E6372797074696F6E2043657274696669636174653020170D3231303431363137353235385A180F32313231303332333137353235385A3050311630140603550403130D61646D696E6973747261746F72310C300A0603550407130345465331283026060355040B131F4546532046696C6520456E6372797074696F6E20436572746966696361746530820122300D06092A864886F70D01010105000382010F003082010A0282010100B0D8DB6F2C7EEA58A89A57275A75ED20A59E42C33D32A00B93B8FC05DBE1A3994A51A193DB81DC54541C02B3EA6F53FE56544CA76F961E12BA26B56B4AEBC8A424A1150A1DF7839751C71E7919703F1E0071F8F494778AA8CA7FB7F4631B122F75AD86D3C5E8B2BD7D9C7C098829F0CE6037D55BB29E93AC1FA4F46D04044586B5BBF465ADB0CA5D2AB2A6D2A9D101A0BDD2E93C21F58574F5487558512616CF183867A12E7D69A167494220C3AA8D37B0EB50370D10A38BC6EDF5494E352BE26013AC20828E544C47ED0E9032DDA178EE2037F64A0D1FDB216F50B741DA4AB182C8D7ECC6B5345C4FFAC9A4F66BC499E60034059ADDE1AEE0EC2EFF631C00310203010001A355305330160603551D25040F300D060B2B0601040182370A030401302E0603551D1104273025A023060A2B060104018237140203A0150C1361646D696E6973747261746F72404D5941440030090603551D1304023000300D06092A864886F70D010105050003820101009BC43A815353CA9E5FDD5256768BEA6FC8FEBF559DFEF10834B182CFC51053622258410DEB29D85459C323885A55F95C9098BC52BEBFA9D6072378420EAF49ED8446751E51554FFF868F03E63EF32B107EF3932E99098511DCC47F4E2F9970B53E27BEC6B029C89D962E27D18BFC802898B9A608B9C0833D26CB8D9FEDF6F5D1C854132FED09905185FF520A22964EC24B3260AEE7F35B6D04A91529F60851946DA85E0B54D2A676C9046DD290EF6814C10B2C6837647F029E2D77D6067B2A8DA898A0B1A9D8CF58B1E8991E294B62D68265378B7541D7FD5086D73E3E00377082A5E78800EFB320B72B7B046172B8BDD032DA486A2F0F55334766C231C1E2EF'
              ValueType = 'Binary'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\SystemCertificates\EFS'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\SystemCertificates\EFS\Certificates\CDE027E73DD0C7A1EBBD9B140ACFC9F589C63D7C\Blob'
         {
              ValueName = 'Blob'
              ValueData = '0200000001000000CC0000001C0000006C0000000100000000000000000000000000000001000000300037006600360065003300640066002D0032006500340036002D0034003300370037002D0061006500610066002D0030003900380065003300630066003100300039006200310000000000000000004D006900630072006F0073006F0066007400200045006E00680061006E006300650064002000430072007900700074006F0067007200610070006800690063002000500072006F00760069006400650072002000760031002E00300000000000030000000100000014000000CDE027E73DD0C7A1EBBD9B140ACFC9F589C63D7C2000000001000000850300003082038130820269A003020102021011D1C8CF4122F9B24D5997DBBBEFF624300D06092A864886F70D01010505003050311630140603550403130D61646D696E6973747261746F72310C300A0603550407130345465331283026060355040B131F4546532046696C6520456E6372797074696F6E2043657274696669636174653020170D3231303431363137353235385A180F32313231303332333137353235385A3050311630140603550403130D61646D696E6973747261746F72310C300A0603550407130345465331283026060355040B131F4546532046696C6520456E6372797074696F6E20436572746966696361746530820122300D06092A864886F70D01010105000382010F003082010A0282010100B0D8DB6F2C7EEA58A89A57275A75ED20A59E42C33D32A00B93B8FC05DBE1A3994A51A193DB81DC54541C02B3EA6F53FE56544CA76F961E12BA26B56B4AEBC8A424A1150A1DF7839751C71E7919703F1E0071F8F494778AA8CA7FB7F4631B122F75AD86D3C5E8B2BD7D9C7C098829F0CE6037D55BB29E93AC1FA4F46D04044586B5BBF465ADB0CA5D2AB2A6D2A9D101A0BDD2E93C21F58574F5487558512616CF183867A12E7D69A167494220C3AA8D37B0EB50370D10A38BC6EDF5494E352BE26013AC20828E544C47ED0E9032DDA178EE2037F64A0D1FDB216F50B741DA4AB182C8D7ECC6B5345C4FFAC9A4F66BC499E60034059ADDE1AEE0EC2EFF631C00310203010001A355305330160603551D25040F300D060B2B0601040182370A030401302E0603551D1104273025A023060A2B060104018237140203A0150C1361646D696E6973747261746F72404D5941440030090603551D1304023000300D06092A864886F70D010105050003820101009BC43A815353CA9E5FDD5256768BEA6FC8FEBF559DFEF10834B182CFC51053622258410DEB29D85459C323885A55F95C9098BC52BEBFA9D6072378420EAF49ED8446751E51554FFF868F03E63EF32B107EF3932E99098511DCC47F4E2F9970B53E27BEC6B029C89D962E27D18BFC802898B9A608B9C0833D26CB8D9FEDF6F5D1C854132FED09905185FF520A22964EC24B3260AEE7F35B6D04A91529F60851946DA85E0B54D2A676C9046DD290EF6814C10B2C6837647F029E2D77D6067B2A8DA898A0B1A9D8CF58B1E8991E294B62D68265378B7541D7FD5086D73E3E00377082A5E78800EFB320B72B7B046172B8BDD032DA486A2F0F55334766C231C1E2EF'
              ValueType = 'Binary'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\SystemCertificates\EFS\Certificates\CDE027E73DD0C7A1EBBD9B140ACFC9F589C63D7C'
         }

         <#
         	This MultiString Value has a value of $null, 
          	Some Security Policies require Registry Values to be $null
          	If you believe ' ' is the correct value for this string, you may change it here.
         #>
         RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\SystemCertificates\EFS\CRLs\'
         {
              ValueName = ''
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\SystemCertificates\EFS\CRLs'
         }

         <#
         	This MultiString Value has a value of $null, 
          	Some Security Policies require Registry Values to be $null
          	If you believe ' ' is the correct value for this string, you may change it here.
         #>
         RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\SystemCertificates\EFS\CTLs\'
         {
              ValueName = ''
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\SystemCertificates\EFS\CTLs'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\Explorer\NoNewAppAlert'
         {
              ValueName = 'NoNewAppAlert'
              ValueData = 1
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\Windows\Explorer'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\System\DefaultAssociationsConfiguration'
         {
              ValueName = 'DefaultAssociationsConfiguration'
              ValueData = '\\fradc01\myad\cicd\defaultapps.xml'
              ValueType = 'String'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\Windows\System'
         }

         <#RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\WindowsUpdate\ElevateNonAdmins'
         {
              ValueName = 'ElevateNonAdmins'
              ValueData = 0
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\Windows\WindowsUpdate'
         }#>

         <#RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\WindowsUpdate\SetDisablePauseUXAccess'
         {
              ValueName = 'SetDisablePauseUXAccess'
              ValueData = 1
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\Windows\WindowsUpdate'
         }#>

         <#RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\WindowsUpdate\SetActiveHoursMaxRange'
         {
              ValueName = 'SetActiveHoursMaxRange'
              ValueData = 1
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\Windows\WindowsUpdate'
         }#>

         <#RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\WindowsUpdate\ActiveHoursMaxRange'
         {
              ValueName = 'ActiveHoursMaxRange'
              ValueData = 18
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\Windows\WindowsUpdate'
         }#>

         <#RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\WindowsUpdate\SetActiveHours'
         {
              ValueName = 'SetActiveHours'
              ValueData = 1
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\Windows\WindowsUpdate'
         }#>

         <#RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\WindowsUpdate\ActiveHoursStart'
         {
              ValueName = 'ActiveHoursStart'
              ValueData = 8
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\Windows\WindowsUpdate'
         }#>

         <#RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\WindowsUpdate\ActiveHoursEnd'
         {
              ValueName = 'ActiveHoursEnd'
              ValueData = 18
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\Windows\WindowsUpdate'
         }#>

         <#RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\WindowsUpdate\SetAutoRestartNotificationDisable'
         {
              ValueName = 'SetAutoRestartNotificationDisable'
              ValueData = 0
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\Windows\WindowsUpdate'
         }#>

         <#RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\WindowsUpdate\ManagePreviewBuilds'
         {
              ValueName = 'ManagePreviewBuilds'
              ValueData = 1
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\Windows\WindowsUpdate'
         }#>

         <#RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\WindowsUpdate\ManagePreviewBuildsPolicyValue'
         {
              ValueName = 'ManagePreviewBuildsPolicyValue'
              ValueData = 0
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\Windows\WindowsUpdate'
         }#>

         <#RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\WindowsUpdate\DeferFeatureUpdates'
         {
              ValueName = 'DeferFeatureUpdates'
              ValueData = 1
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\Windows\WindowsUpdate'
         }#>

         <#RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\WindowsUpdate\BranchReadinessLevel'
         {
              ValueName = 'BranchReadinessLevel'
              ValueData = 32
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\Windows\WindowsUpdate'
         }#>

         <#RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\WindowsUpdate\DeferFeatureUpdatesPeriodInDays'
         {
              ValueName = 'DeferFeatureUpdatesPeriodInDays'
              ValueData = 250
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\Windows\WindowsUpdate'
         }#>

         <#
         	This MultiString Value has a value of $null, 
          	Some Security Policies require Registry Values to be $null
          	If you believe ' ' is the correct value for this string, you may change it here.
         #>
         <#RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\WindowsUpdate\PauseFeatureUpdatesStartTime'
         {
              ValueName = 'PauseFeatureUpdatesStartTime'
              ValueData = $null
              ValueType = 'String'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\Windows\WindowsUpdate'
         }#>

         <#RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\WindowsUpdate\DeferQualityUpdates'
         {
              ValueName = 'DeferQualityUpdates'
              ValueData = 1
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\Windows\WindowsUpdate'
         }#>

         <#RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\WindowsUpdate\DeferQualityUpdatesPeriodInDays'
         {
              ValueName = 'DeferQualityUpdatesPeriodInDays'
              ValueData = 21
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\Windows\WindowsUpdate'
         }#>

         <#
         	This MultiString Value has a value of $null, 
          	Some Security Policies require Registry Values to be $null
          	If you believe ' ' is the correct value for this string, you may change it here.
         #>
         <#RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\WindowsUpdate\PauseQualityUpdatesStartTime'
         {
              ValueName = 'PauseQualityUpdatesStartTime'
              ValueData = $null
              ValueType = 'String'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\Windows\WindowsUpdate'
         }#>

         <#RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\WindowsUpdate\AU\AutoInstallMinorUpdates'
         {
              ValueName = 'AutoInstallMinorUpdates'
              ValueData = 0
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\Windows\WindowsUpdate\AU'
         }#>

         <#RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\WindowsUpdate\AU\NoAutoUpdate'
         {
              ValueName = 'NoAutoUpdate'
              ValueData = 1
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\Windows\WindowsUpdate\AU'
         }#>

         <#RegistryPolicyFile 'DEL_\Software\Policies\Microsoft\Windows\WindowsUpdate\AU\AUOptions'
         {
              ValueName = 'AUOptions'
              ValueData = ''
              Ensure = 'Absent'
              ValueType = 'String'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\Windows\WindowsUpdate\AU'
         }#>

         <#RegistryPolicyFile 'DEL_\Software\Policies\Microsoft\Windows\WindowsUpdate\AU\AutomaticMaintenanceEnabled'
         {
              ValueName = 'AutomaticMaintenanceEnabled'
              ValueData = ''
              Ensure = 'Absent'
              ValueType = 'String'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\Windows\WindowsUpdate\AU'
         }#>

         <#RegistryPolicyFile 'DEL_\Software\Policies\Microsoft\Windows\WindowsUpdate\AU\ScheduledInstallDay'
         {
              ValueName = 'ScheduledInstallDay'
              ValueData = ''
              Ensure = 'Absent'
              ValueType = 'String'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\Windows\WindowsUpdate\AU'
         }#>

         <#RegistryPolicyFile 'DEL_\Software\Policies\Microsoft\Windows\WindowsUpdate\AU\ScheduledInstallTime'
         {
              ValueName = 'ScheduledInstallTime'
              ValueData = ''
              Ensure = 'Absent'
              ValueType = 'String'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\Windows\WindowsUpdate\AU'
         }#>

         <#RegistryPolicyFile 'DEL_\Software\Policies\Microsoft\Windows\WindowsUpdate\AU\ScheduledInstallEveryWeek'
         {
              ValueName = 'ScheduledInstallEveryWeek'
              ValueData = ''
              Ensure = 'Absent'
              ValueType = 'String'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\Windows\WindowsUpdate\AU'
         }#>

         <#RegistryPolicyFile 'DEL_\Software\Policies\Microsoft\Windows\WindowsUpdate\AU\ScheduledInstallFirstWeek'
         {
              ValueName = 'ScheduledInstallFirstWeek'
              ValueData = ''
              Ensure = 'Absent'
              ValueType = 'String'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\Windows\WindowsUpdate\AU'
         }#>

         <#RegistryPolicyFile 'DEL_\Software\Policies\Microsoft\Windows\WindowsUpdate\AU\ScheduledInstallSecondWeek'
         {
              ValueName = 'ScheduledInstallSecondWeek'
              ValueData = ''
              Ensure = 'Absent'
              ValueType = 'String'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\Windows\WindowsUpdate\AU'
         }#>

         <#RegistryPolicyFile 'DEL_\Software\Policies\Microsoft\Windows\WindowsUpdate\AU\ScheduledInstallThirdWeek'
         {
              ValueName = 'ScheduledInstallThirdWeek'
              ValueData = ''
              Ensure = 'Absent'
              ValueType = 'String'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\Windows\WindowsUpdate\AU'
         }#>

         <#RegistryPolicyFile 'DEL_\Software\Policies\Microsoft\Windows\WindowsUpdate\AU\ScheduledInstallFourthWeek'
         {
              ValueName = 'ScheduledInstallFourthWeek'
              ValueData = ''
              Ensure = 'Absent'
              ValueType = 'String'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\Windows\WindowsUpdate\AU'
         }#>

         <#RegistryPolicyFile 'DEL_\Software\Policies\Microsoft\Windows\WindowsUpdate\AU\AllowMUUpdateService'
         {
              ValueName = 'AllowMUUpdateService'
              ValueData = ''
              Ensure = 'Absent'
              ValueType = 'String'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\Windows\WindowsUpdate\AU'
         }#>

         <#RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\WindowsUpdate\AU\IncludeRecommendedUpdates'
         {
              ValueName = 'IncludeRecommendedUpdates'
              ValueData = 1
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\Windows\WindowsUpdate\AU'
         }#>

         <#RegistryPolicyFile 'DELETEKEYS_\Software\Policies\Microsoft\Cryptography'
         {
              ValueName = '**DeleteKeys'
              ValueData = 'Software\Policies\Microsoft\Cryptography\PolicyServers'
              Ensure = 'Absent'
              ValueType = 'String'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\Cryptography'
         }#>

         <#RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Cryptography\AutoEnrollment\AEPolicy'
         {
              ValueName = 'AEPolicy'
              ValueData = 7
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\Cryptography\AutoEnrollment'
         }#>

         <#RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Cryptography\AutoEnrollment\OfflineExpirationPercent'
         {
              ValueName = 'OfflineExpirationPercent'
              ValueData = 10
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\Cryptography\AutoEnrollment'
         }#>

         <#RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Cryptography\AutoEnrollment\OfflineExpirationStoreNames'
         {
              ValueName = 'OfflineExpirationStoreNames'
              ValueData = 'MY'
              ValueType = 'String'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\Cryptography\AutoEnrollment'
         }#>

         <#
         	This MultiString Value has a value of $null, 
          	Some Security Policies require Registry Values to be $null
          	If you believe ' ' is the correct value for this string, you may change it here.
         #>
         <#RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Cryptography\PolicyServers\'
         {
              ValueName = ''
              ValueType = 'String'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\Cryptography\PolicyServers'
         }#>

         <#RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Cryptography\PolicyServers\Flags'
         {
              ValueName = 'Flags'
              ValueData = 0
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\Cryptography\PolicyServers'
         }#>

         <#RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Cryptography\PolicyServers\37c9dc30f207f27f61a2f7c3aed598a6e2920b54\URL'
         {
              ValueName = 'URL'
              ValueData = 'LDAP:'
              ValueType = 'String'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\Cryptography\PolicyServers\37c9dc30f207f27f61a2f7c3aed598a6e2920b54'
         }#>

         <#RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Cryptography\PolicyServers\37c9dc30f207f27f61a2f7c3aed598a6e2920b54\PolicyID'
         {
              ValueName = 'PolicyID'
              ValueData = '{D1E74DB3-855C-4FAA-818E-4AAC3889B1CC}'
              ValueType = 'String'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\Cryptography\PolicyServers\37c9dc30f207f27f61a2f7c3aed598a6e2920b54'
         }#>

         <#RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Cryptography\PolicyServers\37c9dc30f207f27f61a2f7c3aed598a6e2920b54\FriendlyName'
         {
              ValueName = 'FriendlyName'
              ValueData = 'Active Directory Enrollment Policy'
              ValueType = 'String'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\Cryptography\PolicyServers\37c9dc30f207f27f61a2f7c3aed598a6e2920b54'
         }#>

         <#RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Cryptography\PolicyServers\37c9dc30f207f27f61a2f7c3aed598a6e2920b54\Flags'
         {
              ValueName = 'Flags'
              ValueData = 20
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\Cryptography\PolicyServers\37c9dc30f207f27f61a2f7c3aed598a6e2920b54'
         }#>

         <#RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Cryptography\PolicyServers\37c9dc30f207f27f61a2f7c3aed598a6e2920b54\AuthFlags'
         {
              ValueName = 'AuthFlags'
              ValueData = 2
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\Cryptography\PolicyServers\37c9dc30f207f27f61a2f7c3aed598a6e2920b54'
         }#>

         <#RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Cryptography\PolicyServers\37c9dc30f207f27f61a2f7c3aed598a6e2920b54\Cost'
         {
              ValueName = 'Cost'
              ValueData = 2147483645
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\Cryptography\PolicyServers\37c9dc30f207f27f61a2f7c3aed598a6e2920b54'
         }#>

         <#
         	This MultiString Value has a value of $null, 
          	Some Security Policies require Registry Values to be $null
          	If you believe ' ' is the correct value for this string, you may change it here.
         #>
         <#RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\SystemCertificates\ACRS\Certificates\'
         {
              ValueName = ''
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\SystemCertificates\ACRS\Certificates'
         }#>

         <#
         	This MultiString Value has a value of $null, 
          	Some Security Policies require Registry Values to be $null
          	If you believe ' ' is the correct value for this string, you may change it here.
         #>
         <#RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\SystemCertificates\ACRS\CRLs\'
         {
              ValueName = ''
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\SystemCertificates\ACRS\CRLs'
         }#>

         <#
         	This MultiString Value has a value of $null, 
          	Some Security Policies require Registry Values to be $null
          	If you believe ' ' is the correct value for this string, you may change it here.
         #>
         <#RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\SystemCertificates\ACRS\CTLs\'
         {
              ValueName = ''
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\SystemCertificates\ACRS\CTLs'
         }#>

         <#
         	This MultiString Value has a value of $null, 
          	Some Security Policies require Registry Values to be $null
          	If you believe ' ' is the correct value for this string, you may change it here.
         #>
         <#RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\SystemCertificates\CA\Certificates\'
         {
              ValueName = ''
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\SystemCertificates\CA\Certificates'
         }#>

         <#
         	This MultiString Value has a value of $null, 
          	Some Security Policies require Registry Values to be $null
          	If you believe ' ' is the correct value for this string, you may change it here.
         #>
         <#RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\SystemCertificates\CA\CRLs\'
         {
              ValueName = ''
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\SystemCertificates\CA\CRLs'
         }#>

         <#
         	This MultiString Value has a value of $null, 
          	Some Security Policies require Registry Values to be $null
          	If you believe ' ' is the correct value for this string, you may change it here.
         #>
         <#RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\SystemCertificates\CA\CTLs\'
         {
              ValueName = ''
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\SystemCertificates\CA\CTLs'
         }#>

         <#
         	This MultiString Value has a value of $null, 
          	Some Security Policies require Registry Values to be $null
          	If you believe ' ' is the correct value for this string, you may change it here.
         #>
         <#RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\SystemCertificates\Disallowed\Certificates\'
         {
              ValueName = ''
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\SystemCertificates\Disallowed\Certificates'
         }#>

         <#
         	This MultiString Value has a value of $null, 
          	Some Security Policies require Registry Values to be $null
          	If you believe ' ' is the correct value for this string, you may change it here.
         #>
         <#RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\SystemCertificates\Disallowed\CRLs\'
         {
              ValueName = ''
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\SystemCertificates\Disallowed\CRLs'
         }#>

         <#
         	This MultiString Value has a value of $null, 
          	Some Security Policies require Registry Values to be $null
          	If you believe ' ' is the correct value for this string, you may change it here.
         #>
         <#RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\SystemCertificates\Disallowed\CTLs\'
         {
              ValueName = ''
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\SystemCertificates\Disallowed\CTLs'
         }#>

         <#
         	This MultiString Value has a value of $null, 
          	Some Security Policies require Registry Values to be $null
          	If you believe ' ' is the correct value for this string, you may change it here.
         #>
         <#RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\SystemCertificates\DPNGRA\Certificates\'
         {
              ValueName = ''
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\SystemCertificates\DPNGRA\Certificates'
         }#>

         <#
         	This MultiString Value has a value of $null, 
          	Some Security Policies require Registry Values to be $null
          	If you believe ' ' is the correct value for this string, you may change it here.
         #>
         <#RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\SystemCertificates\DPNGRA\CRLs\'
         {
              ValueName = ''
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\SystemCertificates\DPNGRA\CRLs'
         }#>

         <#
         	This MultiString Value has a value of $null, 
          	Some Security Policies require Registry Values to be $null
          	If you believe ' ' is the correct value for this string, you may change it here.
         #>
         <#RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\SystemCertificates\DPNGRA\CTLs\'
         {
              ValueName = ''
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\SystemCertificates\DPNGRA\CTLs'
         }#>

         <#
         	This MultiString Value has a value of $null, 
          	Some Security Policies require Registry Values to be $null
          	If you believe ' ' is the correct value for this string, you may change it here.
         #>
         <#RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\SystemCertificates\FVE\Certificates\'
         {
              ValueName = ''
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\SystemCertificates\FVE\Certificates'
         }#>

         <#
         	This MultiString Value has a value of $null, 
          	Some Security Policies require Registry Values to be $null
          	If you believe ' ' is the correct value for this string, you may change it here.
         #>
         <#RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\SystemCertificates\FVE\CRLs\'
         {
              ValueName = ''
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\SystemCertificates\FVE\CRLs'
         }#>

         <#
         	This MultiString Value has a value of $null, 
          	Some Security Policies require Registry Values to be $null
          	If you believe ' ' is the correct value for this string, you may change it here.
         #>
         <#RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\SystemCertificates\FVE\CTLs\'
         {
              ValueName = ''
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\SystemCertificates\FVE\CTLs'
         }#>

         <#
         	This MultiString Value has a value of $null, 
          	Some Security Policies require Registry Values to be $null
          	If you believe ' ' is the correct value for this string, you may change it here.
         #>
         <#RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\SystemCertificates\FVE_NKP\Certificates\'
         {
              ValueName = ''
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\SystemCertificates\FVE_NKP\Certificates'
         }#>

         <#
         	This MultiString Value has a value of $null, 
          	Some Security Policies require Registry Values to be $null
          	If you believe ' ' is the correct value for this string, you may change it here.
         #>
         <#RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\SystemCertificates\FVE_NKP\CRLs\'
         {
              ValueName = ''
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\SystemCertificates\FVE_NKP\CRLs'
         }#>

         <#
         	This MultiString Value has a value of $null, 
          	Some Security Policies require Registry Values to be $null
          	If you believe ' ' is the correct value for this string, you may change it here.
         #>
         <#RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\SystemCertificates\FVE_NKP\CTLs\'
         {
              ValueName = ''
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\SystemCertificates\FVE_NKP\CTLs'
         }#>

         <#RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\SystemCertificates\Root\Certificates\1B305A45D56B550DF3FEFC679A4BB773B8D9FC34\Blob'
         {
              ValueName = 'Blob'
              ValueData = '0400000001000000100000002CC4CE75527A593CFC16B40D48FD6BE10F00000001000000200000000ED2679908F62EEBB9E51F8FA9005D59E9896FA179B08D8A600684004D0816BD1400000001000000140000006CAF800DBF7A151D0DAA85A795EABFDA72556861190000000100000010000000DB325FEB12A40221C69074FD9BDFFBA55C0000000100000004000000000800000300000001000000140000001B305A45D56B550DF3FEFC679A4BB773B8D9FC3420000000010000005D0300003082035930820241A0030201020210666E7290BA6EF98B496D8DAF1E8DC2F9300D06092A864886F70D01010B0500303F31153013060A0992268993F22C6401191605696E74726131143012060A0992268993F22C64011916046D7961643110300E0603550403130746524143413031301E170D3231303431363138303132335A170D3331303431363138313132335A303F31153013060A0992268993F22C6401191605696E74726131143012060A0992268993F22C64011916046D7961643110300E060355040313074652414341303130820122300D06092A864886F70D01010105000382010F003082010A0282010100CE82A5E679F554A420D533CF45A3DB29787FCD6A0D3435C3B90EBE022985680EBC57710E08DD036249542909E4E18DFA79A5340107765869C011641D4461D54931250A710DE19FE4370A1777490928259C1BFCD097C1C674991898D3F7B1C298DD607CDBB796DABBEC27BEF569677D04D6B04C0EE450CF5A931CD368DCEE72DBA382EFF46E7839EC619B18D3DE8390DE7752E55C60ED4728752D0DCBFC5D302E27D7A91254466F235E7A5825ACB2139EFE0FD53443FBE0133538186278C3ADF2D1812716C8ADB2058CFDBDE1C46CFF02E31B7BD512BEE279928A592DF347F9CEDE8F828AF603BB2823D346096DD18B7C4D20870931BA47C7048CE9CAD753B5D10203010001A351304F300B0603551D0F040403020186300F0603551D130101FF040530030101FF301D0603551D0E041604146CAF800DBF7A151D0DAA85A795EABFDA72556861301006092B06010401823715010403020100300D06092A864886F70D01010B05000382010100592F46F21C26DDFA4E46B107E89E83E3449C67AD7AF210EEE0D5622CCE351AA79C2EFF4936014F8466F7A18E7334A451D1E3573E3B512B716A98F580BD92E183C5B5C06BBCE5EC17070420545156EC62F9038B7F7EC6F8A724C497E12EC7094F21733EF225E4E5B95A41C42AD09F0DAA2C01297CEBE382DF85969F0B743D2FDF3EE0188CA6E4E195E29A3A6C1283A971F19430E8DC0BA6C08AE63555C7B79100ED6CB8D62025A2780213E89502BF75948DD45FFED526FAAAAC4165E162B15937C63104E5910396A5FEAED4C02710A5D687B612D58DD7FAA3937F0A2EBF03AC4FF8DDC814431FCA9DB3F46FAE2606E34739C8558FE5C5EC8830A0CB5201B7FC3A'
              ValueType = 'Binary'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\SystemCertificates\Root\Certificates\1B305A45D56B550DF3FEFC679A4BB773B8D9FC34'
         }#>

         <#
         	This MultiString Value has a value of $null, 
          	Some Security Policies require Registry Values to be $null
          	If you believe ' ' is the correct value for this string, you may change it here.
         #>
         <#RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\SystemCertificates\Root\CRLs\'
         {
              ValueName = ''
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\SystemCertificates\Root\CRLs'
         }#>

         <#
         	This MultiString Value has a value of $null, 
          	Some Security Policies require Registry Values to be $null
          	If you believe ' ' is the correct value for this string, you may change it here.
         #>
         <#RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\SystemCertificates\Root\CTLs\'
         {
              ValueName = ''
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\SystemCertificates\Root\CTLs'
         }#>

         <#
         	This MultiString Value has a value of $null, 
          	Some Security Policies require Registry Values to be $null
          	If you believe ' ' is the correct value for this string, you may change it here.
         #>
         <#RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\SystemCertificates\Trust\Certificates\'
         {
              ValueName = ''
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\SystemCertificates\Trust\Certificates'
         }#>

         <#
         	This MultiString Value has a value of $null, 
          	Some Security Policies require Registry Values to be $null
          	If you believe ' ' is the correct value for this string, you may change it here.
         #>
         <#RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\SystemCertificates\Trust\CRLs\'
         {
              ValueName = ''
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\SystemCertificates\Trust\CRLs'
         }#>

         <#
         	This MultiString Value has a value of $null, 
          	Some Security Policies require Registry Values to be $null
          	If you believe ' ' is the correct value for this string, you may change it here.
         #>
         <#RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\SystemCertificates\Trust\CTLs\'
         {
              ValueName = ''
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\SystemCertificates\Trust\CTLs'
         }#>

         <#
         	This MultiString Value has a value of $null, 
          	Some Security Policies require Registry Values to be $null
          	If you believe ' ' is the correct value for this string, you may change it here.
         #>
         <#RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\SystemCertificates\TrustedPeople\Certificates\'
         {
              ValueName = ''
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\SystemCertificates\TrustedPeople\Certificates'
         }#>

         <#
         	This MultiString Value has a value of $null, 
          	Some Security Policies require Registry Values to be $null
          	If you believe ' ' is the correct value for this string, you may change it here.
         #>
         <#RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\SystemCertificates\TrustedPeople\CRLs\'
         {
              ValueName = ''
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\SystemCertificates\TrustedPeople\CRLs'
         }#>

         <#
         	This MultiString Value has a value of $null, 
          	Some Security Policies require Registry Values to be $null
          	If you believe ' ' is the correct value for this string, you may change it here.
         #>
         <#RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\SystemCertificates\TrustedPeople\CTLs\'
         {
              ValueName = ''
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\SystemCertificates\TrustedPeople\CTLs'
         }#>

         <#
         	This MultiString Value has a value of $null, 
          	Some Security Policies require Registry Values to be $null
          	If you believe ' ' is the correct value for this string, you may change it here.
         #>
         <#RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\SystemCertificates\TrustedPublisher\Certificates\'
         {
              ValueName = ''
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\SystemCertificates\TrustedPublisher\Certificates'
         }#>

         <#
         	This MultiString Value has a value of $null, 
          	Some Security Policies require Registry Values to be $null
          	If you believe ' ' is the correct value for this string, you may change it here.
         #>
         <#RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\SystemCertificates\TrustedPublisher\CRLs\'
         {
              ValueName = ''
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\SystemCertificates\TrustedPublisher\CRLs'
         }#>

         <#
         	This MultiString Value has a value of $null, 
          	Some Security Policies require Registry Values to be $null
          	If you believe ' ' is the correct value for this string, you may change it here.
         #>
         <#RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\SystemCertificates\TrustedPublisher\CTLs\'
         {
              ValueName = ''
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\SystemCertificates\TrustedPublisher\CTLs'
         }#>

         <#RegistryPolicyFile 'Registry(POL): HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services\MaxIdleTime'
         {
              ValueName = 'MaxIdleTime'
              ValueData = 10800000
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services'
         }#>

         RegistryPolicyFile 'Registry(POL): HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services\fResetBroken'
         {
              ValueName = 'fResetBroken'
              ValueData = 1
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services'
         }

         <#RegistryPolicyFile 'Registry(POL): HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services\MaxDisconnectionTime'
         {
              ValueName = 'MaxDisconnectionTime'
              ValueData = 600000
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services'
         }#>

         RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\WindowsStore\RemoveWindowsStore'
         {
              ValueName = 'RemoveWindowsStore'
              ValueData = 1
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\WindowsStore'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\WindowsStore\DisableOSUpgrade'
         {
              ValueName = 'DisableOSUpgrade'
              ValueData = 1
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\WindowsStore'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\WindowsStore\AutoDownload'
         {
              ValueName = 'AutoDownload'
              ValueData = 2
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\WindowsStore'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows Defender\MpEngine\MpBafsExtendedTimeout'
         {
              ValueName = 'MpBafsExtendedTimeout'
              ValueData = 10
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\Windows Defender\MpEngine'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows Defender\MpEngine\MpCloudBlockLevel'
         {
              ValueName = 'MpCloudBlockLevel'
              ValueData = 2
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\Windows Defender\MpEngine'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows Defender\Real-Time Protection\RealtimeScanDirection'
         {
              ValueName = 'RealtimeScanDirection'
              ValueData = 0
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\Windows Defender\Real-Time Protection'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows Defender\Real-Time Protection\IOAVMaxSize'
         {
              ValueName = 'IOAVMaxSize'
              ValueData = 20480
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\Windows Defender\Real-Time Protection'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows Defender\Real-Time Protection\DisableOnAccessProtection'
         {
              ValueName = 'DisableOnAccessProtection'
              ValueData = 0
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\Windows Defender\Real-Time Protection'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows Defender\Real-Time Protection\DisableIOAVProtection'
         {
              ValueName = 'DisableIOAVProtection'
              ValueData = 0
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\Windows Defender\Real-Time Protection'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows Defender\Real-Time Protection\DisableBehaviorMonitoring'
         {
              ValueName = 'DisableBehaviorMonitoring'
              ValueData = 0
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\Windows Defender\Real-Time Protection'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows Defender\Signature Updates\ForceUpdateFromMU'
         {
              ValueName = 'ForceUpdateFromMU'
              ValueData = 1
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\Windows Defender\Signature Updates'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows Defender\Signature Updates\RealtimeSignatureDelivery'
         {
              ValueName = 'RealtimeSignatureDelivery'
              ValueData = 1
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\Windows Defender\Signature Updates'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows Defender\Signature Updates\UpdateOnStartUp'
         {
              ValueName = 'UpdateOnStartUp'
              ValueData = 1
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\Windows Defender\Signature Updates'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows Defender\Signature Updates\ASSignatureDue'
         {
              ValueName = 'ASSignatureDue'
              ValueData = 14
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\Windows Defender\Signature Updates'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows Defender\Signature Updates\SignatureUpdateCatchupInterval'
         {
              ValueName = 'SignatureUpdateCatchupInterval'
              ValueData = 1
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\Windows Defender\Signature Updates'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows Defender\Signature Updates\DisableUpdateOnStartupWithoutEngine'
         {
              ValueName = 'DisableUpdateOnStartupWithoutEngine'
              ValueData = 0
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\Windows Defender\Signature Updates'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows Defender\Signature Updates\SignatureUpdateInterval'
         {
              ValueName = 'SignatureUpdateInterval'
              ValueData = 4
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\Windows Defender\Signature Updates'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows Defender\Spynet\LocalSettingOverrideSpynetReporting'
         {
              ValueName = 'LocalSettingOverrideSpynetReporting'
              ValueData = 0
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\Windows Defender\Spynet'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows Defender\Spynet\DisableBlockAtFirstSeen'
         {
              ValueName = 'DisableBlockAtFirstSeen'
              ValueData = 0
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\Windows Defender\Spynet'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows Defender\Spynet\SpynetReporting'
         {
              ValueName = 'SpynetReporting'
              ValueData = 0
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\Windows Defender\Spynet'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows Defender\Spynet\SubmitSamplesConsent'
         {
              ValueName = 'SubmitSamplesConsent'
              ValueData = 2
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\Windows Defender\Spynet'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows Defender Security Center\Enterprise Customization\Url'
         {
              ValueName = 'Url'
              ValueData = 'https://myazure.intra/helpdesk'
              ValueType = 'String'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\Windows Defender Security Center\Enterprise Customization'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows Defender Security Center\Enterprise Customization\Phone'
         {
              ValueName = 'Phone'
              ValueData = '123 555 7898'
              ValueType = 'String'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\Windows Defender Security Center\Enterprise Customization'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows Defender Security Center\Enterprise Customization\Email'
         {
              ValueName = 'Email'
              ValueData = 'helpdesk@myazure.intra'
              ValueType = 'String'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\Windows Defender Security Center\Enterprise Customization'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows Defender Security Center\Enterprise Customization\CompanyName'
         {
              ValueName = 'CompanyName'
              ValueData = 'MyAzure'
              ValueType = 'String'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\Windows Defender Security Center\Enterprise Customization'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows Defender Security Center\Notifications\DisableNotifications'
         {
              ValueName = 'DisableNotifications'
              ValueData = 0
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\Windows Defender Security Center\Notifications'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows Defender Security Center\Notifications\DisableEnhancedNotifications'
         {
              ValueName = 'DisableEnhancedNotifications'
              ValueData = 0
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\Windows Defender Security Center\Notifications'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows Defender Security Center\Systray\HideSystray'
         {
              ValueName = 'HideSystray'
              ValueData = 0
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\Windows Defender Security Center\Systray'
         }

         <#RegistryPolicyFile 'Registry(POL): HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\ForceStartMenuLogOff'
         {
              ValueName = 'ForceStartMenuLogOff'
              ValueData = 1
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer'
         }#>

         <#RegistryPolicyFile 'Registry(POL): HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\NoStartMenuMFUprogramsList'
         {
              ValueName = 'NoStartMenuMFUprogramsList'
              ValueData = 1
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer'
         }#>

         <#RegistryPolicyFile 'Registry(POL): HKCU:\Software\Policies\Microsoft\Windows\Explorer\HideRecentlyAddedApps'
         {
              ValueName = 'HideRecentlyAddedApps'
              ValueData = 1
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKCU:\Software\Policies\Microsoft\Windows\Explorer'
         }#>

         <#RegistryPolicyFile 'Registry(POL): HKCU:\Software\Policies\Microsoft\Windows\Explorer\HidePeopleBar'
         {
              ValueName = 'HidePeopleBar'
              ValueData = 1
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKCU:\Software\Policies\Microsoft\Windows\Explorer'
         }#>

         <#RegistryPolicyFile 'Registry(POL): HKCU:\Software\Policies\Microsoft\Windows\Explorer\LockedStartLayout'
         {
              ValueName = 'LockedStartLayout'
              ValueData = 1
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKCU:\Software\Policies\Microsoft\Windows\Explorer'
         }#>

         <#RegistryPolicyFile 'Registry(POL): HKCU:\Software\Policies\Microsoft\Windows\Explorer\StartLayoutFile'
         {
              ValueName = 'StartLayoutFile'
              ValueData = '\\fradc01\myad\cicd\client_startmenu.xml'
              ValueType = 'ExpandString'
              TargetType = 'ComputerConfiguration'
              Key = 'HKCU:\Software\Policies\Microsoft\Windows\Explorer'
         }#>

         <#Group '*S-1-5-32-544'
         {
              Members = @('*S-1-5-21-2055282221-2453684760-1948963125-1107')
              GroupName = '*S-1-5-32-544'
         }#>

         AccountPolicy 'SecuritySetting(INF): MaxTicketAge'
         {
              Name = 'Maximum_lifetime_for_user_ticket'
              Maximum_lifetime_for_user_ticket = 10
         }

         AccountPolicy 'SecuritySetting(INF): MaxServiceAge'
         {
              Name = 'Maximum_lifetime_for_service_ticket'
              Maximum_lifetime_for_service_ticket = 600
         }

         AccountPolicy 'SecuritySetting(INF): MaxClockSkew'
         {
              Maximum_tolerance_for_computer_clock_synchronization = 5
              Name = 'Maximum_tolerance_for_computer_clock_synchronization'
         }

         AccountPolicy 'SecuritySetting(INF): MaxRenewAge'
         {
              Name = 'Maximum_lifetime_for_user_ticket_renewal'
              Maximum_lifetime_for_user_ticket_renewal = 7
         }

         AccountPolicy 'SecuritySetting(INF): TicketValidateClient'
         {
              Name = 'Enforce_user_logon_restrictions'
              Enforce_user_logon_restrictions = 'Enabled'
         }

         AccountPolicy 'SecuritySetting(INF): MinimumPasswordAge'
         {
              Minimum_Password_Age = 1
              Name = 'Minimum_Password_Age'
         }

         AccountPolicy 'SecuritySetting(INF): MaximumPasswordAge'
         {
              Name = 'Maximum_Password_Age'
              Maximum_Password_Age = 42
         }

         AccountPolicy 'SecuritySetting(INF): LockoutBadCount'
         {
              Name = 'Account_lockout_threshold'
              Account_lockout_threshold = 0
         }

         AccountPolicy 'SecuritySetting(INF): PasswordComplexity'
         {
              Name = 'Password_must_meet_complexity_requirements'
              Password_must_meet_complexity_requirements = 'Enabled'
         }

         SecurityOption 'SecuritySetting(INF): LSAAnonymousNameLookup'
         {
              Name = 'Network_access_Allow_anonymous_SID_Name_translation'
              Network_access_Allow_anonymous_SID_Name_translation = 'Disabled'
         }

         SecurityOption 'SecuritySetting(INF): ForceLogoffWhenHourExpire'
         {
              Name = 'Network_security_Force_logoff_when_logon_hours_expire'
              Network_security_Force_logoff_when_logon_hours_expire = 'Disabled'
         }

         AccountPolicy 'SecuritySetting(INF): PasswordHistorySize'
         {
              Name = 'Enforce_password_history'
              Enforce_password_history = 24
         }

         AccountPolicy 'SecuritySetting(INF): ClearTextPassword'
         {
              Name = 'Store_passwords_using_reversible_encryption'
              Store_passwords_using_reversible_encryption = 'Disabled'
         }

         AccountPolicy 'SecuritySetting(INF): MinimumPasswordLength'
         {
              Name = 'Minimum_Password_Length'
              Minimum_Password_Length = 7
         }

         SecurityOption 'SecurityRegistry(INF): Network_security_Do_not_store_LAN_Manager_hash_value_on_next_password_change'
         {
              Network_security_Do_not_store_LAN_Manager_hash_value_on_next_password_change = 'Enabled'
              Name = 'Network_security_Do_not_store_LAN_Manager_hash_value_on_next_password_change'
         }

         UserRightsAssignment 'UserRightsAssignment(INF): Bypass_traverse_checking'
         {
              Policy = 'Bypass_traverse_checking'
              Force = $True
              Identity = @('*S-1-5-32-554', '*S-1-5-11', '*S-1-5-32-544', '*S-1-5-20', '*S-1-5-19', '*S-1-1-0')
         }

         UserRightsAssignment 'UserRightsAssignment(INF): Replace_a_process_level_token'
         {
              Policy = 'Replace_a_process_level_token'
              Force = $True
              Identity = @('*S-1-5-20', '*S-1-5-19')
         }

         UserRightsAssignment 'UserRightsAssignment(INF): Shut_down_the_system'
         {
              Policy = 'Shut_down_the_system'
              Force = $True
              Identity = @('*S-1-5-32-550', '*S-1-5-32-549', '*S-1-5-32-551', '*S-1-5-32-544')
         }

         UserRightsAssignment 'UserRightsAssignment(INF): Restore_files_and_directories'
         {
              Policy = 'Restore_files_and_directories'
              Force = $True
              Identity = @('*S-1-5-32-549', '*S-1-5-32-551', '*S-1-5-32-544')
         }

         UserRightsAssignment 'UserRightsAssignment(INF): Force_shutdown_from_a_remote_system'
         {
              Policy = 'Force_shutdown_from_a_remote_system'
              Force = $True
              Identity = @('*S-1-5-32-549', '*S-1-5-32-544')
         }

         UserRightsAssignment 'UserRightsAssignment(INF): Back_up_files_and_directories'
         {
              Policy = 'Back_up_files_and_directories'
              Force = $True
              Identity = @('*S-1-5-32-549', '*S-1-5-32-551', '*S-1-5-32-544')
         }

         UserRightsAssignment 'UserRightsAssignment(INF): Load_and_unload_device_drivers'
         {
              Policy = 'Load_and_unload_device_drivers'
              Force = $True
              Identity = @('*S-1-5-32-550', '*S-1-5-32-544')
         }

         UserRightsAssignment 'UserRightsAssignment(INF): Add_workstations_to_domain'
         {
              Policy = 'Add_workstations_to_domain'
              Force = $True
              Identity = @('*S-1-5-11')
         }

         UserRightsAssignment 'UserRightsAssignment(INF): Generate_security_audits'
         {
              Policy = 'Generate_security_audits'
              Force = $True
              Identity = @('*S-1-5-20', '*S-1-5-19')
         }

         UserRightsAssignment 'UserRightsAssignment(INF): Modify_firmware_environment_values'
         {
              Policy = 'Modify_firmware_environment_values'
              Force = $True
              Identity = @('*S-1-5-32-544')
         }

         UserRightsAssignment 'UserRightsAssignment(INF): Change_the_system_time'
         {
              Policy = 'Change_the_system_time'
              Force = $True
              Identity = @('*S-1-5-32-549', '*S-1-5-32-544', '*S-1-5-19')
         }

         UserRightsAssignment 'UserRightsAssignment(INF): Manage_auditing_and_security_log'
         {
              Policy = 'Manage_auditing_and_security_log'
              Force = $True
              Identity = @('*S-1-5-32-544')
         }

         UserRightsAssignment 'UserRightsAssignment(INF): Take_ownership_of_files_or_other_objects'
         {
              Policy = 'Take_ownership_of_files_or_other_objects'
              Force = $True
              Identity = @('*S-1-5-32-544')
         }

         UserRightsAssignment 'UserRightsAssignment(INF): Adjust_memory_quotas_for_a_process'
         {
              Policy = 'Adjust_memory_quotas_for_a_process'
              Force = $True
              Identity = @('*S-1-5-32-544', '*S-1-5-20', '*S-1-5-19')
         }

         UserRightsAssignment 'UserRightsAssignment(INF): Create_a_pagefile'
         {
              Policy = 'Create_a_pagefile'
              Force = $True
              Identity = @('*S-1-5-32-544')
         }

         UserRightsAssignment 'UserRightsAssignment(INF): Access_this_computer_from_the_network'
         {
              Policy = 'Access_this_computer_from_the_network'
              Force = $True
              Identity = @('*S-1-5-32-554', '*S-1-5-9', '*S-1-5-11', '*S-1-5-32-544', '*S-1-1-0')
         }

         UserRightsAssignment 'UserRightsAssignment(INF): Log_on_as_a_batch_job'
         {
              Policy = 'Log_on_as_a_batch_job'
              Force = $True
              Identity = @('*S-1-5-32-559', '*S-1-5-32-551', '*S-1-5-32-544')
         }

         UserRightsAssignment 'UserRightsAssignment(INF): Profile_single_process'
         {
              Policy = 'Profile_single_process'
              Force = $True
              Identity = @('*S-1-5-32-544')
         }

         UserRightsAssignment 'UserRightsAssignment(INF): Remove_computer_from_docking_station'
         {
              Policy = 'Remove_computer_from_docking_station'
              Force = $True
              Identity = @('*S-1-5-32-544')
         }

         UserRightsAssignment 'UserRightsAssignment(INF): Profile_system_performance'
         {
              Policy = 'Profile_system_performance'
              Force = $True
              Identity = @('*S-1-5-80-3139157870-2983391045-3678747466-658725712-1809340420', '*S-1-5-32-544')
         }

         UserRightsAssignment 'UserRightsAssignment(INF): Allow_log_on_locally'
         {
              Policy = 'Allow_log_on_locally'
              Force = $True
              Identity = @('*S-1-5-9', '*S-1-5-32-550', '*S-1-5-32-549', '*S-1-5-32-548', '*S-1-5-32-551', '*S-1-5-32-544')
         }

         UserRightsAssignment 'UserRightsAssignment(INF): Debug_programs'
         {
              Policy = 'Debug_programs'
              Force = $True
              Identity = @('*S-1-5-32-544')
         }

         UserRightsAssignment 'UserRightsAssignment(INF): Increase_scheduling_priority'
         {
              Policy = 'Increase_scheduling_priority'
              Force = $True
              Identity = @('*S-1-5-90-0', '*S-1-5-32-544')
         }

         UserRightsAssignment 'UserRightsAssignment(INF): Enable_computer_and_user_accounts_to_be_trusted_for_delegation'
         {
              Policy = 'Enable_computer_and_user_accounts_to_be_trusted_for_delegation'
              Force = $True
              Identity = @('*S-1-5-32-544')
         }

         SecurityOption 'SecurityRegistry(INF): Domain_member_Digitally_encrypt_or_sign_secure_channel_data_always'
         {
              Name = 'Domain_member_Digitally_encrypt_or_sign_secure_channel_data_always'
              Domain_member_Digitally_encrypt_or_sign_secure_channel_data_always = 'Enabled'
         }

         SecurityOption 'SecurityRegistry(INF): Microsoft_network_server_Digitally_sign_communications_if_client_agrees'
         {
              Microsoft_network_server_Digitally_sign_communications_if_client_agrees = 'Enabled'
              Name = 'Microsoft_network_server_Digitally_sign_communications_if_client_agrees'
         }

         SecurityOption 'SecurityRegistry(INF): Microsoft_network_server_Digitally_sign_communications_always'
         {
              Name = 'Microsoft_network_server_Digitally_sign_communications_always'
              Microsoft_network_server_Digitally_sign_communications_always = 'Enabled'
         }

         SecurityOption 'SecurityRegistry(INF): Domain_controller_LDAP_server_signing_requirements'
         {
              Domain_controller_LDAP_server_signing_requirements = 'None'
              Name = 'Domain_controller_LDAP_server_signing_requirements'
         }

         <#Group '*S-1-5-32-555'
         {
              Members = @('*S-1-5-21-2055282221-2453684760-1948963125-513')
              GroupName = '*S-1-5-32-555'
         }#>

         <#Group '*S-1-5-32-544'
         {
              Members = @('*S-1-5-21-2055282221-2453684760-1948963125-1108')
              GroupName = '*S-1-5-32-544'
         }#>

         RefreshRegistryPolicy 'ActivateClientSideExtension'
         {
             IsSingleInstance = 'Yes'
         }
     }
}
DSCFromGPO -OutputPath 'C:\Temp\'
