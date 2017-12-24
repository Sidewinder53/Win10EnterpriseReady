if (-Not ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] 'Administrator')) {
 if ([int](Get-CimInstance -Class Win32_OperatingSystem | Select-Object -ExpandProperty BuildNumber) -ge 6000) {
  $CommandLine = "-noprofile -executionpolicy bypass -File `"" + $MyInvocation.MyCommand.Path + "`" " + $MyInvocation.UnboundArguments
  Start-Process -FilePath PowerShell.exe -Verb Runas -ArgumentList $CommandLine
  Exit
 }
}

Write-Host "`nWindows 10 Enterprise Ready by tobias-kleinmann.de`nVersion 0.1"

if (Test-Connection -computer "www.msftncsi.com" -count 1 -quiet) {
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
    $version_url = “https://tobias-kleinmann.de/projects/Win10EnterpriseReady/version.html“
    $version = Invoke-WebRequest -Uri $version_url
    if ('0.1' -ge $version) {
        Write-Host "You're using the latest version!"
    } else {
        $title = "You're running an outdated version of this script."
        $message = "To continue you need to update to version $($version)."
        $yes = New-Object System.Management.Automation.Host.ChoiceDescription "&Update script", "Download the latest version of this script."
        $no = New-Object System.Management.Automation.Host.ChoiceDescription "&Abort script execution", "Stop script execution and don't modify anything."
        $options = [System.Management.Automation.Host.ChoiceDescription[]]($yes, $no)
        $result = $host.ui.PromptForChoice($title, $message, $options, 0) 
        if ($result -eq '1') { exit }

        $update_url = "https://tobias-kleinmann.de/projects/Win10EnterpriseReady/Win10EnterpriseReady_$($version).zip"
        $output = "$PSScriptRoot\Win10EnterpriseReady_$($version).zip"
        Invoke-WebRequest -Uri $update_url -OutFile $output

        Write-Host "The latest version of the script has been downloaded to the current directory. Extract the ZIP file and run the script to continue."
        Write-Host "Press any key to continue ..."
        $x = $host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
        exit
    }
}

if ( $ENV:PROCESSOR_ARCHITECTURE -eq 'AMD64' ) {
    $arch = '64'
} else {
    $arch = '32'
}
Write-Host "System Information:`n"
Write-Host "Windows Version:`t$([Environment]::OSVersion)" 
Write-Host "Architecture:`t`t$($arch)-bit"

$title = "Confirm script execution"
$message = "This script performs profound system modifications without prior warning. Ensure that the above information is correct, that the device is connected to an external power supply and that all other applications have been closed. Do you want to continue?"
$yes = New-Object System.Management.Automation.Host.ChoiceDescription "&Yes - DANGER", "Start script execution and modify system settings."
$no = New-Object System.Management.Automation.Host.ChoiceDescription "&No - SAFETY", "Stop script execution and don't modify anything."
$options = [System.Management.Automation.Host.ChoiceDescription[]]($yes, $no)
$result = $host.ui.PromptForChoice($title, $message, $options, 1) 
if ($result -eq '1') { exit }

Write-Host "Loading Default User profile..."
reg load HKU\Default_User C:\Users\Default\NTUSER.DAT

Write-Host "Disabling Content Delivery Services for Default User..."
Set-ItemProperty -Path 'Registry::HKU\Default_User\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager' -Name SystemPaneSuggestionsEnabled -Value 0
Set-ItemProperty -Path 'Registry::HKU\Default_User\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager' -Name PreInstalledAppsEnabled -Value 0
Set-ItemProperty -Path 'Registry::HKU\Default_User\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager' -Name OemPreInstalledAppsEnabled -Value 0

Write-Host "Setting default Explorer page to 'This PC'..."
New-Item -Path 'Registry::HKU\Default_User\SOFTWARE\Microsoft\Windows\CurrentVersion\CurrentVersion\Explorer\Advanced' -Force | Out-Null
Set-ItemProperty -Path 'Registry::HKU\Default_User\SOFTWARE\Microsoft\Windows\CurrentVersion\CurrentVersion\Explorer\Advanced' -Name LaunchTo -Value 1

Write-Host "Removing 'Task View' from taskbar"
Set-ItemProperty -Path 'Registry::HKU\Default_User\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced' -Name ShowTaskViewButton -Value 0

Write-Host "Removing 'My People' from taskbar..."
New-Item -Path 'Registry::HKU\Default_User\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced\People' -Force | Out-Null
Set-ItemProperty -Path 'Registry::HKU\Default_User\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced\People' -Name PeopleBand -Value 0

Write-Host "Disabling Cortana (system-wide)..."
New-Item -Path 'Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Windows Search' -Force | Out-Null
Set-ItemProperty -Path 'Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Windows Search' -Name AllowCortana -Value 0

Write-Host "Removing Gaming- and Cortana-related tiles from Settings..."
New-Item -Path 'Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer' -Force | Out-Null
Set-ItemProperty -Path 'Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer' -Name SettingsPageVisibility -Value 'hide:gaming-gamebar;gaming-gamedvr;gaming-broadcasting;gaming-gamemode;gaming-trueplay;gaming-xboxnetworking;cortana;cortana-permissions;cortana-notifications;cortana-moredetails;cortana-language;mobile-devices'

Write-Host "Removing OneDrive ($($arch)-bit edition)..."
if ( $arch -eq '64' ) { 
    $odsetuploc = [System.Environment]::ExpandEnvironmentVariables('%SystemRoot%\SysWOW64\OneDriveSetup.exe /uninstall') 
} else {
    $odsetuploc = [System.Environment]::ExpandEnvironmentVariables('%SystemRoot%\System32\OneDriveSetup.exe /uninstall')
}
Invoke-Expression $odsetuploc

Write-Host "Disabling OneDrive ($($arch)-bit edition) via Group Policy..."
New-Item -Path 'Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Wow6432Node\Policies\Microsoft\Windows\OneDrive' -Force | Out-Null
Set-ItemProperty -Path 'Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Wow6432Node\Policies\Microsoft\Windows\OneDrive' -Name DisableFileSyncNGSC -Value 1

Write-Host "Creating empty Start menu Layout..."
New-Item -ItemType Directory -Path 'C:\Windows\deployment\' -Force | Out-Null
'<LayoutModificationTemplate xmlns:defaultlayout="http://schemas.microsoft.com/Start/2014/FullDefaultLayout" xmlns:start="http://schemas.microsoft.com/Start/2014/StartLayout" Version="1" xmlns="http://schemas.microsoft.com/Start/2014/LayoutModification"><LayoutOptions StartTileGroupCellWidth="6" /><DefaultLayoutOverride><StartLayoutCollection><defaultlayout:StartLayout GroupCellWidth="6" /></StartLayoutCollection></DefaultLayoutOverride></LayoutModificationTemplate>' | Out-File -FilePath C:\Windows\deployment\DefaultLayout.xml -Append
Write-Host "Importing empty Start menu Layout.."
Import-StartLayout -LayoutPath "C:\Windows\deployment\DefaultLayout.xml" -MountPath "C:\"

$AppsList = @(
    "Microsoft.BingWeather"
    "Microsoft.GetHelp"
    "Microsoft.Getstarted"
    "Microsoft.Messaging"
    "Microsoft.Microsoft3DViewer"
    "Microsoft.MicrosoftOfficeHub"
    "Microsoft.MicrosoftSolitaireCollection"
    "Microsoft.Office.OneNote"
    "Microsoft.OneConnect"
    "Microsoft.People"
    "Microsoft.Print3D"
    "Microsoft.SkypeApp"
    "Microsoft.Wallet"
    "microsoft.windowscommunicationsapps"
    "Microsoft.WindowsFeedbackHub"
    "Microsoft.WindowsMaps"
    "Microsoft.Xbox.TCUI"
    "Microsoft.XboxApp"
    "Microsoft.XboxGameOverlay"
    "Microsoft.XboxIdentityProvider"
    "Microsoft.XboxSpeechToTextOverlay"
    #"Microsoft.ZuneMusic"
    #"Microsoft.ZuneVideo"
)

Write-Host "Removing Provisioned Applications..."

ForEach ($App in $AppsList) {
    $PackageFullName = (Get-AppxPackage $App).PackageFullName
    $ProPackageFullName = (Get-AppxProvisionedPackage -Online | Where {$_.Displayname -eq $App}).PackageName
 
    If ($PackageFullName) {
        Write-Host "Removing Package: $App"
        Remove-AppxPackage -Package $PackageFullName  | Out-Null
    }
 
    Else {
        Write-Host "Unable To Find Package: $App"
    }
 
    If ($ProPackageFullName) {
        Write-Host "Removing Provisioned Package: $PackageFullName"
        Remove-AppxProvisionedPackage -Online -PackageName $ProPackageFullName | Out-Null
    }
 
    Else {
        Write-Host "Unable To Find Provisioned Package: $App"
    }
}

reg unload HKU\Default_User
Write-Host "`n### Script execution completed ###.`n"
Write-Host "Press any key to continue ..."
$x = $host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")