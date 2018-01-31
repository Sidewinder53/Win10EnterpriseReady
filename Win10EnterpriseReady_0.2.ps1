#region Privilege Elevation on startup

if (-Not ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] 'Administrator')) {
    if ([int](Get-CimInstance -Class Win32_OperatingSystem | Select-Object -ExpandProperty BuildNumber) -ge 6000) {
        $CommandLine = "-noprofile -executionpolicy bypass -File `"" + $MyInvocation.MyCommand.Path + "`" " + $MyInvocation.UnboundArguments
        Start-Process -FilePath PowerShell.exe -Verb Runas -ArgumentList $CommandLine
        Exit
    }
}

#endregion

#region Global App Info

$version = '0.2'
$iniFile = "$PSScriptRoot\config.ini"
$mode = 'manual'
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

#endregion

#region Public functions

function dl_latest {
    $api_response = Invoke-WebRequest -Uri "https://api.github.com/repos/Sidewinder53/Win10EnterpriseReady/releases/latest" | ConvertFrom-Json
    $dl_tag_name = $api_response.'tag_name'
    $dl_name = $api_response.'name'
    $dl_url = $api_response.'zipball_url'
    Invoke-WebRequest -Uri $dl_url -OutFile "$PSScriptRoot\Win10EnterpriseReady_$dl_tag_name.zip"
}

function check_latest {
    $api_response = Invoke-WebRequest -Uri "https://api.github.com/repos/Sidewinder53/Win10EnterpriseReady/releases/latest" | ConvertFrom-Json | % { if (-not ($_.'tag_name' -eq $null)) { $_.'tag_name' -replace "[^0-9\.]" } }
    $up_to_date = $version -ge $api_response
    return $up_to_date
}

#endregion

#region Software update on startup

# Write-Host "Disabling IE First Run wizard to enable update check..." # Better not display this
New-Item -Path 'Registry::HKLM\Software\Policies\Microsoft\Internet Explorer\Main' -Force | Out-Null
Set-ItemProperty -Path 'Registry::HKLM\Software\Policies\Microsoft\Internet Explorer\Main' -Name DisableFirstRunCustomize -Value 1
$internet_con = Test-Connection -computer "www.msftncsi.com" -count 1 -quiet

if ($internet_con) {
    if (check_latest) {
        $status = "(Up to date)"
        $status_color = "Green"
        $perform_update = 0
    } else {
        $status = "#(Outdated)#"
        $status_color = "Red"
        $perform_update = 1
    }
} else {
    $status = "No Int.-Con."
    $status_color = "Gray"
    $perform_update = 0
}

Write-Host -NoNewline "##################################################################`n#       Windows 10 Enterprise Ready by tobias-kleinmann.de       #`n#                 Version 0.2-beta  "
Write-Host -NoNewline "$($status)" -ForegroundColor $status_color
Write-Host -NoNewline "                 #`n#                                                                #`n#        This script is distributed under the MIT License        #`n#          "
Write-Host -NoNewline "github.com/Sidewinder53/Win10EnterpriseReady" -ForegroundColor Gray
Write-Host "          #`n##################################################################`n"

if ( $perform_update -eq 1) {
    Write-Host "You are running an outdated version of this script.`nIn order to ensure maximum stability an update is mandatory."
    if ($internet_con) {
        Write-Host "Downloading..."
        dl_latest
        Write-Host "The latest version of the script has been downloaded to the current directory."
    } else {
        Write-Host "No connection to the update server could be established, please redownload the software manually."
    }
    Write-Host "Press any key to exit this console session ..."
    $x = $host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
    exit
 }
 #endregion

if ( $ENV:PROCESSOR_ARCHITECTURE -eq 'AMD64' ) {
    $arch = '64'
} else {
    $arch = '32'
}
Write-Host "> System Information:`n"
Write-Host "Windows Version:`t$([Environment]::OSVersion)" 
Write-Host "Architecture:`t`t$($arch)-bit"

if([System.IO.File]::Exists($iniFile)){
    Write-Host "Parsing configuration file data...";
    #To store in seperate var: ; New-Variable -Name $store[0] -Value $store[1]
    Get-Content $iniFile | ForEach-Object -Begin {$settings=@{}} -Process {$store = [regex]::split($_,'='); if(($store[0].CompareTo("") -ne 0) -and ($store[0].StartsWith("[") -ne $True) -and ($store[0].StartsWith("#") -ne $True)) {$settings.Add($store[0], $store[1])}}
    if ($settings.Get_Item("unattended_enabled") -eq "true") {
        $mode = "unattended"
        Write-Host "`nConfiguration file contains instruction to enable unattended mode.";
        while(!$Host.UI.RawUI.KeyAvailable -and ($counter++ -lt 10))
        {
            $time_left = 10 - $counter
            Write-Progress -Activity "UNATTENDED AUTOSTART ENABLED - CLOSE THIS WINDOW TO ABORT!" -PercentComplete (100-$counter*10) -SecondsRemaining $time_left -Status "To skip this safety timer press ANY key."
            [Threading.Thread]::Sleep( 1000 )
        }
    }
    $counter = -1
} else {
    #dl_latest
    Write-Host "`nScript execution has been aborted, because the script was unable to find a configuration file." -ForegroundColor Red
    Write-Host "`nThe latest version of the script has been downloaded to the current directory.`nPlease extract all files from this archive and run again."
    Write-Host "Press any key to exit ..."
    $x = $host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
}

if(-not ($mode -eq 'unattended')) {
    $title = ">>> Confirm script execution <<<"
    $message = "This script performs profound system modifications without prior warning. Ensure that the above information is correct, connect your device to an external power source and close all other applications. Do you want to continue?"
    $yes = New-Object System.Management.Automation.Host.ChoiceDescription "&Yes - DANGER", "Start script execution and modify system settings."
    $no = New-Object System.Management.Automation.Host.ChoiceDescription "&No - SAFETY", "Stop script execution and don't modify anything."
    $options = [System.Management.Automation.Host.ChoiceDescription[]]($yes, $no)
    $result = $host.ui.PromptForChoice($title, $message, $options, 1) 
    if ($result -eq '1') { exit }
}

Write-Host "Loading Default User profile..."
reg load HKU\Default_User C:\Users\Default\NTUSER.DAT

if ($settings.Get_Item("disable_cdsrv") -eq "true") {
    Write-Host "Disabling Content Delivery Services for Default User..."
    Set-ItemProperty -Path 'Registry::HKU\Default_User\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager' -Name SystemPaneSuggestionsEnabled -Value 0
    Set-ItemProperty -Path 'Registry::HKU\Default_User\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager' -Name PreInstalledAppsEnabled -Value 0
    Set-ItemProperty -Path 'Registry::HKU\Default_User\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager' -Name OemPreInstalledAppsEnabled -Value 0
}

if ($settings.Get_Item("set_depttp") -eq "true") {
    Write-Host "Setting default Explorer page to 'This PC'..."
    New-Item -Path 'Registry::HKU\Default_User\SOFTWARE\Microsoft\Windows\CurrentVersion\CurrentVersion\Explorer\Advanced' -Force | Out-Null
    Set-ItemProperty -Path 'Registry::HKU\Default_User\SOFTWARE\Microsoft\Windows\CurrentVersion\CurrentVersion\Explorer\Advanced' -Name LaunchTo -Value 1
}

if ($settings.Get_Item("hide_taskview") -eq "true") {
    Write-Host "Removing 'Task View' from taskbar"
    Set-ItemProperty -Path 'Registry::HKU\Default_User\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced' -Name ShowTaskViewButton -Value 0
}

if ($settings.Get_Item("hide_mypeople") -eq "true") {
    Write-Host "Removing 'My People' from taskbar..."
    New-Item -Path 'Registry::HKU\Default_User\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced\People' -Force | Out-Null
    Set-ItemProperty -Path 'Registry::HKU\Default_User\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced\People' -Name PeopleBand -Value 0
}

if ($settings.Get_Item("disable_cortana") -eq "true") {
    Write-Host "Disabling Cortana (system-wide)..."
    New-Item -Path 'Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Windows Search' -Force | Out-Null
    Set-ItemProperty -Path 'Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Windows Search' -Name AllowCortana -Value 0
}

if ($settings.Get_Item("showonly_personalization") -eq "true") {
    Write-Host "Removing all tiles except personalization options from Settings..."
    New-Item -Path 'Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer' -Force | Out-Null
    Set-ItemProperty -Path 'Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer' -Name SettingsPageVisibility -Value 'showonly:personalization-background'
} else {
    if ($settings.Get_Item("hide_cortana") -eq "true" -and $settings.Get_Item("hide_gaming") -eq "true") {
        Write-Host "Removing Cortana and Gaming realted tiles from Settings..."
        New-Item -Path 'Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer' -Force | Out-Null
        Set-ItemProperty -Path 'Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer' -Name SettingsPageVisibility -Value 'hide:cortana;cortana-permissions;cortana-notifications;cortana-moredetails;cortana-language;gaming-gamebar;gaming-gamedvr;gaming-broadcasting;gaming-gamemode;gaming-trueplay;gaming-xboxnetworking'
    } else {
        if ($settings.Get_Item("hide_cortana") -eq "true") {
            Write-Host "Removing Cortana realted tiles from Settings..."
            New-Item -Path 'Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer' -Force | Out-Null
            Set-ItemProperty -Path 'Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer' -Name SettingsPageVisibility -Value 'hide:cortana;cortana-permissions;cortana-notifications;cortana-moredetails;cortana-language'
        }
        if ($settings.Get_Item("hide_gaming") -eq "true") {
            Write-Host "Removing Gaming realted tiles from Settings..."
            New-Item -Path 'Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer' -Force | Out-Null
            Set-ItemProperty -Path 'Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer' -Name SettingsPageVisibility -Value 'hide:gaming-gamebar;gaming-gamedvr;gaming-broadcasting;gaming-gamemode;gaming-trueplay;gaming-xboxnetworking'
        }
    }
}

if ($settings.Get_Item("disable_onedrive") -eq "true") {
    Write-Host "Disabling OneDrive ($($arch)-bit edition)..."
    New-Item -Path 'Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Wow6432Node\Policies\Microsoft\Windows\OneDrive' -Force | Out-Null
    Set-ItemProperty -Path 'Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Wow6432Node\Policies\Microsoft\Windows\OneDrive' -Name DisableFileSyncNGSC -Value 1
}

if ($settings.Get_Item("remove_onedrive") -eq "true") {
    Write-Host "Removing OneDrive ($($arch)-bit edition)..."
    if ( $arch -eq '64' ) { 
        $odsetuploc = [System.Environment]::ExpandEnvironmentVariables('%SystemRoot%\SysWOW64\OneDriveSetup.exe /uninstall') 
    } else {
        $odsetuploc = [System.Environment]::ExpandEnvironmentVariables('%SystemRoot%\System32\OneDriveSetup.exe /uninstall')
    }
    Invoke-Expression $odsetuploc
}

if ($settings.Get_Item("clear_startmenu") -eq "true") {
    Write-Host "Creating empty Start menu Layout..."
    New-Item -ItemType Directory -Path 'C:\Windows\deployment\' -Force | Out-Null
    '<LayoutModificationTemplate xmlns:defaultlayout="http://schemas.microsoft.com/Start/2014/FullDefaultLayout" xmlns:start="http://schemas.microsoft.com/Start/2014/StartLayout" Version="1" xmlns="http://schemas.microsoft.com/Start/2014/LayoutModification"><LayoutOptions StartTileGroupCellWidth="6" /><DefaultLayoutOverride><StartLayoutCollection><defaultlayout:StartLayout GroupCellWidth="6" /></StartLayoutCollection></DefaultLayoutOverride></LayoutModificationTemplate>' | Out-File -FilePath C:\Windows\deployment\DefaultLayout.xml -Append
    Write-Host "Importing empty Start menu Layout.."
    Import-StartLayout -LayoutPath "C:\Windows\deployment\DefaultLayout.xml" -MountPath "C:\"
}

$AppsList = @()

if ($settings.Get_Item("app_remove_pup") -eq "true") {
    $AppsList += 
        "Microsoft.BingWeather","Microsoft.GetHelp","Microsoft.Getstarted","Microsoft.Messaging","Microsoft.Microsoft3DViewer","Microsoft.MicrosoftOfficeHub",
        "Microsoft.MicrosoftSolitaireCollection","Microsoft.OneConnect","Microsoft.People","Microsoft.Print3D","Microsoft.SkypeApp","Microsoft.Wallet",
        "microsoft.windowscommunicationsapps","Microsoft.WindowsFeedbackHub","Microsoft.WindowsMaps"
}

if ($settings.Get_Item("app_remove_onenote") -eq "true") {
    $AppsList += "Microsoft.Office.OneNote"
}

if ($settings.Get_Item("app_remove_gaming") -eq "true") {
    $AppsList += "Microsoft.Xbox.TCUI","Microsoft.XboxApp","Microsoft.XboxGameOverlay","Microsoft.XboxIdentityProvider","Microsoft.XboxSpeechToTextOverlay"
}

if ($settings.Get_Item("app_remove_ZuneMusic") -eq "true") {
    $AppsList += "Microsoft.ZuneMusic"
}

if ($settings.Get_Item("app_remove_ZuneVideoc") -eq "true") {
    $AppsList += "Microsoft.ZuneVideo"
}



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