#region PrivilegeElevation

if (-Not ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] 'Administrator')) {
  if ([int](Get-CimInstance -Class Win32_OperatingSystem | Select-Object -ExpandProperty BuildNumber) -ge 6000) {
    $CommandLine = "-noprofile -executionpolicy bypass -File `"" + $MyInvocation.MyCommand.Path + "`" " + $MyInvocation.UnboundArguments
    Start-Process -FilePath PowerShell.exe -Verb Runas -ArgumentList $CommandLine
    Exit
  }
}

#endregion

#region GlobalAppInfo

$version = '0.3'
$iniFile = "$PSScriptRoot\config.ini"
$size = New-Object System.Management.Automation.Host.Size(120, 50)
$host.ui.rawui.WindowSize = $size   

#endregion

#region FetchUpdateInfo

[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

function check_version {
  $api_response = Invoke-WebRequest -Uri "https://api.github.com/repos/Sidewinder53/Win10EnterpriseReady/releases/latest" | `
    ConvertFrom-Json | `
    ForEach-Object { if (-not ($null -eq $_.'tag_name')) { $_.'tag_name' -replace "[^0-9\.]" } }
  $up_to_date = $version -ge $api_response
  return $up_to_date
}

function download_update {
  $api_response = Invoke-WebRequest -Uri "https://api.github.com/repos/Sidewinder53/Win10EnterpriseReady/releases/latest" | ConvertFrom-Json
  $dl_tag_name = $api_response.'tag_name'
  $dl_url = $api_response.'zipball_url'
  Invoke-WebRequest -Uri $dl_url -OutFile "$PSScriptRoot\Win10EnterpriseReady_$dl_tag_name.zip"
}

#endregion

#region PerformUpdate

# Write-Host "Disabling IE First Run wizard to enable update check..." # Better not display this
New-Item -Path 'Registry::HKLM\Software\Policies\Microsoft\Internet Explorer\Main' -Force | Out-Null
Set-ItemProperty -Path 'Registry::HKLM\Software\Policies\Microsoft\Internet Explorer\Main' -Name DisableFirstRunCustomize -Value 1
$internet_con = Test-Connection -computer "api.github.com" -count 1 -quiet

if ($internet_con) {
  if (check_version) {
    $status = "(Up to date)"
    $status_color = "Green"
    $perform_update = 0
  }
  else {
    $status = "#(Outdated)#"
    $status_color = "Red"
    $perform_update = 1
  }
}
else {
  $status = "No Int.-Con."
  $status_color = "Gray"
  $perform_update = 0
}


Write-Host -NoNewLine "          ###################################################################################################`n"
Write-Host -NoNewLine "          #                           Win10EnterpriseReady by tobias-kleinmann.de                           #`n"
Write-Host -NoNewLine "          #                                  Version $($version)-beta "
Write-Host -NoNewline "$($status)" -ForegroundColor $status_color
Write-Host -NoNewline "                                  #`n"
Write-Host -NoNewline "          #                                                                                                 #`n"
Write-Host -NoNewline "          #                         This script is distributed under the MIT License                        #`n"
Write-Host -NoNewline "          #"
Write-Host -NoNewline "                          github.com/Sidewinder53/Win10EnterpriseReady" -ForegroundColor Gray
write-host -NoNewline "                           #`n"
Write-Host -NoNewline "          ###################################################################################################`n`n`n"

if ( $perform_update -eq 1) {
  Write-Host "You are running an outdated version of this script.`nIn order to ensure maximum stability an update is mandatory."
  Write-Host "Downloading..."
  download_update
  Write-Host "The latest version of the script has been downloaded to the current directory."
  Write-Host "Press any key to exit this console session ..."
  $x = $host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
  exit
}
#endregion

if ( $ENV:PROCESSOR_ARCHITECTURE -eq 'AMD64' ) {
  $arch = '64'
}
else {
  $arch = '32'
}
Write-Host "> Windows OneCore Information:`n"
Write-Host "OneCore Product:`t$([Environment]::OSVersion)"
Write-Host "OneCore SKU:`t`t$(Get-WindowsEdition -Online | Select-Object -ExpandProperty Edition) (#$(Get-WmiObject win32_operatingsystem | Select-Object -ExpandProperty OperatingSystemSKU))"
Write-Host "OneCore Version:`t$((Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion" -Name ReleaseId).ReleaseId)"
Write-Host "OneCore Architecture:`t$($arch)-bit"

if ([System.IO.File]::Exists($iniFile)) {
  Write-Host "`n> Parsing configuration file data..." -NoNewline
  Get-Content $iniFile | ForEach-Object -Begin {$settings = @{}} -Process {$store = [regex]::split($_, '='); if (($store[0].CompareTo("") -ne 0) -and ($store[0].StartsWith("[") -ne $True) -and ($store[0].StartsWith("#") -ne $True)) {$settings.Add($store[0], $store[1])}}
  Write-Host " Done." -ForegroundColor Green
  if ($settings.Get_Item("unattended_enabled") -eq 'true') {
    Write-Host "`nConfiguration file contains instruction to continue in unattended mode.";
    while (!$Host.UI.RawUI.KeyAvailable -and ($counter++ -lt 10)) {
      $time_left = 10 - $counter
      Write-Progress -Activity "UNATTENDED AUTOSTART ENABLED - CLOSE THIS WINDOW TO ABORT!" -PercentComplete (100 - $counter * 10) -SecondsRemaining $time_left -Status "Press ANY key to skip."
      [Threading.Thread]::Sleep( 1000 )
    }
  }
  else {
    $title = "> Confirm script execution"
    $message = "This script will perform profound system modifications, some of which can not be reverted easily. Ensure that all settings in 'config.ini' have been set to your preferences. Verify the above information, connect your device to an external power source and close all other applications. Do you want to continue?"
    $yes = New-Object System.Management.Automation.Host.ChoiceDescription "&Yes - DANGER", "Start script execution and modify system settings."
    $no = New-Object System.Management.Automation.Host.ChoiceDescription "&No - SAFETY", "Stop script execution and keep your current configuration."
    $options = [System.Management.Automation.Host.ChoiceDescription[]]($yes, $no)
    $result = $host.ui.PromptForChoice($title, $message, $options, 1) 
    if ($result -eq '1') { exit }
  }
  $counter = -1
}
else {
  dl_latest
  Write-Host "`nScript execution aborted, configuration file missing." -ForegroundColor Red
  Write-Host "Press any key to exit..."
  $x = $host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
}

# Write-Host "Execution would start at this point. Press any key to exit ..."
# $x = $host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
# exit

Write-Host "Loading Default User profile..."
reg load HKU\Default_User C:\Users\Default\NTUSER.DAT

if ($settings.Get_Item("disable_cdsrv") -eq "true") {
  Write-Host "Disabling Content Delivery Services for Default User..."
  $cdsrvregpath = 'Registry::HKU\Default_User\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager'
  Set-ItemProperty -Path $cdsrvregpath -Name ContentDeliveryAllowed -Value 0
  Set-ItemProperty -Path $cdsrvregpath -Name OemPreInstalledAppsEnabled -Value 0
  Set-ItemProperty -Path $cdsrvregpath -Name PreInstalledAppsEnabled -Value 0
  Set-ItemProperty -Path $cdsrvregpath -Name RotatingLockScreenEnabled -Value 0
  Set-ItemProperty -Path $cdsrvregpath -Name RotatingLockScreenOverlayEnabled -Value 0
  Set-ItemProperty -Path $cdsrvregpath -Name SilentInstalledAppsEnabled -Value 0
  Set-ItemProperty -Path $cdsrvregpath -Name SoftLandingEnabled -Value 0
  Set-ItemProperty -Path $cdsrvregpath -Name SubscribedContent-310093Enabled -Value 0
  Set-ItemProperty -Path $cdsrvregpath -Name SubscribedContent-310093Enabled -Value 0
  Set-ItemProperty -Path $cdsrvregpath -Name SubscribedContent-338387Enabled -Value 0
  Set-ItemProperty -Path $cdsrvregpath -Name SubscribedContent-338388Enabled -Value 0
  Set-ItemProperty -Path $cdsrvregpath -Name SubscribedContent-338389Enabled -Value 0
  Set-ItemProperty -Path $cdsrvregpath -Name SubscribedContent-338389Enabled -Value 0
  Set-ItemProperty -Path $cdsrvregpath -Name SubscribedContentEnabled -Value 0
  Set-ItemProperty -Path $cdsrvregpath -Name SystemPaneSuggestionsEnabled -Value 0
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
}
else {
  if ($settings.Get_Item("hide_cortana") -eq "true" -and $settings.Get_Item("hide_gaming") -eq "true") {
    Write-Host "Removing Cortana and Gaming realted tiles from Settings..."
    New-Item -Path 'Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer' -Force | Out-Null
    Set-ItemProperty -Path 'Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer' -Name SettingsPageVisibility -Value 'hide:cortana;cortana-permissions;cortana-notifications;cortana-moredetails;cortana-language;gaming-gamebar;gaming-gamedvr;gaming-broadcasting;gaming-gamemode;gaming-trueplay;gaming-xboxnetworking'
  }
  else {
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
  }
  else {
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
  Remove-Item -Path "C:\Windows\deployment\DefaultLayout.xml"
}

$appxRemovalList = @()

if ($settings.Get_Item("app_remove_ms_apps") -eq "true") {
  $appxRemovalList += 
  "Microsoft.BingWeather", "Microsoft.GetHelp", "Microsoft.Getstarted", "Microsoft.Messaging", "Microsoft.Microsoft3DViewer", "Microsoft.MicrosoftOfficeHub",
  "Microsoft.MixedReality.Portal", "Microsoft.MicrosoftSolitaireCollection", "Microsoft.OneConnect", "Microsoft.People", "Microsoft.Print3D", "Microsoft.SkypeApp", "Microsoft.MicrosoftStickyNotes",
  "Microsoft.Wallet", "microsoft.windowscommunicationsapps", "Microsoft.WindowsFeedbackHub", "Microsoft.WindowsMaps", "Microsoft.YourPhone", "Microsoft.People",
  "Microsoft.WindowsAlarms", "Microsoft.MicrosoftOfficeHub", "Microsoft.ScreenSketch", "Microsoft.OneConnect"
}

if ($settings.Get_Item("app_remove_pup") -eq "true") {
  $appxRemovalList += 
  "Microsoft.MicrosoftSolitaireCollection" 
}

if ($settings.Get_Item("app_remove_3rd_party") -eq "true") {
  $appxRemovalList +=
  "*DragonManiaLegends", "*HiddenCityMysteryofShadows", "*MarchofEmpires", "*toolbar*", "06DAC6F6.StumbleUpon", "09B6C2D8.TheTreasuresofMontezuma3", 
  "10084FinerCode.ChessTactics", "134D4F5B.Box*", "1430GreenfieldTechnologie.PuzzleTouch*", "1867LennardSprong.PortablePuzzleCollection", "22450.BestVideoConverter", 
  "25920Bala04.Mideo-VideoPlayer", "26720RandomSaladGamesLLC.HeartsDeluxe*", "26720RandomSaladGamesLLC.Hexter", "26720RandomSaladGamesLLC.SimpleMahjong", 
  "26720RandomSaladGamesLLC.SimpleSolitaire*", "26720RandomSaladGamesLLC.Spades", "2703103D.McAfeeCentral", "27345RickyWalker.BlackjackMaster3", 
  "29313JVGoldSoft.5962504421940", "29534ukaszKurant.Logicos", "29534ukaszKurant.Logicos2", "29982CsabaHarmath.UnCompress*", "2FE3CB00.PicsArt-PhotoStudio*", 
  "32988BernardoZamora.SolitaireHD", "34697joal.EasyMovieMaker", "35229MihaiM.QuizforGeeks", "35300Kubajzl.MCGuide", "37442SublimeCo.AlarmClockForYou", 
  "37457BenoitRenaud.HexWar", "39674HytoGame.TexasHoldemOnline", "39806kalinnikol.FreeCellSolitaireHD", "39806kalinnikol.FreeHeartsHD", "41879VbfnetApps.FileDownloader", 
  "46928bounde.EclipseManager*", "47404LurkingDarknessOfRoy.SimpleStrategyRTS", "48682KiddoTest.Frameworkuapbase", "4AE8B7C2.Booking.comPartnerEdition*", 
  "5269FriedChicken.YouTubeVideosDownloader*", "56081SweetGamesBox.SlitherSnake.io", "56491SimulationFarmGames.100BallsOriginal", 
  "57591LegendsSonicSagaGame.Twenty48Solitaire", "59091GameDesignStudio.MahjongDe*", "5A894077.McAfeeSecurity", "64885BlueEdge.OneCalendar*", 
  "6Wunderkinder.Wunderlist", "7475BEDA.BitcoinMiner", "7906AAC0.TOSHIBACanadaPartners*", "7906AAC0.ToshibaCanadaWarrantyService*", "7EE7776C.LinkedInforWindows", 
  "7digitalLtd.7digitalMusicStore*", "828B5831.HiddenCityMysteryofShadows", "89006A2E.AutodeskSketchBook*", "95FE1D22.VUDUMoviesandTV", "9E2F88E3.Twitter", 
  "A278AB0D.DisneyMagicKingdoms", "A278AB0D.DragonManiaLegends*", "A278AB0D.MarchofEmpires", "A34E4AAB.YogaChef*", "A8C75DD4.Therefore", 
  "AD2F1837.DiscoverHPTouchpointManager", "AD2F1837.GettingStartedwithWindows8", "AD2F1837.HPBusinessSlimKeyboard", "AD2F1837.HPConnectedMusic", 
  "AD2F1837.HPConnectedPhotopoweredbySnapfish", "AD2F1837.HPFileViewer", "AD2F1837.HPGames", "AD2F1837.HPJumpStart", "AD2F1837.HPPCHardwareDiagnosticsWindows", 
  "AD2F1837.HPPowerManager", "AD2F1837.HPRegistration", "AD2F1837.HPWelcome", "AD2F1837.SmartfriendbyHPCare", "ASUSCloudCorporation.MobileFileExplorer", 
  "AccuWeather.AccuWeatherforWindows8*", "AcerIncorporated*", "AcerIncorporated.AcerExplorer", "AcrobatNotificationClient", "ActiproSoftwareLLC*", 
  "ActiproSoftwareLLC.562882FEEB491", "AdobeSystemsIncorporated.AdobePhotoshopExpress*", "AdobeSystemsIncorporated.AdobeRevel*", "Amazon.com.Amazon*", 
  "AppUp.IntelAppUpCatalogueAppWorldwideEdition*", "B9ECED6F.ASUSGIFTBOX*", "B9ECED6F.ASUSProductRegistrationProgram", "B9ECED6F.ASUSWelcome", "B9ECED6F.MyASUS", 
  "B9ECED6F.eManual", "BD9B8345.AlbumbySony*", "BD9B8345.MusicbySony*", "BD9B8345.Socialife*", "BD9B8345.VAIOCare*", "BD9B8345.VAIOMessageCenter*", "C27EB4BA.DropboxOEM", 
  "COMPALELECTRONICSINC.AlienwareOSDKits", "COMPALELECTRONICSINC.AlienwareTypeCaccessory", "COMPALELECTRONICSINC.Alienwaredockingaccessory", 
  "ChaChaSearch.ChaChaPushNotification*", "ClearChannelRadioDigital.iHeartRadio*", "CrackleInc.Crackle*", "CyberLinkCorp.ac.AcerCrystalEye*", 
  "CyberLinkCorp.ac.SocialJogger*", "CyberLinkCorp.hs.PowerMediaPlayer14forHPConsumerPC", "CyberLinkCorp.hs.YouCamforHP*", "CyberLinkCorp.id.PowerDVDforLenovoIdea*", 
  "D52A8D61.FarmVille2CountryEscape*", "D5EA27B7.Duolingo-LearnLanguagesforFree*", "DB6EA5DB.CyberLinkMediaSuiteEssentials*", "DailymotionSA.Dailymotion*", 
  "DellInc.AlienwareCommandCenter", "DellInc.AlienwareCustomerConnect", "DellInc.AlienwareProductRegistration", "DellInc.DellCommandUpdate", "DellInc.DellCustomerConnect", 
  "DellInc.DellDigitalDelivery", "DellInc.DellHelpSupport", "DellInc.DellPowerManager", "DellInc.DellProductRegistration", "DellInc.DellShop", 
  "DellInc.DellSupportAssistforPCs", "DeviceDoctor.RAROpener", "DolbyLaboratories.DolbyAccess*", "DolbyLaboratories.DolbyAtmosSoundSystem", "Drawboard.DrawboardPDF*", 
  "DriverToaster*", "E046963F.LenovoCompanion*", "E046963F.LenovoSupport*", "E0469640.CameraMan*", "E0469640.DeviceCollaboration*", "E0469640.LenovoRecommends*", 
  "E0469640.YogaCameraMan*", "E0469640.YogaPhoneCompanion*", "E0469640.YogaPicks*", "ESPNInc.WatchESPN*", "EncyclopaediaBritannica.EncyclopaediaBritannica*", 
  "Evernote.Evernote", "Evernote.Skitch*", "EvilGrogGamesGmbH.WorldPeaceGeneral2017", "F5080380.ASUSPowerDirector*", "Facebook.317180B0BB486", "Facebook.Facebook", 
  "Facebook.InstagramBeta*", "FilmOnLiveTVFree.FilmOnLiveTVFree*", "Fingersoft.HillClimbRacing", "FingertappsInstruments*", "FingertappsOrganizer*", "Flipboard.Flipboard*", 
  "FreshPaint*", "GAMELOFTSA.Asphalt8Airborne*", "GAMELOFTSA.SharkDash*", "GameGeneticsApps.FreeOnlineGamesforLenovo*", "GettingStartedwithWindows8*", "GoogleInc.GoogleSearch", 
  "HPConnectedMusic*", "HPConnectedPhotopoweredbySnapfish*", "HPRegistration*", "HuluLLC.HuluPlus*", "InsightAssessment.CriticalThinkingInsight", "JigsWar*", 
  "K-NFBReadingTechnologiesI.BookPlace*", "KasperskyLab.KasperskyNow*", "KeeperSecurityInc.Keeper", "KindleforWindows8*", "LenovoCorporation.LenovoID*", 
  "LenovoCorporation.LenovoSettings*", "MAGIX.MusicMakerJam*", "McAfeeInc.01.McAfeeSecurityAdvisorforDell", "McAfeeInc.05.McAfeeSecurityAdvisorforASUS", 
  "MobileFileExplorer*", "MusicMakerJam*", "NAMCOBANDAIGamesInc.PAC-MANChampionshipEditionDXfo*", "NAVER.LINEwin8*", "NBCUniversalMediaLLC.NBCSportsLiveExtra*", 
  "Nordcurrent.CookingFever", "Ookla.SpeedtestbyOokla", "PandoraMediaInc.29680B314EFC2", "PinballFx2*", "Playtika.CaesarsSlotsFreeCasino*", "Priceline", 
  "PricelinePartnerNetwork.Priceline.comTheBestDealso", "PublicationsInternational.iCookbookSE*", "RandomSaladGamesLLC.GinRummyProforHP*", 
  "RealtekSemiconductorCorp.RealtekAudioControl", "SAMSUNGELECTRONICSCO.LTD.SamsungPrinterExperience", "ShazamEntertainmentLtd.Shazam*", "SolidRhino.SteelTactics", 
  "SonicWALL.MobileConnect", "SpotifyAB.SpotifyMusic", "SymantecCorporation.NortonStudio*", "TOSHIBATEC.ToshibaPrintExperience", 
  "TelegraphMediaGroupLtd.TheTelegraphforLenovo*", "TheNewYorkTimes.NYTCrossword*", "ThumbmunkeysLtd.PhototasticCollage*", "ToshibaAmericaInformation.ToshibaCentral*", 
  "TripAdvisorLLC.TripAdvisorHotelsFlightsRestaurants*", "TuneIn.TuneInRadio*", "UniversalMusicMobile.HPLOUNGE", "UptoElevenDigitalSolution.mysms-Textanywhere*", 
  "Vimeo.Vimeo*", "Weather.TheWeatherChannelforHP*", "Weather.TheWeatherChannelforLenovo*", "WeatherBug.a.WeatherBug", "WildTangentGames*", "WildTangentGames.-GamesApp-", 
  "WildTangentGames.63435CFB65F55", "WinZipComputing.WinZipUniversal*", "XINGAG.XING", "XeroxCorp.PrintExperience", "YouSendIt.HighTailForLenovo*", "ZinioLLC.Zinio*", 
  "eBayInc.eBay*", "esobiIncorporated.newsXpressoMetro*", "fingertappsASUS.FingertappsInstrumentsrecommendedb*", "fingertappsASUS.JigsWarrecommendedbyASUS*", 
  "fingertappsasus.FingertappsOrganizerrecommendedbyA*", "flaregamesGmbH.RoyalRevolt2*", "king.com*", "king.com.BubbleWitch3Saga", "king.com.CandyCrushSaga", 
  "king.com.CandyCrushSodaSaga", "king.com.ParadiseBay", "sMedioforHP.sMedio360*", "sMedioforToshiba.TOSHIBAMediaPlayerbysMedioTrueLin*", "zuukaInc.iStoryTimeLibrary*"
}

if ($settings.Get_Item("app_remove_onenote") -eq "true") {
  $appxRemovalList += "Microsoft.Office.OneNote"
}

if ($settings.Get_Item("app_remove_gaming") -eq "true") {
  $appxRemovalList += "Microsoft.Xbox.TCUI", "Microsoft.XboxApp", "Microsoft.XboxGameOverlay", "Microsoft.XboxIdentityProvider", "Microsoft.XboxSpeechToTextOverlay"
}

if ($settings.Get_Item("app_remove_ZuneMusic") -eq "true") {
  $appxRemovalList += "Microsoft.ZuneMusic"
}

if ($settings.Get_Item("app_remove_ZuneVideo") -eq "true") {
  $appxRemovalList += "Microsoft.ZuneVideo"
}



Write-Host "Removing Provisioned Applications..."

$instAppxPckgs = Get-AppxPackage -AllUsers | Select-Object PackageFullName, Name
$provAppxPckgs = Get-AppxProvisionedPackage -online | Select-Object PackageName, DisplayName

ForEach ($App in $appxRemovalList) {
  Write-Host "DEBUG: Working item $($App)"
  $instAppxPckgsFullName = ($instAppxPckgs | Where Name -like $App).PackageFullName
  $provAppxPckgsFullName = ($provAppxPckgs | Where DisplayName -like $App).PackageName
 
  if ($instAppxPckgsFullName) {
    Write-Host "Removing Package: $instAppxPckgsFullName"
    Remove-AppxPackage -Package $instAppxPckgsFullName | Out-Null
  }
 
  if ($provAppxPckgsFullName) {
    Write-Host "Removing Provisioned Package: $provAppxPckgsFullName"
    Remove-AppxProvisionedPackage -Online -PackageName $provAppxPckgsFullName | Out-Null
  }
}

reg unload HKU\Default_User
Write-Host "`n`n`n> Script execution completed!`n" -ForegroundColor Green
Write-Host "Press any key to exit..."
$x = $host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")