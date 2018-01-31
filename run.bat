@echo off
@echo ################################################################################
@echo #                     Win10EnterpriseReady, starting up...                     #
@echo ################################################################################
@echo:
ping 127.0.0.1 -n 2 >nul
<nul set /p =Searching for script file... 
if exist "Win10EnterpriseReady_0.2.ps1" (
	@echo Found!
	<nul set /p =Bypassing Microsoft PowerShell Execution Policy...
	powershell.exe -noprofile -executionpolicy bypass -file .\Win10EnterpriseReady_0.2.ps1
	@echo Done!
    exit
) else (
	@echo File missing. Opening download page...
	start "" https://github.com/Sidewinder53/Win10EnterpriseReady
    exit
)