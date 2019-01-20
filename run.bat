@echo off
echo ################################################################################
echo #         Win10EnterpriseReady Launcher, preparing script execution...         #
echo ################################################################################
echo:
ping 127.0.0.1 -n 2 >nul
<nul set /p =Searching for script file... 
if exist "Win10EnterpriseReady.ps1" (
	@echo Found!
	<nul set /p =Bypassing Microsoft PowerShell Execution Policy...
	powershell.exe -noprofile -executionpolicy bypass -file .\Win10EnterpriseReady.ps1
	@echo Done!
    exit
) else (
	echo.
	echo FAILURE: File missing. Opening download page.
	timeout /T 5
	start "" https://github.com/Sidewinder53/Win10EnterpriseReady
    exit
)