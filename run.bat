@echo off
@echo Checking if Debloat script is present...
if exist "Win10EnterpriseReady_0.1.ps1" (
	@echo File found!
	@echo Bypassing Microsoft PowerShell Execution Policy...
	powershell.exe -noprofile -executionpolicy bypass -file .\Win10EnterpriseReady_0.1.ps1
    exit
) else (
	@echo File missing. Opening download page...
	start "" https:\\tobias-kleinmann.de\projects\Win10EnterpriseReady
    exit
)