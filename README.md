*This README will receive a major update with the full release of version 1.0*

# Win10EnterpriseReady
This script can perform the following actions:
- For all users:
	- Disable Cortana
	- Disable OneDrive
	- Remove OneDrive
	- Set UAC (User Account Control) to maximum, as all other setting levels can be bypassed ([Explanation](https://blogs.msdn.microsoft.com/oldnewthing/20160816-00/?p=94105))
	- Disable Microsoft Store
	- Hide tiles in the settings app, like Cortana, Gaming, Mobile Devices and more
	- Configure Windows Update Delivery Optimization
	- Reduce telemetry and feedback notifications
	- Remove potentially unwanted provisioned app packages:
	```Microsoft.BingWeather, Microsoft.GetHelp, Microsoft.Getstarted, Microsoft.Messaging , Microsoft.Microsoft3DViewer, Microsoft.MicrosoftOfficeHub, Microsoft.MicrosoftSolitaireCollection, Microsoft.OneConnect, Microsoft.People, Microsoft.Print3D, Microsoft.SkypeApp, Microsoft.Wallet , Microsoft.WindowsCommunicationsApps, Microsoft.WindowsFeedbackHub, Microsoft.WindowsMaps```
	- Remove Microsoft Office OneNote: ```Microsoft.Office.OneNote```
	- Remove Microsoft Xbox Services: ```Microsoft.Xbox.TCUI, Microsoft.XboxApp, Microsoft.XboxGameOverlay, Microsoft.XboxIdentityProvider, Microsoft.XboxSpeechToTextOverlay```
	- Remove Microsoft Zune applications: ```Microsoft.ZuneMusic``` and ```Microsoft.ZuneVideo```
- For users that are created after script execution:
	- Disable Content Delivery Services
	- Set default Explorer page to 'This PC'
	- Remove 'Task View' button from taskbar
	- Remove 'My People' button from taskbar
	- Remove all tiles from the start menu
	- A few custom explorer and desktop settings (TBA)

## When and where do I use this script?
First: DO NOT RUN THIS SCRIPT ON A MACHINE THAT IS ALREADY IN USE. It is inteded to be used on a device that was set up from scratch with no modifications. Please, do not use this script in your MDT task sequence, don't think about deploying it with your MDM solution and only use it with official Windows images.

This script was tested with the official Windows 10 RS3 release image and Pro SKU. Other editions and versions of Windows are unsupported at this time.

## How do I run this script?
To execute the script on a newly set up Windows image, start 'run.bat' to bypass the PowerShell Execution-Policy. If yours is already set to allow unknown and unsigned scripts to run you can simply execute the PowerShell script it self.