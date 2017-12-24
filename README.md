# Win10EnterpriseReady
This script performs the following actions:
- For all users:
	- Disable Cortana
	- Disable and remove OneDrive
	- Remove Gaming and Cortana related systems setting tiles
	- Remove provisioned applications, such as
		- Bing Weather
		- 3D related apps
		- Skype and other communication apps
		- All XBOX and gaming-related apps
		- Feedback hub
		- *and other consumer apps*
- For users that are created after script execution:
	- Disable Content Delivery Services
	- Set default Explorer page to 'This PC'
	- Remove 'Task View' button from taskbar
	- Remove 'My People' button from taskbar
	- Remove all tiles from the start menu

## When and where do I use this script?
First: DO NOT RUN THIS SCRIPT ON A MACHINE THAT IS ALREADY IN USE. It is inteded to be used on a device that was set up from scratch with no modifications. Please, do not use this script in your MDT task sequence, don't think about deploying it with your MDM solution and only use it with official Windows images.

## How do I run this script?
To execute the script on a newly set up Windows image, start 'run.bat' to bypass the PowerShell Execution-Policy. If yours is already set to allow unknown and unsigned scripts to run you can simply execute the PowerShell script it self.
