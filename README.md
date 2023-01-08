# WindowsConfigurationPowerShell-Scripts

* This repository contains powershell scripts that make deployment and configuration of Windows virtual machines easier.   
* Initially, the scripts in this repo used functionality from Dissasembler0's Windows10-Initial-Setup-Script repository as a basis for the majority of its functionality.
* While Dissassembler0's contribution was an awesome piece of work, I began to add some new functionality as my needs began to diverge from what was available in his script. 
* As of now, these scripts are implemented very basically as they are intended to be run directly on VMs or desktops so the scripts only have that functionality.  If I expand the scope of one or more of these scripts, then I will take the time to add more advanced features of PowerShell...


## Scripts Included


* Configure-Windows10Client.ps1
    - This script was meant to make initial configuration changes on new VMs in my homelab.   It disables a lot of Windows functionality that just isn't needed in this setting while also tweaking settings to my preference.
* Disable-WindowsDefender.ps1
    - This script is meant to be run on an isolated VM that will be used to examine malware and other maliscious software in a Windows 10 Setting.   It disables the firewall, Windows Defender, and also configures the UAC so it doesn't complain unlless actions will have major implications for the OS State.
    

