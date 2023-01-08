
# Lower UAC level (disabling it completely would break apps)
Function SetUACLow {
	Write-Output "Lowering UAC level..."
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "ConsentPromptBehaviorAdmin" -Type DWord -Value 0
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "PromptOnSecureDesktop" -Type DWord -Value 0
}


# Disable Firewall
Function DisableFirewall {
	Write-Output "Disabling Firewall..."
	If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\StandardProfile")) {
		New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\StandardProfile" -Force | Out-Null
	}
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\StandardProfile" -Name "EnableFirewall" -Type DWord -Value 0
}


# Hide Windows Defender SysTray icon
Function HideDefenderTrayIcon {
	Write-Output "Hiding Windows Defender SysTray icon..."
	If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender Security Center\Systray")) {
		New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender Security Center\Systray" -Force | Out-Null
	}
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender Security Center\Systray" -Name "HideSystray" -Type DWord -Value 1
	If ([System.Environment]::OSVersion.Version.Build -eq 14393) {
		Remove-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" -Name "WindowsDefender" -ErrorAction SilentlyContinue
	} ElseIf ([System.Environment]::OSVersion.Version.Build -ge 15063) {
		Remove-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" -Name "SecurityHealth" -ErrorAction SilentlyContinue
	}
}


# Disable Windows Defender
Function DisableDefender {
	Write-Output "Disabling Windows Defender..."
	If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender")) {
		New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender" -Force | Out-Null
	}
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender" -Name "DisableAntiSpyware" -Type DWord -Value 1
	If ([System.Environment]::OSVersion.Version.Build -eq 14393) {
		Remove-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" -Name "WindowsDefender" -ErrorAction SilentlyContinue
	} ElseIf ([System.Environment]::OSVersion.Version.Build -ge 15063) {
		Remove-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" -Name "SecurityHealth" -ErrorAction SilentlyContinue
	}
}


# Disable Windows Defender Cloud
Function DisableDefenderCloud {
	Write-Output "Disabling Windows Defender Cloud..."
	If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Spynet")) {
		New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Spynet" -Force | Out-Null
	}
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Spynet" -Name "SpynetReporting" -Type DWord -Value 0
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Spynet" -Name "SubmitSamplesConsent" -Type DWord -Value 2
}





# Disable Controlled Folder Access (Defender Exploit Guard feature) - Applicable since 1709, requires Windows Defender to be enabled
Function DisableCtrldFolderAccess {
	Write-Output "Disabling Controlled Folder Access..."
	Set-MpPreference -EnableControlledFolderAccess Disabled -ErrorAction SilentlyContinue
}


# Disable Core Isolation Memory Integrity - Applicable since 1803
Function DisableCIMemoryIntegrity {
	Write-Output "Disabling Core Isolation Memory Integrity..."
	Remove-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\HypervisorEnforcedCodeIntegrity" -Name "Enabled" -ErrorAction SilentlyContinue
}


# Disable Windows Defender Application Guard - Applicable since 1709 Enterprise and 1803 Pro. Not applicable to Server
Function DisableDefenderAppGuard {
	Write-Output "Disabling Windows Defender Application Guard..."
	Disable-WindowsOptionalFeature -online -FeatureName "Windows-Defender-ApplicationGuard" -NoRestart -WarningAction SilentlyContinue | Out-Null
}

# Hide Account Protection warning in Defender about not using a Microsoft account
Function HideAccountProtectionWarn {
	Write-Output "Hiding Account Protection warning..."
	If (!(Test-Path "HKCU:\Software\Microsoft\Windows Security Health\State")) {
		New-Item -Path "HKCU:\Software\Microsoft\Windows Security Health\State" -Force | Out-Null
	}
	Set-ItemProperty "HKCU:\Software\Microsoft\Windows Security Health\State" -Name "AccountProtection_MicrosoftAccount_Disconnected" -Type DWord -Value 1
}


# Disable blocking of downloaded files (i.e. storing zone information - no need to do File\Properties\Unblock)
Function DisableDownloadBlocking {
	Write-Output "Disabling blocking of downloaded files..."
	If (!(Test-Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Attachments")) {
		New-Item -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Attachments" | Out-Null
	}
	Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Attachments" -Name "SaveZoneInformation" -Type DWord -Value 1
}


# Disable Windows Script Host (execution of *.vbs scripts and alike)
Function DisableScriptHost {
	Write-Output "Disabling Windows Script Host..."
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows Script Host\Settings" -Name "Enabled" -Type DWord -Value 0
}


# Disable Meltdown (CVE-2017-5754) compatibility flag
Function DisableMeltdownCompatFlag {
	Write-Output "Disabling Meltdown (CVE-2017-5754) compatibility flag..."
	Remove-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\QualityCompat" -Name "cadca5fe-87d3-4b96-b7fb-a231484277cc" -ErrorAction SilentlyContinue
}


# Enable automatic entering recovery mode during boot
# This allows the boot process to automatically enter recovery mode when it detects startup errors (default behavior)
Function EnableBootRecovery {
	Write-Output "Enabling automatic recovery mode during boot..."
	bcdedit /deletevalue `{current`} BootStatusPolicy | Out-Null
}

# Enable System Recovery and Factory reset
Function EnableRecoveryAndReset {
	Write-Output "Enabling System Recovery and Factory reset..."
	reagentc /enable 2>&1 | Out-Null
}

# Disable automatic reboot on crash (BSOD)
Function DisableAutoRebootOnCrash {
	Write-Output "Disabling automatic reboot on crash (BSOD)..."
	Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\CrashControl" -Name "AutoReboot" -Type DWord -Value 0
}




####Disabling Windows Defender and Windows Firewall as well as setting a low UAC Level
#
#This should only be done to allow you to experiment with known maliscious entities in a controlled virtual machine...
#This should not be done on your desktop/laptop/production server no matter how sure you are that you understand
#the entities you are playing with and what they can do.   BE SMART
#########################################################################################################################

EnableRecoveryAndReset
EnableBootRecovery
DisableAutoRebootOnCrash
SetUACLow
DisableDownloadBlocking
DisableMeltdownCompatFlag
DisableScriptHost
DisableFirewall
HideDefenderTrayIcon
HideAccountProtectionWarn
DisableCIMemoryIntegrity
DisableCtrldFolderAccess
DisableDefenderAppGuard
DisableDefenderCloud

