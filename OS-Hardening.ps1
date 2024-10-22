# Enforce password complexity
Write-Host "Enforcing password complexity..."
secedit /export /cfg C:\Windows\Temp\secpol.cfg
(Get-Content C:\Windows\Temp\secpol.cfg).replace("PasswordComplexity = 0", "PasswordComplexity = 1") |
    Set-Content C:\Windows\Temp\secpol.cfg
secedit /configure /db secedit.sdb /cfg C:\Windows\Temp\secpol.cfg /areas SECURITYPOLICY

# Set minimum password length to 12 characters
Write-Host "Setting minimum password length to 12 characters..."
(Get-Content C:\Windows\Temp\secpol.cfg).replace("MinimumPasswordLength = 0", "MinimumPasswordLength = 12") |
    Set-Content C:\Windows\Temp\secpol.cfg
secedit /configure /db secedit.sdb /cfg C:\Windows\Temp\secpol.cfg /areas SECURITYPOLICY

# Set account lockout threshold to 5 invalid login attempts
Write-Host "Setting account lockout threshold to 5 invalid attempts..."
(Get-Content C:\Windows\Temp\secpol.cfg).replace("LockoutBadCount = 0", "LockoutBadCount = 5") |
    Set-Content C:\Windows\Temp\secpol.cfg
secedit /configure /db secedit.sdb /cfg C:\Windows\Temp\secpol.cfg /areas SECURITYPOLICY

# Set lockout duration to 30 minutes
Write-Host "Setting lockout duration to 30 minutes..."
(Get-Content C:\Windows\Temp\secpol.cfg).replace("LockoutDuration = 0", "LockoutDuration = 30") |
    Set-Content C:\Windows\Temp\secpol.cfg
secedit /configure /db secedit.sdb /cfg C:\Windows\Temp\secpol.cfg /areas SECURITYPOLICY

# Enable the Windows Firewall
Write-Host "Enabling Windows Firewall..."
Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled True

# Block all inbound connections except allowed rules
Write-Host "Blocking all inbound connections except allowed rules..."
Set-NetFirewallProfile -Profile Domain,Public,Private -DefaultInboundAction Block

# Allow all outbound connections
Write-Host "Allowing all outbound connections..."
Set-NetFirewallProfile -Profile Domain,Public,Private -DefaultOutboundAction Allow

# Disable unnecessary services
Write-Host "Disabling unnecessary services..."
Set-Service -Name "TermService" -StartupType Disabled   # Remote Desktop
Set-Service -Name "WinRM" -StartupType Disabled         # Windows Remote Management
Set-Service -Name "Spooler" -StartupType Disabled       # Print Spooler

# Secure system directories
Write-Host "Securing system directories..."
icacls "C:\Windows\System32" /inheritance:r /grant:r Administrators:F /deny Users:W /T /C
icacls "C:\Program Files" /inheritance:r /grant:r Administrators:F /deny Users:W /T /C

# Enable audit policies for security monitoring
Write-Host "Configuring audit policies..."
AuditPol /set /category:"Logon/Logoff" /success:enable /failure:enable
AuditPol /set /category:"Privilege Use" /success:enable /failure:enable
AuditPol /set /category:"Object Access" /success:enable /failure:enable
AuditPol /set /category:"Account Management" /success:enable /failure:enable
AuditPol /set /category:"Policy Change" /success:enable /failure:enable

# Adjust log size and retention for security log
Write-Host "Configuring log size and retention..."
wevtutil sl Security /ms:65536 /rt:true /ab:true

# Enforce password complexity
Write-Host "Enforcing password complexity..."
secedit /export /cfg C:\Windows\Temp\secpol.cfg
(Get-Content C:\Windows\Temp\secpol.cfg).replace("PasswordComplexity = 0", "PasswordComplexity = 1") |
    Set-Content C:\Windows\Temp\secpol.cfg
secedit /configure /db secedit.sdb /cfg C:\Windows\Temp\secpol.cfg /areas SECURITYPOLICY

# Set minimum password length to 12 characters
Write-Host "Setting minimum password length to 12 characters..."
(Get-Content C:\Windows\Temp\secpol.cfg).replace("MinimumPasswordLength = 0", "MinimumPasswordLength = 12") |
    Set-Content C:\Windows\Temp\secpol.cfg
secedit /configure /db secedit.sdb /cfg C:\Windows\Temp\secpol.cfg /areas SECURITYPOLICY

# Set account lockout threshold to 5 invalid login attempts
Write-Host "Setting account lockout threshold to 5 invalid attempts..."
(Get-Content C:\Windows\Temp\secpol.cfg).replace("LockoutBadCount = 0", "LockoutBadCount = 5") |
    Set-Content C:\Windows\Temp\secpol.cfg
secedit /configure /db secedit.sdb /cfg C:\Windows\Temp\secpol.cfg /areas SECURITYPOLICY

# Set lockout duration to 30 minutes
Write-Host "Setting lockout duration to 30 minutes..."
(Get-Content C:\Windows\Temp\secpol.cfg).replace("LockoutDuration = 0", "LockoutDuration = 30") |
    Set-Content C:\Windows\Temp\secpol.cfg
secedit /configure /db secedit.sdb /cfg C:\Windows\Temp\secpol.cfg /areas SECURITYPOLICY

# Enable the Windows Firewall
Write-Host "Enabling Windows Firewall..."
Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled True

# Block all inbound connections except allowed rules
Write-Host "Blocking all inbound connections except allowed rules..."
Set-NetFirewallProfile -Profile Domain,Public,Private -DefaultInboundAction Block

# Allow all outbound connections
Write-Host "Allowing all outbound connections..."
Set-NetFirewallProfile -Profile Domain,Public,Private -DefaultOutboundAction Allow

# Disable unnecessary services
Write-Host "Disabling unnecessary services..."
Set-Service -Name "TermService" -StartupType Disabled   # Remote Desktop
Set-Service -Name "WinRM" -StartupType Disabled         # Windows Remote Management
Set-Service -Name "Spooler" -StartupType Disabled       # Print Spooler

# Secure system directories
Write-Host "Securing system directories..."
icacls "C:\Windows\System32" /inheritance:r /grant:r Administrators:F /deny Users:W /T /C
icacls "C:\Program Files" /inheritance:r /grant:r Administrators:F /deny Users:W /T /C

# Enable audit policies for security monitoring
Write-Host "Configuring audit policies..."
AuditPol /set /category:"Logon/Logoff" /success:enable /failure:enable
AuditPol /set /category:"Privilege Use" /success:enable /failure:enable
AuditPol /set /category:"Object Access" /success:enable /failure:enable
AuditPol /set /category:"Account Management" /success:enable /failure:enable
AuditPol /set /category:"Policy Change" /success:enable /failure:enable

# Adjust log size and retention for security log
Write-Host "Configuring log size and retention..."
wevtutil sl Security /ms:65536 /rt:true /ab:true

# Disable SMBv1 protocol
Write-Host "Disabling SMBv1 protocol..."
Disable-WindowsOptionalFeature -Online -FeatureName "SMB1Protocol" -NoRestart

# Enabling automatic updates
Write-Host "Enabling automatic updates..."
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update" /v AUOptions /t REG_DWORD /d 4 /f

# Disabling USB storage
Write-Host "Disabling USB storage..."
reg add "HKLM\SYSTEM\CurrentControlSet\Services\USBSTOR" /v "Start" /t REG_DWORD /d 4 /f

# Disabling Guest account
Write-Host "Disabling Guest account..."
net user Guest /active:no

# Enforcing NTLMv2 authentication
Write-Host "Enforcing NTLMv2 authentication..."
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" /v "LmCompatibilityLevel" /t REG_DWORD /d 5 /f

# Configuring screen saver lock and timeout
Write-Host "Configuring screen saver lock and timeout..."
reg add "HKCU\Control Panel\Desktop" /v "ScreenSaveActive" /t REG_SZ /d 1 /f
reg add "HKCU\Control Panel\Desktop" /v "ScreenSaveTimeOut" /t REG_SZ /d 600 /f
reg add "HKCU\Control Panel\Desktop" /v "ScreenSaverIsSecure" /t REG_SZ /d 1 /f

# Disabling Remote Desktop
Write-Host "Disabling Remote Desktop..."
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server" -Name "fDenyTSConnections" -Value 1

# Setting account expiration policies
Write-Host "Setting account expiration policies..."
wmic useraccount where "Name='Administrator'" set PasswordExpires=True

