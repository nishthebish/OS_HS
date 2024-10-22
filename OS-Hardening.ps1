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
