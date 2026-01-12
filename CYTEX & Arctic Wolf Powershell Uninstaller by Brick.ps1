# CYTEX Powershell Uninstaller by Brick

# Commands to stop the services
Write-Host "[*] Stopping Services..."
Stop-Service WazuhSvc -ErrorAction SilentlyContinue
Stop-Service osqueryd -ErrorAction SilentlyContinue
Stop-Service AWAService -ErrorAction SilentlyContinue   

# Commands to remove the services
Write-Host "[*] Removing Services..."
sc.exe delete WazuhSvc | Out-Null
sc.exe delete osqueryd | Out-Null
sc.exe delete AWAService | Out-Null

# Removes Cytex scheduled task
Write-Host "[*] Removing Scheduled Task..."
Unregister-ScheduledTask -TaskName "CytexIsolation" -Confirm:$false -ErrorAction SilentlyContinue

# Uninstalls Cytex/Osquery/Wazuh MSI packages.
Write-Host "[*] Uninstalling MSI Packages..."
$products = Get-WmiObject -Class Win32_Product |
   Where-Object { $_.Name -match "cytex|osquery|wazuh" }

foreach ($p in $products) {
    Write-Host "Uninstalling $($p.Name)"
    $p.Uninstall() | Out-Null
}

# Arctic Wolf Agent Uninstall (MSI)
Write-Host "[*] Uninstalling Arctic Wolf Agent..."
$awaProduct = Get-WmiObject -Class Win32_Product |
    Where-Object { $_.Name -eq "Arctic Wolf Agent" }

if ($awaProduct) {
    Write-Host "Uninstalling Arctic Wolf Agent..."
    $awaProduct.Uninstall() | Out-Null
} else {
    Write-Host "Arctic Wolf Agent not found."
}

# Arctic Wolf Containment Removal
Write-Host "[*] Removing Arctic Wolf containment rules..."
$awContainmentGroups = @(
    "Arctic Wolf Containment",
    "AWAContainment",
    "Arctic Wolf Isolation"
)

foreach ($grp in $awContainmentGroups) {
    netsh advfirewall firewall delete rule group="$grp" | Out-Null 2>$null
}

# Remove containment policy folder (if present)
Remove-Item "C:\ProgramData\Arctic Wolf\containment" -Recurse -Force -ErrorAction SilentlyContinue
Write-Host "[*] Arctic Wolf containment removed."

# Removes the directories
Write-Host "[*] Removing Directories..."
Remove-Item "C:\Program Files (x86)\ossec-agent" -Recurse -Force -ErrorAction SilentlyContinue                 
Remove-Item "C:\Program Files\osquery" -Recurse -Force -ErrorAction SilentlyContinue                           
Remove-Item "C:\Program Files (x86)\Arctic Wolf Networks\Agent" -Recurse -Force -ErrorAction SilentlyContinue  
Remove-Item "C:\ProgramData\Arctic Wolf\Agent" -Recurse -Force -ErrorAction SilentlyContinue                   

# Removes the downloaded Cytex files
Write-Host "[*] Removing Downloaded Files..."
Remove-Item "$env:USERPROFILE\Downloads\cytex_windows.msi" -Force -ErrorAction SilentlyContinue

# Cleans the registry
Write-Host "[*] Cleaning Registry..."
Remove-Item "HKLM:\Software\osquery" -Recurse -Force -ErrorAction SilentlyContinue
Remove-Item "HKLM:\Software\Wow6432Node\osquery" -Recurse -Force -ErrorAction SilentlyContinue
Remove-Item "HKLM:\SYSTEM\CurrentControlSet\Services\WazuhSvc" -Recurse -Force -ErrorAction SilentlyContinue
Remove-Item "HKLM:\SYSTEM\CurrentControlSet\Services\osqueryd" -Recurse -Force -ErrorAction SilentlyContinue

# Arctic Wolf Agent Registry Keys
Remove-Item "HKLM:\SYSTEM\CurrentControlSet\Services\AWAService" -Recurse -Force -ErrorAction SilentlyContinue
Remove-Item "HKLM:\Software\Arctic Wolf\Agent" -Recurse -Force -ErrorAction SilentlyContinue
Remove-Item "HKLM:\Software\Wow6432Node\Arctic Wolf\Agent" -Recurse -Force -ErrorAction SilentlyContinue

Write-Host "[*] Nuke complete."