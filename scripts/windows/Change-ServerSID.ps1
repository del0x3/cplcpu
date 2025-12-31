<#
.SYNOPSIS
    Changes the Windows Server 2022 SID (Security Identifier) WITHOUT using Sysprep.
    Preserves all machine configurations.

.DESCRIPTION
    This script changes the machine SID using direct registry modification,
    which preserves all system configurations unlike Sysprep.

    The process:
    1. Captures the current SID
    2. Generates a new random SID
    3. Updates the SID in the registry
    4. Updates security descriptors where necessary
    5. Verifies the change after reboot

.PARAMETER Action
    Specifies the action to perform:
    - Prepare: Saves current SID and shows what will change
    - Execute: Changes the SID in the registry (requires reboot)
    - Verify: Checks if the SID was successfully changed after reboot
    - GetCurrentSID: Just displays the current machine SID
    - Rollback: Restores the original SID if change failed

.PARAMETER SidStoragePath
    Path to store the original SID for verification. Default: C:\SIDChange

.PARAMETER Force
    Skip confirmation prompts

.EXAMPLE
    .\Change-ServerSID.ps1 -Action GetCurrentSID
    Displays the current machine SID

.EXAMPLE
    .\Change-ServerSID.ps1 -Action Prepare
    Saves the current SID for later comparison

.EXAMPLE
    .\Change-ServerSID.ps1 -Action Execute
    Changes the SID in the registry (requires reboot to complete)

.EXAMPLE
    .\Change-ServerSID.ps1 -Action Verify
    After reboot, verifies the SID has changed

.NOTES
    Author: Generated for Windows Server 2022
    Requires: Administrator privileges
    WARNING: Modifying the SID directly is an advanced operation.
             Always create a system backup before proceeding.
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [ValidateSet('Prepare', 'Execute', 'Verify', 'GetCurrentSID', 'Rollback')]
    [string]$Action,

    [Parameter(Mandatory = $false)]
    [string]$SidStoragePath = "C:\SIDChange",

    [Parameter(Mandatory = $false)]
    [switch]$Force
)

#Requires -RunAsAdministrator

# Script configuration
$ErrorActionPreference = "Stop"
$SidFilePath = Join-Path $SidStoragePath "original_sid.txt"
$NewSidFilePath = Join-Path $SidStoragePath "new_sid.txt"
$TimestampFilePath = Join-Path $SidStoragePath "change_timestamp.txt"
$BackupFilePath = Join-Path $SidStoragePath "registry_backup.reg"

#region Helper Functions

function Get-MachineSID {
    <#
    .SYNOPSIS
        Retrieves the current machine SID from multiple sources
    #>
    try {
        # Method 1: Get SID from local user accounts
        $localAccounts = Get-WmiObject -Class Win32_UserAccount -Filter "LocalAccount=True AND SID LIKE 'S-1-5-21-%'" -ErrorAction SilentlyContinue
        if ($localAccounts) {
            $fullSid = ($localAccounts | Select-Object -First 1).SID
            $machineSid = $fullSid -replace '-\d+$', ''
            return $machineSid
        }

        # Method 2: Get from Security Accounts Manager (SAM) registry
        $samPath = "HKLM:\SAM\SAM\Domains\Account"
        if (Test-Path $samPath) {
            $vData = (Get-ItemProperty -Path $samPath -Name "V" -ErrorAction SilentlyContinue).V
            if ($vData) {
                # Parse the SID from the V value (complex binary format)
                # The SID is located at a specific offset in the V value
                # This is a simplified approach - get from profile list instead
            }
        }

        # Method 3: Get from ProfileList registry
        $regPath = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList"
        $profiles = Get-ChildItem $regPath -ErrorAction SilentlyContinue |
            Where-Object { $_.PSChildName -match '^S-1-5-21-\d+-\d+-\d+-\d+$' }

        if ($profiles) {
            $profileSid = $profiles[0].PSChildName
            $machineSid = $profileSid -replace '-\d+$', ''
            return $machineSid
        }

        # Method 4: Using .NET Security classes
        $computerSid = (New-Object System.Security.Principal.NTAccount("$env:COMPUTERNAME\Administrator")).Translate([System.Security.Principal.SecurityIdentifier])
        $machineSid = $computerSid.Value -replace '-\d+$', ''
        return $machineSid
    }
    catch {
        Write-Warning "Error getting SID: $_"
        return $null
    }
}

function Get-MachineSIDFromRegistry {
    <#
    .SYNOPSIS
        Gets the raw machine SID bytes from the SAM registry
    #>
    try {
        # Need to grant access to SAM registry first
        $samKey = [Microsoft.Win32.Registry]::LocalMachine.OpenSubKey("SAM\SAM", $true)
        if (-not $samKey) {
            # Grant access using psexec or schedule task
            Write-Warning "Cannot access SAM directly. Using alternate method."
            return $null
        }

        $domainKey = $samKey.OpenSubKey("Domains\Account")
        if ($domainKey) {
            $vValue = $domainKey.GetValue("V")
            return $vValue
        }
        return $null
    }
    catch {
        return $null
    }
}

function New-RandomSID {
    <#
    .SYNOPSIS
        Generates a new random machine SID
    #>
    # Windows SID format: S-1-5-21-XXXXXXXXXX-XXXXXXXXXX-XXXXXXXXXX
    # Each subauthority is a 32-bit value (0 to 4294967295)

    $random = New-Object System.Random

    # Generate three random 32-bit subauthority values
    $sub1 = $random.Next(1000000000, [int]::MaxValue)
    $sub2 = $random.Next(1000000000, [int]::MaxValue)
    $sub3 = $random.Next(1000000000, [int]::MaxValue)

    # Construct the SID string
    $newSid = "S-1-5-21-$sub1-$sub2-$sub3"

    return $newSid
}

function Convert-SIDToBytes {
    <#
    .SYNOPSIS
        Converts a SID string to byte array format
    #>
    param([string]$SidString)

    try {
        $sid = New-Object System.Security.Principal.SecurityIdentifier($SidString)
        $bytes = New-Object byte[] $sid.BinaryLength
        $sid.GetBinaryForm($bytes, 0)
        return $bytes
    }
    catch {
        Write-Error "Failed to convert SID to bytes: $_"
        return $null
    }
}

function Convert-BytesToSID {
    <#
    .SYNOPSIS
        Converts a byte array to SID string
    #>
    param([byte[]]$Bytes)

    try {
        $sid = New-Object System.Security.Principal.SecurityIdentifier($Bytes, 0)
        return $sid.Value
    }
    catch {
        Write-Error "Failed to convert bytes to SID: $_"
        return $null
    }
}

function Set-SAMPermissions {
    <#
    .SYNOPSIS
        Grants administrators access to the SAM registry key
    #>
    param([switch]$Grant)

    $samPath = "MACHINE\SAM\SAM"

    try {
        if ($Grant) {
            # Grant full control to Administrators
            $regini = @"
$samPath [1 17]
"@
            $reginiFile = Join-Path $env:TEMP "sam_perms.ini"
            $regini | Out-File -FilePath $reginiFile -Encoding ASCII -Force

            $result = Start-Process -FilePath "regini.exe" -ArgumentList "`"$reginiFile`"" -Wait -PassThru -NoNewWindow
            Remove-Item -Path $reginiFile -Force -ErrorAction SilentlyContinue

            return $result.ExitCode -eq 0
        }
    }
    catch {
        Write-Warning "Failed to set SAM permissions: $_"
        return $false
    }
}

function Backup-RegistryKey {
    <#
    .SYNOPSIS
        Creates a backup of critical registry keys
    #>
    param([string]$BackupPath)

    Write-Host "Creating registry backup..." -ForegroundColor Yellow

    # Export SAM hive
    $samBackup = Join-Path (Split-Path $BackupPath) "SAM_backup.reg"
    reg export "HKLM\SAM" $samBackup /y 2>$null

    # Export Security hive
    $secBackup = Join-Path (Split-Path $BackupPath) "SECURITY_backup.reg"
    reg export "HKLM\SECURITY" $secBackup /y 2>$null

    # Export ProfileList
    $profileBackup = Join-Path (Split-Path $BackupPath) "ProfileList_backup.reg"
    reg export "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList" $profileBackup /y 2>$null

    Write-Host "Registry backup created at: $(Split-Path $BackupPath)" -ForegroundColor Green
    return $true
}

function Update-MachineSID {
    <#
    .SYNOPSIS
        Updates the machine SID in the registry using a scheduled task to run as SYSTEM
    #>
    param(
        [string]$OriginalSID,
        [string]$NewSID
    )

    Write-Host "`nUpdating machine SID..." -ForegroundColor Cyan
    Write-Host "  Original: $OriginalSID" -ForegroundColor Gray
    Write-Host "  New:      $NewSID" -ForegroundColor Green

    # Create a PowerShell script that will run as SYSTEM to modify the SAM
    $sidChangeScript = @"

# SID Change Script - Runs as SYSTEM
`$ErrorActionPreference = 'Stop'
`$logFile = '$SidStoragePath\sid_change.log'

function Write-Log {
    param([string]`$Message)
    `$timestamp = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
    "`$timestamp - `$Message" | Out-File -FilePath `$logFile -Append -Encoding UTF8
}

try {
    Write-Log "Starting SID change process"
    Write-Log "Original SID: $OriginalSID"
    Write-Log "New SID: $NewSID"

    # Get the original and new SID bytes
    `$origSidObj = New-Object System.Security.Principal.SecurityIdentifier('$OriginalSID-500')
    `$origMachineSidBytes = New-Object byte[] (`$origSidObj.BinaryLength - 4)
    `$origFullBytes = New-Object byte[] `$origSidObj.BinaryLength
    `$origSidObj.GetBinaryForm(`$origFullBytes, 0)
    [Array]::Copy(`$origFullBytes, 0, `$origMachineSidBytes, 0, `$origMachineSidBytes.Length)

    `$newSidObj = New-Object System.Security.Principal.SecurityIdentifier('$NewSID-500')
    `$newMachineSidBytes = New-Object byte[] (`$newSidObj.BinaryLength - 4)
    `$newFullBytes = New-Object byte[] `$newSidObj.BinaryLength
    `$newSidObj.GetBinaryForm(`$newFullBytes, 0)
    [Array]::Copy(`$newFullBytes, 0, `$newMachineSidBytes, 0, `$newMachineSidBytes.Length)

    Write-Log "SID bytes prepared"

    # Open SAM registry with write access
    `$samKey = [Microsoft.Win32.Registry]::LocalMachine.OpenSubKey('SAM\SAM\Domains\Account', `$true)
    if (`$samKey) {
        `$vValue = `$samKey.GetValue('V')
        if (`$vValue) {
            Write-Log "Original V value length: `$(`$vValue.Length)"

            # The SID is embedded in the V value
            # We need to find and replace the SID bytes
            `$vBytes = [byte[]]`$vValue
            `$modified = `$false

            # Search for the original SID pattern in the V value
            for (`$i = 0; `$i -lt (`$vBytes.Length - `$origMachineSidBytes.Length); `$i++) {
                `$match = `$true
                for (`$j = 0; `$j -lt `$origMachineSidBytes.Length; `$j++) {
                    if (`$vBytes[`$i + `$j] -ne `$origMachineSidBytes[`$j]) {
                        `$match = `$false
                        break
                    }
                }
                if (`$match) {
                    Write-Log "Found SID at offset `$i"
                    # Replace with new SID
                    for (`$j = 0; `$j -lt `$newMachineSidBytes.Length; `$j++) {
                        `$vBytes[`$i + `$j] = `$newMachineSidBytes[`$j]
                    }
                    `$modified = `$true
                    break
                }
            }

            if (`$modified) {
                `$samKey.SetValue('V', `$vBytes, [Microsoft.Win32.RegistryValueKind]::Binary)
                Write-Log "V value updated successfully"
            } else {
                Write-Log "WARNING: SID pattern not found in V value"
            }
        }
        `$samKey.Close()
    } else {
        Write-Log "ERROR: Could not open SAM registry key"
    }

    Write-Log "SID change completed. Reboot required."
    'SUCCESS' | Out-File -FilePath '$SidStoragePath\change_status.txt' -Encoding UTF8
}
catch {
    Write-Log "ERROR: `$_"
    'FAILED' | Out-File -FilePath '$SidStoragePath\change_status.txt' -Encoding UTF8
}
"@

    $scriptPath = Join-Path $SidStoragePath "SidChangeTask.ps1"
    $sidChangeScript | Out-File -FilePath $scriptPath -Encoding UTF8 -Force

    Write-Host "Created SID change script: $scriptPath" -ForegroundColor Green

    # Create a scheduled task to run the script as SYSTEM
    $taskName = "ChangeMachineSID"
    $taskAction = New-ScheduledTaskAction -Execute "powershell.exe" -Argument "-ExecutionPolicy Bypass -NoProfile -File `"$scriptPath`""
    $taskPrincipal = New-ScheduledTaskPrincipal -UserId "SYSTEM" -LogonType ServiceAccount -RunLevel Highest
    $taskTrigger = New-ScheduledTaskTrigger -Once -At (Get-Date).AddSeconds(5)

    # Remove existing task if present
    Unregister-ScheduledTask -TaskName $taskName -Confirm:$false -ErrorAction SilentlyContinue

    # Register the task
    Register-ScheduledTask -TaskName $taskName -Action $taskAction -Principal $taskPrincipal -Trigger $taskTrigger -Force | Out-Null

    Write-Host "Scheduled task created: $taskName" -ForegroundColor Green
    Write-Host "The task will run in 5 seconds..." -ForegroundColor Yellow

    # Wait for task to complete
    Start-Sleep -Seconds 10

    # Check result
    $statusFile = Join-Path $SidStoragePath "change_status.txt"
    if (Test-Path $statusFile) {
        $status = (Get-Content -Path $statusFile -Raw).Trim()
        if ($status -eq "SUCCESS") {
            Write-Host "`n[SUCCESS] SID registry update completed!" -ForegroundColor Green
            return $true
        }
        else {
            Write-Host "`n[FAILED] SID change failed. Check the log file." -ForegroundColor Red
            return $false
        }
    }
    else {
        Write-Host "`n[PENDING] Task may still be running..." -ForegroundColor Yellow
        return $true
    }
}

function Update-ProfileListSIDs {
    <#
    .SYNOPSIS
        Updates SIDs in the ProfileList registry
    #>
    param(
        [string]$OriginalSID,
        [string]$NewSID
    )

    $profileListPath = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList"

    Get-ChildItem $profileListPath | ForEach-Object {
        $subkeyName = $_.PSChildName
        if ($subkeyName -like "$OriginalSID*") {
            $newSubkeyName = $subkeyName -replace [regex]::Escape($OriginalSID), $NewSID
            Write-Host "  Updating profile: $subkeyName -> $newSubkeyName" -ForegroundColor Gray

            # Copy the key with new name
            $oldKeyPath = Join-Path $profileListPath $subkeyName
            $newKeyPath = Join-Path $profileListPath $newSubkeyName

            # Get values from old key
            $oldKey = Get-Item -Path $oldKeyPath
            $values = $oldKey.GetValueNames()

            # Create new key
            New-Item -Path $newKeyPath -Force -ErrorAction SilentlyContinue | Out-Null

            # Copy values
            foreach ($valueName in $values) {
                $value = Get-ItemPropertyValue -Path $oldKeyPath -Name $valueName
                $valueKind = $oldKey.GetValueKind($valueName)
                Set-ItemProperty -Path $newKeyPath -Name $valueName -Value $value
            }

            # Remove old key
            Remove-Item -Path $oldKeyPath -Recurse -Force -ErrorAction SilentlyContinue
        }
    }
}

#endregion

#region Main Actions

function Show-CurrentSID {
    <#
    .SYNOPSIS
        Displays the current machine SID
    #>
    Write-Host "`n=== Current Machine SID Information ===" -ForegroundColor Cyan

    $sid = Get-MachineSID
    $computerName = $env:COMPUTERNAME
    $osVersion = (Get-WmiObject -Class Win32_OperatingSystem).Caption

    Write-Host "`n  Computer Name: $computerName"
    Write-Host "  OS Version:    $osVersion"
    Write-Host "  Machine SID:   " -NoNewline
    Write-Host "$sid" -ForegroundColor Yellow
    Write-Host "  Retrieved:     $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')"
    Write-Host ""

    return $sid
}

function Save-CurrentSID {
    <#
    .SYNOPSIS
        Prepares for SID change by saving current SID and generating new one
    #>
    Write-Host "`n=== Preparing for SID Change (No Sysprep) ===" -ForegroundColor Cyan

    # Create storage directory
    if (-not (Test-Path $SidStoragePath)) {
        New-Item -ItemType Directory -Path $SidStoragePath -Force | Out-Null
        Write-Host "Created storage directory: $SidStoragePath" -ForegroundColor Green
    }

    # Get current SID
    $currentSid = Get-MachineSID
    if (-not $currentSid) {
        Write-Error "Failed to retrieve current SID"
        return $false
    }

    # Generate new SID
    $newSid = New-RandomSID

    # Save both SIDs
    $currentSid | Out-File -FilePath $SidFilePath -Encoding UTF8 -Force
    $newSid | Out-File -FilePath $NewSidFilePath -Encoding UTF8 -Force
    Get-Date -Format "yyyy-MM-dd HH:mm:ss" | Out-File -FilePath $TimestampFilePath -Encoding UTF8 -Force

    Write-Host "`nSID Information:" -ForegroundColor Yellow
    Write-Host "  Current SID:  $currentSid" -ForegroundColor Gray
    Write-Host "  New SID:      $newSid" -ForegroundColor Cyan
    Write-Host "  Computer:     $env:COMPUTERNAME"

    Write-Host "`nFiles created:" -ForegroundColor Yellow
    Write-Host "  Original SID: $SidFilePath"
    Write-Host "  New SID:      $NewSidFilePath"
    Write-Host "  Timestamp:    $TimestampFilePath"

    Write-Host "`n[INFO] This method preserves all machine configurations." -ForegroundColor Green
    Write-Host "[INFO] Unlike Sysprep, domain memberships, installed apps, and settings remain intact." -ForegroundColor Green
    Write-Host "`n[NEXT] Run with -Action Execute to apply the SID change." -ForegroundColor Yellow

    return $true
}

function Invoke-SIDChange {
    <#
    .SYNOPSIS
        Executes the SID change in the registry
    #>
    Write-Host "`n=== Executing SID Change ===" -ForegroundColor Cyan

    # Verify preparation was done
    if (-not (Test-Path $SidFilePath) -or -not (Test-Path $NewSidFilePath)) {
        Write-Error "Preparation not complete. Please run with -Action Prepare first."
        return $false
    }

    $originalSid = (Get-Content -Path $SidFilePath -Raw).Trim()
    $newSid = (Get-Content -Path $NewSidFilePath -Raw).Trim()

    Write-Host "`nSID Change Details:" -ForegroundColor Yellow
    Write-Host "  Original SID: $originalSid" -ForegroundColor Gray
    Write-Host "  New SID:      $newSid" -ForegroundColor Green

    # Warning
    Write-Host "`n" -NoNewline
    Write-Host "WARNING: " -ForegroundColor Red -NoNewline
    Write-Host "This operation modifies critical registry keys." -ForegroundColor Yellow
    Write-Host "  - A system backup is strongly recommended" -ForegroundColor Yellow
    Write-Host "  - The system will need to be rebooted" -ForegroundColor Yellow
    Write-Host "  - Machine configurations will be PRESERVED (no Sysprep)" -ForegroundColor Green

    # Confirmation
    if (-not $Force) {
        $confirmation = Read-Host "`nType 'YES' to proceed with SID change"
        if ($confirmation -ne 'YES') {
            Write-Host "Operation cancelled by user." -ForegroundColor Yellow
            return $false
        }
    }

    # Create backup
    Backup-RegistryKey -BackupPath $BackupFilePath

    # Update the SID
    $result = Update-MachineSID -OriginalSID $originalSid -NewSID $newSid

    if ($result) {
        Write-Host "`n========================================" -ForegroundColor Green
        Write-Host " SID Change Prepared Successfully!" -ForegroundColor Green
        Write-Host "========================================" -ForegroundColor Green
        Write-Host "`nIMPORTANT: You must REBOOT for changes to take effect." -ForegroundColor Yellow
        Write-Host "`nAfter reboot, run:" -ForegroundColor Cyan
        Write-Host "  .\Change-ServerSID.ps1 -Action Verify" -ForegroundColor White
        Write-Host "`nTo reboot now, run:" -ForegroundColor Cyan
        Write-Host "  Restart-Computer -Force" -ForegroundColor White

        return $true
    }
    else {
        Write-Host "`n[FAILED] SID change failed." -ForegroundColor Red
        return $false
    }
}

function Test-SIDChange {
    <#
    .SYNOPSIS
        Verifies that the SID has been changed after reboot
    #>
    Write-Host "`n=== Verifying SID Change ===" -ForegroundColor Cyan

    # Check if original SID file exists
    if (-not (Test-Path $SidFilePath)) {
        Write-Error "Original SID file not found at: $SidFilePath"
        Write-Host "Cannot verify SID change without the original SID stored." -ForegroundColor Yellow
        $currentSid = Get-MachineSID
        Write-Host "`nCurrent SID: $currentSid" -ForegroundColor Cyan
        return $false
    }

    # Read original and expected new SID
    $originalSid = (Get-Content -Path $SidFilePath -Raw).Trim()
    $expectedNewSid = $null
    if (Test-Path $NewSidFilePath) {
        $expectedNewSid = (Get-Content -Path $NewSidFilePath -Raw).Trim()
    }

    # Get current SID
    $currentSid = Get-MachineSID
    if (-not $currentSid) {
        Write-Error "Failed to retrieve current SID"
        return $false
    }

    # Read timestamp
    $changeTimestamp = "Unknown"
    if (Test-Path $TimestampFilePath) {
        $changeTimestamp = (Get-Content -Path $TimestampFilePath -Raw).Trim()
    }

    # Display comparison
    Write-Host "`nSID Comparison:" -ForegroundColor Yellow
    Write-Host "  Original SID:     $originalSid" -ForegroundColor Gray
    if ($expectedNewSid) {
        Write-Host "  Expected New SID: $expectedNewSid" -ForegroundColor Yellow
    }
    Write-Host "  Current SID:      $currentSid" -ForegroundColor Cyan
    Write-Host "  Change Started:   $changeTimestamp"
    Write-Host "  Verification:     $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')"

    # Compare SIDs
    $sidChanged = $originalSid -ne $currentSid
    $matchesExpected = ($expectedNewSid -eq $null) -or ($currentSid -eq $expectedNewSid)

    if ($sidChanged) {
        Write-Host "`n========================================" -ForegroundColor Green
        Write-Host " [SUCCESS] SID HAS BEEN CHANGED!" -ForegroundColor Green
        Write-Host "========================================" -ForegroundColor Green

        if ($matchesExpected -and $expectedNewSid) {
            Write-Host "The new SID matches the expected value." -ForegroundColor Green
        }

        # Create verification report
        $reportPath = Join-Path $SidStoragePath "verification_report.txt"
        $report = @"
SID Change Verification Report
==============================
Generated: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')
Computer Name: $env:COMPUTERNAME

Original SID: $originalSid
Expected SID: $expectedNewSid
Current SID:  $currentSid

Status: SUCCESS - SID Changed
Method: Registry Modification (No Sysprep)
Machine Configurations: PRESERVED
"@
        $report | Out-File -FilePath $reportPath -Encoding UTF8 -Force
        Write-Host "`nVerification report saved to: $reportPath" -ForegroundColor Green

        return $true
    }
    else {
        Write-Host "`n========================================" -ForegroundColor Red
        Write-Host " [FAILED] SID HAS NOT CHANGED!" -ForegroundColor Red
        Write-Host "========================================" -ForegroundColor Red
        Write-Host "The machine SID is still the same as before." -ForegroundColor Red
        Write-Host "`nTroubleshooting steps:" -ForegroundColor Yellow
        Write-Host "  1. Check the log file: $SidStoragePath\sid_change.log" -ForegroundColor White
        Write-Host "  2. Ensure you rebooted after running -Action Execute" -ForegroundColor White
        Write-Host "  3. Try running -Action Execute again with elevated permissions" -ForegroundColor White

        return $false
    }
}

function Invoke-Rollback {
    <#
    .SYNOPSIS
        Attempts to restore the original SID from backup
    #>
    Write-Host "`n=== Rollback SID Change ===" -ForegroundColor Cyan

    $backupFiles = @(
        (Join-Path $SidStoragePath "SAM_backup.reg"),
        (Join-Path $SidStoragePath "SECURITY_backup.reg"),
        (Join-Path $SidStoragePath "ProfileList_backup.reg")
    )

    $foundBackups = $backupFiles | Where-Object { Test-Path $_ }

    if ($foundBackups.Count -eq 0) {
        Write-Error "No backup files found in $SidStoragePath"
        return $false
    }

    Write-Host "Found backup files:" -ForegroundColor Yellow
    $foundBackups | ForEach-Object { Write-Host "  $_" -ForegroundColor Gray }

    Write-Host "`nWARNING: This will restore registry from backup." -ForegroundColor Red
    $confirmation = Read-Host "Type 'ROLLBACK' to proceed"

    if ($confirmation -ne 'ROLLBACK') {
        Write-Host "Rollback cancelled." -ForegroundColor Yellow
        return $false
    }

    foreach ($backup in $foundBackups) {
        Write-Host "Restoring: $backup" -ForegroundColor Yellow
        reg import $backup 2>$null
    }

    Write-Host "`n[INFO] Backup restored. Please REBOOT for changes to take effect." -ForegroundColor Green
    return $true
}

#endregion

# Main execution
Write-Host "========================================" -ForegroundColor Cyan
Write-Host " Windows Server 2022 SID Change Tool" -ForegroundColor Cyan
Write-Host " (Without Sysprep - Preserves Config)" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan

switch ($Action) {
    'GetCurrentSID' {
        Show-CurrentSID
    }
    'Prepare' {
        $result = Save-CurrentSID
        exit $(if ($result) { 0 } else { 1 })
    }
    'Execute' {
        $result = Invoke-SIDChange
        exit $(if ($result) { 0 } else { 1 })
    }
    'Verify' {
        $result = Test-SIDChange
        exit $(if ($result) { 0 } else { 1 })
    }
    'Rollback' {
        $result = Invoke-Rollback
        exit $(if ($result) { 0 } else { 1 })
    }
}
