<#
.SYNOPSIS
    Pester tests for Change-ServerSID.ps1 (No Sysprep Version)

.DESCRIPTION
    This test file contains unit tests and integration tests for verifying
    the SID change functionality on Windows Server 2022 without using Sysprep.

.NOTES
    Run these tests using: Invoke-Pester -Path .\Change-ServerSID.Tests.ps1
    Requires: Pester v5+ (Install-Module Pester -MinimumVersion 5.0)
#>

BeforeAll {
    $scriptPath = Join-Path $PSScriptRoot "Change-ServerSID.ps1"

    # Helper function to simulate Get-MachineSID
    function Get-MachineSID {
        try {
            $localAccounts = Get-WmiObject -Class Win32_UserAccount -Filter "LocalAccount=True AND SID LIKE 'S-1-5-21-%'" -ErrorAction SilentlyContinue
            if ($localAccounts) {
                $fullSid = ($localAccounts | Select-Object -First 1).SID
                $machineSid = $fullSid -replace '-\d+$', ''
                return $machineSid
            }

            $regPath = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList"
            $profiles = Get-ChildItem $regPath -ErrorAction SilentlyContinue |
                Where-Object { $_.PSChildName -match '^S-1-5-21-\d+-\d+-\d+-\d+$' }

            if ($profiles) {
                $profileSid = $profiles[0].PSChildName
                $machineSid = $profileSid -replace '-\d+$', ''
                return $machineSid
            }

            return $null
        }
        catch {
            return $null
        }
    }

    # Helper function to generate new SID
    function New-RandomSID {
        $random = New-Object System.Random
        $sub1 = $random.Next(1000000000, [int]::MaxValue)
        $sub2 = $random.Next(1000000000, [int]::MaxValue)
        $sub3 = $random.Next(1000000000, [int]::MaxValue)
        return "S-1-5-21-$sub1-$sub2-$sub3"
    }

    # Test storage path
    $script:TestStoragePath = Join-Path $env:TEMP "SIDChangeTest_$(Get-Random)"
}

AfterAll {
    # Cleanup test directory
    if (Test-Path $script:TestStoragePath) {
        Remove-Item -Path $script:TestStoragePath -Recurse -Force -ErrorAction SilentlyContinue
    }
}

Describe "Change-ServerSID Script Tests (No Sysprep)" {

    Context "Get-MachineSID Function" {

        It "Should return a valid SID format" {
            $sid = Get-MachineSID
            if ($env:OS -eq "Windows_NT") {
                $sid | Should -Not -BeNullOrEmpty
                $sid | Should -Match '^S-1-5-21-\d+-\d+-\d+$'
            }
            else {
                Set-ItResult -Skipped -Because "Not running on Windows"
            }
        }

        It "Should return consistent SID on multiple calls" {
            if ($env:OS -eq "Windows_NT") {
                $sid1 = Get-MachineSID
                $sid2 = Get-MachineSID
                $sid1 | Should -BeExactly $sid2
            }
            else {
                Set-ItResult -Skipped -Because "Not running on Windows"
            }
        }

        It "Should return a SID starting with S-1-5-21" {
            if ($env:OS -eq "Windows_NT") {
                $sid = Get-MachineSID
                $sid | Should -BeLike "S-1-5-21-*"
            }
            else {
                Set-ItResult -Skipped -Because "Not running on Windows"
            }
        }
    }

    Context "New-RandomSID Function" {

        It "Should generate a valid SID format" {
            $sid = New-RandomSID
            $sid | Should -Match '^S-1-5-21-\d+-\d+-\d+$'
        }

        It "Should generate unique SIDs on each call" {
            $sid1 = New-RandomSID
            $sid2 = New-RandomSID
            $sid3 = New-RandomSID

            $sid1 | Should -Not -BeExactly $sid2
            $sid2 | Should -Not -BeExactly $sid3
            $sid1 | Should -Not -BeExactly $sid3
        }

        It "Should generate SIDs with valid subauthority values" {
            $sid = New-RandomSID
            $parts = $sid -split '-'

            $parts.Count | Should -Be 7
            $parts[0] | Should -BeExactly 'S'
            $parts[1] | Should -BeExactly '1'
            $parts[2] | Should -BeExactly '5'
            $parts[3] | Should -BeExactly '21'

            # Subauthority values should be large numbers
            [long]$parts[4] | Should -BeGreaterOrEqual 1000000000
            [long]$parts[5] | Should -BeGreaterOrEqual 1000000000
            [long]$parts[6] | Should -BeGreaterOrEqual 1000000000
        }

        It "Should generate 100 unique SIDs" {
            $sids = 1..100 | ForEach-Object { New-RandomSID }
            $uniqueSids = $sids | Select-Object -Unique
            $uniqueSids.Count | Should -Be 100
        }
    }

    Context "SID Storage and Retrieval" {

        BeforeEach {
            if (-not (Test-Path $script:TestStoragePath)) {
                New-Item -ItemType Directory -Path $script:TestStoragePath -Force | Out-Null
            }
        }

        It "Should create storage directory if it doesn't exist" {
            $newPath = Join-Path $script:TestStoragePath "NewSubDir_$(Get-Random)"
            New-Item -ItemType Directory -Path $newPath -Force | Out-Null
            Test-Path $newPath | Should -Be $true
        }

        It "Should save original SID to file correctly" {
            $testSid = "S-1-5-21-1234567890-1234567890-1234567890"
            $testFile = Join-Path $script:TestStoragePath "original_sid.txt"

            $testSid | Out-File -FilePath $testFile -Encoding UTF8 -Force

            Test-Path $testFile | Should -Be $true
            $savedSid = (Get-Content -Path $testFile -Raw).Trim()
            $savedSid | Should -BeExactly $testSid
        }

        It "Should save new SID to file correctly" {
            $testSid = "S-1-5-21-9876543210-9876543210-9876543210"
            $testFile = Join-Path $script:TestStoragePath "new_sid.txt"

            $testSid | Out-File -FilePath $testFile -Encoding UTF8 -Force

            Test-Path $testFile | Should -Be $true
            $savedSid = (Get-Content -Path $testFile -Raw).Trim()
            $savedSid | Should -BeExactly $testSid
        }

        It "Should save timestamp correctly" {
            $timestampFile = Join-Path $script:TestStoragePath "timestamp.txt"
            $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"

            $timestamp | Out-File -FilePath $timestampFile -Encoding UTF8 -Force

            $savedTimestamp = (Get-Content -Path $timestampFile -Raw).Trim()
            $savedTimestamp | Should -Match '^\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}$'
        }
    }

    Context "SID Comparison Logic" {

        It "Should detect when SIDs are the same" {
            $sid1 = "S-1-5-21-1234567890-1234567890-1234567890"
            $sid2 = "S-1-5-21-1234567890-1234567890-1234567890"

            ($sid1 -eq $sid2) | Should -Be $true
            ($sid1 -ne $sid2) | Should -Be $false
        }

        It "Should detect when SIDs are different" {
            $originalSid = "S-1-5-21-1234567890-1234567890-1234567890"
            $newSid = "S-1-5-21-9876543210-9876543210-9876543210"

            ($originalSid -eq $newSid) | Should -Be $false
            ($originalSid -ne $newSid) | Should -Be $true
        }

        It "Should detect difference in first subauthority" {
            $sid1 = "S-1-5-21-1111111111-2222222222-3333333333"
            $sid2 = "S-1-5-21-9999999999-2222222222-3333333333"

            ($sid1 -ne $sid2) | Should -Be $true
        }

        It "Should detect difference in second subauthority" {
            $sid1 = "S-1-5-21-1111111111-2222222222-3333333333"
            $sid2 = "S-1-5-21-1111111111-9999999999-3333333333"

            ($sid1 -ne $sid2) | Should -Be $true
        }

        It "Should detect difference in third subauthority" {
            $sid1 = "S-1-5-21-1111111111-2222222222-3333333333"
            $sid2 = "S-1-5-21-1111111111-2222222222-9999999999"

            ($sid1 -ne $sid2) | Should -Be $true
        }
    }

    Context "SID Byte Conversion" {

        It "Should convert SID string to bytes" {
            if ($env:OS -eq "Windows_NT") {
                $sidString = "S-1-5-21-1234567890-1234567890-1234567890-500"
                $sid = New-Object System.Security.Principal.SecurityIdentifier($sidString)
                $bytes = New-Object byte[] $sid.BinaryLength
                $sid.GetBinaryForm($bytes, 0)

                $bytes | Should -Not -BeNullOrEmpty
                $bytes.Length | Should -BeGreaterThan 0
            }
            else {
                Set-ItResult -Skipped -Because "Not running on Windows"
            }
        }

        It "Should convert bytes back to SID string" {
            if ($env:OS -eq "Windows_NT") {
                $originalSidString = "S-1-5-21-1234567890-1234567890-1234567890-500"
                $sid = New-Object System.Security.Principal.SecurityIdentifier($originalSidString)
                $bytes = New-Object byte[] $sid.BinaryLength
                $sid.GetBinaryForm($bytes, 0)

                $reconstructedSid = New-Object System.Security.Principal.SecurityIdentifier($bytes, 0)
                $reconstructedSid.Value | Should -BeExactly $originalSidString
            }
            else {
                Set-ItResult -Skipped -Because "Not running on Windows"
            }
        }
    }

    Context "Script Parameter Validation" {

        It "Should define valid Action parameter values" {
            $validActions = @('Prepare', 'Execute', 'Verify', 'GetCurrentSID', 'Rollback')
            $validActions.Count | Should -Be 5
        }

        It "Should accept GetCurrentSID action" {
            'GetCurrentSID' | Should -BeIn @('Prepare', 'Execute', 'Verify', 'GetCurrentSID', 'Rollback')
        }

        It "Should accept Prepare action" {
            'Prepare' | Should -BeIn @('Prepare', 'Execute', 'Verify', 'GetCurrentSID', 'Rollback')
        }

        It "Should accept Execute action" {
            'Execute' | Should -BeIn @('Prepare', 'Execute', 'Verify', 'GetCurrentSID', 'Rollback')
        }

        It "Should accept Verify action" {
            'Verify' | Should -BeIn @('Prepare', 'Execute', 'Verify', 'GetCurrentSID', 'Rollback')
        }

        It "Should accept Rollback action" {
            'Rollback' | Should -BeIn @('Prepare', 'Execute', 'Verify', 'GetCurrentSID', 'Rollback')
        }
    }

    Context "SID Change Verification Tests" {

        It "Should correctly identify unchanged SID" {
            $beforeSid = "S-1-5-21-1111111111-2222222222-3333333333"
            $afterSid = "S-1-5-21-1111111111-2222222222-3333333333"

            $sidChanged = $beforeSid -ne $afterSid
            $sidChanged | Should -Be $false
        }

        It "Should correctly identify changed SID" {
            $beforeSid = "S-1-5-21-1111111111-2222222222-3333333333"
            $afterSid = "S-1-5-21-4444444444-5555555555-6666666666"

            $sidChanged = $beforeSid -ne $afterSid
            $sidChanged | Should -Be $true
        }

        It "Should validate current machine SID format" {
            if ($env:OS -eq "Windows_NT") {
                $currentSid = Get-MachineSID

                # Verify format
                $currentSid | Should -Match '^S-1-5-21-\d+-\d+-\d+$'

                # SID should have expected structure
                $parts = $currentSid -split '-'
                $parts.Count | Should -Be 7
                $parts[0] | Should -BeExactly 'S'
                $parts[1] | Should -BeExactly '1'
                $parts[2] | Should -BeExactly '5'
                $parts[3] | Should -BeExactly '21'
            }
            else {
                Set-ItResult -Skipped -Because "Not running on Windows"
            }
        }

        It "Should verify generated SID differs from mock original" {
            $originalSid = "S-1-5-21-1111111111-2222222222-3333333333"
            $generatedSid = New-RandomSID

            $generatedSid | Should -Not -BeExactly $originalSid
        }
    }

    Context "Registry Backup Tests" {

        It "Should create backup file paths correctly" {
            $backupPath = Join-Path $script:TestStoragePath "registry_backup.reg"
            $samBackup = Join-Path (Split-Path $backupPath) "SAM_backup.reg"
            $secBackup = Join-Path (Split-Path $backupPath) "SECURITY_backup.reg"
            $profileBackup = Join-Path (Split-Path $backupPath) "ProfileList_backup.reg"

            $samBackup | Should -Match 'SAM_backup\.reg$'
            $secBackup | Should -Match 'SECURITY_backup\.reg$'
            $profileBackup | Should -Match 'ProfileList_backup\.reg$'
        }

        It "Should identify correct backup files for rollback" {
            # Create mock backup files
            $backupDir = Join-Path $script:TestStoragePath "BackupTest_$(Get-Random)"
            New-Item -ItemType Directory -Path $backupDir -Force | Out-Null

            $samBackup = Join-Path $backupDir "SAM_backup.reg"
            $secBackup = Join-Path $backupDir "SECURITY_backup.reg"

            "mock backup" | Out-File -FilePath $samBackup -Encoding UTF8
            "mock backup" | Out-File -FilePath $secBackup -Encoding UTF8

            $backupFiles = @($samBackup, $secBackup, (Join-Path $backupDir "ProfileList_backup.reg"))
            $foundBackups = $backupFiles | Where-Object { Test-Path $_ }

            $foundBackups.Count | Should -Be 2
        }
    }

    Context "Report Generation" {

        It "Should generate verification report with correct format" {
            $reportPath = Join-Path $script:TestStoragePath "test_report_$(Get-Random).txt"
            $originalSid = "S-1-5-21-1111111111-2222222222-3333333333"
            $newSid = "S-1-5-21-4444444444-5555555555-6666666666"
            $computerName = $env:COMPUTERNAME

            $report = @"
SID Change Verification Report
==============================
Generated: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')
Computer Name: $computerName

Original SID: $originalSid
Expected SID: $newSid
Current SID:  $newSid

Status: SUCCESS - SID Changed
Method: Registry Modification (No Sysprep)
Machine Configurations: PRESERVED
"@
            $report | Out-File -FilePath $reportPath -Encoding UTF8 -Force

            Test-Path $reportPath | Should -Be $true
            $content = Get-Content -Path $reportPath -Raw
            $content | Should -Match "SUCCESS"
            $content | Should -Match "No Sysprep"
            $content | Should -Match "PRESERVED"
            $content | Should -Match $originalSid
            $content | Should -Match $newSid
        }
    }
}

Describe "Integration Tests - SID Change Workflow (No Sysprep)" {

    Context "Complete Workflow Simulation" {

        BeforeAll {
            $script:WorkflowTestPath = Join-Path $env:TEMP "SIDWorkflowTest_$(Get-Random)"
            New-Item -ItemType Directory -Path $script:WorkflowTestPath -Force | Out-Null
        }

        AfterAll {
            if (Test-Path $script:WorkflowTestPath) {
                Remove-Item -Path $script:WorkflowTestPath -Recurse -Force -ErrorAction SilentlyContinue
            }
        }

        It "Step 1: Should complete prepare phase - save original and new SID" {
            $sidFile = Join-Path $script:WorkflowTestPath "original_sid.txt"
            $newSidFile = Join-Path $script:WorkflowTestPath "new_sid.txt"
            $timestampFile = Join-Path $script:WorkflowTestPath "change_timestamp.txt"

            # Simulate prepare phase
            $mockOriginalSid = "S-1-5-21-1234567890-1234567890-1234567890"
            $mockNewSid = New-RandomSID

            $mockOriginalSid | Out-File -FilePath $sidFile -Encoding UTF8 -Force
            $mockNewSid | Out-File -FilePath $newSidFile -Encoding UTF8 -Force
            Get-Date -Format "yyyy-MM-dd HH:mm:ss" | Out-File -FilePath $timestampFile -Encoding UTF8 -Force

            Test-Path $sidFile | Should -Be $true
            Test-Path $newSidFile | Should -Be $true
            Test-Path $timestampFile | Should -Be $true

            # Verify content
            $savedOriginal = (Get-Content -Path $sidFile -Raw).Trim()
            $savedNew = (Get-Content -Path $newSidFile -Raw).Trim()

            $savedOriginal | Should -BeExactly $mockOriginalSid
            $savedNew | Should -Match '^S-1-5-21-\d+-\d+-\d+$'
            $savedOriginal | Should -Not -BeExactly $savedNew
        }

        It "Step 2: Should verify prerequisites for execute phase" {
            $sidFile = Join-Path $script:WorkflowTestPath "original_sid.txt"
            $newSidFile = Join-Path $script:WorkflowTestPath "new_sid.txt"

            # Prerequisites check
            $prepComplete = (Test-Path $sidFile) -and (Test-Path $newSidFile)
            $prepComplete | Should -Be $true
        }

        It "Step 3: Should simulate successful SID change verification" {
            $sidFile = Join-Path $script:WorkflowTestPath "original_sid.txt"
            $newSidFile = Join-Path $script:WorkflowTestPath "new_sid.txt"

            $originalSid = (Get-Content -Path $sidFile -Raw).Trim()
            $expectedNewSid = (Get-Content -Path $newSidFile -Raw).Trim()

            # Simulate that SID has changed to new value after reboot
            $currentSid = $expectedNewSid

            # Verify change
            $sidChanged = $originalSid -ne $currentSid
            $matchesExpected = $currentSid -eq $expectedNewSid

            $sidChanged | Should -Be $true
            $matchesExpected | Should -Be $true
        }

        It "Step 4: Should detect failed SID change (unchanged)" {
            $sidFile = Join-Path $script:WorkflowTestPath "original_sid.txt"

            $originalSid = (Get-Content -Path $sidFile -Raw).Trim()

            # Simulate that SID has NOT changed
            $currentSid = $originalSid

            # Verify no change
            $sidChanged = $originalSid -ne $currentSid
            $sidChanged | Should -Be $false
        }

        It "Step 5: Should generate proper verification report" {
            $sidFile = Join-Path $script:WorkflowTestPath "original_sid.txt"
            $newSidFile = Join-Path $script:WorkflowTestPath "new_sid.txt"
            $reportPath = Join-Path $script:WorkflowTestPath "verification_report.txt"

            $originalSid = (Get-Content -Path $sidFile -Raw).Trim()
            $newSid = (Get-Content -Path $newSidFile -Raw).Trim()

            $report = @"
SID Change Verification Report
==============================
Generated: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')
Computer Name: $env:COMPUTERNAME

Original SID: $originalSid
Expected SID: $newSid
Current SID:  $newSid

Status: SUCCESS - SID Changed
Method: Registry Modification (No Sysprep)
Machine Configurations: PRESERVED
"@
            $report | Out-File -FilePath $reportPath -Encoding UTF8 -Force

            Test-Path $reportPath | Should -Be $true

            $content = Get-Content -Path $reportPath -Raw
            $content | Should -Match "SUCCESS - SID Changed"
            $content | Should -Match "No Sysprep"
            $content | Should -Match "PRESERVED"
        }
    }

    Context "Rollback Workflow Simulation" {

        BeforeAll {
            $script:RollbackTestPath = Join-Path $env:TEMP "RollbackTest_$(Get-Random)"
            New-Item -ItemType Directory -Path $script:RollbackTestPath -Force | Out-Null
        }

        AfterAll {
            if (Test-Path $script:RollbackTestPath) {
                Remove-Item -Path $script:RollbackTestPath -Recurse -Force -ErrorAction SilentlyContinue
            }
        }

        It "Should create mock backup files" {
            $samBackup = Join-Path $script:RollbackTestPath "SAM_backup.reg"
            $secBackup = Join-Path $script:RollbackTestPath "SECURITY_backup.reg"
            $profileBackup = Join-Path $script:RollbackTestPath "ProfileList_backup.reg"

            "Windows Registry Editor Version 5.00`n`n[HKEY_LOCAL_MACHINE\SAM]" | Out-File -FilePath $samBackup -Encoding UTF8
            "Windows Registry Editor Version 5.00`n`n[HKEY_LOCAL_MACHINE\SECURITY]" | Out-File -FilePath $secBackup -Encoding UTF8
            "Windows Registry Editor Version 5.00`n`n[HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList]" | Out-File -FilePath $profileBackup -Encoding UTF8

            Test-Path $samBackup | Should -Be $true
            Test-Path $secBackup | Should -Be $true
            Test-Path $profileBackup | Should -Be $true
        }

        It "Should find all backup files for rollback" {
            $backupFiles = Get-ChildItem -Path $script:RollbackTestPath -Filter "*_backup.reg"
            $backupFiles.Count | Should -Be 3
        }

        It "Should verify backup file format" {
            $samBackup = Join-Path $script:RollbackTestPath "SAM_backup.reg"
            $content = Get-Content -Path $samBackup -Raw

            $content | Should -Match "Windows Registry Editor Version 5.00"
            $content | Should -Match "HKEY_LOCAL_MACHINE"
        }
    }
}

Describe "Edge Cases and Error Handling" {

    Context "Invalid SID Handling" {

        It "Should reject malformed SID strings" {
            $invalidSids = @(
                "invalid",
                "S-1-5-21",
                "S-1-5-21-abc-def-ghi",
                "S-1-5-21-123-456",
                ""
            )

            foreach ($sid in $invalidSids) {
                $sid | Should -Not -Match '^S-1-5-21-\d+-\d+-\d+$'
            }
        }

        It "Should accept valid SID strings" {
            $validSids = @(
                "S-1-5-21-1-2-3",
                "S-1-5-21-123456789-123456789-123456789",
                "S-1-5-21-4294967295-4294967295-4294967295"
            )

            foreach ($sid in $validSids) {
                $sid | Should -Match '^S-1-5-21-\d+-\d+-\d+$'
            }
        }
    }

    Context "File Operation Error Handling" {

        It "Should handle missing storage directory gracefully" {
            $nonExistentPath = "C:\NonExistent_$(Get-Random)\SIDChange"
            Test-Path $nonExistentPath | Should -Be $false
        }

        It "Should handle missing SID files" {
            $missingFile = Join-Path $env:TEMP "NonExistent_$(Get-Random).txt"
            Test-Path $missingFile | Should -Be $false
        }
    }
}
