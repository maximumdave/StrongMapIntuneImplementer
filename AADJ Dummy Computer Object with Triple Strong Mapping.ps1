# Start global logging - by David Steinhart
$logpath = "C:\StrongMapping"
New-item -itemtype Directory -Path $logpath -ErrorAction SilentlyContinue
try {
    Start-Transcript -Path "$logpath\strong_cert_mapping_script_$((Get-Date).tostring("MMM_dd_yyyy_hh_mm_ss_tt")).txt" -Append
} catch {
    Write-Output "Failed to start logging. Exiting."
    exit (1)
}

# Azure AD Device Sync to Active Directory
# Written by Keith Ng <[email protected]>, April 2023
#
# Sources
# AADx509Sync by tcppapi: https://github.com/tcppapi/AADx509Sync
# AADJ-DummyObjects-Sync-x509 by saqib-s: https://github.com/saqib-s/AADJ-DummyObjects-Sync-x509
# AADJ-x509-Device-Sync by CodyRWhite: https://github.com/CodyRWhite/AADJ-x509-Device-Sync
# Triple Strong Mapping by David Steinhart: https://github.com/maximumdave/StrongMapIntuneChecker

# Azure AD app registration details
# Requires Device.Read.All and Group.Read.All permissions (application, not delegated!)
$tenantId = ""
$clientId = ""
$clientSecret = ""

# Name of the default group of all AD computer objects generated from sync
# Similar to the "Domain Computers" group for domain-joined devices
$defaultGroup = "AADJ Devices"

# The organisational unit the devices and groups should sync to
# Should be a dedicated OU used by this script only
$orgUnit = "OU=AADJ Devices,OU=Computers,OU=domain,DC=local"

# Device/group deletion policies
$removeDeletedDevices = $true # Set to $false if you don't want the script to delete computer objects from AD
$removeDeletedGroups = $true # Set to $false if you don't want the script to delete group objects from AD
$emptyDeviceProtection = $true # Leave as $true (recommended) to prevent the script from deleting computer objects when the device list from Azure AD is empty (could be due to error)
$emptyGroupProtection = $true # Leave as $true (recommended) to prevent the script from deleting group objects when the group list from Azure AD is empty (could be due to error)

# Revoke device certificates on deletion from AD - account running this script must have correct permissions
# When $true, will attempt to revoke any certificates (with reason 6 'certificate hold') that have device ID as CN
# Only takes effect when $removeDeletedDevices = $true
$revokeCertOnDelete = $true

# PowerShell module installation check
# If set to $true, will install and update PowerShell modules as necessary
# Setting this value to $false speeds up the script execution time as it skips the checks - but ensure you have the modules installed!
$moduleChecks = $true

#######################################################################################################################################

# Install/update/import modules - Modified by David Steinhart to always include PSPKI due to cert mapping requirements
$requiredModules = "ActiveDirectory", "Microsoft.Graph", "Microsoft.Graph.Groups", "Microsoft.Graph.Identity.DirectoryManagement", "PSPKI"

Write-Host "Importing required modules..."
foreach ($module in $requiredModules) {
    if ($moduleChecks) {
        # Check if installed version = online version, if not then update it (reinstall)
        [Version]$onlineVersion = (Find-Module -Name $module -ErrorAction SilentlyContinue).Version
        [Version]$installedVersion = (Get-Module -ListAvailable -Name $module | Sort-Object Version -Descending  | Select-Object Version -First 1).Version
        if ($onlineVersion -gt $installedVersion) {
            Write-Host "Installing module $($module)..."
            Install-Module -Name $Module -Scope AllUsers -Force -AllowClobber
            Write-Host "Updating module $($module)..."
            Update-Module -Name $Module -Force -AllowClobber # Added by David Steinhart
        }
    }
    # Import modules
    if (!(Get-Module -Name $module)) {
        if ($module -eq "Microsoft.Graph") { # Do not need to import this entire monstrosity
            continue
        }
        Write-Host "Importing module $($module)..."
        Import-Module -Name $module -Force
    }
}

# Confirm Org Unit exists, else exit
if (!(Get-ADOrganizationalUnit -Filter "distinguishedName -eq `"$($orgUnit)`"")) {
    Write-Host "`nThe specified org unit does not exist! Exiting script..." -ForegroundColor Red
    exit(1)
}

# Check if target security group exists, else create, else exit
Write-Host "`nFetching default group ID..."
try {
    if (($defaultGroupObject = Get-ADGroup -Filter "Name -eq `"$($defaultGroup)`"")) {
        $defaultGroupObject | Move-ADObject -TargetPath $orgUnit # Ensure the default group is in our specified OU
        $defaultGroupId = (Get-ADGroup $defaultGroup -Properties @("primaryGroupToken")).primaryGroupToken
    } else {
        New-ADGroup -Path $orgUnit -Name $defaultGroup -GroupCategory Security -GroupScope Global
        $defaultGroupId = (Get-ADGroup $defaultGroup -Properties @("primaryGroupToken")).primaryGroupToken
    }
} catch {
    Write-Host "`nSomething went wrong while fetching default group ID! Exiting script..." -ForegroundColor Red
    exit(1)
}

# Connect to Microsoft Graph PowerShell, else exit
Write-Host "`nConecting to Microsoft Graph..."
try {
    Connect-MgGraph -AccessToken (ConvertTo-SecureString -String ((Invoke-RestMethod -Uri https://login.microsoftonline.com/$tenantId/oauth2/v2.0/token -Method POST -Body @{Grant_Type="client_credentials";Scope="https://graph.microsoft.com/.default";Client_Id=$clientId;Client_Secret=$clientSecret}).access_token) -AsPlainText -Force)
} catch {
    Write-Host "`nSomething went wrong while connecting to MS Graph! Exiting script..." -ForegroundColor Red
    exit(1)
}

# Confirm devices can be queried, else exit
try {
    Get-MgDevice | Out-Null
} catch {
    Write-Host "`nCannot fetch devices list from Azure AD - do you have the correct app permission set? Exiting script..." -ForegroundColor Red
    exit(1)
}

# Confirm groups can be queried, else exit
try {
    Get-MgGroup | Out-Null
} catch {
    Write-Host "`nCannot fetch groups list from Azure AD - do you have the correct app permission set? Exiting script..." -ForegroundColor Red
    exit(1)
}

# Initialize arrays
$aadDevices = @{} # To store device ID and name of all devices synced from AAD to AD
$aadGroups = @{} # To store group ID and name of all groups synced from AAD to AD

# Pull all AAD joined devices from all devices
Write-Host "`nFetching all Azure AD joined devices..."
foreach ($device in $(Get-MgDevice -Filter "trustType eq 'AzureAD'" -All <#| where-object {$_.deviceid -eq "57258cd6-c7f7-441a-9389-248cbbe56d7e"}#>)) {
    # Clear variables
    $variables = @("guid","sAMAccountName","deviceName","subjectMatch","CAs","issuedCerts","cert","issuer","issuerClean","serialNumber","serialBytes","serialReversed","skiExtension","ski","sha1Provider","publicKeyBytes","sha1Hash","sha1PublicKey","altSecurityIdentities")
    $variables | % {
        Clear-Variable -Name $_ -ErrorAction SilentlyContinue
    }
    
    $guid = $device.DeviceId
    Write-Host "`nProcessing device $($guid)..."

    # Build map to contain devices processed for tracking which devices have been actioned against. Faster to query this than all cloud objects again.
    if (!($aadDevices.ContainsKey($guid))) {
        #Write-Host "Adding device $($guid) to AAD devices dictionary/tracker..."
        $aadDevices.Add($guid, $device.DisplayName)
    }

    # Builds $matches with data chunked out of the $guid value. Then builds the $sAMAccountName based on that. Cannot just use the first 19 characters + $ becuase that might not be unique enough! Must be globally unique in AD!
        # Example $matches output
            #$guid = 9239b30c-421b-4d0b-b5a1-8c47970cf847
            #Name                           Value                                                                                                                                                                                               
            #----                           -----                                                                                                                                                                                               
            #4                              7                                                                                                                                                                                                   
            #3                              8c47970cf84                                                                                                                                                                                         
            #2                              -421b-4d0b-b5a1-                                                                                                                                                                                    
            #1                              9239b30c                                                                                                                                                                                            
            #0                              9239b30c-421b-4d0b-b5a1-8c47970cf847
        # Matching groups 1 and 3 creates a 19 character length string. Adding $ at the end, which indicates a device, equals 20 characters which is the max supported by AD.
        # Result for example is: 9239b30c8c47970cf84$
        # This is not required to match what is presented from Azure becuase certs are used for matching, not sAMAccountName
    $guid -match "^([0-9a-fA-F]{8})(-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-)([0-9a-fA-F]{11})([0-9a-fA-F])$" | Out-Null
    $sAMAccountName = "$($matches[1])"+"$($matches[3])"+"$"

    #region - Get certs from AD and build strong mapping attributes - By David Steinhart
    $deviceName = $guid  # Device hostname
    $subjectMatch = "CN=$deviceName"

    # Get all certificate authorities
    $CAs = Get-CertificationAuthority

    # Query issued certs that match device
    Clear-Variable -name "issuedCerts" -ErrorAction SilentlyContinue
    Clear-Variable -name "cert" -ErrorAction SilentlyContinue
    try {
        foreach ($certAuthority in $CAs) {
            $issuedCerts = foreach ($cert in (Get-IssuedRequest -CertificationAuthority $certAuthority -Property SerialNumber -Filter "CommonName -eq $($deviceName)")) {
                Write-Host "Found certificate $($cert.SerialNumber) for device $($deviceName)..."
                $cert
                #$issuedCerts =+ $cert
            }
        }
    } catch {
        Write-Host "Something went wrong while finding certificates for device $($deviceName)" -ForegroundColor Red
    }


    if ($issuedCerts) {
        # Pick the latest cert if multiple. NO! Get them all for ease of transition!
        Clear-Variable -name "CertRequest" -ErrorAction SilentlyContinue
        $certRequest = $issuedCerts #| Sort-Object NotBefore -Descending | Select-Object -First 1

        # Use Receive-Certificate to get detailed info on the issued certificate
        Clear-Variable -name "cert" -ErrorAction SilentlyContinue
        $certs = Receive-Certificate -RequestRow $certRequest -ErrorAction SilentlyContinue
    } elseif (!$issuedCerts) {
        # Write output if no matching certs found
        Write-Host "No certificates found in CA database for $deviceName."
    }

    # Do operations if cert is found
    if ($certs) {
        $allAltSecID = New-Object System.Collections.Generic.List[object]
        #Clear-Variable -name "allAltSecID" -erroraction SilentlyContinue
        foreach ($cert in $certs){
            # Extract and build contents for the AltSecurityIdentites attribute
            # Issuer
            Clear-Variable -name "issuer" -ErrorAction SilentlyContinue
            Clear-Variable -name "issuerClean" -ErrorAction SilentlyContinue
            $issuer = $cert.IssuerName.Name
            $issuerClean = ($issuer -replace '^CN=', '' -replace ' ', '').Trim()

            # Serial Number
            Clear-Variable -name "serialNumber" -ErrorAction SilentlyContinue
            $serialNumber = $cert.SerialNumber

            # Build Reverse Serial Number
            Clear-Variable -name "serialBytes" -ErrorAction SilentlyContinue
            Clear-Variable -name "serialReversed" -ErrorAction SilentlyContinue
            $serialBytes = for ($i = 0; $i -lt $serialNumber.Length; $i += 2) { $serialNumber.Substring($i, 2) }
            $serialBytes = @()
            for ($i = 0; $i -lt $serialNumber.Length; $i += 2) {
                $serialBytes += $serialNumber.Substring($i, 2)
            }
            [Array]::Reverse($serialBytes)
            $serialReversed = $serialBytes -join ""

            # Build Subject Key Identifier (SKI)
            Clear-Variable -name "skiExtension" -ErrorAction SilentlyContinue
            Clear-Variable -name "ski" -ErrorAction SilentlyContinue
            $skiExtension = $cert.Extensions | Where-Object { $_.Oid.FriendlyName -eq "Subject Key Identifier" }
            if ($skiExtension) {
                $ski = ($skiExtension.Format($false) -replace " ", "").ToLower()
            } else {
                Write-Host "No SKI found in certificate."
                $ski = $null
            }

            # Build SHA1 of Public Key
            Clear-Variable -name "sha1Provider" -ErrorAction SilentlyContinue
            Clear-Variable -name "publicKeyBytes" -ErrorAction SilentlyContinue
            Clear-Variable -name "sha1Hash" -ErrorAction SilentlyContinue
            Clear-Variable -name "sha1PublicKey" -ErrorAction SilentlyContinue
            $sha1Provider = [System.Security.Cryptography.SHA1]::Create()
            $publicKeyBytes = $cert.GetPublicKey()
            $sha1Hash = $sha1Provider.ComputeHash($publicKeyBytes)
            $sha1PublicKey = ($sha1Hash | ForEach-Object { $_.ToString("x2") }) -join ""

            # Combine the built output into single attribute ready for applying to dummy AD computer
            Clear-Variable -name "altSecurityIdentities" -ErrorAction SilentlyContinue
            $altSecurityIdentities = @()
            $altSecurityIdentities += "X509:<I>$issuerClean<SR>$serialReversed"
            if ($ski) {
                $altSecurityIdentities += "X509:<SKI>$ski"
            }
            $altSecurityIdentities += "X509:<SHA1-PUKEY>$sha1PublicKey"

            # Write output to show built attribute
            Write-Host "Generated AltSecurityIdentities entries:"
            $altSecurityIdentities | ForEach-Object { Write-Host $_ }
            $allAltSecID.add($altSecurityIdentities)
        }
        $allAltSecIDarray = foreach ($item in $allAltSecID) {
            if ($item -is [System.Array]) {
                foreach ($subitem in $item) {
                    [string]$subitem
                }
            }
            else {
                [string]$item
            }
        }
    }
    elseif (!$cert) {
        # Write output if unable to get detailed data about the cert
        Write-Host "Unable to retrieve full certificate from CA for RequestID $($certRequest.RequestID)."
    }
    #endregion


    # Create/update AD dummy computer object
    Write-Host "Adding/updating AD object for $($guid)..."
    try {
        if (($adDevice = Get-ADComputer -Filter "Name -eq `"$($guid)`"" -SearchBase $orgUnit)) {
            # If computer object exists, set attributes
            $adDevice | Set-ADComputer -Replace @{"dNSHostName"="$($guid)";"servicePrincipalName"="host/$($guid)";"sAMAccountName"="$($sAMAccountName)";"description"="$($device.DisplayName)";AltSecurityIdentities = $allAltSecIDarray}
        } else {
            # Computer must not exist, create new and set attributes
            $adDevice = New-ADComputer -Name $guid -DNSHostName $guid -ServicePrincipalNames "host/$($guid)" -SAMAccountName $sAMAccountName -Description "$($device.DisplayName)" -Path $orgUnit -AccountPassword $NULL -PasswordNotRequired $False -PassThru
            $adDevice | set-ADComputer -Replace @{AltSecurityIdentities = $altSecurityIdentities}
        }
        # Get the computer object attributes fresh after create/update operations for future use
        $adDevice = Get-ADComputer -Filter "Name -eq `"$($guid)`"" -SearchBase $orgUnit
    } catch {
        # Whole operation failed, bail and write output
        Write-Host "Something went wrong while adding/updating AD object for $($guid)" -ForegroundColor Red
    }

    Write-Host "Changing AD primary group for $($guid)..."
    try {
        if (!((Get-ADGroupMember -Identity $defaultGroup | Select-Object -ExpandProperty Name) -contains $guid)) {
            # Computer is not a member of target group, add it
            Add-ADGroupMember -Identity $defaultGroup -Members $adDevice
        }
        # Set dummy AD computer object primary group to the target group
        Get-ADComputer $adDevice | Set-ADComputer -Replace @{primaryGroupID=$defaultGroupId}
        if ((Get-ADGroupMember -Identity "Domain Computers" | Select-Object -ExpandProperty Name) -contains $guid) {
            # Remove dummy AD computer from "Domain Computers" as its only purpose is to map certs. Proper security design and best practice.
            Remove-ADGroupMember -Identity "Domain Computers" -Members $adDevice -Confirm:$false
        }
    } catch {
        # Whole operation failed, bail and write output
        Write-Host "Something went wrong while changing AD primary group for $($guid)" -ForegroundColor Red
    }

    # Initialize array
    $groups = @{} # To store group ID and name of all groups this device belongs to in AAD

    # Also syncs cloud groups that the cloud computer may be a part of, so those can be used in 802.1x access policies or other purposes. One does not have to maintain group memberships for these devices on-premise. Best practice regarding long term management of this solution.
    # Fetch all groups this device belongs to, then add it to the group
    Write-Host "Fetching all groups for device $($guid)..."
    foreach ($group in Get-MgDeviceMemberOf -DeviceId $device.Id) { # Note $device.Id != $device.DeviceId, $device.Id is the device's object ID
        $groupId = $group.Id
        $groupName = (Get-MgGroup -GroupId $group.Id).DisplayName

        # Build map to contain CLOUD groups processed for tracking which devices have been actioned against. Faster to query this than all CLOUD objects again.
        if (!($aadGroups.ContainsKey($groupId))) {
            #Write-Host "Adding group $($groupId) to AAD groups dictionary/tracker..."
            $aadGroups.Add($groupId, (Get-MgGroup -GroupId $groupId).DisplayName)
        }
        # Build map to contain ON-PREMISES groups processed for tracking which devices have been actioned against. Faster to query this than all ON-PREMISES objects again.
        if (!($groups.ContainsKey($groupId))) {
            #Write-Host "Adding group $($groupId) to groups dictionary for device $($guid)..."
            $groups.Add($groupId, (Get-MgGroup -GroupId $groupId).DisplayName)
        }

        # Create group if doesn't exist already
        #Write-Host "Checking if group $($groupId) exists..."
        if (!($adGroup = Get-ADGroup -Filter "Name -eq `"$($groupId)`"" -SearchBase $orgUnit)) {
            Write-Host "Creating group $($groupId)..."
            try {
                $adGroup = New-ADGroup -Path $orgUnit -Name $groupId -Description $groupName -GroupCategory Security -GroupScope Global
            } catch {
                Write-Host "Something went wrong while creating group $($groupId)" -ForegroundColor Red
            }
        }

        Write-Host "Adding device $($guid) to group $($groupId)..."
        try {
            $adGroup = Get-ADGroup -Filter "Name -eq `"$($groupId)`"" -SearchBase $orgUnit
            if (!(($adGroup | Get-ADGroupMember | Select-Object -ExpandProperty Name) -contains $guid)) {
                # If device is not part of group, add it
                $adGroup | Add-ADGroupMember -Members $adDevice
            }
        } catch {
            # Whole operation failed, bail and write output
            Write-Host "Something went wrong while adding device $($guid) to group $($groupId)" -ForegroundColor Red
        }
    }

    # Remove the device from any AD groups that it should no longer be in
    Write-Host "Removing device $($guid) from any existing AD groups it should no longer be part of..."
    foreach ($group in (Get-ADPrincipalGroupMembership -Identity $adDevice)) {
        # Loop through all groups the device is a member of
        if ($group.Name -eq $defaultGroup) { # Don't remove device from its primary default group
            # Break loop and continue to next item
            continue
        }
        if (!($group.Name -match "^([0-9a-fA-F]{8})(-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-)([0-9a-fA-F]{11})([0-9a-fA-F])$")) { # Don't remove device from non-AAD groups. This would be the case if one added the dummy AD computer object to on-premise only groups.
            # Break loop and continue to next item
            continue
        }
        if (!($groups.ContainsKey($group.Name))) {
            Write-Host "Removing device $($guid) from group $($group.Name)..."
            try {
                $group | Remove-ADGroupMember -Members $adDevice -Confirm:$false
            } catch {
                Write-Host "Something went wrong while removing device $($guid) from group $($group.Name)" -ForegroundColor Red
            }
        }
    }
}

# Remove AD objects that don't exist in Azure AD anymore
# Checks and redundancies because we want to be as sure as possible before deleting

if (($aadDevices.Count -gt 0) -or (!$emptyDeviceProtection)) {
    Write-Host "`nRemoving deleted devices in AAD from AD..."
    $adDevices = Get-ADComputer -Filter * -SearchBase $orgUnit | Where-Object Name -match "^([0-9a-fA-F]{8})(-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-)([0-9a-fA-F]{11})([0-9a-fA-F])$"
    foreach ($device in $adDevices) {
        # Delete the AD device if it doesn't exist in Azure AD
        if (!($aadDevices.ContainsKey($device.Name)) -and !(Get-MgDevice -DeviceId $device.Name -ErrorAction SilentlyContinue)) {
            Write-Host "Removing device $($device.Name)..."
            try {
                if ($removeDeletedDevices) {
                    $device | Remove-ADComputer -Confirm:$false
                    if ($revokeCertOnDelete) {
                        # Revoke certificates where CN = device ID across all certification authorities
                        # Using reason 6 (hold) to allow undo if necessary
                        try {
                            foreach ($certAuthority in Get-CertificationAuthority) {
                                foreach ($cert in (Get-IssuedRequest -CertificationAuthority $certAuthority -Property SerialNumber -Filter "CommonName -eq $($device.DeviceID)")) {
                                    Write-Host "Revoking certificate $($cert.SerialNumber) for device $($device.DisplayName)..."
                                    $cert | Revoke-Certificate -Reason "Hold"
                                }
                            }
                        } catch {
                            Write-Host "Something went wrong while revoking certificates for device $($device.DeviceID)" -ForegroundColor Red
                        }
                    }
                } else {
                    Write-Host "Device $($device.DeviceID) has not been removed from AD due to device deletion policy in script" -ForegroundColor Yellow
                }
            } catch {
                Write-Host "Something went wrong while removing device $($device.DeviceID)" -ForegroundColor Red
            }
        }
    }
} else {
    Write-Host "`nSkipping AD device object deletion as AAD devices list is empty and protection policy is enabled in script" -ForegroundColor Yellow
}

if (($aadGroups.Count -gt 0) -or (!$emptyGroupProtection)) {
    Write-Host "`nRemoving deleted groups in AAD from AD..."
    $adGroups = Get-ADGroup -Filter * -SearchBase $orgUnit | Where-Object Name -match "^([0-9a-fA-F]{8})(-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-)([0-9a-fA-F]{11})([0-9a-fA-F])$"
    foreach ($group in $adGroups) {
        # Delete the AD group if it doesn't exist in Azure AD
        if (!($aadGroups.ContainsKey($group.Name)) -and !(Get-MgGroup -GroupId $group.Name -ErrorAction SilentlyContinue)) {
            Write-Host "Removing group $($group.Name)..."
            try {
                if ($removeDeletedGroups) {
                    $group | Remove-ADGroup -Confirm:$false
                } else {
                    Write-Host "Group $($group.Name) has not been removed from AD due to group deletion policy in script" -ForegroundColor Yellow
                }
            } catch {
                Write-Host "Something went wrong while removing group $($group.Name)" -ForegroundColor Red
            }
        }
    }
} else {
    Write-Host "`nSkipping AD group object deletion as AAD group list is empty and protection policy is enabled in script" -ForegroundColor Yellow
}

Write-Host "`nSync completed!"

# Disconnect from cloud endpoint
Disconnect-MgGraph

# Stop global logging
Stop-Transcript
