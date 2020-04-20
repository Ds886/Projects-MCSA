# The purpose of the project was to deploy a new lab envrionement using Hyper-V that includes Active Directory with two sites, instnaciating GPO policy and deploying a Microsoft based iSCSI storage solution with network wide shares and WDS

#region Modules


# The ADDSDeployment can only be imported after the AD Installed see line 68
#Import-Module ADDSDeployment
Import-Module GroupPolicy

#endregion

#region Constants

    #region Credential

        $C_CRED_LOCAL = New-Object System.Management.Automation.PSCredential -ArgumentList "Administrator",$(ConvertTo-SecureString -AsPlainText "Pa55w.rd" -Force)
        $C_CRED_DOMAIN = New-Object System.Management.Automation.PSCredential -ArgumentList "Proj\Administrator",$(ConvertTo-SecureString -AsPlainText "Pa55w.rd" -Force)

    #endregion

    #region Domain Configurations

        $C_DOMAINNAME="proj.local"
        $C_WINSNAME = "PROJ"

    #endregion

    #region VMNames

        $C_HYPERV_NAME_BASE = "PROJ-BASE-SERVER"
        $C_HYPERV_NAME_DC   = "PROJ-DC-SERVER"
        $C_HYPERV_NAME_STR  = "PROJ-STR-SERVER"
        $C_HYPERV_NAME_FS0  = "PROJ-FS0-SERVER"
        $C_HYPERV_NAME_FS1  = "PROJ-FS1-SERVER"
        $C_HYPERV_NAME_CL1  = "PROJ-CL1"
        $C_HYPERV_NAME_WDS  = "PROJ-WDS-SERVER"

    #endregion

#endregion

#region Scripts

    #region Create Differncing

        function fncCreateBase
        {
             $strVMName = $C_HYPERV_NAME_BASE
             $strPath = "E:\Project1\$strVMName"
             $strHDPath = "$strPath\Virtual Hard Disks\$strVMName-DISK.vhdx"
 
             # Creates the VM
             New-VM -Name $strVMName `
               -NoVHD `
               -Generation 2 `
               -MemoryStartupBytes 2048MB `
               -BootDevice CD `
               -Path $strPath

             # Disable CheckPoint
             Set-VM -VMName $strVMName -CheckpointType Disabled

             # Create a VHD
             New-VHD -Path $strHDPath `
               -SizeBytes 120GB `
               -Dynamic 

             # Attatch VHD to VM
             Add-VMHardDiskDrive -VMName $strVMName `
                  -ControllerType SCSI `
                  -ControllerNumber 0 `
                  -Path $strHDPath
        } 

    #endregion

    #region Set DC

        #region Create DC

            Function fncCreateDC
            {
                $strVMName = $C_HYPERV_NAME_DC
                $strPath = "E:\Project1\$C_HYPERV_NAME_DC"
                $strHDPath = "$strPath\Virtual Hard Disks\$strVMName-DISK.vhdx"
      
                # Creates the VM
                New-VM -Name $strVMName `
                       -NoVHD `
                       -Generation 2 `
                       -MemoryStartupBytes 4096MB `
                       -BootDevice CD `
                       -Path $strPath

                New-VHD -ParentPath "E:\Project1\$C_HYPERV_NAME_BASE\Virtual Hard Disks\$C_HYPERV_NAME_BASE-DISK.vhdx" `
                        -path $strHDPath `
                        -Differencing 

                Add-VMHardDiskDrive -VMName $strVMName `
                                    -ControllerType SCSI `
                                    -ControllerNumber 0 `
                                    -ControllerLocation 1 `
                                    -Path $strHDPath

                Connect-VMNetworkAdapter -VMName $C_HYPERV_NAME_DC `
                                         -SwitchName "PROJ_INTERNAL"

                # Set Hard Disk as startup device(automatically it sets the network device as startup object)
                Set-VMFirmware -VMName $strVMName -FirstBootDevice $(Get-VMFirmware -VMName $strVMName).BootOrder[2]   
            }   

        #endregion 

        #region Set DC name

            function fncSetDCNameIP
            {
                $sbScriptBlock = {
                           # Set Static IP and Computer name
                           New-NetIPAddress -InterfaceAlias "Ethernet" `
                                            -IPAddress 10.0.1.1 `
                                            -DefaultGateway 10.0.1.1 `
                                            -PrefixLength 24 

                           Set-DnsClientServerAddress -InterfaceAlias Ethernet `
                                                      -ServerAddresses "10.0.1.1"

                           Rename-Computer -NewName "TLV-PROJ-DC"

                           Install-WindowsFeature -Name 'DHCP' –IncludeManagementTools -Restart

                           Restart-Computer -Force                       
                }

                Invoke-Command -VMName $C_HYPERV_NAME_DC -Credential $C_CRED_LOCAL -ScriptBlock $sbScriptBlock            
            }
         
        #endregion

        #region Install AD

            Function fncInstallAD
            {
                $sbScriptBlock = {
                         param($C_DOMAINNAME,
                               $C_WINSNAME)

                         # Install Active Directory
                         # Install Features
                         Install-WindowsFeature AD-Domain-Services  -IncludeManagementTools

                         Import-Module ADDSDeployment

                         # Set the basic forest
                         Install-ADDSForest -CreateDnsDelegation:$false `
                                            -DatabasePath "C:\Windows\NTDS" `
                                            -DomainMode Win2012R2 `
                                            -DomainName $C_DOMAINNAME `
                                            -DomainNetbiosName $C_WINSNAME `
                                            -ForestMode Win2012R2 `
                                            -InstallDns:$true `
                                            -LogPath "c:\windows\ntds" `
                                            -NoRebootOnCompletion:$true `
                                            -SysvolPath "c:\windows\sysvol" `
                                            -Force:$true `
                                            -SafeModeAdministratorPassword $(ConvertTo-SecureString "Pa55w.rd" -AsPlainText -Force)

                         Restart-Computer -Force  
                    }

                Invoke-Command -VMName $C_HYPERV_NAME_DC -Credential $C_CRED_LOCAL -ScriptBlock $sbScriptBlock -ArgumentList $C_DOMAINNAME,$C_WINSNAME
            }

        #endregion

        #region Set Site

            Function fncSetSite
            {
                $sbScriptBlock = {
                    Rename-ADObject -Identity "CN=Default-First-Site-Name,CN=Sites,CN=Configuration,DC=PROJ,DC=COM" `
                                    -NewName TLV

                    Get-ADReplicationSite TLV | Set-ADReplicationSite -Replace @{ "location" = "Tel Aviv, Israel" }

                    New-ADReplicationSubnet -Name "10.0.1.0/24" `
                                            -Location "Tel Aviv, Israel"
                    }

                 Invoke-Command -VMName $C_HYPERV_NAME_DC -Credential $C_CRED_DOMAIN -ScriptBlock $sbScriptBlock  
            }

        #endregion

        #region Set DHCP

        function fncSetDHCPInDC
        {
            $sbScriptBlock = {
                            Add-DhcpServerV4Scope -Name "DHCP Scope" -StartRange 10.0.1.100 -EndRange 10.0.1.253 -SubnetMask 255.255.255.0
                            Set-DhcpServerV4OptionValue -DnsServer 10.0.1.1 -Router 10.0.1.1
                            Set-DhcpServerv4Scope -ScopeId 10.0.1.100 -LeaseDuration 1.00:00:00
                            Restart-service dhcpserver
                        }

            Invoke-Command -VMName $C_HYPERV_NAME_DC -Credential $C_CRED_DOMAIN -ScriptBlock $sbScriptBlock 
        }

        #endregion

        #region Create Users
        
            function fncImportUsersFromCSV
            {     
                $sbScriptBlock = {
                param($C_DOMAINNAME)

                #region Create Users Script

                #region Formatting

                    # Format DC path based on $C_DOMAINNAME
                    function fncFormatDC
                    {
                        return $("DC=$C_DOMAINNAME".Replace(".",",DC="))
                    }


                    # Format OU path based on a given syntax subou.subou...subou.primeou for example Users.Test
                    function fncFormatOU
                    {
                         param([string]$strOU)

                         return $([string]$( "OU=$strOU").Replace(".",",OU="))
                    }

                    # Format the path fully
                    function fncFormatFinalString
                    {
                        param([string]$strOU)
 
                        return [string]$("$(fncFormatOU $strOU),$(fncFormatDC)")
                    }

                #endregion

                #region Assistent function for creation of Users based on CSV

                    # Check if OU path exists based on a given the syntax of the OU path as "Sub...SubSubOU.SubOU.OU" for example Users.Test
                    function fncCheckIfOUExist
                    {
                        Param([string]$strOU)

                        return [adsi]::Exists("LDAP://$(fncFormatFinalString $strOU)")
                    }

                    Function fncCheckIfGroupExist
                    {
                        Param([string]$strOU,
                              [string]$strGroup)

                        return [adsi]::Exists("LDAP://CN=$strGroup,$strPath")
                    }

                    # Create OU recusivly in the main path of the domain given the syntax of the OU path as "Sub...SubSubOU.SubOU.OU" for example Users.Test
                    Function fncRecurseCreateOU
                    {
                        param([string]$strOU)
                        $arrOU = $strOU.Split('.')
                        $strPath="$(fncFormatDC)"
                        for ($nCurrOU=$($arrOU.Length-1); $nCurrOU -gt -1; $nCurrOU--)
                        {
                            If(!(Get-ADOrganizationalUnit -Filter "DistinguishedName -eq 'OU=$($arrOU[$nCurrOU]),$strPath'")) 
                            {
                                try
                                {
                                    New-ADOrganizationalUnit -Name $arrOU[$nCurrOU] `
                                                             -Path $strPath `
                                                             -ProtectedFromAccidentalDeletion $false `
                                                             -Server $C_DOMAINNAME 
                                }
                                catch{}
                            }

                            $strPath = "OU=$($arrOU[$nCurrOU])" + ',' + $strPath
                        }
                    }

                    # Creates a new group in an ou named groups under the root
                    Function fncCreateGroup
                    {
                        param($strOU,
                              $strGroupName)
    
                        $strRelvantOU = $strOU.Split('.')[$strOU.Split('.').Length-1]
                        $strPath = fncFormatFinalString "Groups.$strRelvantOU"
   
                        If(!(Get-ADOrganizationalUnit -Filter "DistinguishedName -eq '$strPath'")) 
                        {
                           New-ADOrganizationalUnit -Name "Groups" `
                                                    -Path $(fncFormatFinalString $strRelvantOU) `
                                                    -ProtectedFromAccidentalDeletion $false `
                                                    -Server $C_DOMAINNAME
                        }

                        if (!$(fncCheckIfGroupExist $strOU $strGroupName))
                        {
                            New-ADGroup -DisplayName $strGroupName `
                                        -Name $strGroupName `
                                        -SamAccountName $strGroupName `
                                        -GroupScope Global `
                                        -Path $strPath `
                                        -Server $C_DOMAINNAME `
                                        -ManagedBy "Administrators" `
                                        -GroupCategory Security `
                        }   
                    }

                    # Function To add a single user
                    Function fncAddUser
                    {
                        param([string]$strUserName, 
                              [string]$strFirstName,
                              [string]$strLastName, 
                              [string]$strPassword, 
                              [string]$strOU,
                              [string]$strGroup)
 
                        if($(fncCheckIfOUExist $strOU) -eq $false)
                        {
                            fncRecurseCreateOU $strOU  
                        }

                        try
                        {
                            fncCreateGroup $strOU $strGroup
                        }catch{}

                        try
                        {
                            New-ADUser -SamAccountName $strUserName `
                                       -UserPrincipalName "$strUserName@$C_DOMAINNAME" `
                                       -Name "$strFirstName $strLastName" `
                                       -GivenName "$strFirstName" `
                                       -Surname "$strLastName" `
                                       -Enabled $true `
                                       -DisplayName "$strFirstName $strLastName" `
                                       -Path $(fncFormatFinalString $strOU) `
                                       -AccountPassword $(ConvertTo-SecureString $strPassword -AsPlainText -Force)`
                                       -ChangePasswordAtLogon $true 
                        }catch{}

                        # Add user to a new group. In Identity it is formated as "CN=[Group Name],OU=Groups,OU=[Top most ou(e.g. Marketing in Users.Marketing)],DC=proj,DC=com"
                        try
                        {
                            Add-ADGroupMember -Identity $strGroup `
                                              -Members "$strUserName" `      
                        }catch{}
                    }

                #endregion

                #endregion

                # Import from CSV 
                #===========================================================================
                # Example Of the CSV Format:
                #===========================================================================
                # fname,lname,uname,pass,ou
                # [First Name],[Last Name],[User Name],[Password],[Sub...SubSubOU.SubOU.OU]

                Function fncImportUsersFromCSV
                {
                    param([string]$strPath)
                    $csv = Import-Csv $strPath
                    foreach ($usrCurrUser in $csv)
                    {
                        try
                        {
                            fncAddUser $usrCurrUser.uname $usrCurrUser.fname $usrCurrUser.lname $usrCurrUser.pass $usrCurrUser.ou $usrCurrUser.group
                            echo("User $($usrCurrUser.uname) has been created at $(fncFormatDC $usrCurrUser.ou)")
                        }
                        catch
                        {
                            echo("User $($usrCurrUser.uname) at $(fncFormatDC $usrCurrUser.ou) has failed due to $($_.Exception.Message)")
                        } 
                    }
                }
                    fncImportUsersFromCSV e:\USERS.CSV
                }

                Invoke-Command -VMName $C_HYPERV_NAME_DC -Credential $C_CRED_DOMAIN -ScriptBlock $sbScriptBlock -ArgumentList $C_DOMAINNAME
            }

        #endregion

        #region GPO

            Function fncSetPasswordPolicy
            {
                $sbScriptBlock = {

                    param($C_DOMAINNAME)
                    Set-ADDefaultDomainPasswordPolicy -Identity $C_DOMAINNAME `
                                                  -MaxPasswordAge 120d `
                                                  -ComplexityEnabled $true `
                                                  -MinPasswordLength 7 `
                                                  -PasswordHistoryCount 24 `
                                                  -LockoutDuration 0 `
                                                  -LockoutObservationWindow 0 `
                                                  -LockoutThreshold 3      
                    }

                Invoke-Command -VMName $C_HYPERV_NAME_DC -Credential $C_CRED_DOMAIN -ScriptBlock $sbScriptBlock -ArgumentList $C_DOMAINNAME   
            }

        #endregion

    #endregion

    #region Storage
    
        #region Storage

            #region Create Storage

            Function fncCreateStorageVM
            {
                $strVMName = $C_HYPERV_NAME_STR
                $strPath = "E:\Project1\$strVMName"
                $strHDPath = "$strPath\Virtual Hard Disks\$strVMName-DISK.vhdx"
            
                # Creates the VM
                New-VM -Name $strVMName `
                       -NoVHD `
                       -Generation 2 `
                       -MemoryStartupBytes 2048MB `
                       -Path $strPath
    

                # Creates a new HD
                New-VHD -ParentPath "E:\Project1\$C_HYPERV_NAME_BASE\Virtual Hard Disks\$C_HYPERV_NAME_BASE-DISK.vhdx" `
                        -path $strHDPath `
                        -Differencing

                # Attach main path
                 Add-VMHardDiskDrive -VMName $strVMName `
                                     -Path $strHDPath `
                                     -ControllerNumber 0 

               #region Setting Network  
 
               # Add the internal network switch
  
               Connect-VMNetworkAdapter  -SwitchName "PROJ_ST" -VMName $strVMName

               # Set Hard Disk as startup device(automatically it sets the network device as startup object)
               Set-VMFirmware -VMName $strVMName -FirstBootDevice $(Get-VMFirmware -VMName $strVMName).BootOrder[1]
            }    

            #endregion




            #endregion Create Storage

            #region Initialize Storage

            Function fncInitStr
                                                                                                                                                                                            {
        $sbScriptBlock = {
                    $strVMName = "TLV-PROJ-STR"
                    $strIP1 = "10.0.3.1"
            
                    # Set Static IP and Computer name
                    New-NetIPAddress -InterfaceAlias "Ethernet" `
                                     -IPAddress $strIP1 `
                                     -PrefixLength 24 

                     Set-DnsClientServerAddress -InterfaceAlias "Ethernet" `
                                                -ServerAddresses "10.0.3.1"
       

                     Rename-Computer -NewName $strVMName

                      # Install the iscsi target feature
                     Install-WindowsFeature -Name FS-iSCSITarget-Server, FS-Fileserver `
                                            -IncludeAllSubFeature `
                                            -IncludeManagementTools

                     Restart-Computer -Force
                 }

        Invoke-Command -VMName $C_HYPERV_NAME_STR `
                       -Credential $C_CRED_LOCAL `
                       -ScriptBlock $sbScriptBlock 
    }    

            #endregion

            #region Setup iSCSI target

            Function fncSetiSCSI
            {
                $sbScriptBlock = {
                    Function fncAddDrive
                    {
                        param ( $strDriveName,
                                $strSize)

                        $strPath = "C:\vhd\$($strDriveName).vhdx"
                        echo $strSize

                        # Create New VHD
                        New-IscsiVirtualDisk -path $strPath `
                                             -SizeBytes $strSize

                        # Add vhd to the iscsi server
                        Add-IscsiVirtualDiskTargetMapping -TargetName "iSCSISTR" `
                                                          -Path $strPath
                    }  
                 
                    # Starting iSCSI service
                    Set-Service -Name msiscsi `
                                -StartupType Automatic
                    Start-Service msiscsi         

                    # Set the settings for a new iScsi target server
                    New-IscsiServerTarget -TargetName "iSCSISTR" `
                                          -InitiatorId @("IPAddress:10.0.3.2","IPAddress:10.0.3.3")
                 
                    fncAddDrive "strQuorum" 1GB
                    fncAddDrive "strStorage50G" 50GB
                }

                Invoke-Command -VMName $C_HYPERV_NAME_STR `
                               -Credential $C_CRED_LOCAL `
                               -ScriptBlock $sbScriptBlock
        }
    
            #endregion

        #endregion Storage

        #region FS

            #region Create FS-VM

                function fncNewFSVM
                {
                     param([string]$strVMName)

                     #region Variables
     
                        $strVMName = $strVMName
                        $strPath = "E:\Project1\$strVMName"
                        $strHDPath = "$strPath\Virtual Hard Disks\$strVMName-DISK.vhdx"

                     #endregion

                     #region VM Creation

                     # Creates the VM
                     New-VM -Name $strVMName `
                       -NoVHD `
                       -Generation 2 `
                       -MemoryStartupBytes 2048MB `
                       -BootDevice CD `
                       -Path $strPath`

                     #endregion
 
                     #region Setting Network  
 
                     # Add the internal network switch
                     Connect-VMNetworkAdapter  -SwitchName "PROJ_ST" -VMName $strVMName

                     #endregion

                     #region Setting Storage

                     # Create new main drive
                     New-VHD -ParentPath "E:\Project1\$C_HYPERV_NAME_BASE\Virtual Hard Disks\$C_HYPERV_NAME_BASE-DISK.vhdx" `
                             -path $strHDPath `
                             -Differencing

                     # Attach main path
                    Add-VMHardDiskDrive -VMName $strVMName `
                                     -Path $strHDPath `
                             
                             
                     #Set Hard Disk as boot path (by default it is in the 2th rank)
                     Set-VMFirmware -VMName $strVMName -FirstBootDevice $(Get-VMFirmware -VMName $strVMName).BootOrder[2]     

                     #endregion
                }

                Function fncCreateFSFUll
                {
                    for($nCountVM = 0; $nCountVM -lt 2; $nCountVM ++)
                    {
                        fncNewFSVM "PROJ-FS$nCountVM-Server"
                    }
                }        

            #endregion

            #region Set the FS initial settings

            Function fncSetFSName
            {
                $arrVM = get-vm proj-fs*

                for ($nCountMachine = 0;$nCountMachine -lt 2; $nCountMachine++)
                {
                    $vmFS = $arrVM[$nCountMachine]
        
                    $sbScriptBlock = {
                        param ($nCountMachine)

                        $strVMName = "TLV-PROJ-FS$nCountMachine"
                        $strIP1 = "10.0.3.$($nCountMachine+2)"            

                        # Set Static IP and Computer name
                        New-NetIPAddress -InterfaceAlias "Ethernet" `
                                         -IPAddress $strIP1 `
                                         -PrefixLength 24 `
                                         -Verbose

                         # Install Failover-Clustering
                         Install-WindowsFeature  Failover-Clustering -IncludeAllSubFeature `
                                                                     -IncludeManagementTools
                
                         Install-WindowsFeature FS-FileServer -IncludeAllSubFeature `
                                                              -IncludeManagementTools
                                            
       
                         Rename-Computer -NewName $strVMName
                                 
                         Restart-Computer -Force
                    }

                    Invoke-Command -VMName $vmFS.name -Credential $C_CRED_LOCAL -ScriptBlock $sbScriptBlock -ArgumentList $nCountMachine -AsJob -Verbose
                 }
             }
     
            #endregion

            #region Set iSCSI Initator

                 Function fncSetIscsiInitiator
                 {
                     $arrVM = get-vm proj-fs*

                     for ($nCountMachine = 0;$nCountMachine -lt 2; $nCountMachine++)
                     {
                        $vmFS = $arrVM[$nCountMachine]
        
                        $sbScriptBlock = {
                                param ($nCountMachine)
                    
                                # Autostart iscsiservice on start
                                Set-Service -Name msiscsi -StartupType Automatic
                                Start-Service msiscsi

                                # Set Iscsi target portal
                                New-IscsiTargetPortal –TargetPortalAddress 10.0.3.1
                                Get-IscsiTarget | Connect-IscsiTarget -IsPersistent $true

                                # Initialize disks, format them and bring them online 
                                if($nCountMachine -eq 0)
                                {
                                    get-disk | Where-Object -FilterScript {$_.Size -eq 1GB} | Initialize-Disk -PartitionStyle GPT -PassThru | New-Partition -AssignDriveLetter -UseMaximumSize | Format-Volume -FileSystem NTFS -Confirm:$false -Force | Set-Disk -IsOffline $false 
                                    get-disk | Where-Object -FilterScript {$_.Size -eq 50GB} | Initialize-Disk -PartitionStyle GPT -PassThru | New-Partition -AssignDriveLetter -UseMaximumSize | Format-Volume -FileSystem NTFS -Confirm:$false -Force | Set-Disk -IsOffline $false
                                }
                            }

                        Invoke-Command -VMName $vmFS.name -Credential $C_CRED_LOCAL -ScriptBlock $sbScriptBlock -ArgumentList $nCountMachine
                      }
                  }

            #endregion

            #region Join DC
        
                function fncAddNetworkInfrastructureToFSForDC
                {
                    $arrVM = Get-VM "PROJ-FS*"
            

                    # Add Network Adapater    
                    foreach($vm in $arrVM)
                    {
                        Add-VMNetworkAdapter -VMName $vm.name -SwitchName "PROJ_INTERNAL"
                    }

                    for ($nCountMachine = 0;$nCountMachine -lt 2; $nCountMachine++)
                    {
                        $vmFS = $arrVM[$nCountMachine]

                        $sbScriptBlock = {
                            param ($nCountMachine, 
                                   $cred,
                                   $domain )
            
                            # Change IP to 10.0.1.0/24 range. 10.0.1.1 is used by DC
                            Get-NetIPAddress -InterfaceAlias "Ethernet 2" | New-NetIpAddress  -IPAddress "10.0.1.$($nCountMachine+2)" -PrefixLength 24

                            Set-DnsClientServerAddress -InterfaceAlias "Ethernet 2" -ServerAddresses "10.0.1.1"

                            Add-Computer -DomainName $domain `
                                          -Credential $cred

                            Restart-Computer -Force
                        }

                        Invoke-Command -VMName $vmFS.name `
                                       -Credential $C_CRED_LOCAL `
                                       -ScriptBlock $sbScriptBlock `
                                       -ArgumentList $nCountMachine, $C_CRED_DOMAIN, $C_DOMAINNAME `
                                       -AsJob
                    }
                }

            #endregion
 
            #region Set Failover Clustering Networking

                Function fncSetFailoverClustering
                {
                     $arrVM = get-vm "proj-fs*"
             
                     foreach($vm in $arrVM)
                     {
                        Add-VMNetworkAdapter -VMName $vm.name -SwitchName "PROJ_FS"
                     }

                     for ($nCountMachine = 0;$nCountMachine -lt 2; $nCountMachine++)
                     {
                        $vmFS = $arrVM[$nCountMachine]
        
                        $sbScriptBlock = {
                                param ($nCountMachine)
                        
                                Get-NetIPAddress -InterfaceAlias "Ethernet 3" | New-NetIpAddress  -IPAddress "10.0.2.$($nCountMachine+1)" -PrefixLength 24                        
                            }

                        Invoke-Command -VMName $vmFS.name `
                                       -Credential $C_CRED_DOMAIN `
                                       -ScriptBlock $sbScriptBlock `
                                       -ArgumentList $nCountMachine
                     }

                     $sbScriptBlock = {
                        Test-Cluster –Node TLV-PROJ-FS0, TLV-PROJ-FS1 
            
                        New-Cluster -Name FSFailover `
                                    -Node TLV-PROJ-FS0, TLV-PROJ-FS1 `
                                    -StaticAddress 10.0.2.30/24,10.0.1.30/24 `
                                    -IgnoreNetwork 10.0.3.0/24 `
                                    -AdministrativeAccessPoint ActiveDirectoryAndDns -
                        }

                    Invoke-Command -VMName $C_HYPERV_NAME_FS0 `
                                   -Credential $C_CRED_DOMAIN `
                                   -ScriptBlock $sbScriptBlock 
                }

            #endregion  

        #endregion

    #endregion

    #region Shares
   
        #region Create shares for each department
    
            Function fncCreateShares
            {
                    $sbScriptBlock = {
                        Add-ClusterFileServerRole -Storage "Cluster Disk 1" `
                                                  -Name SharedStorage `
                                                  -StaticAddress 10.0.1.40/24 `
                                                  -IgnoreNetwork 10.0.2.0/24, 10.0.3.0/24

                        Function fncCreateShare
                        {
                            param([string]$strName)
                              
                            $strTempName = $strName.Replace(" ","")
                            $strPath = "f:\$strName"
                            mkdir $strPath 
                            New-SmbShare -Name $strName `
                                         -Path $strPath `
                                         -FullAccess "Proj\Admin$strTempName" `
                                         -ChangeAccess "Proj\Man$strTempName", "Proj\Users$strTempName"
                                     
                                     
                        }

                        fncCreateShare "Costumer Services"
                        fncCreateShare "Human Resources"
                        fncCreateShare "Management"
                        fncCreateShare "Manufacturing"
                        fncCreateShare "Marketing"
                        fncCreateShare "Sales"

                    }

                    Invoke-Command -VMName $C_HYPERV_NAME_FS0 `
                                   -Credential $C_CRED_DOMAIN `
                                   -ScriptBlock $sbScriptBlock  `
                                  
            }

        #endregion        

    #endregion

    #region WDS

        #region WDS Setup

            #region Create WDS
            
                Function fncCreateWDS
                {
                    $strVMName = $C_HYPERV_NAME_WDS
                    $strPath = "E:\Project1\$strVMName"
                    $strHDPath = "$strPath\Virtual Hard Disks\$C_HYPERV_NAME_CL1-DISK.vhdx"          
            
      
                    # Creates the VM
                    New-VM -Name $strVMName `
                           -NoVHD `
                           -Generation 2 `
                           -MemoryStartupBytes 3062MB `
                           -BootDevice CD `
                           -Path $strPath

                    New-VHD -ParentPath "E:\Project1\$C_HYPERV_NAME_BASE\Virtual Hard Disks\$C_HYPERV_NAME_BASE-DISK.vhdx" `
                            -path $strHDPath `
                            -Differencing 

                     Add-VMHardDiskDrive -VMName $strVMName `
                                         -ControllerType SCSI `
                                         -ControllerNumber 0 `
                                         -ControllerLocation 1 `
                                         -Path $strHDPath

                      Connect-VMNetworkAdapter -VMName $strVMName `
                                               -SwitchName "PROJ_INTERNAL"

                      # Set Hard Disk as startup device(automatically it sets the network device as startup object)
                      Set-VMFirmware -VMName $strVMName -FirstBootDevice $(Get-VMFirmware -VMName $strVMName).BootOrder[2]
                }

            #endregion
    
            #region Init WDS name and IP

                function fncInitWDS
                {               
                    $sbScriptBlock = {
                           param($strName)
                           $strVMName = $strName

                            # Set Static IP and Computer name
                               New-NetIPAddress -InterfaceAlias "Ethernet" `
                                                -IPAddress 10.0.1.4 `
                                                -DefaultGateway 10.0.1.1 `
                                                -PrefixLength 24 
                    
            
                           # Set DNS Settings
                           Set-DnsClientServerAddress -InterfaceAlias "Ethernet" `
                                                      -ServerAddresses "10.0.1.1"
       

                           Rename-Computer -NewName $strVMName
                                       
                           Restart-Computer -Force
                        }

                    Invoke-Command -VMName $C_HYPERV_NAME_WDS `
                                   -Credential $C_CRED_LOCAL `
                                   -ScriptBlock $sbScriptBlock `
                                   -ArgumentList $C_HYPERV_NAME_WDS
                }

            #endregion

            #region Join WDS to the Domain
            
                function fncWDSJoinDC
                {           
                    $sbScriptBlock = {
                                param ($cred,
                                       $domain )
            
                                Add-Computer -DomainName $domain `
                                             -Credential $cred

                                Restart-Computer -Force
                            }

                            Invoke-Command -VMName $C_HYPERV_NAME_WDS `
                                           -Credential $C_CRED_LOCAL `
                                           -ScriptBlock $sbScriptBlock `
                                           -ArgumentList $C_CRED_DOMAIN, $C_DOMAINNAME `
                                           -AsJob
                }

            #endregion

        #endregion

        #region Setup CL1

            #region Create CL1

                Function fncCreateCL1
                {  
                    $strVMName = $C_HYPERV_NAME_CL1
                    $strPath = "E:\Project1\$C_HYPERV_NAME_CL1"
                    $strHDPath = "E:\Project1\$C_HYPERV_NAME_CL1\Virtual Hard Disks\$C_HYPERV_NAME_CL1-DISK.vhdx"          
            
      
                    # Creates the VM
                    New-VM -Name $strVMName `
                           -NoVHD `
                           -Generation 2 `
                           -MemoryStartupBytes 1024MB `
                           -BootDevice CD `
                           -Path $strPath

                     New-VHD -path $strHDPath `
                            -SizeBytes 50gb `
                            -Dynamic

                     Add-VMHardDiskDrive -VMName $strVMName `
                                         -ControllerType SCSI `
                                         -ControllerNumber 0 `
                                         -ControllerLocation 1 `
                                         -Path $strHDPath

                     Connect-VMNetworkAdapter -VMName $C_HYPERV_NAME_CL1 `
                                               -SwitchName "PROJ_INTERNAL"
                }

                #endregion

        #endregion

    #endregion

#endregion

#region triggers

    #region Base
        
        # Slide 01
        #fncCreateBase

        # Slide 05
        #attrib.exe +R "E:\Project1\$C_HYPERV_NAME_BASE\Virtual Hard Disks\$C_HYPERV_NAME_BASE-DISK.vhdx"

    #endregion

    #region DC
        
        # Slide 06
        #fncCreateDC

        # Slide 08
        #fncSetDCNameIP

        # Slide 09
        #fncInstallAD

        # Slide 10
        #fncSetSite

        # Slide 12
        #fncSetDHCPInDC

        # Slide 13
        #fncImportUsersFromCSV

        # Slide 15
        #fncSetPasswordPolicy

    #endregion

    #region Storage

        # Slide 17
        #fncCreateStorageVM

        # Slide 18
        #fncInitStr

        # Slide 19
        #fncSetiSCSI

        # Slide 20
        #fncCreateFSFUll

        # Slide 21
        #fncSetFSName

        # Slide 22
        #fncSetIscsiInitiator

        # Slide 23
        #fncAddNetworkInfrastructureToFSForDC

        # Slide 24
        #fncSetFailoverClustering

    #endregion

    #region Shares
        
        # Slide 25
        #fncCreateShares
            
    #endregion

    #region WDS

        #region WDS
            
            # Slide 29
            #fncCreateWDS

            # Slide 30
            #fncInitWDS

            # Slide 31
            #fncWDSJoinDC

            # Slide 39
            #fncCreateCL1

        #endregion        
        
    #endregion

#endregion