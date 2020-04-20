# The purpose of the project was to deploy in an Hyper-V envrioenment a Network with two main sites(each with seprate Microsoft based infrastructre),  Limit the logon hours to particular groups and set up  a Storage solution where the users are locked to the network storage

# During the course the lecturer repurposed the Storage solution to incorprate both iSCSI and DFS infrastructure so the script accompany both at least on superficial level

#region Modules

# The ADDSDeployment can only be imported after the AD Installed see line 68
#Import-Module ADDSDeployment
Import-Module GroupPolicy

#endregion

#region Constants

    #region Credential

        $C_CRED_LOCAL = New-Object System.Management.Automation.PSCredential -ArgumentList "Administrator",$(ConvertTo-SecureString -AsPlainText "Pa55w.rd" -Force)
        $C_CRED_DOMAIN = New-Object System.Management.Automation.PSCredential -ArgumentList "spider\Administrator",$(ConvertTo-SecureString -AsPlainText "Pa55w.rd" -Force)
        $C_CRED_DOMAIN_AFTER_CHANGE = New-Object System.Management.Automation.PSCredential -ArgumentList "spider\root",$(ConvertTo-SecureString -AsPlainText "Pa55w.rd" -Force)

    #endregion

    #region Domain Configurations

        $C_DOMAINNAME="spider.com"
        $C_WINSNAME = "spider"

    #endregion

    #region VMNames

        #region Base

            $C_HYPERV_NAME_BASE = "PROJ-BASE-SERVER"
            $C_HYPERV_NAME_NAT = "PROJ-NAT" 

        #endregion               

        #region New York

            $C_HYPERV_NAME_NY_DC = "NY-DC1"
            $C_HYPERV_NAME_NY_FS1 = "NY-FS1"
            $C_HYPERV_NAME_NY_CL1 = "NY-CL1"
            $C_HYPERV_NAME_NY_CL2 = "NY-CL2"

        #endregion

        #region TLV

            $C_HYPERV_NAME_TLV_DC = "TLV-DC1"
            $C_HYPERV_NAME_TLV_FS1 = "TLV-FS1"
            $C_HYPERV_NAME_TLV_FS2 = "TLV-FS2"
            $C_HYPERV_NAME_TLV_CL1 = "TLV-CL1"
            $C_HYPERV_NAME_TLV_CL2 = "TLV-CL2"

        #endregion

    #endregion

    #region Switch names
        $C_HYPERV_NAME_SWITCH_NY = "Switch-NY"
        $C_HYPERV_NAME_SWITCH_TLV = "Switch-TLV"
    #endregion

  #endregion

    #region Scritps
        
        #region Differncing

            #region Create Differncing

            function fncCreateBase
            {
                 $strVMName = $C_HYPERV_NAME_BASE
                 $strPath = "f:\Project1\$strVMName"
                 $strHDPath = "$strPath\Virtual Hard Disks\$strVMName-DISK.vhdx"
 
                 # Creates the VM
                 New-VM -Name $strVMName `
                   -NoVHD `
                   -Generation 2 `
                   -MemoryStartupBytes 4096MB `
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

        #endregion

        #region Infrastructure

            #region Create Switch
                function fncCreateHyperSwitch
                {
                    New-VMSwitch -Name $C_HYPERV_NAME_SWITCH_NY -SwitchType Private
                    New-VMSwitch -Name $C_HYPERV_NAME_SWITCH_TLV -SwitchType Private
                }
            #endregion

            #region Create Switch Server

            function fncCreateSwitchServer
            {
                #region Variables
     
                    $strVMName = $C_HYPERV_NAME_NAT
                    $strPath = "f:\Project1\$strVMName"
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
                         Connect-VMNetworkAdapter  -SwitchName $C_HYPERV_NAME_SWITCH_NY -VMName $strVMName
                         Add-VMNetworkAdapter  -SwitchName $C_HYPERV_NAME_SWITCH_TLV -VMName $strVMName


                         #endregion

                #region Setting Storage

                         # Create new main drive
                         New-VHD -ParentPath "f:\Project1\$C_HYPERV_NAME_BASE\Virtual Hard Disks\$C_HYPERV_NAME_BASE-DISK.vhdx" `
                                 -path $strHDPath `
                                 -Differencing

                         # Attach main path
                        Add-VMHardDiskDrive -VMName $strVMName `
                                         -Path $strHDPath `
                             
                             
                         #Set Hard Disk as boot path (by default it is in the 2th rank)
                         Set-VMFirmware -VMName $strVMName -FirstBootDevice $(Get-VMFirmware -VMName $strVMName).BootOrder[2]     

                #endregion
            }

            #endergion

            #region Init Domain
            function fncInitDomain
            {
            $sbScriptBlock = {
                             param($C_DOMAINNAME,
                                   $C_WINSNAME)

                             # Install Active Directory
                             # Install Features
                         
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

                    Invoke-Command -VMName $C_HYPERV_NAME_TLV_DC -Credential $C_CRED_LOCAL -ScriptBlock $sbScriptBlock -ArgumentList $C_DOMAINNAME,$C_WINSNAME
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

                    Invoke-Command -VMName $C_HYPERV_NAME_TLV_DC -Credential $C_CRED_DOMAIN -ScriptBlock $sbScriptBlock -ArgumentList $C_DOMAINNAME
                }

            #endregion

            #region Configure Password Policy

            function fncConfigGlobalPassPolicy
            {
                $sbGlobalPassPolicy ={
                    Set-ADDefaultDomainPasswordPolicy -Identity yellow.com `
                                                      -MinPasswordLength 8 `
                                                      -MaxPasswordAge 90d `
                                                      -ComplexityEnabled $true
                }

                Invoke-Command -VMName $C_HYPERV_NAME_TLV_DC -Credential $C_CRED_DOMAIN -ScriptBlock $sbGlobalPassPolicy
            }

            #endregion

       

        #endregion
        
            #region Configure the Switch server
                function fncInitSwitch
                {
                    $sbInitNAT = {
                    param($strName,
                           $strIp,
                           $strGateway)
                            # Set Static IP and Computer name
                           New-NetIPAddress -InterfaceAlias "Ethernet" `
                                            -IPAddress 192.168.3.1 `                                       
                                            -PrefixLength 24 

                            New-NetIPAddress -InterfaceAlias "Ethernet 2" `
                                            -IPAddress 192.168.1.1 `                                        
                                            -PrefixLength 24 

                            Set-DnsClientServerAddress -InterfaceAlias "Ethernet 2" `
                                                      -ServerAddresses 192.168.1.2

                            Rename-Computer -NewName $strName

                            Install-WindowsFeature -Name 'RemoteAccess' -IncludeAllSubFeature –IncludeManagementTools
                         
                            #Enable ICMP in firewall
                            netsh advfirewall firewall add rule name="ICMP Allow incoming V4 echo request" protocol="icmpv4:8,any" dir=in action=allow

                            #IPv6
                            netsh advfirewall firewall add rule name="ICMP Allow incoming V6 echo request" protocol="icmpv6:8,any" dir=in action=allow

                            Restart-Computer -Force           
                    }

                    Invoke-Command -VMName $C_HYPERV_NAME_NAT -Credential $C_CRED_LOCAL -ScriptBlock $sbInitNAT  -ArgumentList $C_HYPERV_NAME_NAT -AsJob
                

                }
            #endregion

        #endregion

        #region Configure Domain

            #region Create DC
        
             function fncNewDCVM
                    {
                         param([string]$strVMName,
                                [string]$strNetwork)

                         #region Variables
     
                            $strVMName = $strVMName
                            $strPath = "f:\Project1\$strVMName"
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
                         Connect-VMNetworkAdapter  -SwitchName $strNetwork -VMName $strVMName

                         #endregion

                         #region Setting Storage

                         # Create new main drive
                         New-VHD -ParentPath "f:\Project1\$C_HYPERV_NAME_BASE\Virtual Hard Disks\$C_HYPERV_NAME_BASE-DISK.vhdx" `
                                 -path $strHDPath `
                                 -Differencing

                         # Attach main path
                        Add-VMHardDiskDrive -VMName $strVMName `
                                         -Path $strHDPath `
                             
                             
                         #Set Hard Disk as boot path (by default it is in the 2th rank)
                         Set-VMFirmware -VMName $strVMName -FirstBootDevice $(Get-VMFirmware -VMName $strVMName).BootOrder[2]     

                         #endregion
                    }

                    Function fncCreateDC
                    {
                        fncNewDCVM -strVMName $C_HYPERV_NAME_TLV_DC -strNetwork $C_HYPERV_NAME_SWITCH_TLV
                        fncNewDCVM -strVMName $C_HYPERV_NAME_NY_DC -strNetwork $C_HYPERV_NAME_SWITCH_NY
                    
                    }        

              #endregion   

            #region Configure DC
                function fncInitDC
                {
                    $sbInitNAT = {
                    param($strName,
                           $strIp,
                           $strGateway)
                          # Set Static IP and Computer name
                           New-NetIPAddress -InterfaceAlias "Ethernet" `
                                            -IPAddress $strIp `
                                            -DefaultGateway $strGateway `
                                            -PrefixLength 24 

                           Set-DnsClientServerAddress -InterfaceAlias "Ethernet" `
                                                      -ServerAddresses 192.168.1.2
                           
                               


                            Rename-Computer -NewName $strName

                            Install-WindowsFeature -Name "AD-Domain-Services" -IncludeAllSubFeature –IncludeManagementTools
                            Install-WindowsFeature -Name "DHCP" -IncludeAllSubFeature –IncludeManagementTools
                        
                            #Enable ICMP in firewall
                            netsh advfirewall firewall add rule name="ICMP Allow incoming V4 echo request" protocol="icmpv4:8,any" dir=in action=allow

                            #IPv6
                            netsh advfirewall firewall add rule name="ICMP Allow incoming V6 echo request" protocol="icmpv6:8,any" dir=in action=allow

                            Restart-Computer -Force           
                    }

                    Invoke-Command -VMName $C_HYPERV_NAME_NY_DC -Credential $C_CRED_LOCAL -ScriptBlock $sbInitNAT  -ArgumentList $C_HYPERV_NAME_NY_DC, "192.168.3.2", "192.168.3.1" -AsJob
                    Invoke-Command -VMName $C_HYPERV_NAME_TLV_DC -Credential $C_CRED_LOCAL -ScriptBlock $sbInitNAT  -ArgumentList $C_HYPERV_NAME_TLV_DC, "192.168.1.2", "192.168.1.1" -AsJob

                }
            #endregion        

            #region Init Domain
            function fncInitDomain
            {
                $sbScriptBlock = {
                             param($C_DOMAINNAME,
                                   $C_WINSNAME)

                             # Install Active Directory
                             # Install Features
                         
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

                    Invoke-Command -VMName $C_HYPERV_NAME_TLV_DC -Credential $C_CRED_LOCAL -ScriptBlock $sbScriptBlock -ArgumentList $C_DOMAINNAME,$C_WINSNAME
            }
            #endregion

            #region Create Users


               function fncCreateUsers
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

                Invoke-Command -VMName $C_HYPERV_NAME_TLV_DC -Credential $C_CRED_DOMAIN -ScriptBlock $sbScriptBlock -ArgumentList $C_DOMAINNAME
                }


       


        #endregion

            #region Connect NY-DC to the domain
                function fncConnectNY
                {
                    $sbConnectNY={
                        param($C_HYPERV_NAME_TLV_DC,
                              $C_DOMAINNAME, 
                              $C_CRED_DOMAIN)
                        Install-ADDSDomainController -InstallDns `
                                                     -DomainName $C_DOMAINNAME `
                                                     -Credential $C_CRED_DOMAIN `
                                                     -NoGlobalCatalog:$false `
                                                     -CreateDnsDelegation:$false `
                                                     -CriticalReplicationOnly:$false `
                                                     -DatabasePath "C:\Windows\NTDS" `
                                                     -LogPath "C:\Windows\NTDS" `
                                                     -NoRebootOnCompletion:$false `
                                                     -ReplicationSourceDC $("$C_HYPERV_NAME_TLV_DC"+"."+"$C_DOMAINNAME") `
                                                     -SiteName "NY" `
                                                     -SysvolPath "C:\Windows\SYSVOL" `
                                                     -Force:$true `
                                                      -SafeModeAdministratorPassword $(ConvertTo-SecureString "Pa55w.rd" -AsPlainText -Force)



                    }
                    Invoke-Command -VMName $C_HYPERV_NAME_NY_DC -Credential $C_CRED_LOCAL -ScriptBlock $sbConnectNY -ArgumentList $C_HYPERV_NAME_TLV_DC, $C_DOMAINNAME, $C_CRED_DOMAIN

                }
            #endregion

            #region Set DHCP
                function fncSetDHCP
                {
                     $sbDHCPTLV= {
                            Add-DhcpServerV4Scope -Name "DHCP Scope" -StartRange 192.168.1.100 -EndRange 192.168.1.253 -SubnetMask 255.255.255.0
                            Set-DhcpServerV4OptionValue -DnsServer 192.168.1.2 -Router 192.168.1.2
                            Set-DhcpServerv4Scope -ScopeId 192.168.1.100 -LeaseDuration 1.00:00:00
                            Restart-service dhcpserver
                        }
                    $sbDHCPNY= {
                            Add-DhcpServerV4Scope -Name "DHCP Scope" -StartRange 192.168.3.100 -EndRange 192.168.3.253 -SubnetMask 255.255.255.0
                            Set-DhcpServerV4OptionValue -DnsServer 192.168.3.2 -Router 192.168.3.2
                            Set-DhcpServerv4Scope -ScopeId 192.168.1.100 -LeaseDuration 1.00:00:00
                            Restart-service dhcpserver
                        }


                        Invoke-Command -VMName $C_HYPERV_NAME_NY_DC -Credential $C_CRED_DOMAIN -ScriptBlock $sbDHCPNY
                        #Invoke-Command -VMName $C_HYPERV_NAME_TLV_DC -Credential $C_CRED_DOMAIN -ScriptBlock $sbDHCPTLV
    

                }
            #endregion

            #region Get locked Users
            function fncGetLockedUsers
            {
                Search-ADAccount –LockedOut | Select  distnguishedname, name 
                Search-ADAccount –LockedOut | Select  distnguishedname, name  |
                                Export-Csv -Path $("c:\lockedusers\locked"+ $(Get-Date -Format "dd/MM/yyyy-HH:mm") + ".csv")

            }
            #endregion

            #region Set Logon Hours
            function fncSetLogonHours
            {
                $sbSetLogonHours={
                
                    $hours =  get-aduser "templatemanulogon"
                    echo $hours
                    $arrUsers = Get-ADUser -SearchBase "OU=ManufacturingOU=spider,DC=spider,dc=com" -Filter *
                    foreach($usrUser in $arrUsers)
                    {
                        Set-ADUser -identity $usrUser.SamAccountName -Replace @{logonhours = $hours[0].logonhours}
                    }
                }
                Invoke-Command -VMName $C_HYPERV_NAME_TLV_DC -Credential $C_CRED_DOMAIN -ScriptBlock $sbSetLogonHours
            }
            #endregion
        #endregion

        #region Storage

            #region Setup ISCSI Target
                function fncSetISCSITarget
                {
                    $sbSetISCSITarget={
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
                
                       Install-WindowsFeature FS-iSCSITarget-Server -IncludeManagementTools -IncludeAllSubFeature


                 
                       #Starting iSCSI service
                       Set-Service -Name msiscsi `
                                    -StartupType Automatic
                       Start-Service msiscsi         

                        # Set the settings for a new iScsi target server
                        New-IscsiServerTarget -TargetName "iSCSISTR" `
                                              -InitiatorId @("IPAddress:10.0.1.3","IPAddress:10.0.1.4",,"IPAddress:10.0.3.3")
                 
                   
                        fncAddDrive "strStorage50G" 50GB
                    
                    }
                    Invoke-Command -VMName $C_HYPERV_NAME_NAT -Credential $C_CRED_LOCAL -ScriptBlock $sbSetISCSITarget
                }
            #endregion

            #region Create FS

             function fncNewFSVM
                    {
                         param([string]$strVMName,
                                [string]$strNetwork)

                         #region Variables
     
                            $strVMName = $strVMName
                            $strPath = "f:\Project1\$strVMName"
                            $strHDPath = "$strPath\Virtual Hard Disks\$strVMName-DISK.vhdx"

                         #endregion

                         #region VM Creation

                         # Creates the VM
                         New-VM -Name $strVMName `
                           -NoVHD `
                           -Generation 2 `
                           -MemoryStartupBytes 1024MB `
                           -BootDevice CD `
                           -Path $strPath`

                         #endregion
 
                         #region Setting Network  
 
                         # Add the internal network switch
                         Connect-VMNetworkAdapter  -SwitchName $strNetwork -VMName $strVMName

                         #endregion

                         #region Setting Storage

                         # Create new main drive
                         New-VHD -ParentPath "f:\Project1\$C_HYPERV_NAME_BASE\Virtual Hard Disks\$C_HYPERV_NAME_BASE-DISK.vhdx" `
                                 -path $strHDPath `
                                 -Differencing

                         # Attach main path
                        Add-VMHardDiskDrive -VMName $strVMName `
                                         -Path $strHDPath `
                             
                             
                         #Set Hard Disk as boot path (by default it is in the 2th rank)
                         Set-VMFirmware -VMName $strVMName -FirstBootDevice $(Get-VMFirmware -VMName $strVMName).BootOrder[2]     

                         #endregion
                    }

                    Function fncCreateFS
                    {
                        fncNewFSVM -strVMName $C_HYPERV_NAME_TLV_FS1 -strNetwork $C_HYPERV_NAME_SWITCH_TLV
                        fncNewFSVM -strVMName $C_HYPERV_NAME_TLV_FS2 -strNetwork $C_HYPERV_NAME_SWITCH_TLV
                        fncNewFSVM -strVMName $C_HYPERV_NAME_NY_FS1 -strNetwork $C_HYPERV_NAME_SWITCH_NY
                    
                    }        

              #endregion   

            #region Configure FS
                function fncInitFS
                {
                    $sbInitNAT = {
                    param($strName,
                           $strIp,
                           $strGateway,
                           $C_DOMAINNAME,
                           $C_CRED_DOMAIN_AFTER_CHANGE,
                           $C_CRED_LOCAL)

                       
                          # Set Static IP and Computer name
                           New-NetIPAddress -InterfaceAlias "Ethernet" `
                                            -IPAddress $strIp `
                                            -DefaultGateway $strGateway `
                                            -PrefixLength 24 

                           Set-DnsClientServerAddress -InterfaceAlias "Ethernet" `
                                                      -ServerAddresses 192.168.1.2
                           
                            Rename-Computer -NewName $strName

                           Add-Computer -DomainName $C_DOMAINNAME -Credential $C_CRED_DOMAIN_AFTER_CHANGE -LocalCredential $C_CRED_LOCAL 

                            Install-WindowsFeature FS-DFS-Replication  -IncludeAllSubFeature -IncludeManagementTools
                         
                            #Enable ICMP in firewall
                            netsh advfirewall firewall add rule name="ICMP Allow incoming V4 echo request" protocol="icmpv4:8,any" dir=in action=allow

                            #IPv6
                            netsh advfirewall firewall add rule name="ICMP Allow incoming V6 echo request" protocol="icmpv6:8,any" dir=in action=allow


                            Restart-Computer -Force           
                    }

                    Invoke-Command -VMName $C_HYPERV_NAME_NY_FS1  `
                                   -Credential $C_CRED_LOCAL  `
                                   -ScriptBlock $sbInitNAT   `
                                   -ArgumentList $C_HYPERV_NAME_NY_FS1, "192.168.3.3", "192.168.3.1", $C_DOMAINNAME, $C_CRED_DOMAIN_AFTER_CHANGE  `
                                   -AsJob

                    Invoke-Command -VMName $C_HYPERV_NAME_TLV_FS1 `
                                   -Credential $C_CRED_LOCAL `
                                   -ScriptBlock $sbInitNAT  `
                                   -ArgumentList $C_HYPERV_NAME_TLV_FS1, "192.168.1.3", "192.168.1.1", $C_DOMAINNAME, $C_CRED_DOMAIN_AFTER_CHANGE, $C_CRED_LOCAL `
                                   -AsJob
                               

                    Invoke-Command -VMName $C_HYPERV_NAME_TLV_FS2 `
                                   -Credential $C_CRED_LOCAL `
                                   -ScriptBlock $sbInitNAT  `
                                   -ArgumentList $C_HYPERV_NAME_TLV_FS2, "192.168.1.4", "192.168.1.1", $C_DOMAINNAME, $C_CRED_DOMAIN_AFTER_CHANGE, $C_CRED_LOCAL `
                                   -AsJob


                               

                
                }
            #endregion

            #region Join File Server to domain
             function fncJoinFStoDomain
                {
                    $sbInitNAT = {
                    param($C_DOMAINNAME,
                           $C_CRED_DOMAIN_AFTER_CHANGE,
                           $C_CRED_LOCAL)

                            Add-Computer -DomainName $C_DOMAINNAME -Credential $C_CRED_DOMAIN_AFTER_CHANGE -LocalCredential $C_CRED_LOCAL 
                            Restart-Computer -Force 
                           }
                
                
                    Invoke-Command -VMName $C_HYPERV_NAME_NY_FS1 `
                                   -Credential $C_CRED_LOCAL  `
                                   -ScriptBlock $sbInitNAT   `
                                   -ArgumentList $C_DOMAINNAME,  `
                                   $C_CRED_DOMAIN_AFTER_CHANGE,   `
                                   $C_CRED_LOCAL -AsJob

                    Invoke-Command -VMName $C_HYPERV_NAME_TLV_FS1 `
                                   -Credential $C_CRED_LOCAL `
                                   -ScriptBlock $sbInitNAT  `
                                   -ArgumentList $C_DOMAINNAME, $C_CRED_DOMAIN_AFTER_CHANGE, $C_CRED_LOCAL `
                               

                    Invoke-Command -VMName $C_HYPERV_NAME_TLV_FS2 `
                                   -Credential $C_CRED_LOCAL `
                                   -ScriptBlock $sbInitNAT  `
                                   -ArgumentList $C_DOMAINNAME, $C_CRED_DOMAIN_AFTER_CHANGE, $C_CRED_LOCAL `
                }
            #endregion
            
            #region Connect the File Servers to the iSCSI Target
                function fncConnectISCSIInitators
                {
            
                 # GEt all the tlv file servers
                 $arrVM = get-vm tlv-fs*

                 # iterate the initialization config
                 for ($nCountMachine = 0;$nCountMachine -lt 2; $nCountMachine++)
                 {
                    $vmFS = $arrVM[$nCountMachine]
        
                    $sbScriptBlock = {
                            param ($nCountMachine,
                                    $nISCSITargetPortal)

                    
                            # Autostart iscsiservice on start
                            Set-Service -Name msiscsi -StartupType Automatic
                            Start-Service msiscsi

                            Enable-NetFirewallRule  FPS-ICMP*

                            # Set Iscsi target portal
                            New-IscsiTargetPortal –TargetPortalAddress $nISCSITargetPortal
                            Get-IscsiTarget | Connect-IscsiTarget -IsPersistent $true

                            # Initialize disks, format them and bring them online 
                            if($nCountMachine -eq 0)
                            {                            
                                get-disk | Where-Object -FilterScript {$_.Size -eq 50GB} `
                                         | Initialize-Disk -PartitionStyle GPT -PassThru `
                                         | New-Partition -AssignDriveLetter -UseMaximumSize `
                                         | Format-Volume -FileSystem NTFS -Confirm:$false -Force `
                                         | Set-Disk -IsOffline $false
                            }
                        }

                    Invoke-Command -VMName $vmFS.name -Credential $C_CRED_DOMAIN_AFTER_CHANGE -ScriptBlock $sbScriptBlock -ArgumentList $nCountMachine, 192.168.1.1
                  }

                   $sbScriptBlockNY = {
                            param ($nISCSITargetPortal)
                    
                            # Autostart iscsiservice on start
                            Set-Service -Name msiscsi -StartupType Automatic
                            Start-Service msiscsi

                            # Set Iscsi target portal
                            New-IscsiTargetPortal –TargetPortalAddress $nISCSITargetPortal
                            Get-IscsiTarget | Connect-IscsiTarget -IsPersistent $true                     
                       
                        }
                    Invoke-Command -VMName $C_HYPERV_NAME_NY_FS1 -Credential $C_CRED_DOMAIN_AFTER_CHANGE -ScriptBlock $sbScriptBlockNY -ArgumentList 192.168.3.1 -AsJob
                }
            #endregion

            #region Configure Quota to users
            function fncConfigureQuota
            {
             
                    $sbSetISCSITarget={
                        #Install the Quota manager fearure
                        Install-WindowsFeature –Name FS-Resource-Manager –IncludeManagementTools -IncludeAllSubFeature
                    
                        #Create new template with 1GB limit
                        New-FsrmQuotaTemplate -Name "1GB limit" -Description "limit usage to 1 GB." -Size 1GB

                    
                        mkdir c:\HomeFolder

                        #Create Quota to the HomeFolder Share
                        $path =Get-Item "c:\Share\HomeFolder*"
                        New-FsrmQuota -Path $path -Template "1GB limit"              
                                       
                    }
                    Invoke-Command -VMName $C_HYPERV_NAME_NY_FS1 -Credential $C_CRED_DOMAIN_AFTER_CHANGE -ScriptBlock $sbSetISCSITarget -AsJob
                    Invoke-Command -VMName $C_HYPERV_NAME_TLV_FS1 -Credential $C_CRED_DOMAIN_AFTER_CHANGE -ScriptBlock $sbSetISCSITarget -AsJob
                    Invoke-Command -VMName $C_HYPERV_NAME_TLV_FS2 -Credential $C_CRED_DOMAIN_AFTER_CHANGE -ScriptBlock $sbSetISCSITarget -AsJob
            

            }
            #endregion

            #region Create Home folder to each user
                    function fncCreateHomeFolderToEachUser
                    {
                    
                        $sbScriptBlock = {            
                            Install-WindowsFeature RSAT-AD-PowerShell
                            $arrUsers = Get-ADUser -SearchBase "OU=Management,OU=spider,DC=spider,dc=com" -Filter *
                            foreach($user in $arrUsers)
                            {
                          
                                  Set-ADUser $USER -ProfilePath "\\spider.com\spider\test\homefolderusername%"
                            }                                    

                    }

                     Invoke-Command -VMName $C_HYPERV_NAME_TLV_FS1 -Credential $C_CRED_DOMAIN_AFTER_CHANGE -ScriptBlock $sbScriptBlock
                    }
            #endregion

            #region Set Login script to each user
                    function fncSetLogonScript
                    {
                    
                        $sbScriptBlock = {            
                            Install-WindowsFeature RSAT-AD-PowerShell
                            $arrUsers = Get-ADUser -SearchBase "OU=spider,DC=spider,dc=com" -Filter *
                            foreach($user in $arrUsers)
                            {
                          
                                  Set-ADUser $USER -ScriptPath "\\spider.com\spider\logonscript\logonscript.ps1"
                            }                                    

                    }

                     Invoke-Command -VMName $C_HYPERV_NAME_TLV_FS1 -Credential $C_CRED_DOMAIN_AFTER_CHANGE -ScriptBlock $sbScriptBlock
                    }
            #endregion

        #endregion

#endregion

    #region Triggers
        
        #region Differencing

            #fncCreateBase

        #endregion

        #region Switch
        
            #fncCreateHyperSwitch

            #fncCreateSwitchServer
        
            #fncInitSwitch

        #endregion

        #region Domain

            #fncCreateDC

            #fncInitDC
        
            #fncInitDomain

            #fncCreateUsers

            #fncConnectNY
        
            #fncSetDHCP

            #fncSetLogonHours

        #endregion

        #region Storage

            #fncSetISCSITarget

            #fncCreateFS

            #fncInitFS

            #fncJoinFStoDomain
            
            #fncConnectISCSIInitators

            #fncConfigureQuota

            #fncCreateHomeFolderToEachUser

            #fncSetLogonScript

        #endregion

    #endregion


