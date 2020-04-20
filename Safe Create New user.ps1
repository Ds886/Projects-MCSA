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
                                   -ChangePasswordAtLogon $true `
                                   -ScriptPath "\\spider.com\spider\logonscript\logonscript.ps1" `
                                   -ProfilePath "\\spider.com\spider\test\homefolderusername%" 
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