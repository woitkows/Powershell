# Set title and backround
$host.ui.RawUI.WindowTitle = "mbIT Employee Modifications and Employee AD Information"
$Host.UI.RawUI.BackgroundColor = "Black"

#import active-drectory
Import-Module ActiveDirectory

Clear-Host

Write-Host "


"
#Create Menu of Items
[int]$Option = 0
while ( $Option -lt 1 -or $Option -gt 7 ){
Write-host "1. Termination" -ForegroundColor  Cyan
Write-host "2. New Hire" -ForegroundColor Yellow
Write-host "3. Password Reset" -ForegroundColor White
Write-host "4. Reactivate a User" -ForegroundColor Gray
Write-host "5. Unlock Users Account" -ForegroundColor Green
Write-host "6. Find All Locked Users" -ForegroundColor Red
Write-host "7. All Expired Passwords NYC MGB" -ForegroundColor White
[Int]$Option = read-host "Please enter an option 1 to 7..." } 
Switch( $Option ){
  
  1{

#get UserName
$termuser = read-host "Please enter the firstname.lastname of the user you would like to terminate"

#Exports Group Memberships to CSV
$target = "\\server\path\to\CSV\Termination Groups\" + $termuser + ".csv"
Get-ADPrincipalGroupMembership $termuser | Export-Csv -path $target
write-host "* Group Memberships archived to" $target

#Move to "Disabled Users" OU
Get-ADUser $termuser| Move-ADObject -TargetPath 'OU=,OU=,OU=,OU=,DC=,DC=,DC=,DC='
write-host "* " $termuser "moved to Disabled Users"

#Change Description to "Terminated YYYY.MM.DD - CURRENT USER"
$terminatedby = $env:username
$termDate = get-date -uformat "%m.%d.%Y"
$termUserDesc = "Terminated " + $termDate + " - " + $terminatedby
set-ADUser $termuser -Description $termUserDesc 
write-host "* " $termuser "description set to" $termUserDesc

#removes from all distribution groups
$dlists =(Get-ADUser $termuser -Properties memberof | select -expand memberof)
foreach($dlist in $dlists){Remove-ADGroupMember $termuser -Identity $dlist -Confirm:$False}
write-host "* Removed from all distribution and security groups"

#disable user
Disable-ADAccount -Identity $termuser

#Show User to Confirm Account is Disabled
Get-ADUser -Identity $termuser 

write-host "*** " $termuser "account has been disabled ***"
write-host "
#
#
#
"
Read-Host 'Press Enter to Continue....' | Out-Null}



  2{

#Create New Accounts

# Get New User variables
write-host "Please enter the new users first name." -ForegroundColor Cyan

$firstname = Read-Host

write-host "Please enter the new users last name." -ForegroundColor Cyan

$lastname = Read-Host

Write-host "Please enter the password for the new user" -ForegroundColor Cyan

$password = Read-Host -AsSecureString


#Create users Home directory folder

write-host "Creating Users Folder on Users server" -ForegroundColor Blue

New-Item -ItemType Directory -Path "\\homedrive\Users\$($firstname).$($lastname)"


$homedir = "\\homedrive\users\($($firstname).$($lastname)"


#Create New User

Write-Host "Creating New User"

New-ADUser -Name "$firstname $lastname" -AccountPassword $password -AllowReversiblePasswordEncryption $False  -ChangePasswordAtLogon $False -City "New York" -Company mcgarrybowen -Country US -DisplayName "$firstname $lastname" -EmailAddress "$($firstname).$($lastname)@mcgarrybowen.com" -HomeDirectory $homedir -HomeDrive U: -PasswordNeverExpires $False -PasswordNotRequired $False -Path "OU=NYC5,OU=McGarryBowen,OU=Employees,OU=Users,OU=US,DC=americas,DC=media,DC=global,DC=loc" -SamAccountName "$($firstname).$($lastname)" -UserPrincipalName "$($firstname).$($lastname)@mcgarrybowen.com" -GivenName $firstname -Surname $lastname -Enabled $true

#Import Groups

$Groups = Read-Host "What department is the user for group import? (Name of the CSV)"

$NCSV = Import-CSV "\\servershare\sharepath\to\csv\New Hire Groups\$($Groups).csv"

$ncsv | % {  
Add-ADGroupMember -Identity $_.distinguishedName -Member "$($firstname).$($lastname)"}

#Set Permission on Home Folder

Write-Host "Setting Permissions on Users Nonclient Folder" -ForegroundColor Yellow

$ACL = Get-Acl "\\homedrive\users\$($firstname).$($lastname)"

$Ar = New-Object system.Security.AccessControl.FileSystemAccessRule("$($firstname).$($lastname)", "FullControl", "ContainerInherit, ObjectInherit", "None", "Allow")

$ACL.SetAccessRule($Ar)

Set-Acl "\\homedrive\Users\$($firstname).$($lastname)" $Acl


#Set Description
$createdby = $env:username
$createDate = get-date -uformat "%m.%d.%Y"
$createUserDesc = "Created on " + $createDate + " - " + $createdby
set-ADUser "$($firstname).$($lastname)" -Description $createUserDesc


Get-ADUser -Identity "$($firstname).$($lastname)"

#Pause
Read-Host 'Press Enter to Continue....' | Out-Null

 }

     

  3{

#Ask for User Account
Write-host "Please enter the firstname.lastname of the user who require their password reset:" -foregroundcolor Cyan

# Get User Variable
$User = Read-Host 

Write-host "Please enter the password for the new user" -ForegroundColor Red

#Password Variable not in plain text
$password = Read-Host -AsSecureString

#Set Password
Set-ADAccountPassword -Identity $User -NewPassword $password

#Confirm Password Last Set
Get-ADUser -Identity $user -Properties passwordlastset | Select-Object Name, passwordlastset

Read-Host 'Press Enter to Continue....' | Out-Null}

  4{

#Get User Variable
Write-Host "Please Enter the firstname.lastname of the user you want to reactivate..."
$reuser = Read-Host

#Enable the disabled Account and Move it.
Enable-ADAccount -Identity $reuser 

#Move User Object to Employees OU
Get-aduser $reuser | Move-ADObject -TargetPath "OU=,OU=,OU=,OU=,OU=,DC=,DC=,DC=,DC="

#Reimport user accounts

$csv = Import-CSV "\\servershare\folder\to\csv\Termination Groups\$($reuser).csv"

$csv | % {  
Add-ADGroupMember -Identity $_.distinguishedName -Member $reuser 
}

#Change Description to "Reactivated MM.DD.YYYY - CURRENT USER"
$reactivatedby = $env:username
$reactDate = get-date -uformat "%m.%d.%Y"
$reactUserDesc = "Reactivated " + $reactDate + " - " + $reactivatedby
set-ADUser $reuser -Description $reactUserDesc 
write-host "* " $reuser "description set to" $reactUserDesc

Read-Host 'Press Enter to Continue....' | Out-Null
  }
  
  5{
  
 #Unlocking a  User Account

 #Prevent Errors from showing
$ErrorActionPreference = 'silentlycontinue'

Write-Host "Please type the firstname.lastname of the account that is locked out" -ForegroundColor Cyan
#User Variable
$lockUser = Read-host 


Get-ADUser -Identity $lockuser -Properties lockedout| select Name, lockedout

$Name = $lockuser
$User = Get-ADUser -LDAPFilter "(sAMAccountName=$Name)"

#Beginning If statement
If ($User -eq $Null) {``


write-host "User does not exist in AD" 

Read-Host 'Press Enter to Continue....' | Out-Null

powershell -noexit -file $MyInvocation.MyCommand.Path 1
    return



}

Else
{
write-host ""
}
#End of If Statement
$confirmunlock = Read-Host "Would you like to unlock this account? y/n" -confirm

if ($confirmunlock -eq 'y') 

{

Unlock-ADAccount -Identity $lockuser

write-host "You have chosen to unlock $lockuser account"

}
else
{
write-host " You have chosen not to unlock this account. If this is an error please start again " -ForegroundColor Blue
}

Write-Host "





"

Get-ADUser -Identity $lockuser -Properties lockedout | select Name, lockedout

write-host "


"

Read-Host 'Press Enter to Continue....' | Out-Null
  
  
  
  
  }
  6{
  #Find all Locked Out Users in mcgarrybowen NYC


#Variable for Locked Users
$alllock = Search-ADAccount -LockedOut -SearchBase "OU=,OU=,OU=,OU=,OU=,DC=,DC=,DC=,DC=" | Select Name, LockedOut

#start if statement
If ($alllock -eq $null)

{write-host "There are currently no locked out users."

}

else

{

$alllock

}

#end if statement

Read-Host 'Press Enter to Continue....' | Out-Null

  }
  7{
  #Get-ADUser -Filter PasswordExpired 

$expiredpass = Get-ADUser -Filter {enabled -eq $true} -Properties PasswordExpired -SearchBase "OU=,OU=,OU=,OU=,OU=,DC=,DC=,DC=,DC=" | Where-Object {$_.PasswordExpired -eq $True} | select Name, PasswordExpired | Sort-Object Name

#start if statement

If ($expiredpass -eq $null)

{write-host "There are currently no password expired accounts."

}

else

{

write-host ($expiredpass | Format-Table | Out-String)

}

#end if statement

Read-Host 'Press Enter to Continue....' | Out-Null
  
  }

 

  }

#default{<#run a default action or call a function here #>}


if (!$Work) {
    powershell -noexit -file $MyInvocation.MyCommand.Path 1
    return
}


