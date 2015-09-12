#Script to get users from Active Directory who have not checked in within 30 Days and email a person or distro group


Import-module Activedirectory

#Date Math 
$30day = (Get-Date).AddDays(-30)
 
#Get Disabled Users from OU
$Users = Get-ADUser -Filter {lastlogondate -le $30day} -Properties lastlogonTimestamp -SearchBase "OU=,OU=, DC=,DC=,DC= ,DC=" | Format-List Name, Enabled, @{N='lastlogonTimestamp'; E={[DateTime]::FromFileTime([Int64] $_.lastlogonTimestamp)}} | Out-String
 
#Email Information
$smtpServer = "internalSMTPRelay.dc.local.loc"
$from = "fromaddress@emailaddress.com"
$emailaddress = "emailto@emailaddress.com" 
$subject = "Users that have not Logged in 30 Days"
$body = "

Hello,

Here are a list of users who have not logged in 30 Days:

$users"

Send-MailMessage -SmtpServer $smtpServer -From $from -To $emailaddress -Subject "$subject" -Body $body -Priority High