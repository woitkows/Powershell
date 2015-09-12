#This script finds any users that have been enabled but sit in an OU for ACtive Employees


#Get Disabled Users from OU
$da = Get-ADUser -Filter {Enabled -eq $false} -SearchBase "OU=,OU=,OU=,OU=,DC=,DC=,DC=,DC=" | Format-List Name, Enabled | Out-String


#Email Information
$smtpServer = "internalSMTPRelay.domain.loc"
$from = "fromaddress@domain.com"
$emailaddress = "#toaddress@domain.loc"
$subject = "Disabled Users in Active Employees"
$body = "

Hello,

Below is a users that are in the active Employees OU and are disabled.

$da"

Send-MailMessage -SmtpServer $smtpServer -From $from -To $emailaddress -Subject "$subject" -Body $body -Priority High