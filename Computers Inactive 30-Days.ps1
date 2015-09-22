# Gets time stamps for all computers in the domain that have not logged in since after 30 days

import-module activedirectory 
$DaysInactive = 30 
$time = (Get-Date).Adddays(-($DaysInactive))
 
# Get all AD computers with lastLogonTimestamp less than our time
$dc = Get-ADComputer -Searchbase "OU=bacon,DC=your,DC=domain" -Filter {LastLogonTimeStamp -le $time} -Properties LastLogonTimeStamp | Format-List Name, @{N='lastlogonTimestamp'; E={[DateTime]::FromFileTime([Int64] $_.lastlogonTimestamp)}} | Out-String
 
#Email Information
$smtpServer = "internalSMTPRelay..your.company"
$from = "from@address.com"
$emailaddress = "emailaddress@email.com"
$subject = "Computers that have not signed into the domain in 30 Days or longer."

$body = "

Hello,

Below are computers that have not signed into the domain in 30 Days or longer

$dc"


Send-MailMessage -SmtpServer $smtpServer -From $from -To $emailaddress -Subject "$subject" -Body $body -Priority High
