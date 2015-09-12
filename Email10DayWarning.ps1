#This script emails users for 10 days until their password expires. It lets them know the date and time it expires.

Import-Module ActiveDirectory
#OU array for multiple OU search
$OU = @("OU=,OU=,OU=,OU=,OU=,DC=,DC=,DC=,DC=","OU=,OU=,OU=,OU=,OU=,DC=,DC=,DC=,DC=","OU=,OU=,OU=,OU=,OU=,DC=,DC=,DC=,DC=loc","OU=,OU=,OU=,OU=,OU=,DC=,DC=,DC=,DC=")
for ($i=0; $i -le 3; $i++) {
    
$users = get-aduser -SearchBase $OU[$i] -filter * -properties Name, PasswordNeverExpires, PasswordExpired, PasswordLastSet, EmailAddress |where {$_.Enabled -eq "True"} | where { $_.PasswordNeverExpires -eq $false } | where { $_.passwordexpired -eq $false }

#SMTP & Emaiil Information + some date math
$smtpServer = "internalSMTPRelay.domain.loc"
$from = "fromaddress@domain.com"


foreach ($user in $users)
{
	$Name = (Get-ADUser $user | foreach { $_.Name})
	$emailaddress = $user.emailaddress
	$passwordSetDate = (get-aduser $user -properties * | foreach { $_.PasswordLastSet })
	$expirydate = $passwordSetDate.adddays(60)
    $warningstartdate = $passwordSetDate.adddays(50)
    $today = get-date 
    $subjDate = $expirydate.ToString("D")
    $subjTime = $expirydate.ToString("t")
    $subject = "WARNING!!! Your Email Password will expire on $subjDate $subjTime"
    $body = "Dear $Name, 

WARNING!!!!!! Your Email Password is set to expire on $subjDate $subjTime.

If you do not change your email password by $subjDate $subjTime you will be locked out of your email. To change your email password please follow the directions in this link {link}
		   
Thank You,
mbIT"


    if ($today -ge $warningstartdate) 
   
    
    {Send-MailMessage -SmtpServer $smtpServer -From $from -To $emailaddress -Subject "$subject" -Body $body -Priority High
    
        }
    } #end foreach
} #end for i loop