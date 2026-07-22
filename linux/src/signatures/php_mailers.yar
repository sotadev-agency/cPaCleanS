/*
  PHP Mailer backdoor detection rules for cPaCleanS
  Covers: hardcoded SMTP credentials, mass mail loops, spam relay headers
*/

rule PHP_Mailer_SMTP_Credentials {
    meta:
        description = "PHPMailer/SwiftMailer with hardcoded SMTP credentials"
        severity = "critical"
        category = "mailer_backdoor"
    strings:
        $pm   = "PHPMailer"  nocase ascii
        $sw   = "SwiftMailer" nocase ascii
        $pass = "->Password" nocase ascii
        $user = "->Username" nocase ascii
        $smtp = "SMTPAuth"   nocase ascii
        $raw_pass = "smtp_pass" nocase ascii
        $raw_user = "smtp_user" nocase ascii
    condition:
        ($pm and $pass and ($user or $smtp)) or
        ($sw and $pass) or
        ($raw_pass and $raw_user)
}

rule PHP_Mailer_Mass_Loop {
    meta:
        description = "Mass email sending loop (mail() inside foreach/for)"
        severity = "critical"
        category = "mailer_backdoor"
    strings:
        $foreach = "foreach"        nocase ascii
        $for_kw  = "for("          nocase ascii
        $mail_fn = "mail("         nocase ascii
        $bcc     = "Bcc:"          ascii
        $rcpt    = "Rcpt:"         ascii
    condition:
        (($foreach or $for_kw) and $mail_fn) or $bcc or $rcpt
}

rule PHP_Mailer_Spam_Headers {
    meta:
        description = "Spam relay — hardcoded anti-spam header bypass"
        severity = "high"
        category = "mailer_backdoor"
    strings:
        $h1 = "X-Mailer:"     ascii
        $h2 = "X-Spam:"       ascii
        $h3 = "X-Priority:"   ascii
        $h4 = "Reply-To:"     ascii
        $h5 = "X-Originating-IP:" ascii
        $php = "<?php"        nocase ascii
    condition:
        $php and (2 of ($h*))
}

rule PHP_Mailer_Email_List_Embedded {
    meta:
        description = "Embedded email address list (mass mailing payload)"
        severity = "high"
        category = "mailer_backdoor"
    strings:
        $arr = /array\s*\(\s*['"][a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}['"]/  nocase
        $mail_fn = "mail(" nocase ascii
    condition:
        $arr and $mail_fn
}
