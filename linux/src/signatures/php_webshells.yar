/*
  PHP Web Shell detection rules for cPaCleanS
  Covers: c99, r57, WSO, b374k, IndoXploit, Alfa, FilesMan and generic patterns
*/

rule PHP_Webshell_Known_Names {
    meta:
        description = "Known PHP web shell by name or internal string"
        severity = "critical"
        category = "webshell"
    strings:
        $n1  = "c99shell"         nocase ascii
        $n2  = "r57shell"         nocase ascii
        $n3  = "FilesMan"         nocase ascii
        $n4  = "b374k"            nocase ascii
        $n5  = "wso_version"      nocase ascii
        $n6  = "p0wny@shell"      nocase ascii
        $n7  = "alfa shell"       nocase ascii
        $n8  = "IndoXploit"       nocase ascii
        $n9  = "priv8 mailer"     nocase ascii
        $n10 = "locus7shell"      nocase ascii
        $n11 = "LockShell"        nocase ascii
        $n12 = "anarchy shell"    nocase ascii
        $n13 = "cgitelnet"        nocase ascii
        $n14 = "madshell"         nocase ascii
        $n15 = "darkc0de"         nocase ascii
        $n16 = "ayyildiz"         nocase ascii
        $n17 = "nshell"           nocase ascii
        $n18 = "remview"          nocase ascii
    condition:
        any of ($n*)
}

rule PHP_Webshell_Eval_Decode_Chain {
    meta:
        description = "Multi-layer decode chain used by PHP web shells"
        severity = "critical"
        category = "webshell"
    strings:
        $c1 = "eval(gzinflate(base64_decode("    nocase ascii
        $c2 = "eval(gzdecode(base64_decode("      nocase ascii
        $c3 = "eval(str_rot13(gzinflate("         nocase ascii
        $c4 = "eval(base64_decode(gzinflate("     nocase ascii
        $c5 = "eval(gzuncompress(base64_decode("  nocase ascii
        $c6 = "@eval(stripslashes("               nocase ascii
        $c7 = "eval(str_rot13(base64_decode("     nocase ascii
    condition:
        any of ($c*)
}

rule PHP_Webshell_FileManager {
    meta:
        description = "PHP-based web file manager shell"
        severity = "critical"
        category = "webshell"
    strings:
        $f1 = "file_get_contents" nocase ascii
        $f2 = "file_put_contents" nocase ascii
        $f3 = "chmod("            nocase ascii
        $f4 = "system("           nocase ascii
        $sh1 = "passthru("        nocase ascii
        $sh2 = "shell_exec("      nocase ascii
        $key = "$_POST["          nocase ascii
    condition:
        $key and (($f1 or $f2) and $f3) and ($f4 or $sh1 or $sh2)
}

rule PHP_Webshell_Base64_Payload {
    meta:
        description = "Encoded PHP payload with execute-on-load pattern"
        severity = "critical"
        category = "webshell"
    strings:
        $e1 = /\$[a-z]{1,4}\s*=\s*base64_decode\s*\(/ nocase
        $e2 = /eval\s*\(\s*\$[a-z]{1,4}/ nocase
        $e3 = /assert\s*\(\s*\$[a-z]{1,4}/ nocase
    condition:
        $e1 and ($e2 or $e3)
}
