/*
  PHP Backdoor detection rules for cPaCleanS
  Covers: exec from user input, reverse shells, hex eval, LFI/RFI, process injection
*/

rule PHP_Backdoor_Exec_User_Input {
    meta:
        description = "Command execution using superglobal user input"
        severity = "critical"
        category = "backdoor"
    strings:
        $s1  = "system($_GET"      nocase ascii
        $s2  = "system($_POST"     nocase ascii
        $s3  = "system($_REQUEST"  nocase ascii
        $s4  = "exec($_GET"        nocase ascii
        $s5  = "exec($_POST"       nocase ascii
        $s6  = "exec($_REQUEST"    nocase ascii
        $s7  = "passthru($_GET"    nocase ascii
        $s8  = "passthru($_POST"   nocase ascii
        $s9  = "shell_exec($_GET"  nocase ascii
        $s10 = "shell_exec($_POST" nocase ascii
        $s11 = "popen($_GET"       nocase ascii
        $s12 = "popen($_POST"      nocase ascii
    condition:
        any of ($s*)
}

rule PHP_Backdoor_Reverse_Shell {
    meta:
        description = "PHP reverse shell connecting back to attacker"
        severity = "critical"
        category = "backdoor"
    strings:
        $sock1 = "fsockopen"             nocase ascii
        $sock2 = "stream_socket_client"  nocase ascii
        $proc  = "proc_open"             nocase ascii
        $sh1   = "/bin/sh"               ascii
        $sh2   = "/bin/bash"             ascii
        $sh3   = "cmd.exe"               nocase ascii
        $sh4   = "/bin/sh -i"            ascii
    condition:
        ($sock1 or $sock2 or $proc) and ($sh1 or $sh2 or $sh3 or $sh4)
}

rule PHP_Backdoor_Hex_Eval {
    meta:
        description = "hex2bin with large blob leading to code execution"
        severity = "critical"
        category = "backdoor"
    strings:
        $h1 = /hex2bin\s*\(\s*["'][0-9a-fA-F]{80,}/ nocase
        $h2 = /\\x[0-9a-fA-F]{2}(\\x[0-9a-fA-F]{2}){20,}/ ascii
    condition:
        any of ($h*)
}

rule PHP_Backdoor_LFI_RFI {
    meta:
        description = "Local/Remote File Inclusion via user-controlled path"
        severity = "critical"
        category = "backdoor"
    strings:
        $i1 = "include($_GET"         nocase ascii
        $i2 = "include($_POST"        nocase ascii
        $i3 = "include($_REQUEST"     nocase ascii
        $i4 = "include_once($_GET"    nocase ascii
        $i5 = "require($_GET"         nocase ascii
        $i6 = "require($_POST"        nocase ascii
        $i7 = "require_once($_GET"    nocase ascii
        $i8 = "require_once($_POST"   nocase ascii
    condition:
        any of ($i*)
}

rule PHP_Backdoor_PcntlExec {
    meta:
        description = "pcntl_exec for native process execution (rare, always suspicious)"
        severity = "critical"
        category = "backdoor"
    strings:
        $p = "pcntl_exec" nocase ascii
    condition:
        $p
}

rule PHP_Backdoor_Obfuscated_Callback {
    meta:
        description = "Obfuscated execution via reflection or callback abuse"
        severity = "high"
        category = "backdoor"
    strings:
        $r1 = "ReflectionFunction"             nocase ascii
        $r2 = "->invoke("                      nocase ascii
        $r3 = "register_shutdown_function"     nocase ascii
        $d  = /["'](system|exec|passthru|shell_exec|assert)["']/ nocase
    condition:
        ($r1 and $r2) or ($r3 and $d)
}
