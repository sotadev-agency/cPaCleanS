/*
  PHP Encoder/Obfuscator detection rules for cPaCleanS
  Covers: IonCube, Zend Guard, SourceGuardian, Obfuscator.io
  NOTE: These encoders are also used legitimately by commercial plugins.
        Severity is "high" to flag for review, not auto-quarantine.
*/

rule PHP_IonCube_Encoded {
    meta:
        description = "PHP file encoded with IonCube Loader (review for hidden malware)"
        severity = "high"
        category = "encoded_php"
    strings:
        $ic1 = "ionCube"                         nocase ascii
        $ic2 = "IonCube PHP Encoder"             nocase ascii
        $ic3 = "ioncube_read_file"               nocase ascii
        $ic4 = "the ionCube PHP Loader"          nocase ascii
        $ic5 = "This file is protected by ioncube" nocase ascii
    condition:
        any of ($ic*)
}

rule PHP_Zend_Guard_Encoded {
    meta:
        description = "PHP file encoded with Zend Guard (review for hidden malware)"
        severity = "high"
        category = "encoded_php"
    strings:
        $zg1 = "@Zend;"          ascii
        $zg2 = "Zend Guard"      nocase ascii
        $zg3 = "Zend Optimizer"  nocase ascii
        $zg4 = "zend_loader"     nocase ascii
    condition:
        any of ($zg*)
}

rule PHP_SourceGuardian_Encoded {
    meta:
        description = "PHP file encoded with SourceGuardian (review for hidden malware)"
        severity = "high"
        category = "encoded_php"
    strings:
        $sg1 = "SourceGuardian" nocase ascii
        $sg2 = "sg_load("       nocase ascii
        $sg3 = "sg_validate"    nocase ascii
    condition:
        any of ($sg*)
}

rule PHP_Obfuscator_IO {
    meta:
        description = "PHP file obfuscated with Obfuscator.io or similar tool"
        severity = "high"
        category = "encoded_php"
    strings:
        $ob1 = "Obfuscated by Obfuscator.io"   nocase ascii
        $ob2 = "eval(function(p,a,c,k,e,d)"    nocase ascii
        $ob3 = "eval(function(p,a,c,k,e,r)"    nocase ascii
    condition:
        any of ($ob*)
}

rule PHP_Generic_Massive_Obfuscation {
    meta:
        description = "PHP with heavy string obfuscation typical of encoded malware droppers"
        severity = "high"
        category = "obfuscation"
    strings:
        $chr_chain = /(\$[a-z_]{1,5}\s*=\s*chr\s*\(\d+\)\s*\.?\s*){8,}/ nocase
        $hex_str   = /\\x[0-9a-fA-F]{2}(\\x[0-9a-fA-F]{2}){15,}/
    condition:
        any of ($chr_chain, $hex_str)
}
