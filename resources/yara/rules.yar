rule WebShell_Generic {
    meta:
        description = "Detects generic PHP/Python/Perl webshell patterns"
        severity = "CRITICAL"
        rule_id = "YARA-WEBSHELL-001"
    strings:
        $php_eval = "system($_POST"
        $php_eval2 = "eval($_POST"
        $c99 = "c99shell"
    condition:
        any of them
}

rule ReverseShell_Generic {
    meta:
        description = "Detects reverse shell script payloads"
        severity = "CRITICAL"
        rule_id = "YARA-REVSHELL-001"
    strings:
        $nc_e = "nc -e /bin/bash"
        $bash_tcp = "bash -i >& /dev/tcp"
    condition:
        any of them
}

rule CryptoMiner_Generic {
    meta:
        description = "Detects cryptocurrency miner binaries or scripts"
        severity = "HIGH"
        rule_id = "YARA-MINER-001"
    strings:
        $str1 = "stratum+tcp://"
        $xmrig = "xmrig"
    condition:
        any of them
}

rule ELFDropper_Generic {
    meta:
        description = "Detects ELF executable droppers or packed binaries"
        severity = "HIGH"
        rule_id = "YARA-DROPPER-001"
    strings:
        $elf = { 7F 45 4C 46 }
        $upx = "UPX!"
    condition:
        $elf at 0 and $upx
}

rule ObfuscatedScript_Generic {
    meta:
        description = "Detects heavily obfuscated bash or python execution"
        severity = "MEDIUM"
        rule_id = "YARA-OBFUSCATED-001"
    strings:
        $b64_python = "import base64; exec(base64.b64decode"
    condition:
        any of them
}

rule PersistenceScript_Generic {
    meta:
        description = "Detects suspicious persistence installation scripts"
        severity = "HIGH"
        rule_id = "YARA-PERSISTENCE-001"
    strings:
        $ld_preload = "/etc/ld.so.preload"
    condition:
        any of them
}
