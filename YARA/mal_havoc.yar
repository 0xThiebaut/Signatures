rule mal_loader_havoc_x64: TESTING MALWARE LOADER TA0005 T1027 T1027_007 {
    meta:
        id = "4P6Z0kQNZdiDMvT7A21ygW"
        fingerprint = "e734c13b40a026fc382af496be7eeec1a6da1bbf40de28090c854a0500b736cd"
        version = "1.0"
        creation_date = "2023-04-11"
        first_imported = "2023-04-11"
        last_modified = "2023-04-11"
        status = "TESTING"
        sharing = "TLP:WHITE"
        source = "THIEBAUT.DEV"
        author = "Maxime THIEBAUT (@0xThiebaut)"
        description = "Detects Havoc C2's import hashing algorithm"
        category = "MALWARE"
        malware = "LOADER"
        mitre_att = "T1027.007"
        reference = "https://github.com/HavocFramework/Havoc/blob/1248ff9ecc964325447128ae3ea819f1ad10b790/Teamserver/data/implants/Shellcode/Source/Utils.c"
        hash = "d3ca24a6588c46c60646c9f6f19a916b8e108e20f74d0b721393d972a72b39fc"

    strings:
        $hashing = {
            b8 05 15 00 00  // mov     eax, ??
            ?? be 11        // movsx   ??, byte ptr [rcx]
            48 ff c1        // inc     rcx
            84 ??           // test    ??, ??
            74 ??           // jz      short ??
            6b c0 ??        // imul    eax, ??
            01 ??           // add     eax, ??
            eb ??           // jmp     short ??
            c3              // retn
        }
    condition:
        $hashing
}

rule mal_loader_custom_havoc_x64: TESTING MALWARE LOADER TA0005 T1027 T1027_007 {
    meta:
        id = "1EmdHiqQ6Y4163shVAW5yI"
        fingerprint = "46c414b56ccf97ef65b1f1603aa64705a8ffb39b5d9e270e00d21774e79b561a"
        version = "1.0"
        creation_date = "2023-04-11"
        first_imported = "2023-04-11"
        last_modified = "2023-04-11"
        status = "TESTING"
        sharing = "TLP:WHITE"
        source = "THIEBAUT.DEV"
        author = "Maxime THIEBAUT (@0xThiebaut)"
        description = "Detects a suspicious hashing algorithm similar (but not equal) to Havoc C2's import hashing with customized salt"
        category = "MALWARE"
        malware = "LOADER"
        mitre_att = "T1027.007"
        reference = "https://github.com/HavocFramework/Havoc/blob/1248ff9ecc964325447128ae3ea819f1ad10b790/Teamserver/data/implants/Shellcode/Source/Utils.c"
        hash = "b3dc5d08346a76c235ce29f0b4557abb0ef049c3cd7b676a615196a74dfbc5f9"

    strings:
        $hashing = {
            b8 ?? ?? ?? ??  // mov     eax, ??
            ?? be 11        // movsx   ??, byte ptr [rcx]
            48 ff c1        // inc     rcx
            84 ??           // test    ??, ??
            74 ??           // jz      short ??
            6b c0 ??        // imul    eax, ??
            01 ??           // add     eax, ??
            eb ??           // jmp     short ??
            c3              // retn
        }
    condition:
        $hashing and for any i in(1..#hashing): (
            uint32(@hashing[i]+1) != 0x1505 // Exclude Havoc C2 salt
        )
}
