rule mal_syscall_hellshall: TESTING MALWARE OBFUSCATOR TA0002 T1106 {
    meta:
        id = "okKC4Zt2kjWBvbcVqTf6F"
        fingerprint = "3770e9ec6fe18a9709ce7bc0cd8f454a94261eeb283496d4eb1b6c0781e92d69"
        version = "1.0"
        creation_date = "2023-04-11"
        first_imported = "2023-04-11"
        last_modified = "2023-04-11"
        status = "TESTING"
        sharing = "TLP:WHITE"
        source = "THIEBAUT.DEV"
        author = "Maxime THIEBAUT (@0xThiebaut)"
        description = "Detects suspicious syscall extraction and indirect syscall used in HellsHall"
        category = "MALWARE"
        malware = "OBFUSCATOR"
        mitre_att = "T1106"
        reference = "https://github.com/Maldev-Academy/HellHall"
        hash = "b3dc5d08346a76c235ce29f0b4557abb0ef049c3cd7b676a615196a74dfbc5f9"

    strings:
        $convert = {
            80 ?? 4c    // cmp     byte ptr [??], 4Ch
            75 ??       // jnz     ??
            80 ?? 01 8b // cmp     byte ptr [??+1], 8Bh
            75 ??       // jnz     ??
            80 ?? 02 d1 // cmp     byte ptr [??+2], 0D1h
            75 ??       // jnz     ??
            80 ?? 03 b8 // cmp     byte ptr [??+3], 0B8h
            75 ??       // jnz     ??
            80 ?? 08 f6 // cmp     byte ptr [??+8], 0F6h
            75 ??       // jnz     ??
            80 ?? 09 04 // cmp     byte ptr [??+9], 4
            75 ??       // jnz     ??
            80 ?? 0a 25 // cmp     byte ptr [??+0Ah], 25h
            74          // jz      ??
        }
        $syscall = {
            49 89 ca    // mov     r10, rcx
            8b 44 24 ?? // mov     eax, [rsp+dwNumber]
            ff 64 24 ?? // jmp     [rsp+pSyscall]
        }
    condition:
        any of them
}
