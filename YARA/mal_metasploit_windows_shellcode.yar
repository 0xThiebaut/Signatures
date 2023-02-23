rule mal_metasploit_shellcode_windows_pingback_reverse_tcp: RELEASED MALWARE BACKDOOR TA0011 T1095 {
    meta:
        id = "5G85R2pF2ch4aUwWEzqu5t"
        fingerprint = "870b0365c881e045049deb6ce71af19204fb713536e6fcb7466e26ab37970e15"
        version = "1.0"
        creation_date = "2021-09-02"
        first_imported = "2023-02-23"
        last_modified = "2023-02-23"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "THIEBAUT.DEV"
        author = "Maxime THIEBAUT (@0xThiebaut)"
        description = "Detects Metasploit import-hashes from the windows/pingback_reverse_tcp payload"
        category = "MALWARE"
        malware = "BACKDOOR"
        mitre_att = "T1095"
        reference = "https://blog.nviso.eu/2021/09/02/anatomy-and-disruption-of-metasploit-shellcode/"
        hash = "6675cdf56a8dbde5b5d745145ad41c7a717000d7dd03ac4baa88c8647733d0ab"

    strings:
        $import_full    = "ws2_32"                  // 64-bit
        $import_part    = {33 32 [03] 77 73 32 5F}  // 32-bit
        $imphashes      = {
                            4c 77 26 07 // kernel32.dll::LoadLibraryA
                            [10-30]
                            29 80 6b 00 // ws2_32.dll::WSAStartup
                            [10-30]
                            02 00       // AF_INET
                            [10-30]
                            ea 0f df e0 // ws2_32.dll::WSASocketA
                            [05-25]
                            99 a5 74 61 // ws2_32.dll::connect
                            [45-65]
                            75 6e 4d 61 // ws2_32.dll::closesocket
                            [15-35]
                            f0 b5 a2 56 // kernel32.dll::ExitProcess
                          }
    condition:
        any of ($import_*) and $imphashes
}

rule mal_metasploit_shellcode_windows_powershell_tcp: RELEASED MALWARE BACKDOOR TA0011 T1095 {
    meta:
        id = "6an4dnzmZYlWYU4nyMMJoM"
        fingerprint = "fc43b130e92407e09022ba96e76ce9b34266af67bef678a12eda739b7895487a"
        version = "1.0"
        creation_date = "2021-09-02"
        first_imported = "2023-02-23"
        last_modified = "2023-02-23"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "THIEBAUT.DEV"
        author = "Maxime THIEBAUT (@0xThiebaut)"
        description = "Detects Metasploit import-hashes from the windows/powershell_bind_tcp and windows/powershell_reverse_tcp payloads"
        category = "MALWARE"
        malware = "BACKDOOR"
        mitre_att = "T1095"
        reference = "https://blog.nviso.eu/2021/09/02/anatomy-and-disruption-of-metasploit-shellcode/"
        hash = "e26603ef85151596b0faf5ab7dc82ae655d37ec8aef204b329553cf5bc5b730b"
        hash = "9e017c8a6e0078f06dfb898721f3ef7c49f797bc8e2073ff338407dbb5a92297"

    strings:
        $imphashes      = {
                            31 8b 6f 87 // kernel32.dll::WinExec
                            [01-20]
                            f0 b5 a2 56 // kernel32.dll::ExitProcess
                            [01-20]
                            a6 95 bd 9d // kernel32.dll::GetVersion
                            [10-30]
                            47 13 72 6f // ntdll.dll::RtlExitUserThread
                          }
    condition:
        all of them
}

rule mal_metasploit_shellcode_windows_shell_bind_tcp: RELEASED MALWARE BACKDOOR TA0011 T1095 {
    meta:
        id = "4uKthQU886pm3rYwVJD705"
        fingerprint = "335fd73453b337e1c1b818c6df849657bde8bb552bddbe170ae07cfc842eb559"
        version = "1.0"
        creation_date = "2021-09-02"
        first_imported = "2023-02-23"
        last_modified = "2023-02-23"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "THIEBAUT.DEV"
        author = "Maxime THIEBAUT (@0xThiebaut)"
        description = "Detects Metasploit import-hashes from the windows/shell_bind_tcp payload"
        category = "MALWARE"
        malware = "BACKDOOR"
        mitre_att = "T1095"
        reference = "https://blog.nviso.eu/2021/09/02/anatomy-and-disruption-of-metasploit-shellcode/"
        hash = "826232cee9ccd0ee22c82685d7841e09c4fd17e2101736f43d8c6f1621e2fcb3"

    strings:
        $import_full    = "ws2_32"                  // 64-bit
        $import_part    = {33 32 [03] 77 73 32 5F}  // 32-bit
        $imphashes      = {
                            4c 77 26 07 // kernel32.dll::LoadLibraryA
                            [10-30]
                            29 80 6b 00 // ws2_32.dll::WSAStartup
                            [10-30]
                            ea 0f df e0 // ws2_32.dll::WSASocketA
                            [02-20]
                            02 00       // AF_INET
                            [05-25]
                            c2 db 37 67 // ws2_32.dll::bind
                            [02-10]
                            b7 e9 38 ff // ws2_32.dll::listen
                            [02-10]
                            74 ec 3b e1 // ws2_32.dll::accept
                            [02-20]
                            75 6e 4d 61 // ws2_32.dll::closesocket
                            [35-55]
                            79 cc 3f 86 // kernel32.dll::CreateProcessA
                            [05-25]
                            08 87 1d 60 // kernel32.dll::WaitForSingleObject
                            [00-10]
                            f0 b5 a2 56 // kernel32.dll::ExitProcess
                            [00-10]
                            a6 95 bd 9d // kernel32.dll::GetVersion
                            [10-30]
                            47 13 72 6f // ntdll.dll::RtlExitUserThread
                          }
    condition:
        any of ($import_*) and $imphashes
}

rule mal_metasploit_shellcode_windows_shell_hidden_bind_tcp: RELEASED MALWARE BACKDOOR TA0011 T1095 {
    meta:
        id = "6HQ4oEHcqNUBbmJxwjBpVZ"
        fingerprint = "cf568dda6d7ec12ed2e9ed3f24865b92bb243cae359f3c7264c8819f4ae8a430"
        version = "1.0"
        creation_date = "2021-09-02"
        first_imported = "2023-02-23"
        last_modified = "2023-02-23"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "THIEBAUT.DEV"
        author = "Maxime THIEBAUT (@0xThiebaut)"
        author = "Maxime THIEBAUT (@0xThiebaut)"
        description = "Detects Metasploit import-hashes from the windows/shell_hidden_bind_tcp payload"
        category = "MALWARE"
        malware = "BACKDOOR"
        mitre_att = "T1095"
        reference = "https://blog.nviso.eu/2021/09/02/anatomy-and-disruption-of-metasploit-shellcode/"
        hash = "166a5d9715d238d7902dbc505df2b2769fa68db337a2de1405be430513f7a938"

    strings:
        $import_full    = "ws2_32"                  // 64-bit
        $import_part    = {33 32 [03] 77 73 32 5F}  // 32-bit
        $imphashes      = {
                            4c 77 26 07 // kernel32.dll::LoadLibraryA
                            [10-30]
                            29 80 6b 00 // ws2_32.dll::WSAStartup
                            [10-30]
                            ea 0f df e0 // ws2_32.dll::WSASocketA
                            [02-20]
                            02 00       // AF_INET
                            [05-25]
                            c2 db 37 67 // ws2_32.dll::bind
                            [05-25]
                            f1 a2 77 29 // ws2_32.dll::setsockopt
                            [02-15]
                            b7 e9 38 ff // ws2_32.dll::listen
                            [30-50]
                            94 ac be 33 // ws2_32.dll::WSAAccept
                            [05-25]
                            75 6e 4d 61 // ws2_32.dll::closesocket
                            [40-60]
                            79 cc 3f 86 // kernel32.dll::CreateProcessA
                            [05-25]
                            08 87 1d 60 // kernel32.dll::WaitForSingleObject
                            [02-15]
                            f0 b5 a2 56 // kernel32.dll::ExitProcess
                            [01-10]
                            a6 95 bd 9d // kernel32.dll::GetVersion
                            [10-30]
                            47 13 72 6f // ntdll.dll::RtlExitUserThread
                          }
    condition:
        any of ($import_*) and $imphashes
}
