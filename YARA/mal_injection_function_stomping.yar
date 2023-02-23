rule mal_injection_function_stomping: TESTING MALWARE LOADER TA0005 T1055 {
    meta:
        id = "6UdqYRxOBY0mQcVrIM50lI"
        fingerprint = "e8b5822216df6bd8255e0ba031646293d9beff7148a729b7893b5875559d0e96"
        version = "1.0"
        creation_date = "2022-01-25"
        status = "TESTING"
        sharing = "TLP:WHITE"
        source = "THIEBAUT.DEV"
        author = "Maxime THIEBAUT (@0xThiebaut)"
        description = "Detects suspicious strings related to the FunctionStomping PoC by Ido Veltzman"
        category = "MALWARE"
        malware = "LOADER"
        mitre_att = "T1055"
        reference = "https://github.com/Idov31/FunctionStomping/blob/9ed837b51616147c0b36235583c9d26d72e3d3cb/header/functionstomping.hpp"

    strings:
        $stomp_err      = "The function name is misspelled or the function is unstompable"  ascii wide fullword
        $stomp_ok       = "Successfuly stomped the function"                                ascii wide fullword
        $ok_func_base   = "Got function base"                                               ascii wide fullword
        $ok_perms       = "Changed protection to WCX instead of RWX"                        ascii wide fullword
        $err_stomp_size = "Cannot write more than 4096 bytes"                               ascii wide fullword
        $err_stomp      = "Failed to overwrite function"                                    ascii wide fullword

    condition:
        uint16(0) == 0x5a4d and (any of ($stomp_*) or 4 of them)
}
