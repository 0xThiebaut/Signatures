rule mal_poshc2_powershell_dropper : TESTING MALWARE PoshC2 PowerShell TA0002 T1059 T1059_001 S0378 TLP_CLEAR {
    meta:
        id = "6gqe4Hlhi4JUyF27Jwi3Lc"
        fingerprint = "f3d3210233d5e9c8f55422509e89147806e7e744f59ded82c89bfc90a6210868"
        version = "1.0"
        score = 90
        date = "2023-12-12"
        modified = "2023-12-20"
        status = "TESTING"
        sharing = "TLP:CLEAR"
        source = "THIEBAUT.DEV"
        author = "Maxime THIEBAUT (@0xThiebaut)"
        description = "Detects a PoshC2 PowerShell dropper in raw format"
        category = "TOOL"
        tool = "POSHC2"
        mitre_att = "T1059.001"
        mitre_att = "S0378"
        reference = "https://github.com/nettitude/PoshC2/blob/517903431ab43e6d714b24b0752ba111f5d4c2f1/resources/payload-templates/dropper.ps1"
        hash = "55f081dc700fc2018200ef93a6a0b03c4a677a0bd076cfe69e385f27041c133d"

    strings:
        $config_DomainFrontHeader       = "$df=@("
        $config_PayloadCommsHost        = "$urls=@("
        $config_ConnectURLImplantType   = "$curl=\""
        $config_KillDate                = "[datetime]::ParseExact(\""
        $config_Proxyuser               = "$username = \""
        $config_Proxypass               = "$password = \""
        $config_Proxyurl                = "$proxyurl = \""
        $config_ConnectURL              = "$script:s=\"https://$($h)"
        $config_UserAgent               = ".Headers.Add(\"User-Agent\",\""
        $config_Referrer                = ".Headers.Add(\"Referer\",\""
        $config_Key                     = "= dec -key "
        $config_PayloadDomainCheck      = "![Environment]::UserDomainName.Contains(\""
        $config_StageRetries            = /\$limit=[^\n]+\nif\(\$[^)]+\)\{\n\s+\$wait = [^\n]+\n/
        $config_Payload                 = "$env:computername;$env:PROCESSOR_ARCHITECTURE" nocase
        
        $logic_decode       = "[System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String([System.Text.Encoding]::UTF8.GetString"
        $logic_certificate  = "[System.Net.ServicePointManager]::ServerCertificateValidationCallback = {$true}"
        $logic_cookie       = ".Headers.Add([System.Net.HttpRequestHeader]::Cookie, \"SessionID="
        $logic_admin        = "[System.Security.Principal.WindowsBuiltInRole]::Administrator"
        $logic_current      = "[System.Security.Principal.WindowsIdentity]::GetCurrent()"
        $logic_now          = "(Get-Date -Format \"yyyy-MM-dd\")"
        $logic_arch         = "$env:PROCESSOR_ARCHITECTURE"
        $logic_computer     = "$($env:computername)$"
        $logic_domain       = "$env:userdomain"
        $logic_user         = "$env:username"
        $logic_exec         = "| iex"
        
    condition:
        7 of ($config_*) and 7 of ($logic_*)
}

rule mal_poshc2_powershell_dropper_encoded : TESTING MALWARE PoshC2 PowerShell TA0002 T1059 T1059_001 S0378 TLP_CLEAR {
    meta:
        id = "13uYcQW8xjt8f3JerpyQoq"
        fingerprint = "d5edaa9e00b1e1f73c90b46ffada0ac3ca07f9981da8873b9ee9cfbf0a51843d"
        version = "1.0"
        score = 90
        date = "2023-12-12"
        modified = "2023-12-12"
        status = "TESTING"
        sharing = "TLP:CLEAR"
        source = "THIEBAUT.DEV"
        author = "Maxime THIEBAUT (@0xThiebaut)"
        description = "Detects a PoshC2 PowerShell dropper in raw base64 format"
        category = "TOOL"
        tool = "POSHC2"
        mitre_att = "T1059.001"
        mitre_att = "S0378"
        reference = "https://github.com/nettitude/PoshC2/blob/517903431ab43e6d714b24b0752ba111f5d4c2f1/poshc2/server/payloads/Payloads.py#L192-L203"
        hash = "2a9b652584969a2f3be76556c39bd3cf4bd01082b014ef88db4083489371d149"

    strings:
        $config_DomainFrontHeader       = "$df=@("      base64 base64wide
        $config_PayloadCommsHost        = "$urls=@("    base64 base64wide
        $config_ConnectURLImplantType   = "$curl=\""    base64 base64wide
        $config_KillDate                = "[datetime]::ParseExact(\"" base64 base64wide
        $config_Proxyuser               = "$username = \""  base64 base64wide
        $config_Proxypass               = "$password = \""  base64 base64wide
        $config_Proxyurl                = "$proxyurl = \""  base64 base64wide
        $config_ConnectURL              = "$script:s=\"https://$($h)"       base64 base64wide
        $config_UserAgent               = ".Headers.Add(\"User-Agent\",\""  base64 base64wide
        $config_Referrer                = ".Headers.Add(\"Referer\",\""     base64 base64wide
        $config_Key                     = "= dec -key " base64 base64wide
        $config_PayloadDomainCheck      = "![Environment]::UserDomainName.Contains(\"" base64 base64wide
        
        $logic_decode       = "[System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String([System.Text.Encoding]::UTF8.GetString" base64 base64wide
        $logic_certificate  = "[System.Net.ServicePointManager]::ServerCertificateValidationCallback = {$true}" base64 base64wide
        $logic_cookie       = ".Headers.Add([System.Net.HttpRequestHeader]::Cookie, \"SessionID=" base64 base64wide
        $logic_admin        = "[System.Security.Principal.WindowsBuiltInRole]::Administrator" base64 base64wide
        $logic_current      = "[System.Security.Principal.WindowsIdentity]::GetCurrent()" base64 base64wide
        $logic_now          = "(Get-Date -Format \"yyyy-MM-dd\")" base64 base64wide
        $logic_arch         = "$env:PROCESSOR_ARCHITECTURE" base64 base64wide
        $logic_computer     = "$($env:computername)$" base64 base64wide
        $logic_domain       = "$env:userdomain" base64 base64wide
        $logic_user         = "$env:username"   base64 base64wide
        $logic_exec         = "| iex" base64 base64wide
        
    condition:
        7 of ($config_*) and 7 of ($logic_*)
}

rule sus_poshc2_powershell_dropper_compressed : TESTING MALWARE PoshC2 PowerShell TA0002 T1059 T1059_001 S0378 TLP_CLEAR {
    meta:
        id = "6CQ26vt9y1LVld89aKt86P"
        fingerprint = "0d893f84fa2fde67fa5a861713e4136bd0a0de60f10a74a38a0d0a0669bc38bc"
        version = "1.0"
        score = 80
        date = "2023-12-12"
        modified = "2023-12-12"
        status = "TESTING"
        sharing = "TLP:CLEAR"
        source = "THIEBAUT.DEV"
        author = "Maxime THIEBAUT (@0xThiebaut)"
        description = "Detects a potential PoshC2 PowerShell dropper in encoded bat format"
        category = "TOOL"
        tool = "POSHC2"
        mitre_att = "T1059.001"
        mitre_att = "S0378"
        reference = "https://github.com/nettitude/PoshC2/blob/517903431ab43e6d714b24b0752ba111f5d4c2f1/poshc2/server/payloads/Payloads.py#L150-L151"
        hash = "7e2c8e4ef2952cb98f920950b92637c80d8cfbe80c72a00e7879c6967b67f244"

    strings:
        $b64_logic_execute      = "IEX(New-Object IO.StreamReader((New-Object System.IO.Compression.GzipStream([IO.MemoryStream][Convert]::FromBase64String('" ascii wide base64
        $b64_logic_decompresse  = "[IO.Compression.CompressionMode]::Decompress)),[Text.Encoding]::ASCII)).ReadToEnd()" ascii wide base64
        
        $logic_execute      = "IEX(New-Object IO.StreamReader((New-Object System.IO.Compression.GzipStream([IO.MemoryStream][Convert]::FromBase64String('" ascii wide
        $logic_decompresse  = "[IO.Compression.CompressionMode]::Decompress)),[Text.Encoding]::ASCII)).ReadToEnd()" ascii wide
        
    condition:
        all of ($b64_logic_*) or all of ($logic_*)
}

rule sus_poshc2_powershell_downloader : TESTING MALWARE PoshC2 PowerShell TA0002 T1059 T1059_001 S0378 TLP_CLEAR {
    meta:
        id = "2z6jle24UXFDdZ2MHfew2S"
        fingerprint = "1077e9ec8221154f574db5caaad51d55279a97248a623fc0c957e70e32068cb8"
        version = "1.0"
        score = 80
        date = "2023-12-12"
        modified = "2023-12-12"
        status = "TESTING"
        sharing = "TLP:CLEAR"
        source = "THIEBAUT.DEV"
        author = "Maxime THIEBAUT (@0xThiebaut)"
        description = "Detects a potential PoshC2 PowerShell command"
        category = "TOOL"
        tool = "POSHC2"
        mitre_att = "T1059.001"
        mitre_att = "S0378"
        reference = "https://github.com/nettitude/PoshC2/blob/517903431ab43e6d714b24b0752ba111f5d4c2f1/poshc2/server/payloads/Payloads.py#L157-L160"
        hash = "41961f2013990222c163902ea2b32308917c9a83c1b98e79cec8c22a7b9f8d24"

    strings:
        $b64_logic_decode   = "[System.Net.ServicePointManager]::ServerCertificateValidationCallback = {$true};$MS=[System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String((new-object system.net.webclient).downloadstring('" ascii wide base64
        $b64_logic_execute  = "')));IEX $MS" ascii wide base64
        
        $logic_decode   = "[System.Net.ServicePointManager]::ServerCertificateValidationCallback = {$true};$MS=[System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String((new-object system.net.webclient).downloadstring('" ascii wide
        $logic_execute  = "')));IEX $MS" ascii wide
        
    condition:
        all of ($b64_logic_*) or all of ($logic_*)
}

rule mal_poshc2_csharp_dropper : TESTING MALWARE PoshC2 CSharp TA0002 T1106 S0378 TLP_CLEAR {
    meta:
        id = "1mLYuakNHWfHRtjgZq79fZ"
        fingerprint = "afc8525a70fd540070fa45dece00ee117a69aab7d64c728c840bf675667c916e"
        version = "1.0"
        score = 95
        date = "2023-12-12"
        modified = "2023-12-19"
        status = "TESTING"
        sharing = "TLP:CLEAR"
        source = "THIEBAUT.DEV"
        author = "Maxime THIEBAUT (@0xThiebaut)"
        description = "Detects a potential PoshC2 C# dropper"
        category = "TOOL"
        tool = "POSHC2"
        mitre_att = "T1106"
        mitre_att = "S0378"
        reference = "https://github.com/nettitude/PoshC2/blob/517903431ab43e6d714b24b0752ba111f5d4c2f1/resources/payload-templates/dropper.cs"
        hash = "b360900f0804c834e9add505ed52cf0a9552b5333ee2513f53b889f090e2dc86"

    strings:
        $config_DomainFrontHeader   = "dfarray"   
        $config_Reserved            = "dfhead"    
        $config_PayloadCommsHost    = "basearray"
        $config_UserAgent           = "User-Agent"  wide
        $config_Referrer            = "Referer"     wide
        
        $logic_type         = "Sharp"
        $logic_base_addr    = "DllBaseAddress"
        $logic_header       = "SessionID={0}" wide
        $logic_principal    = "WindowsPrincipal"
        $logic_role         = "WindowsBuiltInRole"
        $logic_certs        = "ServerCertificateValidationCallback"
        $logic_killdate     = "yyyy-MM-dd"               wide
        $logic_hostname     = "COMPUTERNAME"             wide
        $logic_architecture = "PROCESSOR_ARCHITECTURE"   wide
        $logic_windir       = "windir"                   wide
        $logic_payload      = "{0};{1};{2};{3};{4};"     wide
        $logic_implant      = "ImplantCore"
        $logic_time         = "Parse_Beacon_Time"
        $logic_url          = "{0}/{1}{2}/?{3}"             wide
        $logic_regex_image  = "(?<=\")[^\"]*(?=\")|[^\" ]+" wide
        $logic_random       = "...................@..........................Tyscf"    wide
        $logic_regex_time   = "(?<t>[0-9]{1,9})(?<u>[h,m,s]{0,1})"                     wide
        $logic_regex_beacon = "(?<=(beacon)\\s{1,})(?<t>[0-9]{1,9})(?<u>[h,m,s]{0,1})" wide
        
        $config_RandomURI       = "RANDOMURI19901(.*)10991IRUMODNAR"   wide
        $config_AllBeaconURLs   = "URLS10484390243(.*)34209348401SLRU" wide
        $config_KillDate        = "KILLDATE1665(.*)5661ETADLLIK"       wide
        $config_Sleep           = "SLEEP98001(.*)10089PEELS"           wide
        $config_Jitter          = "JITTER2025(.*)5202RETTIJ"           wide
        $config_Key             = "NEWKEY8839394(.*)4939388YEKWEN"     wide
        $config_AllBeaconImages = "IMGS19459394(.*)49395491SGMI"       wide
        
        $command_runexe = "run-exe"     wide
        $command_rundll = "run-dll"     wide
        $command_multi  = "multicmd"    wide
        $command_separator   = "!d-3dion@LD!-d"     wide
        $command_loadmodule  = "loadmodule"         wide
        $command_rundll_back = "run-dll-background" wide
        $command_runexe_back = "run-exe-background" wide
        $command_default     = "run-exe Core.Program Core {0}" wide
        
        $error_command  = "[-] Error running assembly, unrecognised command: " wide
        $error_assembly = "[-] Error running assembly: "    wide
        $error_running  = "[+] Running background task"     wide
        $error_time     = "[X] Invalid time \"{0}\""        wide

    condition:
        6 of ($config_*)
        or 8 of ($logic_*)
        or 4 of ($command_*)
        or 3 of ($error_*)
}

rule mal_poshc2_csharp_implant_pbind : TESTING MALWARE PoshC2 CSharp TA0002 T1570 S0378 TLP_CLEAR {
    meta:
        id = "6B1pAjnKeWtygZdCBmusiL"
        fingerprint = "f3927ca262cc441f70eb08783297a1dc1b06e5b873ea5fb8df76f0ba2dc5c4b1"
        version = "1.0"
        score = 95
        date = "2023-12-28"
        modified = "2023-12-28"
        status = "TESTING"
        sharing = "TLP:CLEAR"
        source = "THIEBAUT.DEV"
        author = "Maxime THIEBAUT (@0xThiebaut)"
        description = "Detects a potential PoshC2 C# implant communicating using named pipes"
        category = "TOOL"
        tool = "POSHC2"
        mitre_att = "T1570"
        mitre_att = "S0378"
        reference = "https://github.com/nettitude/PoshC2/blob/517903431ab43e6d714b24b0752ba111f5d4c2f1/resources/payload-templates/pbind.cs"
        hash = "1cc2408055a29aa0a64d803b91921aecf0bcde7f6ba8cff589fe285afb6aff29"

    strings:
        $logic_config_PBindPipeName   = "pipeName"
        $logic_config_PBindSecret     = "secret"
        $logic_config_Key             = "encryption"
        
        $logic_type     = "Sharp"
        $logic_main     = "PbindConnect"
        $logic_server   = "NamedPipeServerStream"
        $logic_decoy    = "Microsoft Error: 151337" wide
        $logic_principal    = "WindowsPrincipal"
        $logic_role         = "WindowsBuiltInRole"
        $logic_hostname     = "COMPUTERNAME"             wide
        $logic_architecture = "PROCESSOR_ARCHITECTURE"   wide
        $logic_windir       = "windir"                   wide
        $logic_payload      = "PBind-Connected: {0};{1};{2};{3};{4};"     wide
        
        $command_runexe      = "run-exe"    wide
        $command_rundll      = "run-dll"    wide
        $command_kill        = "KILL"       wide
        $command_command     = "COMMAND"    wide
        $command_loadmodule  = "loadmodule" wide
        $command_rundll_back = "run-dll-background" wide
        $command_runexe_back = "run-exe-background" wide
        $command_default     = "run-exe Core.Program Core {0}" wide
        $command_background  = "get-bg" wide
        
        $error_background   = "[+] Running task in background, run get-bg to get background output."    wide
        $error_concurrency  = "[*] Only run one task in the background at a time per implant."          wide
        $error_loading      = "Error loading modules {0}"   wide
        $error_success      = "Module loaded successfully"  wide
        $error_output       = "[-] No output"               wide
        $error_input        = "$[-] Cannot read from pipe"  wide
        $error_rasm         = "RAsm Exception: "            wide
     
    condition:
        10 of ($logic_*)
        or 4 of ($command_*)
        or 3 of ($error_*)
}

rule mal_poshc2_csharp_implant_fcomm : TESTING MALWARE PoshC2 CSharp TA0002 T1570 S0378 TLP_CLEAR {
    meta:
        id = "5NWaRGfawc5Iz5dcuwSjm3"
        fingerprint = "5dfc2bc96ebea3030af1dfec817578d48273d1407fb6c558e297606dd25c0a78"
        version = "1.0"
        score = 95
        date = "2023-12-28"
        modified = "2023-12-28"
        status = "TESTING"
        sharing = "TLP:CLEAR"
        source = "THIEBAUT.DEV"
        author = "Maxime THIEBAUT (@0xThiebaut)"
        description = "Detects a potential PoshC2 C# implant communicating using files"
        category = "TOOL"
        tool = "POSHC2"
        mitre_att = "T1570"
        mitre_att = "S0378"
        reference = "https://github.com/nettitude/PoshC2/blob/517903431ab43e6d714b24b0752ba111f5d4c2f1/resources/payload-templates/fcomm.cs"
        hash = "34d23737c23201d3563409a6fd85cbc3badf08a87acf9b279951f2cf59e6a5de"

    strings:
        $logic_config_FCommFileName   = "filename" 
        $logic_config_Key             = "encryption"
        
        $logic_type     = "Sharp"
        $logic_main     = "FCommConnect"
        $logic_principal    = "WindowsPrincipal"
        $logic_role         = "WindowsBuiltInRole"
        $logic_hostname     = "COMPUTERNAME"             wide
        $logic_architecture = "PROCESSOR_ARCHITECTURE"   wide
        $logic_windir       = "windir"                   wide
        $logic_payload      = "FComm-Connected: {0};{1};{2};{3};{4};"     wide
        $logic_init         = "INIT" wide
        $logic_task         = "TASK" wide
        
        $command_runexe      = "run-exe"    wide
        $command_rundll      = "run-dll"    wide
        $command_loadmodule  = "loadmodule" wide
        $command_kill        = "kill-implant"       wide
        $command_rundll_back = "run-dll-background" wide
        $command_runexe_back = "run-exe-background" wide
        $command_default     = "run-exe Core.Program Core {0}" wide
        $command_background  = "get-bg" wide
    
        $error_background       = "[!] Killed Implant."        wide
        $error_loading          = "Error loading modules {0}"  wide
        $error_success          = "Module loaded successfully" wide
        $error_rasm             = "RAsm Exception: "           wide
        $error_not_implemented  = "[!] This is not implemented yet in FComm implant types." wide
     
    condition:
        11 of ($logic_*)
        or 4 of ($command_*)
        or 3 of ($error_*)
}

rule sus_poshc2_cpp_clr_loader : TESTING MALWARE PoshC2 CSharp TA0002 T1106 S0378 TLP_CLEAR {
    meta:
        id = "6r4MOH3k6F4KxRygiZUqTi"
        fingerprint = "0844c38e9a59cee2a95d1d540c73eecf24cc13c8c78340aa782ce732d84de6c1"
        version = "1.0"
        score = 70
        date = "2023-12-20"
        modified = "2023-01-12"
        status = "TESTING"
        sharing = "TLP:CLEAR"
        source = "THIEBAUT.DEV"
        author = "Maxime THIEBAUT (@0xThiebaut)"
        description = "Detects a potential PoshC2 C++ loader for .NET (CLR)"
        category = "TOOL"
        tool = "POSHC2"
        mitre_att = "T1106"
        mitre_att = "S0378"
        reference = "https://github.com/nettitude/PoshC2/commits/517903431ab43e6d714b24b0752ba111f5d4c2f1/resources/payload-templates/Sharp_v4_x64_Shellcode.b64"
        hash = "9d4791e69b25f808857df130111c29276e52ece8df7810410a146b76d499be38"

    strings:
        $clr_library  = "mscoree.dll"       wide
        $clr_create   = "CLRCreateInstance" fullword
        $clr_exit     = "CorExitProcess"    fullword
        $clr_assembly = "TVqQAAMAAAAEAAAA"  ascii wide
        $version_2    = "v2.0.50727"        wide fullword
        $version_4    = "v4.0.30319"        wide fullword
        
        $tamper_amsi = "AmsiScanBuffer" fullword
        $tamper_etw  = "EtwEventWrite"  fullword
        
        $patch_x86_etw = {
            C7 45 ?? C2 14 00 00 // mov     [ebp+dwEtwPatch], 14C2h (ret    0x14)
        }
        
        $patch_x86_amsi = {
            C7 45 ?? B8 57 00 07 // mov     [ebp+dwAmsiPatch_1], 70057B8h (mov    eax,0x80070057)
            C7 45 ?? 80 C2 18 00 // mov     [ebp+dwAmsiPatch_2], 18C280h (ret    0x18)
        }
        
        $patch_x64_amsi = {
            C7 45 ?? B8 57 00 07 // mov     [rbp+57h+dwAmsiPatch_1], 70057B8h (mov    eax,0x80070057)
            66 C7 45 ?? 80 C3    // mov     [rbp+57h+dwAmsiPatch_2], 0C380h (ret)
        }
        

    condition:
        all of ($clr_*)
        and any of ($version_*)
        and all of ($tamper_*)
        and any of ($patch_*)
}

rule mal_poshc2_powershell_implant_pbind : TESTING MALWARE PoshC2 PowerShell TA0002 T1059 T1059_001 S0378 TLP_CLEAR {
    meta:
        id = "2b9L5k9lPNq5Piz2yfzVQW"
        fingerprint = "f792f37f83e0f7f2abce77059002f111141be07c42a89ffe02c50d6865104cd0"
        version = "1.0"
        score = 80
        date = "2023-12-28"
        modified = "2023-12-28"
        status = "TESTING"
        sharing = "TLP:CLEAR"
        source = "THIEBAUT.DEV"
        author = "Maxime THIEBAUT (@0xThiebaut)"
        description = "Detects a PoshC2 PowerShell PBind implant in raw format"
        category = "TOOL"
        tool = "POSHC2"
        mitre_att = "T1059.001"
        mitre_att = "S0378"
        reference = "https://github.com/nettitude/PoshC2/blob/517903431ab43e6d714b24b0752ba111f5d4c2f1/resources/payload-templates/pbind.ps1"
        hash = "919e6dd0c0d0035cdcf2117b7bb510d75366c06d8bb4a61ab79cb7bd8b11796b"

    strings:
        $config_PBindSecret   = "-secret "
        $config_Key           = "-key "
        $config_PBindPipeName = "-pname "
        
        $logic_invoke       = "invoke-pserv"
        $logic_decoy        = "Microsoft Error: 151337"
        $logic_op_command   = "COMMAND"
        $logic_op_killpipe  = "KILLPIPE"
        $logic_op_again     = "GOAGAIN"
        $logic_op_sure      = "SURE"
        $logic_op_exit      = "EXIT"
        $logic_flag_l       = "123456PS "
        $logic_flag_R       = ">654321"
        $logic_exec         = "Invoke-Expression "
        
        $error_crypto       = "This should never fire! - crypto failure"
        $error_output       = "No output from command"
        $error_upload       = "ErrorUpload: "
        $error_waiting      = "Waiting for client connection" 
        $error_connected    = "Connection established"
        
    condition:
        all of ($config_*) and (
            6 of ($logic_*)
            or all of ($error_*)
        )
}

rule mal_poshc2_powershell_implant_pbind_encoded : TESTING MALWARE PoshC2 PowerShell TA0002 T1059 T1059_001 S0378 TLP_CLEAR {
    meta:
        id = "1UwLrHSDILHyg8HpTWsWBU"
        fingerprint = "51412293b3f8844155e990d736df4e61cac9a24d5436e5cf923989ffe14dba69"
        version = "1.0"
        score = 80
        date = "2023-12-28"
        modified = "2023-12-28"
        status = "TESTING"
        sharing = "TLP:CLEAR"
        source = "THIEBAUT.DEV"
        author = "Maxime THIEBAUT (@0xThiebaut)"
        description = "Detects a PoshC2 PowerShell PBind implant in encoded format"
        category = "TOOL"
        tool = "POSHC2"
        mitre_att = "T1059.001"
        mitre_att = "S0378"
        reference = "https://github.com/nettitude/PoshC2/blob/517903431ab43e6d714b24b0752ba111f5d4c2f1/resources/payload-templates/pbind.ps1"
        hash = "7777d6dc337c7179e1ed6831d085436aee8d9bb390709a02c5d6c8459d39c540"

    strings:
        $config_PBindSecret   = "-secret "  base64 base64wide
        $config_Key           = "-key "     base64 base64wide
        $config_PBindPipeName = "-pname "   base64 base64wide
        
        $logic_invoke       = "invoke-pserv"            base64 base64wide
        $logic_decoy        = "Microsoft Error: 151337" base64 base64wide
        $logic_op_command   = "COMMAND"                 base64 base64wide
        $logic_op_killpipe  = "KILLPIPE"                base64 base64wide
        $logic_op_again     = "GOAGAIN"                 base64 base64wide
        $logic_op_sure      = "SURE"                    base64 base64wide
        $logic_op_exit      = "EXIT"                    base64 base64wide
        $logic_flag_l       = "123456PS "               base64 base64wide
        $logic_flag_R       = ">654321"                 base64 base64wide
        $logic_exec         = "Invoke-Expression "      base64 base64wide
        
        $error_crypto       = "This should never fire! - crypto failure" base64 base64wide
        $error_output       = "No output from command"                   base64 base64wide
        $error_upload       = "ErrorUpload: "                            base64 base64wide
        $error_waiting      = "Waiting for client connection"            base64 base64wide
        $error_connected    = "Connection established"                   base64 base64wide
        
    condition:
        all of ($config_*) and (
            6 of ($logic_*)
            or all of ($error_*)
        )
}
