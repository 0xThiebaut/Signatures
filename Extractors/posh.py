from argparse import ArgumentParser
from glob import iglob
from json import dumps
from os import path
from re import MULTILINE, search
from ssl import create_default_context, CERT_NONE
from sys import stderr, stdin
from typing import Any, Dict
from urllib.error import URLError
from urllib.parse import urlparse
from urllib.request import HTTPError, urlopen

from malduck import base64, gzip, Extractor, YaraStringMatch
from malduck.extractor import ExtractManager, ExtractorModules
from malduck.procmem import ProcessMemory
from malduck.yara import YaraMatch

from dnfile import ClrMetaData


def is_b64(char):
    char = chr(char)
    return (
        "a" <= char <= "z"
        or "A" <= char <= "Z"
        or "0" <= char <= "9"
        or char in ["+", "/", "="]
    )


@Extractor.yara(
    r"""
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
"""
)
class PoshC2PowerShellDropper(Extractor):
    family = "PoshC2 PowerShell Dropper"

    @Extractor.string
    def config_DomainFrontHeader(
        self, p: ProcessMemory, addr: int, match: YaraStringMatch
    ) -> Dict[str, Any]:
        addr += len(match.content)
        data = p.readv_until(addr, b")")
        if data:
            data = data.decode("utf8")
            return {"DomainFrontHeader": data[1:-1]}

    @Extractor.string
    def config_PayloadCommsHost(
        self, p: ProcessMemory, addr: int, match: YaraStringMatch
    ) -> Dict[str, Any]:
        addr += len(match.content)
        data = p.readv_until(addr, b")")
        if data:
            data = data.decode("utf8")
            return {"PayloadCommsHost": data[1:-1]}

    @Extractor.string
    def config_ConnectURLImplantType(
        self, p: ProcessMemory, addr: int, match: YaraStringMatch
    ) -> Dict[str, Any]:
        addr += len(match.content)
        data = p.readv_until(addr, b'"')
        if data:
            self.ConnectURLImplantType = data.decode("utf8")

    @Extractor.string
    def config_KillDate(
        self, p: ProcessMemory, addr: int, match: YaraStringMatch
    ) -> Dict[str, Any]:
        addr += len(match.content)
        data = p.readv_until(addr, b'"')
        if data:
            return {"KillDate": data.decode("utf8")}

    @Extractor.string
    def config_Proxyuser(
        self, p: ProcessMemory, addr: int, match: YaraStringMatch
    ) -> Dict[str, Any]:
        addr += len(match.content)
        data = p.readv_until(addr, b'"')
        if data:
            return {"Proxyuser": data.decode("utf8")}

    @Extractor.string
    def config_Proxypass(
        self, p: ProcessMemory, addr: int, match: YaraStringMatch
    ) -> Dict[str, Any]:
        addr += len(match.content)
        data = p.readv_until(addr, b'"')
        if data:
            return {"Proxypass": data.decode("utf8")}

    @Extractor.string
    def config_Proxyurl(
        self, p: ProcessMemory, addr: int, match: YaraStringMatch
    ) -> Dict[str, Any]:
        addr += len(match.content)
        data = p.readv_until(addr, b'"')
        if data:
            return {"Proxyurl": data.decode("utf8")}

    @Extractor.string
    def config_ConnectURL(
        self, p: ProcessMemory, addr: int, match: YaraStringMatch
    ) -> Dict[str, Any]:
        addr += len(match.content)
        data = p.readv_until(addr, b'"')
        if data:
            self.ConnectURL = data.decode("utf8")
            return {"ConnectURL": data.decode("utf8")}

    @Extractor.string
    def config_UserAgent(
        self, p: ProcessMemory, addr: int, match: YaraStringMatch
    ) -> Dict[str, Any]:
        addr += len(match.content)
        data = p.readv_until(addr, b'"')
        if data:
            return {"UserAgent": data.decode("utf8")}

    @Extractor.string
    def config_Referer(
        self, p: ProcessMemory, addr: int, match: YaraStringMatch
    ) -> Dict[str, Any]:
        addr += len(match.content)
        data = p.readv_until(addr, b'"')
        if data:
            return {"Referer": data.decode("utf8")}

    @Extractor.string
    def config_Key(
        self, p: ProcessMemory, addr: int, match: YaraStringMatch
    ) -> Dict[str, Any]:
        addr += len(match.content)
        data = p.readv_until(addr, b" ")
        if data:
            return {"Key": data.decode("utf8")}

    @Extractor.string
    def config_PayloadDomainCheck(
        self, p: ProcessMemory, addr: int, match: YaraStringMatch
    ) -> Dict[str, Any]:
        addr += len(match.content)
        data = p.readv_until(addr, b'"')
        if data:
            return {"PayloadDomainCheck": data.decode("utf8")}

    @Extractor.string
    def config_StageRetries(
        self, p: ProcessMemory, addr: int, match: YaraStringMatch
    ) -> Dict[str, Any]:
        groups = search(
            r"\$limit=(?P<limit>[^\n]+)\nif\(\$(?P<retries>[^)]+)\)\{\n\s+\$wait = (?P<wait>[^\n]+)\n",
            match.content.decode("utf8"),
            MULTILINE,
        )
        if groups:
            limit = groups.group("limit")
            retries = groups.group("retries")
            wait = groups.group("wait")
            return {
                "StageRetriesLimit": int(limit) if limit.isdecimal() else limit,
                "StageRetries": bool(retries)
                if retries in ["true", "false"]
                else retries,
                "StageRetriesInitialWait": int(wait) if wait.isdecimal() else wait,
            }

    @Extractor.string
    def config_Payload(
        self, p: ProcessMemory, addr: int, match: YaraStringMatch
    ) -> Dict[str, Any]:
        payload = p.readv_until(addr + len(match.content), b'"')
        payload = payload.decode("utf8")
        url = payload.split(";")[-1]
        return {"URLID": int(url) if url.isdecimal() else url}

    @Extractor.rule
    def mal_poshc2_powershell_dropper(
        self, p: ProcessMemory, matches: YaraMatch
    ) -> Dict[str, Any]:
        if (
            self.ConnectURL
            and self.ConnectURLImplantType
            and self.ConnectURLImplantType.index(self.ConnectURL) == 0
        ):
            return {"ImplantType": self.ConnectURLImplantType[len(self.ConnectURL) :]}


@Extractor.yara(
    r"""
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
"""
)
class PoshC2PowerShellDropperEncoded(Extractor):
    family = "PoshC2 PowerShell Dropper (Encoded)"

    @Extractor.string
    def config_PayloadCommsHost(
        self, p: ProcessMemory, addr: int, match: YaraStringMatch
    ) -> Dict[str, Any]:
        length = len(match.content)
        wide = match.content[-1] == 0x00
        width = 2 if wide else 1

        while (
            (b := p.readv(addr - width, width))
            and is_b64(b[0])
            and not (wide and (len(b) != 2 or b[1] != 0x00))
        ):
            addr -= len(b)
            length += len(b)

        while (
            (b := p.readv(addr + length, width))
            and is_b64(b[0])
            and not (wide and (len(b) != 2 or b[1] != 0x00))
        ):
            length += len(b)

        content = p.readv(addr, length)
        encoded = content.decode("utf-16le" if wide else "utf8")
        decoded = base64.decode(encoded)
        self.push_procmem(ProcessMemory(decoded))


@Extractor.yara(
    r"""
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
"""
)
class PoshC2PowerShellDropperCompressed(Extractor):
    family = "PoshC2 PowerShell Dropper (Compressed)"

    @Extractor.string
    def b64_logic_execute(
        self, p: ProcessMemory, addr: int, match: YaraStringMatch
    ) -> Dict[str, Any]:
        encoded = bytearray(match.content)

        while (b := p.readv(addr + len(encoded), 1)) and is_b64(b[0]):
            encoded.extend(b)

        decoded = base64.decode(encoded)
        self.push_procmem(ProcessMemory(decoded))

    @Extractor.string
    def logic_execute(
        self, p: ProcessMemory, addr: int, match: YaraStringMatch
    ) -> Dict[str, Any]:
        encoded = bytearray([])
        addr += len(match.content)
        wide = match.content[-1] == 0x00

        while (
            (b := p.readv(addr + len(encoded), 2 if wide else 1))
            and is_b64(b[0])
            and not (wide and (len(b) != 2 or b[1] != 0x00))
        ):
            encoded.extend(b)

        encoded = encoded.decode("utf-16le" if wide else "utf8")
        decoded = base64.decode(encoded)
        decompressed = gzip.decompress(decoded)
        self.push_procmem(ProcessMemory(decompressed))


@Extractor.yara(
    r"""
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
"""
)
class PoshC2PowerShellCommand(Extractor):
    family = "PoshC2 PowerShell Downloader"

    @Extractor.string
    def b64_logic_decode(
        self, p: ProcessMemory, addr: int, match: YaraStringMatch
    ) -> Dict[str, Any]:
        encoded = bytearray(match.content)

        while (b := p.readv(addr + len(encoded), 1)) and is_b64(b[0]):
            encoded.extend(b)

        decoded = base64.decode(encoded)
        self.push_procmem(ProcessMemory(decoded))

    @Extractor.string
    def logic_decode(
        self, p: ProcessMemory, addr: int, match: YaraStringMatch
    ) -> Dict[str, Any]:
        addr += len(match.content)
        wide = match.content[-1] == 0x00
        separator = match.content[-2 if wide else -1 :]

        content = p.readv_until(addr, separator)
        if content:
            content = content.decode("utf-16le" if wide else "utf8")

            netloc = urlparse(content).netloc
            delim = content.index(netloc) + len(netloc)

            FirstURL = content[:delim]
            ImplantType = content[-3:]
            if ImplantType != "_rp":
                raise ValueError
            QuickCommand = content[delim + 1 : -3]

            return {
                "FirstURL": FirstURL,
                "QuickCommand": QuickCommand,
                "ImplantType": ImplantType,
            }


@Extractor.yara(
    r"""
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
"""
)
class PoshC2PowerShellPBind(Extractor):
    family = "PoshC2 PowerShell PBind"

    @Extractor.string
    def config_PBindSecret(
        self, p: ProcessMemory, addr: int, match: YaraStringMatch
    ) -> Dict[str, Any]:
        addr += len(match.content)
        data = p.readv_until(addr, b" ")
        if data:
            return {"PBindSecret": data.decode("utf8")}

    @Extractor.string
    def config_PBindPipeName(
        self, p: ProcessMemory, addr: int, match: YaraStringMatch
    ) -> Dict[str, Any]:
        addr += len(match.content)
        data = p.readv_until(addr, b"\n")
        if data:
            return {"PBindPipeName": data.decode("utf8")}

    @Extractor.string
    def config_Key(
        self, p: ProcessMemory, addr: int, match: YaraStringMatch
    ) -> Dict[str, Any]:
        addr += len(match.content)
        data = p.readv_until(addr, b" ")
        if data and data != b"$key":
            return {"Key": data.decode("utf8")}


@Extractor.yara(
    r"""
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
"""
)
class PoshC2PowerShellPBindEncoded(Extractor):
    family = "PoshC2 PowerShell PBind (Encoded)"

    @Extractor.string
    def config_PBindPipeName(
        self, p: ProcessMemory, addr: int, match: YaraStringMatch
    ) -> Dict[str, Any]:
        length = len(match.content)
        wide = match.content[-1] == 0x00
        width = 2 if wide else 1

        while (
            (b := p.readv(addr - width, width))
            and is_b64(b[0])
            and not (wide and (len(b) != 2 or b[1] != 0x00))
        ):
            addr -= len(b)
            length += len(b)

        while (
            (b := p.readv(addr + length, width))
            and is_b64(b[0])
            and not (wide and (len(b) != 2 or b[1] != 0x00))
        ):
            length += len(b)

        content = p.readv(addr, length)
        encoded = content.decode("utf-16le" if wide else "utf8")
        decoded = base64.decode(encoded)
        self.push_procmem(ProcessMemory(decoded))


@Extractor.yara(
    r"""
// Modified for .NET identification
rule mal_poshc2_csharp_dropper : TESTING MALWARE PoshC2 CSharp TA0002 T1106 S0378 TLP_CLEAR {
    meta:
        id = "1mLYuakNHWfHRtjgZq79fZ"
        fingerprint = "CUSTOMIZED"
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
        
        $clr_base     = {
            42 53 4A 42     // Magic
            01 00           // Major
            01 00           // Minor
            00 00 00 00     // Reserved
            0C 00 00 00     // Version length
            76 ?? 2E 30 2E  // Version
            }
                
        $clr_UserDomainCheck = {                
            72 ?? ?? ?? 70 // ldstr    aReplacemedomai // "#REPLACEMEDOMAIN#"
            28 ?? ?? ?? 0A // call     bool [mscorlib]System.String::IsNullOrEmpty(string)
            3A ?? ?? ?? ?? // brtrue   loc_A9
            28 ?? ?? ?? 0A // call     string [mscorlib]System.Environment::get_UserDomainName()
        }
                
        $clr_KillDate = {
            72 ?? ?? ?? 70 // ldstr    aReplacekilldat // "#REPLACEKILLDATE#"
            72 ?? ?? ?? 70 // ldstr    aYyyyMmDd      // "yyyy-MM-dd"
            28 ?? ?? ?? 0A // call     class [mscorlib]System.Globalization.CultureInfo [mscorlib]System.Globalization.CultureInfo::get_InvariantCulture()
            28 ?? ?? ?? 0A // call     valuetype [mscorlib]System.DateTime [mscorlib]System.DateTime::ParseExact(string, string, class [mscorlib]System.IFormatProvider)
            28 ?? ?? ?? 0A // call     valuetype [mscorlib]System.DateTime [mscorlib]System.DateTime::get_Now()
            28 ?? ?? ?? 0A // call     bool [mscorlib]System.DateTime::op_GreaterThan(valuetype [mscorlib]System.DateTime, valuetype [mscorlib]System.DateTime)
            39 ?? ?? ?? ?? // brfalse  loc_811
        }
                
        $clr_Headers = {
            ??             // ldloc.1
            6F ?? ?? ?? 0A // callvirt instance class [System]System.Net.WebHeaderCollection [System]System.Net.WebClient::get_Headers()
            72 ?? ?? ?? 70 // ldstr    aUserAgent     // "User-Agent" or "Referer"
            72 ?? ?? ?? 70 // ldstr    aReplaceuserage // "#REPLACEUSERAGENT#" or "#REPLACEREFERER#"
            6F ?? ?? ?? 0A // callvirt instance void [System]System.Collections.Specialized.NameValueCollection::Add(string, string)
        }
                
        $clr_Proxies = {
            73 ?? ?? ?? 0A // newobj   instance void [System]System.Net.WebClient::.ctor()
            ??             // stloc.1
            72 ?? ?? ?? 70 // ldstr    aReplaceproxyur // "#REPLACEPROXYURL#"
            ??             // stloc.2
            72 ?? ?? ?? 70 // ldstr    aReplaceproxyus // "#REPLACEPROXYUSER#"
            ??             // stloc.3
            72 ?? ?? ?? 70 // ldstr    aReplaceproxypa // "#REPLACEPROXYPASSWORD#"
        }
                
        $clr_Retries_long = {
            28 ?? ?? ?? 06 // call     void Program::AUnTrCrts()
            20 ?? ?? ?? 4C // ldc.i4   #REPLACESTAGERRETRIESLIMIT#
            ??             // stloc.1
            20 ?? ?? ?? ?? // ldc.i4   #REPLACESTAGERRETRIESWAIT# * 1000
            ??             // stloc.2
            16             // ldc.i4.0
            73 ?? ?? ?? 0A // newobj   instance void [mscorlib]System.Threading.ManualResetEvent::.ctor(bool)
        }
                
        $clr_Retries_short = {
            28 ?? ?? ?? 06 // call     void Program::AUnTrCrts()
            1F ??          // ldc.i4.s   #REPLACESTAGERRETRIESLIMIT#
            ??             // stloc.1
            20 ?? ?? ?? ?? // ldc.i4   #REPLACESTAGERRETRIESWAIT# * 1000
            ??             // stloc.2
            16             // ldc.i4.0
            73 ?? ?? ?? 0A // newobj   instance void [mscorlib]System.Threading.ManualResetEvent::.ctor(bool)
        }
                
        $clr_Arrays = {
            8D ?? ?? ?? ?? // newarr   [mscorlib]System.String
            25             // dup
            16             // ldc.i4.0
            72 ?? ?? ?? 70 // ldstr    aReplacedf     // "#REPLACEDF#" or "#REPLACEBASEURL#"
            A2             // stelem.ref
            80 ?? ?? ?? 04 // stsfld   string[] Program::dfarray // or Program::basearray 
        }
                
        $clr_Comms = {
            28 ?? ?? ?? 0A // call     string [mscorlib]System.String::Format(string, object[])
            13 ??          // stloc.s  0xB
            72 ?? ?? ?? 70 // ldstr    aReplacekey    // "#REPLACEKEY#"
            13 ??          // stloc.s  0xC
            11 ??          // ldloc.s  8
            13 ??          // stloc.s  7
            11 ??          // ldloc.s  7
            72 ?? ?? ?? 70 // ldstr    aReplacestartur // "#REPLACESTARTURL#"
            28 ?? ?? ?? 0A // call     string [mscorlib]System.String::Concat(string, string)
        }

    condition:
        (
            6 of ($config_*)
            or 8 of ($logic_*)
            or 4 of ($command_*)
            or 3 of ($error_*)
        ) and 2 of ($clr_*)
}
"""
)
class PoshC2CSharpDropper(Extractor):
    family = "PoshC2 CSharp Dropper"

    @Extractor.string
    def clr_base(
        self, p: ProcessMemory, addr: int, match: YaraStringMatch
    ) -> Dict[str, Any]:
        class Wrapper:
            def __init__(self, p: ProcessMemory) -> None:
                self.__p = p

            def get_data(self, start=0, length=None):
                if length is None:
                    length = self.__p.length - start

                return self.__p.readv(start, length)

            def get_offset_from_rva(self, rva):
                return rva

            def get_string_at_rva(self, rva):
                return self.__p.asciiz(rva)

        self.clr = ClrMetaData(Wrapper(p), addr, 0x48, lazy_load=False)

    @Extractor.string
    def clr_UserDomainCheck(
        self, p: ProcessMemory, addr: int, match: YaraStringMatch
    ) -> Dict[str, Any]:
        try:
            self.UserDomainCheck.append(addr)
        except AttributeError:
            self.UserDomainCheck = [addr]

    @Extractor.string
    def clr_KillDate(
        self, p: ProcessMemory, addr: int, match: YaraStringMatch
    ) -> Dict[str, Any]:
        try:
            self.KillDate.append(addr)
        except AttributeError:
            self.KillDate = [addr]

    @Extractor.string
    def logic_payload(
        self, p: ProcessMemory, addr: int, match: YaraStringMatch
    ) -> Dict[str, Any]:
        url = p.utf16z(addr).decode("utf8").split(";")[-1]
        return {"URLID": int(url) if url.isdecimal() else url}

    @Extractor.string
    def clr_Headers(
        self, p: ProcessMemory, addr: int, match: YaraStringMatch
    ) -> Dict[str, Any]:
        try:
            self.Headers.append(addr)
        except AttributeError:
            self.Headers = [addr]

    @Extractor.string
    def clr_Proxies(
        self, p: ProcessMemory, addr: int, match: YaraStringMatch
    ) -> Dict[str, Any]:
        try:
            self.Proxies.append(addr)
        except AttributeError:
            self.Proxies = [addr]

    @Extractor.string("clr_Retries_short", "clr_Retries_long")
    def clr_Retries(
        self, p: ProcessMemory, addr: int, match: YaraStringMatch
    ) -> Dict[str, Any]:
        try:
            self.Retries.append(addr)
        except AttributeError:
            self.Retries = [addr]

    @Extractor.string
    def clr_Arrays(
        self, p: ProcessMemory, addr: int, match: YaraStringMatch
    ) -> Dict[str, Any]:
        try:
            self.Arrays.append(addr)
        except AttributeError:
            self.Arrays = [addr]

    @Extractor.string
    def clr_Comms(
        self, p: ProcessMemory, addr: int, match: YaraStringMatch
    ) -> Dict[str, Any]:
        try:
            self.Comms.append(addr)
        except AttributeError:
            self.Comms = [addr]

    def __clr_memberref(self, p: ProcessMemory, addr: int):
        index = p.uint32v(addr) & 0xFFFFFF
        metadata = self.clr.streams[b"#~"]
        return metadata.MemberRef[index - 1]

    def __clr_typeref(self, p: ProcessMemory, addr: int):
        index = p.uint32v(addr) & 0xFFFFFF
        metadata = self.clr.streams[b"#~"]
        return metadata.TypeRef[index - 1]

    def __clr_usref(self, p: ProcessMemory, addr: int):
        index = p.uint32v(addr) & 0xFFFFFF
        return self.clr.streams[b"#US"].get_us(index).value

    def __clr_methoddef(self, p: ProcessMemory, addr: int):
        index = p.uint32v(addr) & 0xFFFFFF
        metadata = self.clr.streams[b"#~"]
        return metadata.MethodDef[index - 1]

    def __clr_field(self, p: ProcessMemory, addr: int):
        index = p.uint32v(addr) & 0xFFFFFF
        metadata = self.clr.streams[b"#~"]
        return metadata.Field[index - 1]

    def __clr_UserDomainCheck(self, p: ProcessMemory):
        for addr in self.UserDomainCheck:
            if self.__clr_memberref(p, addr + 0x06).Name != "IsNullOrEmpty":
                continue

            if self.__clr_memberref(p, addr + 0x10).Name != "get_UserDomainName":
                continue

            return self.__clr_usref(p, addr + 0x01)

    def __clr_KillDate(self, p: ProcessMemory):
        for addr in self.KillDate:
            if self.__clr_usref(p, addr + 0x06) != "yyyy-MM-dd":
                continue

            if self.__clr_memberref(p, addr + 0x0B).Name != "get_InvariantCulture":
                continue

            if self.__clr_memberref(p, addr + 0x10).Name != "ParseExact":
                continue

            if self.__clr_memberref(p, addr + 0x15).Name != "get_Now":
                continue

            if self.__clr_memberref(p, addr + 0x1A).Name != "op_GreaterThan":
                continue

            return self.__clr_usref(p, addr + 0x01)

    def __clr_Headers(self, p: ProcessMemory):
        for addr in self.Headers:
            if self.__clr_memberref(p, addr + 0x02).Name != "get_Headers":
                continue

            if self.__clr_memberref(p, addr + 0x11).Name != "Add":
                continue

            yield (self.__clr_usref(p, addr + 0x07), self.__clr_usref(p, addr + 0x0C))

    def __clr_Proxies(self, p: ProcessMemory):
        for addr in self.Proxies:
            if self.__clr_memberref(p, addr + 0x01).Name != ".ctor":
                continue

            return (
                self.__clr_usref(p, addr + 0x07),
                self.__clr_usref(p, addr + 0x0D),
                self.__clr_usref(p, addr + 0x13),
            )

    def __clr_Retries(self, p: ProcessMemory):
        for addr in self.Retries:
            if self.__clr_methoddef(p, addr + 0x01).Name != "AUnTrCrts":
                continue

            short = p.uint8v(addr + 0x05) == 0x1F

            if self.__clr_memberref(p, addr + 0x10 if short else 0x13).Name != ".ctor":
                continue

            return (
                p.uint8v(addr + 0x06) if short else p.uint32v(addr + 0x06),
                p.uint32v(addr + (0x09 if short else 0x0C)),
            )

    def __clr_Arrays(self, p: ProcessMemory):
        for addr in self.Arrays:
            ref = self.__clr_typeref(p, addr + 0x01)
            if ref.TypeNamespace != "System" or ref.TypeName != "String":
                continue

            yield (
                self.__clr_field(p, addr + 0x0E).Name,
                self.__clr_usref(p, addr + 0x08),
            )

    def __clr_Comms(self, p: ProcessMemory):
        for addr in self.Comms:
            if self.__clr_memberref(p, addr + 0x01).Name != "Format":
                continue

            if self.__clr_memberref(p, addr + 0x1A).Name != "Concat":
                continue

            return (self.__clr_usref(p, addr + 0x08), self.__clr_usref(p, addr + 0x15))

    @Extractor.rule
    def mal_poshc2_csharp_dropper(self, p: ProcessMemory, match: YaraMatch):
        try:
            (Proxyurl, Proxyuser, Proxypass) = self.__clr_Proxies(p)
            (Key, ConnectURL) = self.__clr_Comms(p)
        except:
            return False

        # https://github.com/nettitude/PoshC2/blob/517903431ab43e6d714b24b0752ba111f5d4c2f1/poshc2/server/payloads/Payloads.py#L214
        ImplantType = ConnectURL[-2:]
        if ImplantType != "?c":
            raise ValueError
        ConnectURL = ConnectURL[:-2]

        config = {
            "KillDate": self.__clr_KillDate(p),
            "Proxyurl": Proxyurl,
            "Proxyuser": Proxyuser,
            "Proxypass": Proxypass,
            "Key": Key,
            "ConnectURL": ConnectURL,
            "ImplantType": ImplantType,
        }

        try:
            config["UserDomainCheck"] = self.__clr_UserDomainCheck(p)
        except AttributeError:
            pass

        try:
            (StageRetriesLimit, StageRetriesInitialWait) = self.__clr_Retries(p)
            config["StageRetriesLimit"] = StageRetriesLimit
            config["StageRetriesInitialWait"] = StageRetriesInitialWait // 1000
            config["StageRetries"] = True
        except AttributeError:
            config["StageRetries"] = False

        for header, value in self.__clr_Headers(p):
            if header == "User-Agent":
                config["UserAgent"] = value
            elif header == "Referer":
                config["Referrer"] = value

        for field, value in self.__clr_Arrays(p):
            if field == "dfarray" and value:
                try:
                    config["DomainFrontHeader"].append(value)
                except KeyError:
                    config["DomainFrontHeader"] = value
                except AttributeError:
                    config["DomainFrontHeader"] = [config["DomainFrontHeader"], value]
            elif field == "basearray" and value:
                try:
                    config["PayloadCommsHost"].append(value)
                except KeyError:
                    config["PayloadCommsHost"] = value
                except AttributeError:
                    config["DomainFrontHeader"] = [config["DomainFrontHeader"], value]

        return config


@Extractor.yara(
    r"""
// Modified for .NET identification
rule mal_poshc2_csharp_implant_pbind : TESTING MALWARE PoshC2 CSharp TA0002 T1570 S0378 TLP_CLEAR {
    meta:
        id = "6B1pAjnKeWtygZdCBmusiL"
        fingerprint = "CUSTOMIZED"
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
     
        $clr_base     = {
            42 53 4A 42     // Magic
            01 00           // Major
            01 00           // Minor
            00 00 00 00     // Reserved
            0C 00 00 00     // Version length
            76 ?? 2E 30 2E  // Version
        }
                
        $clr_Configs = {
            72 ?? ?? ?? 70 // ldstr    aName // "#REPLACEPBINDPIPENAME#"
            80 ?? ?? ?? 04 // stsfld   string Program::pipeName
            72 ?? ?? ?? 70 // ldstr    aSecret // "#REPLACEPBINDSECRET#"
            80 ?? ?? ?? 04 // stsfld   string Program::secret
            72 ?? ?? ?? 70 // ldstr    aKey // "#REPLACEKEY#"
            80 ?? ?? ?? 04 // stsfld   string Program::encryption
        }

    condition:
        (
            10 of ($logic_*)
            or 4 of ($command_*)
            or 3 of ($error_*)
        ) and 2 of ($clr_*)
}
"""
)
class PoshC2CSharpPBind(Extractor):
    family = "PoshC2 CSharp PBind"

    @Extractor.string
    def clr_base(
        self, p: ProcessMemory, addr: int, match: YaraStringMatch
    ) -> Dict[str, Any]:
        class Wrapper:
            def __init__(self, p: ProcessMemory) -> None:
                self.__p = p

            def get_data(self, start=0, length=None):
                if length is None:
                    length = self.__p.length - start

                return self.__p.readv(start, length)

            def get_offset_from_rva(self, rva):
                return rva

            def get_string_at_rva(self, rva):
                return self.__p.asciiz(rva)

        self.clr = ClrMetaData(Wrapper(p), addr, 0x48, lazy_load=False)

    @Extractor.string
    def clr_Configs(
        self, p: ProcessMemory, addr: int, match: YaraStringMatch
    ) -> Dict[str, Any]:
        try:
            self.Configs.append(addr)
        except AttributeError:
            self.Configs = [addr]

    def __clr_usref(self, p: ProcessMemory, addr: int):
        index = p.uint32v(addr) & 0xFFFFFF
        return self.clr.streams[b"#US"].get_us(index).value

    def __clr_field(self, p: ProcessMemory, addr: int):
        index = p.uint32v(addr) & 0xFFFFFF
        metadata = self.clr.streams[b"#~"]
        return metadata.Field[index - 1]

    def __clr_Configs(self, p: ProcessMemory):
        for addr in self.Configs:
            if self.__clr_field(p, addr + 0x06).Name != "pipeName":
                continue

            if self.__clr_field(p, addr + 0x10).Name != "secret":
                continue

            if self.__clr_field(p, addr + 0x1A).Name != "encryption":
                continue

            return (
                self.__clr_usref(p, addr + 0x01),
                self.__clr_usref(p, addr + 0x0B),
                self.__clr_usref(p, addr + 0x15),
            )

        raise AttributeError

    @Extractor.rule
    def mal_poshc2_csharp_implant_pbind(self, p: ProcessMemory, match: YaraMatch):
        try:
            (PBindPipeName, PBindSecret, Key) = self.__clr_Configs(p)
        except AttributeError:
            return

        return {
            "PBindPipeName": PBindPipeName,
            "PBindSecret": PBindSecret,
            "Key": Key,
        }


@Extractor.yara(
    r"""
// Modified for .NET identification
rule mal_poshc2_csharp_implant_fcomm : TESTING MALWARE PoshC2 CSharp TA0002 T1570 S0378 TLP_CLEAR {
    meta:
        id = "5NWaRGfawc5Iz5dcuwSjm3"
        fingerprint = "CUSTOMIZED"
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
     
        $clr_base     = {
            42 53 4A 42     // Magic
            01 00           // Major
            01 00           // Minor
            00 00 00 00     // Reserved
            0C 00 00 00     // Version length
            76 ?? 2E 30 2E  // Version
        }
                
        $clr_Configs = {
            72 ?? ?? ?? 70 // ldstr    aFile // "#REPLACEFCOMMFILENAME#"
            80 ?? ?? ?? 04 // stsfld   string Program::filename
            72 ?? ?? ?? 70 // ldstr    aKey // "#REPLACEKEY#"
            80 ?? ?? ?? 04 // stsfld   string Program::encryption
        }

    condition:
        (
            11 of ($logic_*)
            or 4 of ($command_*)
            or 3 of ($error_*)
        ) and 2 of ($clr_*)
}
"""
)
class PoshC2CSharpFComm(Extractor):
    family = "PoshC2 CSharp FComm"

    @Extractor.string
    def clr_base(
        self, p: ProcessMemory, addr: int, match: YaraStringMatch
    ) -> Dict[str, Any]:
        class Wrapper:
            def __init__(self, p: ProcessMemory) -> None:
                self.__p = p

            def get_data(self, start=0, length=None):
                if length is None:
                    length = self.__p.length - start

                return self.__p.readv(start, length)

            def get_offset_from_rva(self, rva):
                return rva

            def get_string_at_rva(self, rva):
                return self.__p.asciiz(rva)

        self.clr = ClrMetaData(Wrapper(p), addr, 0x48, lazy_load=False)

    @Extractor.string
    def clr_Configs(
        self, p: ProcessMemory, addr: int, match: YaraStringMatch
    ) -> Dict[str, Any]:
        try:
            self.Configs.append(addr)
        except AttributeError:
            self.Configs = [addr]

    def __clr_usref(self, p: ProcessMemory, addr: int):
        index = p.uint32v(addr) & 0xFFFFFF
        return self.clr.streams[b"#US"].get_us(index).value

    def __clr_field(self, p: ProcessMemory, addr: int):
        index = p.uint32v(addr) & 0xFFFFFF
        metadata = self.clr.streams[b"#~"]
        return metadata.Field[index - 1]

    def __clr_Configs(self, p: ProcessMemory):
        for addr in self.Configs:
            if self.__clr_field(p, addr + 0x06).Name != "filename":
                continue

            if self.__clr_field(p, addr + 0x10).Name != "encryption":
                continue

            return (self.__clr_usref(p, addr + 0x01), self.__clr_usref(p, addr + 0x0B))

        raise AttributeError

    @Extractor.rule
    def mal_poshc2_csharp_implant_fcomm(self, p: ProcessMemory, match: YaraMatch):
        try:
            (FCommFileName, Key) = self.__clr_Configs(p)
        except AttributeError:
            return

        return {
            "FCommFileName": FCommFileName,
            "Key": Key,
        }


@Extractor.yara(
    r"""
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
"""
)
class PoshC2CPlusPlusLoader(Extractor):
    family = "PoshC2 C++ Loader"

    @Extractor.string
    def clr_assembly(
        self, p: ProcessMemory, addr: int, match: YaraStringMatch
    ) -> Dict[str, Any]:
        encoded = (
            p.utf16z(addr) if p.uint8v(addr + 1) == 0 else p.readv_until(addr, b"\0")
        )
        decoded = base64.decode(encoded)
        self.push_procmem(ProcessMemory(decoded))


if __name__ == "__main__":
    parser = ArgumentParser(description="Extract PoshC2 configurations")

    group = parser.add_mutually_exclusive_group()
    group.add_argument(
        "-f",
        "--file",
        type=str,
        nargs="*",
        help="Glob expression to PoshC2 payloads (passive)",
    )
    group.add_argument(
        "-u", "--url", type=str, nargs="*", help="URL to a PoshC2 server (active)"
    )

    args = parser.parse_args()

    manager = ExtractManager(ExtractorModules())

    if args.file:
        for expression in args.file:
            for match in iglob(expression, recursive=True, include_hidden=True):
                if path.isdir(match):
                    continue
                print(match, file=stderr, flush=True)
                manager.configs = dict()
                manager.push_file(match)
                for config in manager.config:
                    print(dumps(config, indent="  "), flush=True)
    elif args.url:
        # Disable SSL pinning
        selfsigned = create_default_context()
        selfsigned.check_hostname = False
        selfsigned.verify_mode = CERT_NONE

        paths = [
            "adsense/troubleshooter/1631343/",
            "adServingData/PROD/TMClient/6/8736/",
            "advanced_search/",
            "async/newtab/",
            "babel-polyfill/6.3.14/polyfill.min.js=/",
            "bh/sync/aol/",
            "bootstrap/3.1.1/bootstrap.min.js/",
            "branch-locator/search.asp/",
            "business/home.asp&ved=/",
            "business/retail-business/insurance.asp/",
            "cdba/",
            "cisben/marketq/",
            "classroom/sharewidget/widget_stable.html/",
            "client_204/",
            "load/pages/index.php/",
            "putil/2018/0/11/po.html/",
            "qqzddddd/2018/load.php/",
            "status/995598521343541248/query=/",
            "TOS/",
            "trader-update/history&pd=/",
            "types/translation/v1/articles/",
            "uasclient/0.1.34/modules/",
            "usersync/tradedesk/",
            "utag/lbg/main/prod/utag.15.js/",
            "vfe01s/1/vsopts.js/",
            "vssf/wppo/site/bgroup/visitor/",
            "wpaas/load.php/",
            "web/20110920084728/",
            "webhp/",
            "work/embedded/search/",
            "GoPro5/black/2018/",
            "Philips/v902/",
        ]

        for host in args.url:
            manager.configs = dict()
            for url in (
                [host]
                if urlparse(host).path
                else [f"{host}/{path}_cs" for path in paths]
            ):
                try:
                    with urlopen(url, context=selfsigned) as p:
                        print(url, file=stderr, flush=True)
                        manager.push_procmem(ProcessMemory(p.read()))
                        break
                except (HTTPError, URLError):
                    pass
            if not manager.config:
                print(host, file=stderr, flush=True)
            else:
                for config in manager.config:
                    print(dumps(config, indent="  "), flush=True)
    else:
        manager.push_procmem(ProcessMemory(stdin.buffer.read()))
