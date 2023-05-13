import "pe"

rule sus_pe_free_without_allocation: TESTING SUSPICIOUS TA0005 T1027 T1027_007 {
    meta:
        id = "5BqhLNZUKDAagE3Pf0GHSf"
        fingerprint = "7b6b4edcc9349c23ff837084934c15034888c8dd744a5cb32bf662802bdc822b"
        version = "1.1"
        creation_date = "2023-05-13"
        first_imported = "2023-05-13"
        last_modified = "2023-05-13"
        status = "TESTING"
        sharing = "TLP:WHITE"
        source = "THIEBAUT.DEV"
        author = "Maxime THIEBAUT (@0xThiebaut)"
        description = "Detects an executable importing functions to free memory without importing allocation functions, often indicative of dynamic import resolution"
        category = "INFO"
        mitre_att = "T1027.007"

    condition:
        pe.number_of_imports <= 3   // Restrict to low-import executables
        and (pe.imports("kernel32.dll", "VirtualFree") or pe.imports("kernel32.dll", "VirtualFreeEx"))
        and not (
            pe.imports("gdi32.dll")
            or pe.imports("kernel32.dll", "VirtualAlloc")
            or pe.imports("kernel32.dll", "VirtualAlloc2")
            or pe.imports("kernel32.dll", "VirtualAlloc2FromApp")
            or pe.imports("kernel32.dll", "VirtualAllocEx")
            or pe.imports("kernel32.dll", "VirtualAllocExNuma")
            or pe.imports("kernel32.dll", "VirtualAllocFromApp")
        )
}
