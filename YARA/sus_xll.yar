import "pe"

rule sus_xll_xlAutoOpen_empty: TESTING SUSPICIOUS TA0003 T1137 T1137_006 {
    meta:
        id = "IKlkRzFlrc1iw7JdK41Ul"
        fingerprint = "1d2ba344475b2ebafb1524ebc273f9219a56bfa136d7afb218b49f2c88ac8938"
        version = "1.1"
        creation_date = "2023-05-13"
        first_imported = "2023-05-13"
        last_modified = "2023-05-13"
        status = "TESTING"
        sharing = "TLP:WHITE"
        source = "THIEBAUT.DEV"
        author = "Maxime THIEBAUT (@0xThiebaut)"
        description = "Detects an Excel XLL file exporting an empty xlAutoOpen function, often indicative of hidden logic inside DllMain"
        category = "INFO"
        mitre_att = "T1137.006"
        reference = "https://learn.microsoft.com/en-us/office/client-developer/excel/creating-xlls#turning-dlls-into-xlls-add-in-manager-interface-functions"
        reference = "https://learn.microsoft.com/en-us/office/client-developer/excel/xlautoopen"

    condition:
        pe.exports("xlAutoOpen")
        and (
            uint8(pe.export_details[pe.exports_index("xlAutoOpen")].offset) == 0xC3  // ret
            or (
                uint16(pe.export_details[pe.exports_index("xlAutoOpen")].offset) == 0xC033     // xor eax eax
                and uint8(pe.export_details[pe.exports_index("xlAutoOpen")].offset+2) == 0xC3  // xor eax eax
            )
        )
}

rule sus_xll_xlAutoClose_empty: TESTING SUSPICIOUS TA0003 T1137 T1137_006 {
    meta:
        id = "6of2wrJksv1WZcHOthgatn"
        fingerprint = "819b0f27d9d0ebdf486646a0d9e71e1cb12c4c3691094d8633e0c93a07cbc24b"
        version = "1.0"
        creation_date = "2023-05-13"
        first_imported = "2023-05-13"
        last_modified = "2023-05-13"
        status = "TESTING"
        sharing = "TLP:WHITE"
        source = "THIEBAUT.DEV"
        author = "Maxime THIEBAUT (@0xThiebaut)"
        description = "Detects an Excel XLL file exporting the optional xlAutoClose as an empty function"
        category = "INFO"
        mitre_att = "T1137.006"
        reference = "https://learn.microsoft.com/en-us/office/client-developer/excel/xlautoclose"

    condition:
        pe.exports("xlAutoClose")
        and (
            uint8(pe.export_details[pe.exports_index("xlAutoClose")].offset) == 0xC3  // ret
            or (
                uint16(pe.export_details[pe.exports_index("xlAutoClose")].offset) == 0xC033     // xor eax eax
                and uint8(pe.export_details[pe.exports_index("xlAutoClose")].offset+2) == 0xC3  // xor eax eax
            )
        )
}
