import "pe"

rule sus_xll_xlAutoOpen_empty: TESTING SUSPICIOUS TA0003 T1137 T1137_006 {
    meta:
        id = "IKlkRzFlrc1iw7JdK41Ul"
        fingerprint = "b9036a33ba3b98bce231ab8ba20113a1c5d2eabab31f83ceca4fadfaf11b7942"
        version = "1.0"
        creation_date = "2023-05-13"
        first_imported = "2023-05-13"
        last_modified = "2023-05-13"
        status = "TESTING"
        sharing = "TLP:WHITE"
        source = "THIEBAUT.DEV"
        author = "Maxime THIEBAUT (@0xThiebaut)"
        description = "Detects an Excel XLL file with as sole export an empty xlAutoOpen function, often indicative of hidden logic inside DllMain"
        category = "INFO"
        mitre_att = "T1137.006"
        reference = "https://learn.microsoft.com/en-us/office/client-developer/excel/creating-xlls#turning-dlls-into-xlls-add-in-manager-interface-functions"

    condition:
        pe.number_of_exports == 1
        and pe.export_details[0].name == "xlAutoOpen"
        and uint8(pe.export_details[0].offset) == 0xC3  // ret
}
