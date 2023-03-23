rule weird_png_data_after_end {
    meta:
        id = "B6qzTNn5O3u7peuIgFwSO"
        fingerprint = "465b1a8b40ba9999f28e82ddf96162ff498f8ac395468daa335a18b51a3dd999"
        version = "1"
        creation_date = "2023-03-23"
        first_imported = "2023-03-23"
        last_modified = "2023-03-23"
        status = "TESTING"
        sharing = "TLP:WHITE"
        source = "THIEBAUT.DEV"
        author = "Maxime THIEBAUT (@0xThiebaut)"
        description = "Detects data suspiciously located after a PNG's end header"
        category = "INFO"
        mitre_att = "T1027.003"
        reference = "https://isc.sans.edu/diary/Windows+11+Snipping+Tool+Privacy+Bug+Inspecting+PNG+Files/29660"
        reference = "https://www.bleepingcomputer.com/news/microsoft/windows-11-snipping-tool-privacy-bug-exposes-cropped-image-content/"

    strings:
        $header = {89 50 4E 47 0D 0A 1A 0A}
        $chunk_IHDR = {00 00 00 0D 49 48 44 52}
        $chunk_IEND = {00 00 00 00 49 45 4E 44}
        $types = /PLTE|IDAT|bKGD|cHRM|dSIG|eXIf|gAMA|hIST|iCCP|iTXt|pHYs|sBIT|sPLT|sRGB|sTER|tEXt|tIME|tRNS|zTXt/

    condition:
        // A PNG starts with a header...
        $header at 0x00
        // and is followed by the mandatory image header chunk.
        and $chunk_IHDR at 0x08
        // An acropalypse image requires a...
        and for any i in (1..#types): (
            // valid end chunk...
            $chunk_IEND at (uint32be(@types[i]-4) + @types[i] + 4 + 4) and
            // with additional data afterwards
            (uint32be(@types[i]-4) + @types[i] + 4 + 4 + 0xC) < filesize
            // at least anoth end chunk can be found
        )
}

rule weird_png_acropalypse {
    meta:
        id = "3hzbpn9OXCHvKIyYNY0M29"
        fingerprint = "e15a66d520dfad4c1e7716321e904fa388ede127eabfec8105356f1799ea6443"
        version = "1"
        creation_date = "2023-03-23"
        first_imported = "2023-03-23"
        last_modified = "2023-03-23"
        status = "TESTING"
        sharing = "TLP:WHITE"
        source = "THIEBAUT.DEV"
        author = "Maxime THIEBAUT (@0xThiebaut)"
        description = "Detects a cropped PNG leaking original data"
        category = "INFO"
        mitre_att = "T1027.003"
        reference = "https://isc.sans.edu/diary/Windows+11+Snipping+Tool+Privacy+Bug+Inspecting+PNG+Files/29660"
        reference = "https://www.bleepingcomputer.com/news/microsoft/windows-11-snipping-tool-privacy-bug-exposes-cropped-image-content/"

    strings:
        $chunk_IEND = {00 00 00 00 49 45 4E 44}

    condition:
        weird_png_data_after_end and $chunk_IEND at filesize-0xC
}
