rule weird_png_data_after_end {
    meta:
        id = "B6qzTNn5O3u7peuIgFwSO"
        fingerprint = "9aacd62b49ab6c51b9483329c699e72690da0152b6a191c950b4ae01dd9bc7e4"
        version = "1.2"
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
        $chunk_IEND = {00 00 00 00 49 45 4E 44}
        $types = /PLTE|IDAT|bKGD|cHRM|dSIG|eXIf|gAMA|hIST|iCCP|iTXt|pHYs|sBIT|sPLT|sRGB|sTER|tEXt|tIME|tRNS|zTXt/

    condition:
        // A PNG starts with a header...
        uint32(0) == 0x474e5089 and uint32(4) == 0x0a1a0a0d
        // and is followed by the mandatory image header chunk.
        and uint32(8) == 0x0d000000 and uint32(12) == 0x52444849
        // An malformed PNG requires a...
        and for any i in (1..#types): (
            // valid end-chunk...
            $chunk_IEND at (uint32be(@types[i]-4) + @types[i] + 0x08) and
            // with additional data afterwards.
            (uint32be(@types[i]-4) + @types[i] + 0x14) < filesize
        )
}

rule weird_png_acropalypse {
    meta:
        id = "3hzbpn9OXCHvKIyYNY0M29"
        fingerprint = "500cdc0437a0f12a10ad740186dcef7852c11ebc415efeecd2d1b4cf2d62ef60"
        version = "1.1"
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
        // An acropalypse PNG has data after the first end-chuck as well as an end-chunk closing the file.
        weird_png_data_after_end and $chunk_IEND at filesize-0x0C
}
