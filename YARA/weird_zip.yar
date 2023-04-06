rule weird_zip_high_compression_ratio {
    meta:
        id = "5n0TXEMYZ3x4OEpXEa4PUm"
        fingerprint = "526a726a0bde1ab1fb5832fea08c150b49771f7dbea2bc65ea342bea59ef3d44"
        version = "1"
        creation_date = "2023-04-06"
        first_imported = "2023-04-06"
        last_modified = "2023-04-06"
        status = "TESTING"
        sharing = "TLP:WHITE"
        source = "THIEBAUT.DEV"
        author = "Maxime THIEBAUT (@0xThiebaut)"
        description = "Detects single-entry ZIP files with a suspiciously high compression ratio (>100:1) and decompressed size above the 500MB AV limit"
        category = "INFO"
        mitre_att = "T1027.001"
        reference = "https://twitter.com/Cryptolaemus1/status/1633099154623803394"
        hash = "4d9a6dfca804989d40eeca9bb2d90ef33f3980eb07ca89bbba06d0ef4b37634b"

    condition:
        // Find ZIP files...
        uint32(filesize-22) == 0x06054b50 
        // with only one entry on disk...
        and uint16(filesize-14) == 1
        // and only one entry in directory.
        and uint16(filesize-12) == 1
        // Where the directory...
        and uint32(uint32(filesize-6)) == 0x02014b50
        // has an uncompressed size larger than the AV limit...
        and uint32(uint32(filesize-6)+24) >= 500MB
        // while the compressed ration is high (>100:1 compression ratio)
        and uint32(uint32(filesize-6)+20) * 100 < uint32(uint32(filesize-6)+24)
}
