rule rtf_Suspicious_Objects 
{
    meta:
        author = "K3rnelcallz"
        description = "Detects suspicious OCX/OLE objects in RTF"
        sha = "ad33071cc79da45d8c40aff73925403acfbd946da48b24ce0c4479f7ad21f660"
        source = "mbazaar"
        Mod_Date = "15-12-25"
        Tags = "exploit: cve-2017-11882"
    
    strings:
        $rtf_header = "{\\rtf" ascii
        $obj1 = "\\objocx" ascii 
        $obj2 = "\\object" ascii
        $obj3 = "\\objupdate" ascii
        $obj4 = "\\objdata" ascii
        $bin = "\\bin" ascii

    condition:
        $rtf_header at 0 and
        ($obj1 or $obj2) and
        all of ($obj3, $obj4) and $bin
}