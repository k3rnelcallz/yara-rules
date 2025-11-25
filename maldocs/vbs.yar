rule vbe_file
{
    meta: 
        author = "k3rnelcallz"
        family = "masslogger"
        sample = "bd50ea97aeed23c603c272f3fb237063553cf2a1fd09582b2115f6d7702acc9b"
        filename = "CF N°6100.vbe"
    
    strings:
        $s1 = "WScript.CreateObject" wide
        $s2 = /\("WScript\.Ne"\s*&\s*"twork"\)/ ascii

    condition: 
        $s1 or $s2
}

