rule vbe_file
{
    meta: 
        author = "k3rnelcallz"
        family = "masslogger"
        sample = "bd50ea97aeed23c603c272f3fb237063553cf2a1fd09582b2115f6d7702acc9b"
        filename = "CF N°6100.vbe"
        creation_date = "29-11-25"
		last_modified = "29-11-25"
		source = "Malwarebazaar"
		category = "Info"
    
    strings:
        $s1 = "WScript.CreateObject" wide
        $s2 = /\("WScript\.Ne"\s*&\s*"twork"\)/ ascii

    condition: 
        $s1 or $s2
}

rule obf_1 : agent_tesla 
{
	meta: 
		author= "k3rnelcallz"
		filename= "Holiday_Booking.vbs"
		fileType= "vbs"
		//filesize= "15.47KB"
		source= "Malwarebazaar"
		sha= "d9dcc750e92090e36769db3f0ed8997a0f68c81ebdaef0f7ad5716735fbabf0c"
		tags= "AgentTesla, Loader"
	
	strings:

		//powershell usage for encoding
		$ps_enc= /\$\w+\s*=\s\[system\.Text\.encoding\]::Unicode\.GetStri/ nocase

		//matches fragments for base64 conversion
		$frag_1= /Call\s\w+\(\"ng\(\[system\.c\"\)/ nocase
		$frag_2= /Call\s\w+\(\"onvert\]::Fromba\"/ nocase

		//invoke expression calls
		$iex= /Call\s\w+\(\"iex\s\$\w+\"\)/ nocase

		//network pattern used
		$net_obj= /\"Wscript\.Ne\"\s&\s\"twork\"/ nocase

		$test1= /\w+\s\w+\s=\s\w+\.\w+\(\"Wscript\.Ne\"\s&\s\"twork\"\)/ nocase
	
	condition:
		uint16(0) != 0x5A4D and filesize < 50KB and 3 of them
}