rule doc : doc_1 
{
	meta:
		author = "k3rnelcallz"
		date = "23-12-25"
		source = "Malwarebazar"
		description = "Detecting Malicious Macro Embeded DOC"
		sample = "1362bd550b6bce1a99388bbb4a8eccfe085f7a38770a502701b3c064c0a1f461"
		tags = "hlsofficeaam, doc, macros, obfuscated"

	strings:
		/* Doc Header */
		$magic = { D0 CF 11 E0 }

		/* Office Doc Indicator*/
		$doc = "[Content_Types].xml" ascii 
		
		/* Kernel32 abuse */
	 	$loadlib = "LoadLibraryA" ascii nocase
	 	$kernel32 = "kernel32" ascii nocase
	 	$sleep = "Sleep" ascii nocase
	 	
	 	/* UserForm payload source */
	 	$textbox2 = "TextBox2" ascii
	 	$textbox1 = "TextBox1" ascii

        /* Drop Path */
		$userform = "C:\\ProgramData\\HLSOffice" ascii wide

		/* Suspicious Loader */
		$xldr1 = "ExtractOrgDoc"
		$xldr2 = "ExtractLoader"
		$xldr3 = "loaderpath"
		$xldr4 = "LoaderData"

	condition:
		$magic 
		and $doc
		and $userform and
		3 of ($loadlib, $kernel32, $sleep, $textbox1, $textbox2)
		and
		3 of ($xldr*)
}