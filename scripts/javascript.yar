rule js_powershell_usage
{
	meta:
		author = "k3rnelcallz"
		sha = "42aa8d13849dba889ff65c323b27d7b14a442909471b7f366b0512803e84c260"
		mod_date = "12-13-25"
		description = "Powershell objects usage with cleanup routine for payload"
		source = "mbazaar"
        tags = "Family: Rhadamanthys"

	strings:
		$s1 = "fromCharCode" nocase ascii wide
		$s2 = "Bypass" nocase ascii wide
		$s3 = "eval(String" nocase ascii wide
		$s4 = "Start-Sleep" nocase ascii wide
		$s5 = "ActiveXObject" ascii wide
		$s6 = "Invoke-Expression\x20(IrM" nocase wide
		$s7 = "['DeleteFile'](WScript['ScriptFullName'])" nocase ascii wide //Cleanup routine

	condition: 
		($s1 or $s2 or $s3 or $s4 or $s5)
		and ($s6 and $s7)
}
rule js_sig_block_usage 
{
	meta: 
		author = "k3rnelcallz"
		sha = "5d26c74c808d39201faa95bc10100843df0d0931ff5c5b0b4de28f9277ac2d36"
		mod_date = "12-13-25"
		description = "signature block with random with function in between"
		source = "mbazaar"
        samples = "4+"
        tags = "Family: Rhadamanthys"
		
	strings: 
		$sig_block_marker1 = "// SIG // Begin signature block" ascii wide
		$sig_block_marker2 = "// SIG // End signature block" ascii wide
		$f = "function" ascii wide

	condition: 
		any of ($sig_block_marker*)
		and $f
}

rule Targeted_JS_Dropper_Variant {
    meta:
        description = "Detects specific JS dropper variant using ActiveX and identified obfuscation strings"
        author = "k3rnelcallz"
        reference = 'malwarebazaar'
        date = "29-12-25"

    strings:
        //most unique function name identified
        $fn_del = "ThreeCharsDEL" ascii wide

        //repetitive function pattern
        $fn_ww = "function WWWWWWWWW(" ascii wide

        //specific obfuscation technique: split/join to hide strings
        $obfs_split = ".split('>').join('')" ascii wide

        //ActiveX and File System interaction
        $ax_1 = "ActiveXObject" ascii wide
        $ax_2 = ".FileExists" ascii wide

        //Variable name patterns (using regex to handle minor variations)
        // Matches "var urlname" followed by many 'o's
        $var_url = /var\s+urlnameo{5,}/ ascii wide

        //Matches the "this.MJUBCB..." pattern 
        $var_obfs = /this\.[A-Z]{5,}\s*\+=\s*['"]/ ascii wide
        
     	//hex-to-decimal/hex conversion function
        $fn_d2h = "this.d2h" ascii wide

    condition:

        $fn_del or (3 of ($fn_ww, $obfs_split, $ax_1, $ax_2, $var_url, $var_obfs, $fn_d2h))
}

rule Obfs_behavior_wmi {
    meta:
        description = "detection for JS Loader focusing on WMI/ADSI discovery and XOR loops"
        author = "k3rnelcallz"
        reference = "malwarebazaar"
        sha = "2e5934e38666e63c23f5906e5175a1bf5c230972cb57bb8c07dab0630921fa43"

    strings:
        /* Unique XOR de-obfuscation pattern: "number * number + number & 255" */
        $xor_math = { 2A [1-10] 2B [1-10] 26 20 32 35 35 } 

        /* Critical ActiveX Objects - often used in combination by this threat */
        $obj1 = "Schedule.Service"
        $obj2 = "Win32_Process"
        $obj3 = "ADODB.Stream"
        $obj4 = "OpenDSObject"  // ADSI - Very specific to domain recon
        
        /* Specific behavioral artifacts */
        $sid_admin = "-512"      // Domain Admin SID check
        $stealth = "ShowWindow = 0"
        $rand_seed = "Math.random() * 900000"

    condition:
        (filesize < 300KB) and ($xor_math and 2 of ($obj*, $sid_admin, $stealth, $rand_seed))
}