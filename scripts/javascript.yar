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