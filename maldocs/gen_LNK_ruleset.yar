rule is_LNK 
{ 
	meta:
		author = "k3rnelcallz"
		description = "Rule identifying (LNK) shortcut files."
		sha256 = "4f2617a971b9c78c8b215d6cb65525ff56f0633a3bcd381695a19efe08156a04"		
		creation_date = "2-12-25"
		last_modified = "2-12-25"
		source = "Malwarebazaar"
		category = "Info"

	strings:
		$lnk = {4C 00 00 00 01 14 02}

	condition:
		$lnk at 0
}

rule pwsh_in_LNK
{
	meta: 
		author = "k3rnelcallz"
		description = "Rule identifying (LNK) shortcut files."
		sha256 = "4f2617a971b9c78c8b215d6cb65525ff56f0633a3bcd381695a19efe08156a04"		
		creation_date = "2-12-25"
		last_modified = "2-12-25"
		source = "Malwarebazaar"
		category = "Info"
	
	strings:
		$ = "powershell" ascii wide nocase
		$ = "Invoke-" ascii wide nocase
		$ = "https:" ascii wide nocase
		$ = "WebRequest" ascii wide nocase
		$ = "-Exec" ascii wide nocase
	
	condition: 
		is_LNK and any of them
}

rule files_in_LNK
{
	meta: 
		author = "k3rnelcallz"
		description = "Rule identifying (LNK) shortcut files."
		sha256 = "4f2617a971b9c78c8b215d6cb65525ff56f0633a3bcd381695a19efe08156a04"		
		creation_date = "2-12-25"
		last_modified = "2-12-25"
		source = "Malwarebazaar"
		category = "Info"
	
	strings:
		$ = ".exe" ascii wide nocase
		$ = ".pdf" ascii wide nocase
		$ = ".lnk" ascii wide nocase
	
	condition: 
		is_LNK and any of them	
}
	
rule persistence_in_LNK
{
	meta: 
		author = "k3rnelcallz"
		description = "Rule identifying (LNK) shortcut files."
		sha256 = "4f2617a971b9c78c8b215d6cb65525ff56f0633a3bcd381695a19efe08156a04"		
		creation_date = "2-12-25"
		last_modified = "2-12-25"
		source = "Malwarebazaar"
		category = "Info"
	
	strings:
		$ = "ScheduledTaskTrigger" ascii wide nocase
		$ = "ScheduledTask" ascii wide nocase
		$ = "\temp" ascii wide nocase
	
	condition: 
		is_LNK and any of them
}	