rule powershell_dropper { 

	meta: 
		author = "k3rnelcallz"
		description = "powershell dropper with hidden bypass execution and persistence"
		sha256 = "f9e832c9cd54668c35bab5077df30af51ced5f9473d570e73b369437a632523a"
        creation_date = "11-2-25"
		last_modified = "12-2-25"
		source = "Malwarebazaar"
		category = "Info"

	strings:
		/* downloading indicators */
		$e1 = "-ExecutionPolicy bypass" nocase
		$e2 = "-windowstyle hidden" nocase
		$e3 = "System.Net.WebClient" nocase
		$e4 = "DownloadFile" nocase

 		/* embeded batch script */
 		$bat = ".bat"
 		$run = "\\CurrentVersion\\Run"

 	condition:
 		uint16(0) != 0x5A4D 
 		and
 		(
 		(3 of ($e*))
 		or
 		($bat and $run)
 		)
}

rule Suspicious_PowerShell_AssemblyLoader
{
    meta:
        description = "Detects PowerShell scripts loading assemblies from memory and hiding payloads"
        author = "k3rnelcallz"
        sha256 = "56e0cfc0fb789f7d8d7cef0b8497eef95563f46bb383d5f38061347657eaa445"
		source = "malwarebazaar"
        creation_date = "11-2-25"
		last_modified = "12-2-25"
		source = "Malwarebazaar"
		category = "Info"
        
    strings:
        // Reflection-based assembly loading
        $load = "[System.Reflection.Assembly]::Load"
        $invoke = ".Invoke("

        // Process monitoring
        $getProcess = "Get-Process"
        $mz_b64 = "TVqQAAMAAAAEAAAA"

        // Framework tool path reference
        $aspnet_compiler = "Aspnet_compiler.exe"

        // Extra suspicious markers
        $blackhawk = "BLACKHAWK.DOWN"
        $shoot     = "SHOOT"

    condition:
        // Must have assembly loading + invocation
        $load and $invoke
        // And either process monitoring or embedded PE payload
        and ($getProcess or $mz_b64)
        // And at least one of the suspicious markers
        and any of ($blackhawk,$shoot,$aspnet_compiler)
}
