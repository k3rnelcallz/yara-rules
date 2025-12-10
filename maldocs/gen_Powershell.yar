rule powershell_dropper { 

	meta: 
		author = "k3rnelcallz"
		description = "powershell dropper with hidden bypass execution and persistence"
		sha256 = "f9e832c9cd54668c35bab5077df30af51ced5f9473d570e73b369437a632523a"
        creation_date = "1-12-25"
		last_modified = "2-12-25"
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
        creation_date = "1-12-25"
		last_modified = "2-12-25"
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
rule pwsh_getEnvironmentVariable
{
    meta:
        description = "Scripts detects environment variables"
        author = "k3rnelcallz"
        sha = "37c72ba7697589aac2275e9f44de1e821aa4ef8ad7b54f6db91339681457aec1"
        source = "mbazaar"
        creation_date = "12_10_25"
        modified_date = "12_10_25"
        category = "Info"
    
    strings:
        $g1 = "GetEnvironmentVariable('USERPROFILE'))" ascii
        $g2 = "GetEnvironmentVariable('TEMP'))" ascii
        $g3 = "GetEnvironmentVariable('TMP'))" ascii

    condition:
        any of ($g*)
}
rule pwsh_Disable_WindowsDefender 
{
    meta:
        description = "Detects scripts attempting to disable Windows Defender"
        author = "k3rnelcallz"
        sha = "37c72ba7697589aac2275e9f44de1e821aa4ef8ad7b54f6db91339681457aec1"
        source = "mbazaar"
        creation_date = "12_10_25"
        modified_date = "12_10_25"
        category = "Info"

    strings: 
        $disable_av1 = "Disable-WindowsDefender" ascii
        $disable_av2 = "Set-MpPreference -DisableRealtimeMonitoring $true"
        $disable_av3 = "Set-MpPreference -MAPSReporting Disabled"
        $disable_av4 = "Set-MpPreference -SubmitSamplesConsent NeverSend"
        $cmd_error_action_stop = "-ErrorAction Stop"

    condition:
        $disable_av1 and (
        $disable_av2 or $disable_av3 or $disable_av4) 
        and  $cmd_error_action_stop  

}
rule Stop_Antivirus_Services
{
meta:
        description = "Detects attempts to stop common antivirus services"
        author = "k3rnelcallz"
        sha = "37c72ba7697589aac2275e9f44de1e821aa4ef8ad7b54f6db91339681457aec1"
        source = "mbazaar"
        creation_date = "12_10_25"
        modified_date = "12_10_25"
        category = "Info"

    strings:
        $av_service_1 = "avp"   // Kaspersky
        $av_service_2 = "McShield"  // McAfee
        $av_service_3 = "avgnt"   // Avira
        $av_service_4 = "avguard" // Avira
        $av_service_5 = "avastsvc" // Avast
        $av_service_6 = "mbamservice" // Malwarebytes
        $av_service_7 = "SBAMSvc" // Vipre
        $av_service_8 = "SAVService" // Sophos
        $cmd_stop_service = "Stop-Service"

    condition:
        $cmd_stop_service and any of ($av_service_*)
}