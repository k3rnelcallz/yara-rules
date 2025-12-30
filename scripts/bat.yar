rule BAT_File_Generic
{
    meta:
        author = "k3rnelcallz"
        description = "Generic Windows batch file identification"
        sha = "7a3962542b2a4b3f2b4d157c2efbcfaba87f347419de7b2671b84be71c93234e"
        tags = "generic"

    strings:
        $bat_magic1 = "@echo off" ascii nocase
        $bat_magic2 = "echo off" ascii nocase
        $bat_magic3 = "%~f0" ascii
        $bat_magic4 = "%~dp0" ascii
        $bat_magic5 = "cmd /c" ascii nocase

    condition:
        uint16(0) == 0x4040 and
        1 of ($bat_magic*)
}
rule Bat_Relaunch_Hidden
{
    meta:
        author = "k3rnelcallz"
        description = "malicious bat runs in hidden mode"
        sha = "7a3962542b2a4b3f2b4d157c2efbcfaba87f347419de7b2671b84be71c93234e"
        tags = "Koadic"
        
    strings:
        $ = "!RANDZIP!.zip"
        $ = "-WindowStyle Hidden"
        $ = "pdfFile"
        $ = "\\Contacts\\Stdwk"
        $ = "\\Contacts\\!RANDZIP!.zip"
        $ = "\\Contacts\\!RANDZIP!.zip"
        $ = "\\Contacts\\!RANDSTZIP!.zip"
        $ = "\\Contacts\\doku"
        $ = "\\Contacts\\!RANDSTARTUP!.bat"
        $ = "\\Microsoft\\Windows\\Start Menu\\Programs\\Startup"
        $ = "FromBase64String"
        $ = "%STARTUPBATCPY%"

    condition:
        all of them
}

rule bat_loader: malicious_png_dropper
{
	meta:
		author = "k3rnelcallz"
		reference = "Malwarebazaar"
		sha = "05527965d2e4af174710298457ba56c449d575aa2937971a6fa785f9a75fdea9"
		description = "Bat loader drops decoded code and executes, cleanup"
		date = "31-12-25"
        tags = "loader, dropper"

	strings:
		$temp_b64 = />>"?%TEMP%\\[A-Za-z0-9_\-]+\.b64"?\s+echo/i

        $ps_convert = "[System.Convert]::FromBase64String"
        $ps_write   = "[System.IO.File]::WriteAllBytes"
        $ps_get_content = "Get-Content -Raw"

        $calls_payload = /call\s+"%TEMP%\\.*\.bat"/ nocase
        $del_payload   = /del\s+"%TEMP%\\.*\.(bat|b64)"/ nocase

    condition:
        $temp_b64 and
        2 of ($ps_convert, $ps_write, $ps_get_content) and
        1 of ($calls_payload, $del_payload)
}