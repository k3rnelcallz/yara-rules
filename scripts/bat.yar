rule BAT_File_Generic
{
    meta:
        author = "kz"
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
rule bat_relaunch_
{
    meta:
        author = "kz"
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
        $ = "\Contacts\\doku"
        $ = "\\Contacts\\!RANDSTARTUP!.bat"
        $ = "\\Microsoft\\Windows\\Start Menu\\Programs\\Startup"
        $ = "FromBase64String"
        $ = "%STARTUPBATCPY%"

    condition:
        all of them
}