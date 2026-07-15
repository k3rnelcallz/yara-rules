import "pe"

rule Ransomware_Win_TOKYOCORE_fsociety {
    meta:
        author       = "k3rnelcallz"
        date         = "2026-07-14"
        malware      = "TOKYOCORE / fsociety"
        family       = "Ransomware-Wiper"
        threat_level = "High"
        hash_sha256  = "386fbb57ba83864ee57a9e8a271c6dc215dc20bb1521ee85ad414f0dc67babdc"
        version      = "1.0"

    strings:
        // ---------- Brand / theme markers (highest confidence) ----------
        $b1  = "TOKYOCORERansom" ascii wide
        $b2  = "tokyocore_ss.png" ascii wide
        $b3  = "tokyocore_data_" ascii wide
        $b4  = "tokyocore_data.zip" ascii wide
        $b5  = "fsociety_sond.mp3" ascii wide
        $b6  = "fsociety_ss.png" ascii wide
        $b7  = "fsociety ransomware activated" ascii wide
        $b8  = "Heartbeat - ransomware active" ascii wide
        $b9  = "\"footer\":{\"text\":\"fsociety - We are finally free\"}" ascii
        $b10 = "We are fsociety. We are finally free." ascii wide
        $b11 = "Access denied. We are fsociety. We are finally free." ascii wide
        $b12 = "MEDS OWN YOR SYSTEM" ascii wide
        $b13 = "@meds in a ticket to ask for more time" ascii wide
        $b14 = "RansomAgent/1.0" ascii wide
        $b15 = "SOFTWARE\\Microsoft\\Windows NT\\CrrentVersion\\Winlogon\\Notify\\tokyocore" ascii wide

        // ---------- Persistence & service abuse ----------
        $p1  = "sc create Windowspdate binPath=" ascii
        $p2  = "sc create Systempdate binPath=" ascii
        $p3  = "sc create WinpdateSvc binPath=" ascii
        $p4  = "schtasks /create /tn \"Windowspdate\"" ascii
        $p5  = "schtasks /create /tn \"Systempdate\"" ascii
        $p6  = "schtasks /create /tn \"Bootpdate\"" ascii
        $p7  = "\\Windowspdate.exe" ascii wide
        $p8  = "wmic /namespace:\\\\root\\sbscription path __EventFilter create Name=\"WindowspdateFilter\"" ascii

        // ---------- Wiper / brick behavior ----------
        $w1  = "\\\\.\\PhysicalDrive0" ascii wide
        $w2  = "Yor PC is now permanently bricked." ascii wide
        $w3  = "Yor Windows is gone forever." ascii wide
        $w4  = "Yor compter is schedled for irreversible data corrption" ascii wide
        $w5  = "bcdedit /set {crrent} bootmenpolicy legacy" ascii
        $w6  = "Clear-SecreBootKeys" ascii wide

        // ---------- File markers dropped on host ----------
        $f1  = "C:\\Windows\\Temp\\.syslock" ascii wide
        $f2  = "C:\\Windows\\Temp\\.keyfile" ascii wide
        $f3  = "C:\\Windows\\System32\\bootexec.bat" ascii wide

        // ---------- Data-theft / recon modules ----------
        $d1  = "Starting data theft..." ascii wide
        $d2  = "Data theft completed" ascii wide
        $d3  = "\\WiFi_Passwords.json" ascii wide
        $d4  = "\\Discord_Tokens.json" ascii wide
        $d5  = "\\Browser_Passwords.json" ascii wide
        $d6  = "\\Browser_Cookies.json" ascii wide
        $d7  = "\\SystemInfo.json" ascii wide
        $d8  = "netsh wlan show profile" ascii wide
        $d9  = "\\discord\\Local Storage\\leveldb" ascii wide

        // ---------- C2 / webhook (network IOCs) ----------
        $c1  = "/api/victim/log" ascii wide
        $c2  = "/api/victim/data" ascii wide
        $c3  = "/api/victim/command?victim_id=" ascii wide
        $c4  = "/api/victim/archive" ascii wide
        $c5  = "discord.com/api/webhooks/1454863659766513665" ascii wide
        $c6  = "http://192.168.1.23:5000" ascii wide
        $c7  = "http://files.catbox.moe/azo8qi.mp3" ascii wide

        // ---------- Ransom UI / autorun.inf ----------
        $u1  = "Yor files have been encrypted. Send $50 to MEDS to decrypt." ascii wide
        $u2  = "Enter the decryption key to restore yor data" ascii wide
        $u3  = "open=fsociety.exe" ascii wide
        $u4  = "action=Open folder to view files" ascii wide
        $u5  = "\\\\%s\\%s\\Windows\\Temp\\fsociety.exe" ascii wide

    condition:
        uint16(0) == 0x5A4D and                             // PE (MZ)
        filesize < 15MB and
        (
            2 of ($b*) or                                   // any 2 brand markers = strong hit
            (1 of ($b*) and 2 of ($c*)) or                 // brand + C2
            (1 of ($b*) and 2 of ($p*)) or                 // brand + persistence
            (1 of ($w*) and 1 of ($b*)) or                 // wiper + brand
            6 of ($b*, $p*, $w*, $f*, $d*, $c*, $u*)       // broad hunting fallback
        )
}
