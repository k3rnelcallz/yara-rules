rule ELF_PPC_DDoSBot_HTTP_Flooder {
    meta:
        description = "ELF32 PPC DDoS Bot with HTTP flood capability"
        author = "k3rnelcallz"
        sha256 = "d794ff8d3dcf66118ce0cc12ea946e071a1af8e6a6f889b1295415268f4ddba2"
        ref = "https://urlhaus.abuse.ch/url/3850305/"
        
    strings:
        $c2_token   = "token=%s&guid=%s"
        $getinfo    = "getinfo xxx"
        $http_flood = "Connection: keep-alive\r\nContent-Length: 0"
        $samp       = "SAMPg"
        $bot_start  = "shit bot commenced"
        $ua_webkit  = "AppleWebKit/537.36"
        $watchdog   = "watchdog"
        
    condition:
        uint16(0) == 0x457f and    // ELF magic
        4 of ($c2_token, $getinfo, $http_flood, $samp, $bot_start, $ua_webkit, $watchdog)
}