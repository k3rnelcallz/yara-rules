rule ELF_PPC_DDoSBot_HTTP_Flooder {
    meta:
        description = "ELF32 PPC DDoS Bot with HTTP flood capability"
        author = "Analysis"
        
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