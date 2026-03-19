import "elf"

rule multi_protocol_backdoor_curl_openssl {
    meta:
        sha =  "bcf35e2480f41447067f92db298ec77848bbb056cbe28a47acfba6d046132650"
        filename = "MALWARE.efi"
        tags = "elf, trojan, mirai, backdoor"

    strings:
        // Cryptographic Identifiers
        $crypto1 = "Poly1305 for x86_64" ascii
        $crypto2 = "RC4 for x86_64, CRYPTOGAMS" ascii
        $crypto3 = "ChaCha20-Poly1305" ascii

        // Botnet/Backdoor Protocol Strings
        $proto1 = "CONNECT_ONLY is required" ascii
        $proto2 = "Sec-WebSocket-Key" ascii
        $proto3 = "SOCKS5 connect request" ascii
        $proto4 = "UID FETCH %s BODY" ascii
        $proto5 = "RCPT TO:<%s>" ascii

        // Bruteforce patterns
        $brute1 = "LOGIN %s %s" ascii
        $brute2 = "AUTHENTICATE %s %s" ascii
        $brute3 = "User-Agent: %s" ascii

    condition:

        uint32be(0) == 0x464c457f and
        (any of ($crypto*)) and (3 of ($proto*) or 2 of ($brute*))
}
