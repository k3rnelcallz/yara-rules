rule hta_dropper {
	
	meta: 
		description = "hta file with wscript"
		author = "k3rnelcallz"
		reference = "malwarebazaar"
		sha256 = "59707a70be5a6f88ec5e4a404479ba69457d8b34358e58e9399d2f327a2e5005"

	strings: 
		/* hta indicators */ 
		$hta1 = {3C 68 74 6D 6C 3E}  // magic_bytes
		$hta2 = "<HTA:APPLICATION" nocase 


		/* vbscripts for automation */
		$vbs1 = "CreateObject(\"WScript.Shell\")" nocase
		$vbs2 = "Scripting.FileSystemObject" nocase
		$vbs3 = "CreateObject(\"MSXML2." nocase
		$vbs4 = "CreateObject(\"ADODB." nocase

		/* payload download and execute */
		$dl1 = "ServerXMLHTTP" nocase
		$dl2 = "http.Open" nocase
    	$dl3 = "SaveToFile" nocase

    	/* persistence setup */
    	$persist1 = "CurrentVersion\\Run" nocase
    	$persist2 = "/sc onlogon" nocase
    	$persist3 = "schtasks /create" nocase

	condition: 	
		($hta2 or $hta1) and
		(( $vbs1 and $vbs4 and $dl1 and $dl3 ) or ( $vbs2 and $vbs3 and $dl2))
		and
		($persist1 and $persist2 and $persist3)
}

 rule hta_hiding_window 
{
    meta:
    	author = "k3rnelcallz"
        description = "Detects JavaScript hiding browser windows via resizeTo/moveTo"
        sha256 = "2e5934e38666e63c23f5906e5175a1bf5c230972cb57bb8c07dab0630921fa43"
        ref = "malwarebazaar"

    strings:
    // ActiveX/WMI usage
        $a1 = /ActiveXObject/i
        $a2  = /GetObject/i
        $a3   = /ExecQuery/i
        $a4  = /Enumerator/i

        // Window hiding tricks
        $r = /window\.resizeTo\s*\(/i
        $m = /window\.moveTo\s*\(/i

    condition:
        $r and $m and any of ($a*)
 }


