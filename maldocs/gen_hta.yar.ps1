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