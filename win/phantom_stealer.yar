rule phantom_stealer {
	meta:
		author = "k3rnellcallz"
		date = "16-07-26"
		family = "stealer/cryptor"
		sha = "b8719f39f6aceed3cf69ae9b49fbeb69da4e12ad8273296dcb004290f81eab22, 0593b9a2c09ed235e48ceb2b86b64feb9de1eaa58893af1dce532da959f27c69"
	
	strings: 

		//--- threatactor branding, using discord, telegram, and browser fetch--- 
		$b = "PhantomStealer"
		$d = "DiscordCreditCardRecovery"
		$s = "TelegramCookiesRecovery"
		$n = "get_ChromiumBrowsersFound"

		// -- exfilteration methods used -- 
		$e = "SendScreenShotSmtp"
		$e1 = "SmtpCreditCardRecovery"
		$e2 = "SendClipBoardSmtp"
		$e3 = "SendDiscordFile"
		$e4 = "ExportToNetscapeFormat"
		$e5 = "ExtractEmbeddedDumpTool"
		$e6 = "MultiFiledownloader"

		// --- get cookie, cards, av info. --- 

		$a = "GetExpiringSoonCards"
		$a1 = "GetExpiredCards"
		$a2 = "GetValidCookies"
		$a3 = "GetAntivirus"
		$a4 = "GenerateRandomData"
		$a5 = "DecryptBase64"
		$a6 = "ExportToNetscapeFormat"
		$a7 = "ExtractEmbeddedDumpTool"
		$a8 = "GrabDirectoryAsync"
		$a9 = "GetAllCookies"
		$a10 = "GetExpiredCards"
		$a11 = "GetExpiringSoonCards"
		$a12 = "PrintAllRecoveries"
		$a13 = "get_TotalCreditCardCount"
		$a14 = "get_TotalCookieCount"
		$a15 = "TryDecryptCreditCardNumber"
		$a16 = "GetValidCookies"
		$a17 = "SandBox"
		$a18 = "SaveAndSendToFile"
		$a19 = "HasAnalysisToolsRunning"
		$a20 = "CaptureFullScreen"
		$a21 = "GetCookiesByDomain"
		$a22 = "GetCreditCardsByCardholder"
		$a23 = "GetCreditCardsByBrowser"

	condition: 
		3 of ($e*) and 
		5 of ($a*) and $b and $d and $s and $n 

}
