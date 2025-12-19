rule xml_detects_CHMOD77_Network
{ 
	meta: 
		author = "k3rnelcallz"
		description = "xml rule for Network and chmod detection"
		sample = "608f19d820f0e79a534724412b18fb3e1720a5361371fd91fc42d7f7fc398c10"
		sample2 = "d398255e433f8448063cedc9a518ad5bcac30eebaabadee33b4840f455bed8f3"
		sample3 = "f9fa1bf29cacff53e39865e45fc05d2164314c0f2877f9720ca604d50f00df71"
	
	strings:
		$x1 = "http" 
		$x2 = "curl"
		$x3 = "chmod 777"
	
	condition:
		$x3 or any of ($x1, $x2)	
}