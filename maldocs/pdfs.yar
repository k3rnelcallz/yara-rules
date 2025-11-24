rule pdf1 {
	meta: 
		author = "k3rnelcallz"
		description = "Phishing pdf drops malicious ZIP"	
		reference = "https://bazaar.abuse.ch/sample/36caf3ba9df00968517e783cc25747cb9e1b0c30124c1f6d75bf2341f98f4c7b/"
		filename = "Tax Payment Notice.pdf"
		sample = "36caf3ba9df00968517e783cc25747cb9e1b0c30124c1f6d75bf2341f98f4c7b"

	strings: 
		$magic = { 25 50 44 46 } //%PDF
		$url = "http://www.itdd.club/" ascii nocase

	condition:
		$magic and 
		$url 		
}	
rule pdf2: obs_url 
{ 	meta: 
		author = "k3rnelcallz"
		desc = "social eng russian lang"
		sample = "fc31dfb6b521c5cce4a13c61fe86547d12bfeb75cc8466283dfccb74250734b0"
		
	strings:
		$magic = "%PDF-"
		$uri = "/S /URI"
		$button = "/FT /Btn"
		
	condition: 
		$magic and $uri and $button 
}