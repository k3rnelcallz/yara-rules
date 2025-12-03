rule pdf1 
{
	meta: 
		author = "k3rnelcallz"
		description = "Phishing pdf drops malicious ZIP"	
		filename = "Tax Payment Notice.pdf"
		sha256 = "f9e832c9cd54668c35bab5077df30af51ced5f9473d570e73b369437a632523a"
        creation_date = "28-11-25"
		last_modified = "28-11-25"
		source = "Malwarebazaar"
		category = "Info"

	strings: 
		$magic = { 25 50 44 46 } //%PDF
		$url = "http://" ascii nocase

	condition:
		$magic and
		$url 		
}	
rule pdf2
{ 	meta: 
		author = "k3rnelcallz"
		desc = "social eng russian lang"
		sample = "fc31dfb6b521c5cce4a13c61fe86547d12bfeb75cc8466283dfccb74250734b0"
		sha256 = "f9e832c9cd54668c35bab5077df30af51ced5f9473d570e73b369437a632523a"
        creation_date = "28-11-25"
		last_modified = "28-11-25"
		source = "Malwarebazaar"
		category = "Info"
		
	strings:
		$magic = "%PDF-"
		$uri = "/S /URI"
		$button = "/FT /Btn"
		
	condition: 
		$magic and $uri and $button 
}
rule is_PDF 
{
	meta: 
		author = "k3rnelcallz"
		description = "Rule identifying PDF files"
		sha256 = "f9e832c9cd54668c35bab5077df30af51ced5f9473d570e73b369437a632523a"		
		creation_date = "28-11-25"
		last_modified = "03-12-25"
		source = "Malwarebazaar"
		category = "Info"

	strings:
		$pdf = {25 50 44 46 2D} //%PDF-

	condition:
		$pdf at 0
}

rule url_in_PDF
{
	meta: 
		author = "k3rnelcallz"
		description = "Urls in PDF files"
		sah256 = "f9e832c9cd54668c35bab5077df30af51ced5f9473d570e73b369437a632523a"		
		creation_date = "28-11-25"
		last_modified = "03-12-25"
		source = "Malwarebazaar"
		category = "Info"

	strings:
		$uri_key = "/URI"
		$http = "http:"
		$https = "https:"

	condition:
		is_PDF and (2 of ($uri_key, $http, $https))		
}

rule Suspicious_Key_in_PDF
{
	meta: 
		author = "k3rnelcallz"
		description = "Rule identifying PDF files"
		sha256 = "fc31dfb6b521c5cce4a13c61fe86547d12bfeb75cc8466283dfccb74250734b0"
		creation_date = "28-11-25"
		last_modified = "03-12-25"
		source = "Malwarebazaar"
		category = "Info"

	strings:
		$open_action = "/OpenAction"
		$acro_form = "/AcroForm"

	condition:
		is_PDF and any of ($open_action, $acro_form)
}
