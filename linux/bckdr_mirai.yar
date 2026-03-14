import "elf"

rule linux_backdoor_persistence
{
	meta:
		sha = "6d10382a478f71b121be340ff622ff62e58458f290f35217b1b0fd23865a8b4e"
		filename = "random"
		tags = "mirai, trojan, botnet, backdoor" 
	 
	strings: 
	// persistence mechanism	
		 $a1= "Description=AutoStart Service" ascii
		 $a2= "After=network-online.target" ascii
		 $a3= "Requires=network-online.target" ascii
		 $a4= "WantedBy=multi-user.target" ascii
		 $a5= "/etc/systemd/system/%s.service" ascii	 
	
	//network activity 
		$c1_domain= /xd\.killaurasleep\.top/ nocase
		$c2_ip= /151\.240\.13\.91/ nocase
	
	//downloading commands
		$n1= "cd /tmp;rm -rf bkd;wget http://"
		$n2= "chmod +x bkd;./bkd;rm -rf bkd"
	
		 
	condition: 
		//uint32(0) == 0x7F454C46  and  // Elf magic
		//uint32be(0) == 0x7f454c46 and 
		elf.machine == elf.EM_X86_64 and
		filesize < 500KB and
		(4 of ($a*)) 
		and (all of ($c*)) and
		(any of ($n*))
}