
import "elf"

rule mirai_aarch64_arm { 

	meta: 
		Sha256 = “9ff218d40f0810b1f8dfaa9f667432fb278fb8d53cc33e89bd20eca0406691b6”
		filename =“aarch64”
		filesize =  “117.84 KB”
		tags = “linux, mirai, password bruteforcing, telnet, aarch64” 


	strings: 
		// searching for system path

		$path1 = "/proc/cpuinfo"  ascii
		$path2 = "/proc/devices" ascii
		$path3 = "/proc/self/exe" ascii
		$path4 = "/proc/net/tcp" ascii
		$path5 = "/dev/null" ascii
		$path6 = "/dev/console" ascii
		$path7 = "/dev/urandom" ascii

		// password bruteforcing
		$b1 = "password"       nocase 
		$b2 = "supportadmin" nocase
		$b3 = "telnetadmin" nocase
		$b4 = "admintelecom" nocase
		$b5 = "on_support" nocase
		$b6 = "boards123" nocase
		$b7 = "onuser123" nocase
		$b8 = "tplinkgp" nocase
		$b9 = "support_gp" nocase
		$b10 = "serviceC0mp!" nocase
		$b11 = "linuxshell" nocase
		$b12 = "haver123" nocase
		$b13 = "88888888" nocase
		$b14 = "cisco123" nocase
		$b15 = "admintelecom1" nocase

		// network commands
		$n1 = "ping; sh" nocase
		$n2 = "/bin/busybox FASTCAT" nocase

	condition: 

		uint32be(0) == 0x7F454C46 and
		(4 of ($path*)) and (8 of ($b*)) and (any of ($n*))

}
