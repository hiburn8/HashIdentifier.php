<php # Author: Hiburn8 (hiburn8.org)?>

<pre>

  _    _           _       _____    _            _   _  __ _
 | |  | |         | |     |_   _|  | |          | | (_)/ _(_)
 | |__| | __ _ ___| |__     | |  __| | ___ _ __ | |_ _| |_ _  ___ _ __
 |  __  |/ _` / __| '_ \    | | / _` |/ _ \ '_ \| __| |  _| |/ _ \ '__|
 | |  | | (_| \__ \ | | |  _| || (_| |  __/ | | | |_| | | | |  __/ |
 |_|  |_|\__,_|___/_| |_| |_____\__,_|\___|_| |_|\__|_|_| |_|\___|_|
 -------------------------------------------------PHP-Edition----------
	Version: 1.1
	Coded By: Hiburn8
	Original Python Code By: Psycho_Coder <https://psychocoder.github.io/>
 ----------------------------------------------------------------------

USAGE: HashIdentifier.php?h=d9729feb74992cc3482b350163a1a010
</pre>

<?php
error_reporting(E_ERROR | E_PARSE);

$HASHES = array
  (
	array("Blowfish(Eggdrop)", "^\+[a-zA-Z0-9\/\.]{12}$"),
	array("Blowfish(OpenBSD) - Hashcat Mode 3200", "^\$2a\$[0-9]{0,2}?\$[a-zA-Z0-9\/\.]{53}$"),
	array("Blowfish crypt  - Hashcat Mode 3200", "^\$2[axy]{0,1}\$[a-zA-Z0-9./]{8}\$[a-zA-Z0-9./]{1,}$"),
	array("DES(Unix)", "DES crypt", "DES hash(Traditional)", "^.{0,2}[a-zA-Z0-9\/\.]{11}$"),
	array("MD5(Unix)", "^\$1\$.{0,8}\$[a-zA-Z0-9\/\.]{22}$"),
	array("MD5(APR) - Hashcat Mode 1600", "Apache MD5 - Hashcat Mode 1600", "^\$apr1\$.{0,8}\$[a-zA-Z0-9\/\.]{22}$"),
	array("MD5(MyBB >= 1.2) - Hashcat Mode 2811", "^[a-fA-F0-9]{32}:[a-z0-9]{8}$"),
	array("MD5(ZipMonster)", "^[a-fA-F0-9]{32}$"),
	array("MD5 crypt", "FreeBSD MD5", "Cisco-IOS MD5 - Hashcat Mode 500", "^\$1\$[a-zA-Z0-9./]{8}\$[a-zA-Z0-9./]{1,}$"),
	array("MD5 apache crypt", "^\$apr1\$[a-zA-Z0-9./]{8}\$[a-zA-Z0-9./]{1,}$"),
	array("MD5(Joomla) - Hashcat Mode 400", "^[a-fA-F0-9]{32}:[a-zA-Z0-9]{16,32}$"),
	array("MD5(Wordpress) - Hashcat Mode 400", "^\$P\$[a-zA-Z0-9\/\.]{31}$"),
	array("MD5(phpBB3) - Hashcat Mode 400", "^\$H\$[a-zA-Z0-9\/\.]{31}$"),
	array("MD5(Cisco PIX) - Hashcat Mode 2400", "^[a-zA-Z0-9\/\.]{16}$"),
	array("MD5(osCommerce) - Hashcat Mode 21", "xt:Commerce - Hashcat Mode 21", "^[a-fA-F0-9]{32}:[a-zA-Z0-9]{2}$"),
	array("MD5(Palshop)", "^[a-fA-F0-9]{51}$"),
	array("MD5(IP.Board >= 2 - Hashcat Mode 2811)", "^[a-fA-F0-9]{32}:.{5}$"),
	array("MD5(Chap) - Hashcat Mode 4800", "^[a-fA-F0-9]{32}:[0-9]{32}:[a-fA-F0-9]{2}$"),
	array("Juniper Netscreen/SSG (ScreenOS)", "^[a-zA-Z0-9]{30}:[a-zA-Z0-9]{4,}$"),
	array("Fortigate (FortiOS)  - Hashcat Mode 7000", "^[a-fA-F0-9]{47}$"),
	array("Minecraft(Authme)", "^\$sha\$[a-zA-Z0-9]{0,16}\$[a-fA-F0-9]{64}$"),
	array("Lotus Domino", "^\(?[a-zA-Z0-9\+\/]{20}\)?$"),
	array("Lineage II C4", "^0x[a-fA-F0-9]{32}$"),
	array("CRC-96(ZIP)", "^[a-fA-F0-9]{24}$"),
	array("NT crypt", "^\$3\$[a-zA-Z0-9./]{8}\$[a-zA-Z0-9./]{1,}$"),
	array("Skein-1024", "^[a-fA-F0-9]{256}$"),
	array("RIPEMD-320", "RIPEMD-320(HMAC)", "^[A-Fa-f0-9]{80}$"),
	array("EPi hash - Hashcat Mode 123", "^0x[A-F0-9]{60}$"),
	array("EPiServer 6.x < v4  - Hashcat Mode 141", "^\$episerver\$\*0\*[a-zA-Z0-9]{22}==\*[a-zA-Z0-9\+]{27}$"),
	array("EPiServer 6.x >= v4 - Hashcat Mode 1441", "^\$episerver\$\*1\*[a-zA-Z0-9]{22}==\*[a-zA-Z0-9]{43}$"),
	array("Cisco IOS SHA256 - Hashcat Mode 5700", "^[a-zA-Z0-9]{43}$"),
	array("SHA-1(Django) - Hashcat Mode 124", "^sha1\$.{0,32}\$[a-fA-F0-9]{40}$"),
	array("SHA-1 crypt", "^\$4\$[a-zA-Z0-9./]{8}\$[a-zA-Z0-9./]{1,}$"),
	array("SHA-1(Hex)", "^[a-fA-F0-9]{40}$"),
	array("SHA-1(LDAP) Base64 - Hashcat Mode 101", "Netscape LDAP SHA - Hashcat Mode 101", "NSLDAP - Hashcat Mode 101", "^\{SHA\}[a-zA-Z0-9+/]{27}=$"),
	array("SHA-1(LDAP) Base64 + salt", "^\{SSHA\}[a-zA-Z0-9+/]{28,}[=]{0,3}$"),
	array("SHA-512(Drupal)", "^\$S\$[a-zA-Z0-9\/\.]{52}$"),
	array("SHA-512 crypt", "^\$6\$[a-zA-Z0-9./]{8}\$[a-zA-Z0-9./]{1,}$"),
	array("SHA-256(Django)", "^sha256\$.{0,32}\$[a-fA-F0-9]{64}$"),
	array("SHA-256 crypt", "^\$5\$[a-zA-Z0-9./]{8}\$[a-zA-Z0-9./]{1,}$"),
	array("SHA-384(Django)", "^sha384\$.{0,32}\$[a-fA-F0-9]{96}$"),
	array("SHA-256(Unix) - Hashcat Mode 7400", "^\$5\$.{0,22}\$[a-zA-Z0-9\/\.]{43,69}$"),
	array("SHA-512(Unix) - Hashcat Mode 1800", "^\$6\$.{0,22}\$[a-zA-Z0-9\/\.]{86}$"),
	array("SHA-384", "SHA3-384", "Skein-512(384)", "Skein-1024(384)", "^[a-fA-F0-9]{96}$"),
	array("SHA-512  - Hashcat Mode 1700", "SHA-512(HMAC)", "SHA3-512", "Whirlpool", "SALSA-10", "SALSA-20", "Keccak-512", "Skein-512", "Skein-1024(512)", "^[a-fA-F0-9]{128}$"),
	array("SSHA-1", "^({SSHA})?[a-zA-Z0-9\+\/]{32,38}?(==)?$"),
	array("SSHA-1(Base64) - Hashcat Mode 111", "Netscape LDAP SSHA - Hashcat Mode 111", "NSLDAPS - Hashcat Mode 111", "^\{SSHA\}[a-zA-Z0-9]{32,38}?(==)?$"),
	array("SSHA-512(Base64) - Hashcat Mode 1711", "LDAP {SSHA512} - Hashcat Mode 1711", "^\{SSHA512\}[a-zA-Z0-9+]{96}$"),
	array("Oracle 11g - Hashcat Mode 112", "^S:[A-Z0-9]{60}$"),
	array("SMF >= v1.1 - Hashcat Mode 121", "^[a-fA-F0-9]{40}:[0-9]{8}&"),
	array("MySQL 5.x - Hashcat Mode 300", "^\*[a-f0-9]{40}$"),
	array("MySQL 3.x - Hashcat Mode 200", "DES(Oracle)", "LM", "VNC", "FNV-164", "^[a-fA-F0-9]{16}$"),
	array("OSX v10.7 - Hashcat Mode 1722", "^[a-fA-F0-9]{136}$"),
	array("OSX v10.8 - Hashcat Mode 7100", "^\$ml\$[a-fA-F0-9$]{199}$"),
	array("SAM(LM_Hash:NT_Hash)", "^[a-fA-F0-9]{32}:[a-fA-F0-9]{32}$"),
	array("MSSQL(2000) - Hashcat Mode 131", "^0x0100[a-f0-9]{0,8}?[a-f0-9]{80}$"),
	array("MSSQL(2005) - Hashcat Mode 132", "MSSQL(2008)", "^0x0100[a-f0-9]{0,8}?[a-f0-9]{40}$"),
	array("MSSQL(2012) - Hashcat Mode 1731", "^0x02[a-f0-9]{0,10}?[a-f0-9]{128}$"),
	array("substr(md5(\$pass),0,16)", "substr(md5(\$pass),16,16)", "substr(md5(\$pass),8,16)", "CRC-64", "^[a-fA-F0-9./]{16}$"),
	array("MySQL 4.x - Hashcat Mode 300", "SHA-1  - Hashcat Mode 100", "HAVAL-160", "SHA-1(MaNGOS)", "SHA-1(MaNGOS2)", "TIGER-160", "RIPEMD-160", "RIPEMD-160(HMAC)", "TIGER-160(HMAC)", "Skein-256(160)", "Skein-512(160)", "^[a-f0-9]{40}$"),
	array("SHA-256 - Hashcat Mode 1400", "SHA-256(HMAC)", "SHA-3(Keccak)", "GOST R 34.11-94 - Hashcat Mode 6900", "RIPEMD-256", "HAVAL-256", "Snefru-256", "Snefru-256(HMAC)", "RIPEMD-256(HMAC)", "Keccak-256", "Skein-256", "Skein-512(256)", "^[a-fA-F0-9]{64}$"),
	array("SHA-1(Oracle)", "HAVAL-192", "OSX v10.4, v10.5, v10.6 - Hashcat Mode 122", "Tiger-192", "TIGER-192(HMAC)", "^[a-fA-F0-9]{48}$"),
	array("SHA-224", "SHA-224(HMAC)", "HA121AL-224", "Keccak-224", "Skein-256(224)", "Skein-512(224)", "^[a-fA-F0-9]{56}$"),
	array("Adler32", "FNV-32", "ELF-32", "Joaat", "CRC-32", "CRC-32B", "GHash-32-3", "GHash-32-5", "FCS-32", "Fletcher-32", "XOR-32", "^[a-f0-9]{8}$"),
	array("CRC-16-CCITT", "CRC-16", "FCS-16", "^[a-fA-F0-9]{4}$"),
	array("MD5(HMAC(Wordpress))", "MD5(HMAC)", "MD5  - Hashcat Mode 0", "RIPEMD-128", "RIPEMD-128(HMAC)", "Tiger-128", "Tiger-128(HMAC)", "RAdmin v2.x - Hashcat Mode 9800", "NTLM - Hashcat Mode 1000", "Domain Cached Credentials(DCC) - Hashcat Mode 1100", "Domain Cached Credentials 2(DCC2)", "MD4 - Hashcat Mode 900", "MD2", "MD4(HMAC)", "MD2(HMAC)", "Snefru-128", "Snefru-128(HMAC)", "HAVAL-128", "HAVAL-128(HMAC)", "Skein-256(128)", "Skein-512(128)", "MSCASH2", "^[0-9A-Fa-f]{32}$")
);

function identify_hashes($input_hash, $HASHES){
	$res = array();

	foreach ($HASHES as $items) {
	    if(preg_match("/".end($items)."/",$input_hash)){
			for($i=0;$i<(count($items)-1);$i++){
				array_push($res, $items[$i]);
			}
	    }
	}
    return $res;
}

if(isset($_GET["h"]) && (!empty($_GET["h"]))){ 
	$input_hash = $_GET["h"];
	$results = identify_hashes($input_hash, $HASHES);

	if (empty($results)){
		echo "Sorry we are unable to identify the type of hash";
	}
	else{
		if (count($results) > 2){
			echo "Most Probable Hash Algorithms found:<br>";
			echo "[+] " . $results[0] . "<br>";
			echo "[+] " . $results[1] . "<br><br>";

			echo "Other Possible Hash Algorithms found:<br>";
			for($i = 2; $i < (count($results)); ++$i) {
    			echo "[+] " . $results[$i] . "<br>";
			}
		}
		else{
			echo "Hash Algorithms found:<br>";
			for($i = 0; $i < (count($results)); ++$i) {
    			echo "[+] " . $results[$i] . "<br>";
			}
		}
	}
}
else{
	echo "Please enter the hash. No input hash found.";
}
?>

<!--
TODO:

    10 = md5($pass.$salt)
    20 = md5($salt.$pass)
    30 = md5(unicode($pass).$salt)
    40 = md5($salt.unicode($pass))
    50 = HMAC-MD5 (key = $pass)
    60 = HMAC-MD5 (key = $salt)
   110 = sha1($pass.$salt)
   120 = sha1($salt.$pass)
   130 = sha1(unicode($pass).$salt)
   140 = sha1($salt.unicode($pass))
   150 = HMAC-SHA1 (key = $pass)
   160 = HMAC-SHA1 (key = $salt)
   400 = phpass
  1410 = sha256($pass.$salt)
  1420 = sha256($salt.$pass)
  1430 = sha256(unicode($pass).$salt)
  1431 = base64(sha256(unicode($pass)))
  1440 = sha256($salt.unicode($pass))
  1450 = HMAC-SHA256 (key = $pass)
  1460 = HMAC-SHA256 (key = $salt)
  1710 = sha512($pass.$salt)
  1720 = sha512($salt.$pass)
  1730 = sha512(unicode($pass).$salt)
  1740 = sha512($salt.unicode($pass))
  1750 = HMAC-SHA512 (key = $pass)
  1760 = HMAC-SHA512 (key = $salt)
  2410 = Cisco-ASA MD5
  2500 = WPA/WPA2
  2600 = Double MD5
  3200 = bcrypt, Blowfish(OpenBSD)
  3300 = MD5(Sun)
  3500 = md5(md5(md5($pass)))
  3610 = md5(md5($salt).$pass)
  3710 = md5($salt.md5($pass))
  3720 = md5($pass.md5($salt))
  3800 = md5($salt.$pass.$salt)
  3910 = md5(md5($pass).md5($salt))
  4010 = md5($salt.md5($salt.$pass))
  4110 = md5($salt.md5($pass.$salt))
  4210 = md5($username.0.$pass)
  4300 = md5(strtoupper(md5($pass)))
  4400 = md5(sha1($pass))
  4500 = Double SHA1
  4600 = sha1(sha1(sha1($pass)))
  4700 = sha1(md5($pass))
  4800 = iSCSI CHAP authentication
  4900 = sha1($salt.$pass.$salt)
  5000 = SHA-3(Keccak)
  5100 = Half MD5
  5200 = Password Safe SHA-256
  5300 = IKE-PSK MD5
  5400 = IKE-PSK SHA1
  5500 = NetNTLMv1-VANILLA / NetNTLMv1-ESS
  5600 = NetNTLMv2
  5800 = Android PIN
  6300 = AIX {smd5}
  6400 = AIX {ssha256}
  6500 = AIX {ssha512}
  6700 = AIX {ssha1}
  7200 = GRUB 2
  7300 = IPMI2 RAKP HMAC-SHA1
  7900 = Drupal7
  8400 = WBB3, Woltlab Burning Board 3
  8900 = scrypt
  9200 = Cisco $8$
  9300 = Cisco $9$
 10000 = Django (PBKDF2-SHA256)
 10200 = Cram MD5
 10300 = SAP CODVN H (PWDSALTEDHASH) iSSHA-1
 11000 = PrestaShop
 11100 = PostgreSQL Challenge-Response Authentication (MD5)
 11200 = MySQL Challenge-Response Authentication (SHA1)
 11400 = SIP digest authentication (MD5)

* Specific hash types:
   11 = Joomla < 2.5.18
   12 = PostgreSQL   
   23 = Skype
  124 = Django (SHA-1)
  133 = PeopleSoft
 1421 = hMailServer
 2611 = vBulletin < v3.8.5
 2612 = PHPS
 2711 = vBulletin > v3.8.5
3711 = Mediawiki B type
 3721 = WebEdition CMS
 7600 = Redmine Project Management Web App
-->



















