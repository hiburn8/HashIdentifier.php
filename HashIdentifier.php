<php # Author: Hiburn8 (hiburn8.org)?>

<pre>

  _    _           _       _____    _            _   _  __ _
 | |  | |         | |     |_   _|  | |          | | (_)/ _(_)
 | |__| | __ _ ___| |__     | |  __| | ___ _ __ | |_ _| |_ _  ___ _ __
 |  __  |/ _` / __| '_ \    | | / _` |/ _ \ '_ \| __| |  _| |/ _ \ '__|
 | |  | | (_| \__ \ | | |  _| || (_| |  __/ | | | |_| | | | |  __/ |
 |_|  |_|\__,_|___/_| |_| |_____\__,_|\___|_| |_|\__|_|_| |_|\___|_|
 -------------------------------------------------PHP-Edition----------
	Version: 1
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
	array("Blowfish(OpenBSD)", "^\$2a\$[0-9]{0,2}?\$[a-zA-Z0-9\/\.]{53}$"),
	array("Blowfish crypt", "^\$2[axy]{0,1}\$[a-zA-Z0-9./]{8}\$[a-zA-Z0-9./]{1,}$"),
	array("DES(Unix)", "DES crypt", "DES hash(Traditional)", "^.{0,2}[a-zA-Z0-9\/\.]{11}$"),
	array("MD5(Unix)", "^\$1\$.{0,8}\$[a-zA-Z0-9\/\.]{22}$"),
	array("MD5(APR)", "Apache MD5", "^\$apr1\$.{0,8}\$[a-zA-Z0-9\/\.]{22}$"),
	array("MD5(MyBB)", "^[a-fA-F0-9]{32}:[a-z0-9]{8}$"),
	array("MD5(ZipMonster)", "^[a-fA-F0-9]{32}$"),
	array("MD5 crypt", "FreeBSD MD5", "Cisco-IOS MD5", "^\$1\$[a-zA-Z0-9./]{8}\$[a-zA-Z0-9./]{1,}$"),
	array("MD5 apache crypt", "^\$apr1\$[a-zA-Z0-9./]{8}\$[a-zA-Z0-9./]{1,}$"),
	array("MD5(Joomla)", "^[a-fA-F0-9]{32}:[a-zA-Z0-9]{16,32}$"),
	array("MD5(Wordpress)", "^\$P\$[a-zA-Z0-9\/\.]{31}$"),
	array("MD5(phpBB3)", "^\$H\$[a-zA-Z0-9\/\.]{31}$"),
	array("MD5(Cisco PIX)", "^[a-zA-Z0-9\/\.]{16}$"),
	array("MD5(osCommerce)", "xt:Commerce", "^[a-fA-F0-9]{32}:[a-zA-Z0-9]{2}$"),
	array("MD5(Palshop)", "^[a-fA-F0-9]{51}$"),
	array("MD5(IP.Board)", "^[a-fA-F0-9]{32}:.{5}$"),
	array("MD5(Chap)", "^[a-fA-F0-9]{32}:[0-9]{32}:[a-fA-F0-9]{2}$"),
	array("Juniper Netscreen/SSG (ScreenOS)", "^[a-zA-Z0-9]{30}:[a-zA-Z0-9]{4,}$"),
	array("Fortigate (FortiOS)", "^[a-fA-F0-9]{47}$"),
	array("Minecraft(Authme)", "^\$sha\$[a-zA-Z0-9]{0,16}\$[a-fA-F0-9]{64}$"),
	array("Lotus Domino", "^\(?[a-zA-Z0-9\+\/]{20}\)?$"),
	array("Lineage II C4", "^0x[a-fA-F0-9]{32}$"),
	array("CRC-96(ZIP)", "^[a-fA-F0-9]{24}$"),
	array("NT crypt", "^\$3\$[a-zA-Z0-9./]{8}\$[a-zA-Z0-9./]{1,}$"),
	array("Skein-1024", "^[a-fA-F0-9]{256}$"),
	array("RIPEMD-320", "RIPEMD-320(HMAC)", "^[A-Fa-f0-9]{80}$"),
	array("EPi hash", "^0x[A-F0-9]{60}$"),
	array("EPiServer 6.x < v4", "^\$episerver\$\*0\*[a-zA-Z0-9]{22}==\*[a-zA-Z0-9\+]{27}$"),
	array("EPiServer 6.x >= v4", "^\$episerver\$\*1\*[a-zA-Z0-9]{22}==\*[a-zA-Z0-9]{43}$"),
	array("Cisco IOS SHA256", "^[a-zA-Z0-9]{43}$"),
	array("SHA-1(Django)", "^sha1\$.{0,32}\$[a-fA-F0-9]{40}$"),
	array("SHA-1 crypt", "^\$4\$[a-zA-Z0-9./]{8}\$[a-zA-Z0-9./]{1,}$"),
	array("SHA-1(Hex)", "^[a-fA-F0-9]{40}$"),
	array("SHA-1(LDAP) Base64", "Netscape LDAP SHA", "NSLDAP", "^\{SHA\}[a-zA-Z0-9+/]{27}=$"),
	array("SHA-1(LDAP) Base64 + salt", "^\{SSHA\}[a-zA-Z0-9+/]{28,}[=]{0,3}$"),
	array("SHA-512(Drupal)", "^\$S\$[a-zA-Z0-9\/\.]{52}$"),
	array("SHA-512 crypt", "^\$6\$[a-zA-Z0-9./]{8}\$[a-zA-Z0-9./]{1,}$"),
	array("SHA-256(Django)", "^sha256\$.{0,32}\$[a-fA-F0-9]{64}$"),
	array("SHA-256 crypt", "^\$5\$[a-zA-Z0-9./]{8}\$[a-zA-Z0-9./]{1,}$"),
	array("SHA-384(Django)", "^sha384\$.{0,32}\$[a-fA-F0-9]{96}$"),
	array("SHA-256(Unix)", "^\$5\$.{0,22}\$[a-zA-Z0-9\/\.]{43,69}$"),
	array("SHA-512(Unix)", "^\$6\$.{0,22}\$[a-zA-Z0-9\/\.]{86}$"),
	array("SHA-384", "SHA3-384", "Skein-512(384)", "Skein-1024(384)", "^[a-fA-F0-9]{96}$"),
	array("SHA-512", "SHA-512(HMAC)", "SHA3-512", "Whirlpool", "SALSA-10", "SALSA-20", "Keccak-512", "Skein-512", "Skein-1024(512)", "^[a-fA-F0-9]{128}$"),
	array("SSHA-1", "^({SSHA})?[a-zA-Z0-9\+\/]{32,38}?(==)?$"),
	array("SSHA-1(Base64)", "Netscape LDAP SSHA", "NSLDAPS", "^\{SSHA\}[a-zA-Z0-9]{32,38}?(==)?$"),
	array("SSHA-512(Base64)", "LDAP {SSHA512}", "^\{SSHA512\}[a-zA-Z0-9+]{96}$"),
	array("Oracle 11g", "^S:[A-Z0-9]{60}$"),
	array("SMF >= v1.1", "^[a-fA-F0-9]{40}:[0-9]{8}&"),
	array("MySQL 5.x", "^\*[a-f0-9]{40}$"),
	array("MySQL 3.x", "DES(Oracle)", "LM", "VNC", "FNV-164", "^[a-fA-F0-9]{16}$"),
	array("OSX v10.7", "^[a-fA-F0-9]{136}$"),
	array("OSX v10.8", "^\$ml\$[a-fA-F0-9$]{199}$"),
	array("SAM(LM_Hash:NT_Hash)", "^[a-fA-F0-9]{32}:[a-fA-F0-9]{32}$"),
	array("MSSQL(2000)", "^0x0100[a-f0-9]{0,8}?[a-f0-9]{80}$"),
	array("MSSQL(2005)", "MSSQL(2008)", "^0x0100[a-f0-9]{0,8}?[a-f0-9]{40}$"),
	array("MSSQL(2012)", "^0x02[a-f0-9]{0,10}?[a-f0-9]{128}$"),
	array("substr(md5(\$pass),0,16)", "substr(md5(\$pass),16,16)", "substr(md5(\$pass),8,16)", "CRC-64", "^[a-fA-F0-9./]{16}$"),
	array("MySQL 4.x", "SHA-1", "HAVAL-160", "SHA-1(MaNGOS)", "SHA-1(MaNGOS2)", "TIGER-160", "RIPEMD-160", "RIPEMD-160(HMAC)", "TIGER-160(HMAC)", "Skein-256(160)", "Skein-512(160)", "^[a-f0-9]{40}$"),
	array("SHA-256", "SHA-256(HMAC)", "SHA-3(Keccak)", "GOST R 34.11-94", "RIPEMD-256", "HAVAL-256", "Snefru-256", "Snefru-256(HMAC)", "RIPEMD-256(HMAC)", "Keccak-256", "Skein-256", "Skein-512(256)", "^[a-fA-F0-9]{64}$"),
	array("SHA-1(Oracle)", "HAVAL-192", "OSX v10.4, v10.5, v10.6", "Tiger-192", "TIGER-192(HMAC)", "^[a-fA-F0-9]{48}$"),
	array("SHA-224", "SHA-224(HMAC)", "HAVAL-224", "Keccak-224", "Skein-256(224)", "Skein-512(224)", "^[a-fA-F0-9]{56}$"),
	array("Adler32", "FNV-32", "ELF-32", "Joaat", "CRC-32", "CRC-32B", "GHash-32-3", "GHash-32-5", "FCS-32", "Fletcher-32", "XOR-32", "^[a-f0-9]{8}$"),
	array("CRC-16-CCITT", "CRC-16", "FCS-16", "^[a-fA-F0-9]{4}$"),
	array("MD5(HMAC(Wordpress))", "MD5(HMAC)", "MD5", "RIPEMD-128", "RIPEMD-128(HMAC)", "Tiger-128", "Tiger-128(HMAC)", "RAdmin v2.x", "NTLM", "Domain Cached Credentials(DCC)", "Domain Cached Credentials 2(DCC2)", "MD4", "MD2", "MD4(HMAC)", "MD2(HMAC)", "Snefru-128", "Snefru-128(HMAC)", "HAVAL-128", "HAVAL-128(HMAC)", "Skein-256(128)", "Skein-512(128)", "MSCASH2", "^[0-9A-Fa-f]{32}$")
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
	}
}
else{
	echo "Please enter the hash. No input hash found.";
}
?>























