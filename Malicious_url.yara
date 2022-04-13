rule malicious_url
{
	meta:
	description="This rule will find malicious url in the malware"
	strings:
	$a="http://leftthenhispar.ru/zapoy/gate.php"
	$b="http://reninparwil.com/zapoy/gate.php"
	$c="http://reptertinrom.ru/zapoy/gate.php"
	condition:
	($a or $b or $c)
	
} 
