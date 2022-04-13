rule Changing_registery_value
{
	meta:
	description="This rule will check if the malware changing values in registry"
	strings:
	$a="RegCheckKeyA" 
	$b="RegSetValue"
	$c="RegOpenCurrentUser"
	condition:
	($a or $b and $c)
	
} 
