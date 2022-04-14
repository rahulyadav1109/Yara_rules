import "hash"
rule hash
{
	meta:
		description="finding files using md5 hash"
	strings:
		$a= { 4D 5A }
		
	condition:
		$a at 0 and hash.md5(0, filesize) == "3C4DE20E464146BEC844471867BD1628"
}
