rule cobaltstrike_beacon_reflective_dll
{
	meta:
		author = "susu"
		description = "Reflective DLL?"
	strings:
		$a_x64 = {4D 5A 41 52 55}
	condition:
		any of them
}