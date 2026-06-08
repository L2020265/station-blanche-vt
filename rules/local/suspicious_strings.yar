rule Suspicious_PowerShell_Indicators
{
    meta:
        description = "Indicateurs PowerShell suspects génériques"
        severity = "medium"
    strings:
        $a = "powershell" nocase
        $b = "Invoke-Expression" nocase
        $c = "FromBase64String" nocase
        $d = "-EncodedCommand" nocase
    condition:
        2 of them
}

rule Suspicious_Windows_LOLBins
{
    meta:
        description = "Usage potentiel de LOLBins Windows"
        severity = "medium"
    strings:
        $a = "rundll32.exe" nocase
        $b = "regsvr32.exe" nocase
        $c = "mshta.exe" nocase
        $d = "wscript.exe" nocase
        $e = "cscript.exe" nocase
    condition:
        any of them
}
