import "pe"

rule Suspicious_PE_Characteristics
{
    meta:
        description = "Static indicators commonly associated with packed or suspicious PE files"
        author = "Malware Research Suite"
        version = "1.0"

    condition:
        uint16(0) == 0x5A4D and
        pe.number_of_sections > 0 and
        (
            for any i in (0..pe.number_of_sections - 1):
                (
                    pe.sections[i].entropy >= 7.2
                )
        )
}

rule Suspicious_Execution_APIs
{
    meta:
        description = "Detects strings associated with process or memory manipulation APIs"
        author = "Malware Research Suite"

    strings:
        $a1 = "VirtualAlloc" ascii wide
        $a2 = "VirtualProtect" ascii wide
        $a3 = "VirtualAllocEx" ascii wide
        $a4 = "WriteProcessMemory" ascii wide
        $a5 = "CreateRemoteThread" ascii wide
        $a6 = "OpenProcess" ascii wide

    condition:
        uint16(0) == 0x5A4D and
        2 of them
}

rule PowerShell_Indicators
{
    meta:
        description = "Detects PowerShell-related strings"
        author = "Malware Research Suite"

    strings:
        $p1 = "powershell.exe" ascii wide nocase
        $p2 = "powershell" ascii wide nocase
        $p3 = "-encodedcommand" ascii wide nocase
        $p4 = "-executionpolicy" ascii wide nocase
        $p5 = "Invoke-Expression" ascii wide nocase

    condition:
        uint16(0) == 0x5A4D and
        1 of them
}

rule Command_Shell_Indicators
{
    meta:
        description = "Detects command shell related strings"
        author = "Malware Research Suite"

    strings:
        $c1 = "cmd.exe" ascii wide nocase
        $c2 = "/c" ascii wide
        $c3 = "command.com" ascii wide nocase

    condition:
        uint16(0) == 0x5A4D and
        1 of them
}

rule Network_Indicators
{
    meta:
        description = "Detects common networking APIs"
        author = "Malware Research Suite"

    strings:
        $n1 = "WinHttpOpen" ascii wide
        $n2 = "WinHttpConnect" ascii wide
        $n3 = "InternetOpenA" ascii wide
        $n4 = "InternetOpenW" ascii wide
        $n5 = "URLDownloadToFileA" ascii wide
        $n6 = "URLDownloadToFileW" ascii wide
        $n7 = "WSAStartup" ascii wide
        $n8 = "connect" ascii wide

    condition:
        uint16(0) == 0x5A4D and
        2 of them
}

rule Persistence_Indicators
{
    meta:
        description = "Detects strings associated with common persistence locations"
        author = "Malware Research Suite"

    strings:
        $r1 = "Software\\Microsoft\\Windows\\CurrentVersion\\Run" ascii wide nocase
        $r2 = "Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce" ascii wide nocase
        $r3 = "schtasks" ascii wide nocase
        $r4 = "Startup" ascii wide nocase

    condition:
        uint16(0) == 0x5A4D and
        1 of them
}

rule Anti_Analysis_Indicators
{
    meta:
        description = "Detects common anti-analysis related API names"
        author = "Malware Research Suite"

    strings:
        $a1 = "IsDebuggerPresent" ascii wide
        $a2 = "CheckRemoteDebuggerPresent" ascii wide
        $a3 = "NtQueryInformationProcess" ascii wide
        $a4 = "OutputDebugStringA" ascii wide
        $a5 = "OutputDebugStringW" ascii wide

    condition:
        uint16(0) == 0x5A4D and
        1 of them
}
