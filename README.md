Malware Research Suite

<p align="center">
  <img src="https://img.shields.io/badge/STATUS-RESEARCH-8B5CF6?style=for-the-badge" alt="Research">
  <img src="https://img.shields.io/badge/STATIC%20ANALYSIS-ONLY-00B894?style=for-the-badge" alt="Static Analysis">
  <img src="https://img.shields.io/badge/PLATFORM-WINDOWS-0078D6?style=for-the-badge" alt="Windows">
  <img src="https://img.shields.io/badge/LICENSE-MIT-F59E0B?style=for-the-badge" alt="MIT License">
</p><p align="center">
  <strong>A modular static-analysis toolkit for Windows PE malware research.</strong>
</p><p align="center">
  Analyze samples as data without executing them.
</p>---

Overview

Malware Research Suite is a multi-language static-analysis project designed for examining Windows PE files and organizing the resulting artifacts into structured research reports.

The project combines native analysis, scripting, detection rules, structured reporting, and a local report interface.

Core capabilities

- PE32 / PE32+ identification
- File hashing
- PE header inspection
- Section analysis
- Section entropy calculation
- Import and export analysis
- Suspicious API identification
- String extraction
- URL, domain, and IPv4 artifact extraction
- Registry-path detection
- PowerShell and command-shell indicators
- Persistence indicators
- Anti-analysis indicators
- YARA rule scanning
- JSON report generation
- Local report visualization

«Important: Static indicators are evidence for investigation, not automatic proof that a file is malicious.»

---

Architecture

                    ┌─────────────────────┐
                    │   PE Sample / File   │
                    └──────────┬──────────┘
                               │
                               ▼
                    ┌─────────────────────┐
                    │   Analysis Engine   │
                    │       Python        │
                    └──────────┬──────────┘
                               │
             ┌─────────────────┼─────────────────┐
             ▼                 ▼                 ▼
       ┌───────────┐     ┌────────────┐    ┌───────────┐
       │ PE Parser │     │   YARA     │    │ Artifacts │
       │           │     │   Rules    │    │ / Strings │
       └─────┬─────┘     └─────┬──────┘    └─────┬─────┘
             │                 │                  │
             └─────────────────┼──────────────────┘
                               ▼
                    ┌─────────────────────┐
                    │    JSON Report      │
                    └──────────┬──────────┘
                               │
                               ▼
                    ┌─────────────────────┐
                    │   PHP Report UI     │
                    └─────────────────────┘

---

Project Structure

malware-research-suite/
│
├── cpp/
│   └── pe_research.cpp
│
├── go/
│   └── malware_static.go
│
├── python/
│   └── analyzer.py
│
├── php/
│   └── report.php
│
├── yara/
│   └── rules.yar
│
├── asm/
│   └── pe_constants.asm
│
├── schemas/
│   └── report.schema.json
│
├── reports/
│   └── .gitkeep
│
├── samples/
│   └── .gitkeep
│
├── requirements.txt
├── README.md
├── LICENSE
└── .gitignore

---

Components

Component| Purpose
Python| Main static-analysis engine
C++| Native PE inspection
Go| Dependency-light PE analysis
PHP| Local report viewer
YARA| Pattern-based static detection
JSON| Standardized report format
ASM| PE/COFF constants and offsets
".gitignore"| Prevents samples/build artifacts from being committed

---

Analysis Pipeline

Input
  │
  ├── SHA-256 / SHA-1 / MD5
  │
  ├── File-format validation
  │
  ├── PE header parsing
  │
  ├── Section analysis
  │      └── Entropy
  │      └── Characteristics
  │      └── Raw/virtual sizes
  │
  ├── Import analysis
  │
  ├── Export analysis
  │
  ├── String extraction
  │      ├── ASCII
  │      └── UTF-16LE
  │
  ├── Artifact extraction
  │      ├── URLs
  │      ├── Domains
  │      ├── IPv4
  │      └── Registry paths
  │
  ├── Indicator classification
  │
  ├── YARA scanning
  │
  └── JSON report
          │
          ▼
       Report UI

---

Detection Categories

Execution

Examples of static indicators associated with process or execution behavior:

CreateProcess
WinExec
ShellExecute
CreateThread

Memory

VirtualAlloc
VirtualProtect
VirtualAllocEx
WriteProcessMemory

Networking

WinHttpOpen
WinHttpConnect
InternetOpenA
InternetOpenW
WSAStartup
connect

Persistence

CurrentVersion\Run
CurrentVersion\RunOnce
schtasks
Startup

Anti-analysis

IsDebuggerPresent
CheckRemoteDebuggerPresent
NtQueryInformationProcess
OutputDebugString

These indicators are intentionally treated as research artifacts, not definitive classifications.

---

Entropy

The suite calculates Shannon entropy for relevant sections.

A section with unusually high entropy can be worth investigating because it may indicate compression, encryption, packing, or simply high-entropy legitimate data.

Entropy
0.0 ─────────────────────────────── 8.0

Low                              High
│                                  │
└───────────────┬──────────────────┘
                │
             7.2+
          investigate

The threshold is a heuristic and should not be interpreted as a malware verdict.

---

YARA

Custom YARA rules are stored under:

yara/rules.yar

The rules cover static indicators such as:

- Suspicious PE characteristics
- Process/memory APIs
- PowerShell strings
- Command-shell indicators
- Network APIs
- Persistence artifacts
- Anti-analysis APIs

YARA:

"YARA Project" (https://reference-url-citation.invalid/0)

---

JSON Reports

All analysis components use a common report structure defined by:

schemas/report.schema.json

Example:

{
  "schema_version": "1.0",
  "tool": "Malware Research Suite",
  "safety": {
    "sample_executed": false,
    "network_access": false,
    "sample_modified": false
  },
  "file": {
    "name": "sample.exe",
    "sha256": "..."
  },
  "indicators": {},
  "yara_matches": []
}

This makes reports portable between the Python, C++, Go, and PHP components.

---

Installation

Requirements

- Windows
- Python 3.10+
- Go
- C++ compiler with C++20 support
- PHP 8+
- YARA / "yara-python"

Python dependencies

python -m pip install -r requirements.txt

C++ dependencies

The native analyzer uses Windows APIs and standard C++ libraries.

Example build:

cl /std:c++20 /EHsc pe_research.cpp /link Advapi32.lib

Go

go build -o malware_static.exe malware_static.go

---

Usage

Python

python analyzer.py sample.exe

Generate a JSON report:

python analyzer.py sample.exe --output reports/sample.json

C++

pe_research.exe sample.exe

Go

malware_static.exe sample.exe

Or:

malware_static.exe sample.exe reports/sample.json

PHP Report Viewer

Start the local server:

php -S 127.0.0.1:8080 -t php

Then open:

http://127.0.0.1:8080/report.php

---

Research Workflow

01  Acquire sample
        ↓
02  Preserve original
        ↓
03  Calculate hashes
        ↓
04  Validate file format
        ↓
05  Perform static analysis
        ↓
06  Review PE structures
        ↓
07  Inspect imports/exports
        ↓
08  Extract strings/artifacts
        ↓
09  Run YARA
        ↓
10  Generate JSON report
        ↓
11  Review findings

---

Safety Model

The suite is designed around non-executing analysis.

The static-analysis components should not:

- Execute analyzed samples
- Inject into processes
- Modify analyzed samples
- Establish persistence
- Deploy payloads
- Act as malware
- Make network requests on behalf of analyzed samples

The "samples/" directory is ignored by Git so potentially sensitive binaries are not accidentally committed to the repository.

---

False Positives

Static analysis is inherently probabilistic.

For example:

VirtualAlloc

does not mean a program is malicious.

Likewise:

High entropy

does not automatically mean a file is packed.

A proper investigation should correlate multiple independent artifacts before reaching a conclusion.

---

Technologies

<p align="center"><img src="https://img.shields.io/badge/C%2B%2B-00599C?style=for-the-badge&logo=c%2B%2B&logoColor=white">
<img src="https://img.shields.io/badge/Python-3776AB?style=for-the-badge&logo=python&logoColor=white">
<img src="https://img.shields.io/badge/Go-00ADD8?style=for-the-badge&logo=go&logoColor=white">
<img src="https://img.shields.io/badge/PHP-777BB4?style=for-the-badge&logo=php&logoColor=white">
<img src="https://img.shields.io/badge/YARA-8B5CF6?style=for-the-badge">
<img src="https://img.shields.io/badge/JSON-000000?style=for-the-badge&logo=json&logoColor=white"></p>---

References

Microsoft PE Format

"Microsoft PE Format Documentation" (https://reference-url-citation.invalid/1)

YARA

"YARA Documentation" (https://reference-url-citation.invalid/2)

Python

"Python Documentation" (https://reference-url-citation.invalid/3)

Go

"Go Documentation" (https://reference-url-citation.invalid/4)

PHP

"PHP Documentation" (https://reference-url-citation.invalid/5)

---

License

This project is released under the MIT License.

See ""LICENSE"" (LICENSE).

---

Disclaimer

This project is intended for authorized malware research, reverse engineering, incident response, and defensive security analysis.

Only analyze files you are authorized to possess and investigate.

---

<p align="center">
  <sub>Malware Research Suite · Static Analysis · PE Research</sub>
</p>
