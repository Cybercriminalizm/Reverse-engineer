Malware Research Suite

«A modular static-analysis toolkit for Windows PE research, malware triage, artifact extraction, and structured report generation.»

""Platform" (https://img.shields.io/badge/platform-Windows-0078D6)" (#)
""C++" (https://img.shields.io/badge/C%2B%2B-20-00599C)" (#)
""Go" (https://img.shields.io/badge/Go-1.22%2B-00ADD8)" (#)
""Python" (https://img.shields.io/badge/Python-3.10%2B-3776AB)" (#)
""License" (https://img.shields.io/badge/license-MIT-green)" (LICENSE)
""Status" (https://img.shields.io/badge/status-research-orange)" (#)

---

Overview

Malware Research Suite is a multi-language static-analysis project designed for analyzing Windows PE files without executing the analyzed sample.

The project combines several specialized components into a common research workflow:

- PE/COFF structure analysis
- Cryptographic file hashing
- Section and entropy analysis
- Import/export inspection
- Suspicious API identification
- String and artifact extraction
- Network-related artifact discovery
- Registry and persistence indicators
- YARA-based pattern matching
- Structured JSON reporting
- Local report visualization
- Cross-language analysis components

The project is designed around a simple principle:

«Treat the sample as data, not as something to execute.»

---

Features

File Identification

- MD5
- SHA-1
- SHA-256
- File size
- File format identification
- PE signature validation

PE Analysis

- DOS header
- PE signature
- Machine architecture
- PE32 / PE32+
- Section table
- Entry-point RVA
- Image base
- Image size
- Subsystem
- DLL characteristics
- PE timestamp
- Import table
- Export table
- TLS information
- Resource metadata

Section Analysis

For each section, the suite can collect:

- Name
- Virtual address
- Virtual size
- Raw offset
- Raw size
- Characteristics
- Entropy
- Executable/readable/writable properties

High-entropy sections can be flagged for further investigation.

«High entropy is an indicator, not proof of packing or malicious behavior.»

Artifact Extraction

The research pipeline can identify artifacts such as:

- ASCII strings
- UTF-16LE strings
- URLs
- Domains
- IPv4 addresses
- Registry paths
- PowerShell-related strings
- Command-shell indicators
- Persistence-related strings

Import Analysis

Potentially interesting APIs can be grouped into categories such as:

- Process manipulation
- Memory manipulation
- Networking
- Persistence
- Anti-analysis
- Command execution

Import names are treated as research indicators, not automatic malware verdicts.

YARA

YARA rules can be used to identify patterns across analyzed samples.

The repository includes rules for research indicators involving:

- PE characteristics
- Suspicious execution APIs
- PowerShell
- Command shells
- Networking
- Persistence
- Anti-analysis

Official documentation:

- "YARA Documentation" (https://yara.readthedocs.io/)
- "YARA GitHub" (https://github.com/VirusTotal/yara)

---

Architecture

                    ┌─────────────────────┐
                    │     PE Sample       │
                    │     as raw data     │
                    └──────────┬──────────┘
                               │
                               ▼
                    ┌─────────────────────┐
                    │    Python Engine    │
                    │  Primary Analyzer   │
                    └──────────┬──────────┘
                               │
              ┌────────────────┼────────────────┐
              ▼                ▼                ▼
       ┌─────────────┐ ┌─────────────┐ ┌─────────────┐
       │ C++ Parser  │ │ Go Analyzer │ │ YARA Rules  │
       └─────────────┘ └─────────────┘ └─────────────┘
              │                │                │
              └────────────────┼────────────────┘
                               ▼
                    ┌─────────────────────┐
                    │   JSON Report       │
                    │  Shared Schema      │
                    └──────────┬──────────┘
                               │
                               ▼
                    ┌─────────────────────┐
                    │    PHP Viewer       │
                    │ Local Report UI      │
                    └─────────────────────┘

---

Repository Structure

malware-research-suite/
│
├── cpp/
│   └── pe_research.cpp
│
├── go/
