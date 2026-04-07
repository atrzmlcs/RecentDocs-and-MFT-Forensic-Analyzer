# 🔍 RecentDocs Forensic Analyzer

[![Python Version](https://img.shields.io/badge/python-3.8%2B-blue.svg)](https://python.org)
[![License](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)
[![DFIR](https://img.shields.io/badge/DFIR-Forensics-red.svg)]()

A digital forensics tool that **recovers evidence of deleted files** from Windows Registry RecentDocs keys.

## 🎯 What It Does

When someone deletes a file on Windows, the filename often remains in the Registry. This tool finds those traces and tells you:

- **What** files were accessed
- **When** they were accessed (or approximate timeframe)
- **Whether** they've been deleted

## 🚨 Real-World Use Cases

| Scenario | How This Tool Helps |
|----------|---------------------|
| **Insider Threat** | Employee accessed confidential files before resigning, then deleted them |
| **Data Theft** | Prove sensitive documents were opened before being wiped |
| **Cover-up Investigation** | Recover evidence of deleted files after Recycle Bin was emptied |
| **Incident Response** | Identify what files an attacker accessed during a breach |

## 📊 Quick Example

**Command:**
```bash
python recentdocs_analyzer.py -f NTUSER.DAT -m \$MFT -o report.csv

## 🗺️ MITRE ATT&CK Mapping

| Scenario | MITRE Technique | How This Tool Helps |
|----------|----------------|---------------------|
| Insider Threat | T1005 - Data from Local System | Proves employee accessed confidential files before resigning |
| Cover-up Investigation | T1070.004 - Indicator Removal: File Deletion | Recovers filenames of files deleted to hide evidence |
| Data Theft Investigation | TA0009 - Collection | Identifies what sensitive data was gathered before exfiltration |
| Incident Response | T1005 + T1070.004 | Shows what files attacker accessed AND deleted during breach |
