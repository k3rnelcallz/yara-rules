# 🧬 YARA Rules for Malware Research

Curated YARA rules focused on detecting malware loaders, droppers, document exploits, and obfuscated scripts.

![Rules](https://img.shields.io/badge/YARA-detections-blue)
![Platform](https://img.shields.io/badge/Platform-Windows-lightgrey)
![PRs](https://img.shields.io/badge/PRs-Welcome-brightgreen)

---

## 📌 Scope

- Windows PE malware
- Script-based loaders (PowerShell, HTA, JS, VBS)
- Office & PDF weaponization

---

## 📁 Repository Structure

yara-rules/
├── maldocs/


---

## 🚀 Usage

```bash
yara64.exe -r rules/ suspicious_dir/
