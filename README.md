# Phantom
An Advanced tool for bypassing AV/EDR.
This project showcases a memory injection tool designed to deploy XOR-encrypted shellcode into remote processes.
The tool also incorporates multiple anti-analysis techniques, including virtual machine detection, debugger detection, and static analysis tools detection.
This tool can be used for advanced cybersecurity testing, allowing users to execute shellcode covertly in a controlled environment.




# Features

**[+] Obfuscation Techniques:** Employs XOR encryption to avoid signature-based detection.

**[+] Memory Injection:** Allocates and manipulates memory for shellcode injection.

**[+] Anti-Debugging/Anti-Sandboxing:** Validates environnement first to detect if its in a sandbox or if debuggers/analysis Tools are present.




# Getting Started

**Installation**


1- Clone the repository:
```
git clone https://github.com/Cyb3rV1c/Phantom
```


2- Build both tools (Phantom & Xor_Encryptor)



**Usage**

1. Add your .raw shellcode file in the same directory as the Xor_Encryptor Tool

2. Execute the tool :

```
.\Encryptor_xor.exe reverseshell.raw
```


# Example Output

**Execution** & **Reverse Shell Confirmation**


![Shellcode_Injected](https://github.com/user-attachments/assets/34738791-a780-4dd9-905c-763d72b76ed1)


**Memory Dump**

![In Memory](https://github.com/user-attachments/assets/dbfa3449-bce2-41d3-9196-9ea3cca788d6)


# Technical Details

**Virtual Machine Detection:**
Utilizes GetSystemInfo() and GlobalMemoryStatusEx() to detect hardware characteristics, such as CPU cores and available RAM, which can help identify virtual environments.

**Debugger Detection:**
Uses the Toolhelp API with CreateToolhelp32Snapshot(), Process32FirstW(), and Process32NextW() to scan for running processes and check for known debugger processes (like x64dbg, ida.exe, etc.).

**Static Analysis Tools Detection:**
Similar to debugger detection, the Toolhelp API is also used to detect common analysis tools (e.g., ProcessHacker, PeStudio, ProcMon) by checking their process names.

**Shellcode Injection:**
Remote Process Injection via OpenProcess(), VirtualAllocEx(), WriteProcessMemory(), and CreateRemoteThread() to inject and execute XOR-encrypted shellcode into a remote process.

**XOR Encryption/Decryption:**
A simple XOR-based decryption routine is used to deobfuscate the shellcode before injection, providing a layer of evasion from static analysis.

**Shellcode Encryption:**
**Separate Tool:** A dedicated tool is provided for XOR encryption of shellcode to obfuscate it before integrating the shellcode in Phantom Tool.


# Disclaimer
**This project is intended for educational and research purposes only.**

The code provided in this repository is designed to help individuals understand and improve their knowledge of cybersecurity, ethical hacking, and malware analysis techniques. It must not be used for malicious purposes or in any environment where you do not have explicit permission from the owner.
