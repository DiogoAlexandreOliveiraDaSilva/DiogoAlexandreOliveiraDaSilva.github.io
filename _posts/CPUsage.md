---
layout: post
title: CPUsage - ISITDU 2024
date: 2024-10-30 18:25:40
description: Writeup for a forensics CTF in ISITDU 2024
tags: forensics
categories: ctf
---

# CPUsage

**Author:** p4pa  
**Team:** xSTF  

## INFO
- **CTF:** ISITDU 2024
- **Challenge:** CPUsage
- **Category:** Forensics
- **Description:** My friend noticed high CPU usage after opening his laptop. I took a memory dump of his laptop and need you to investigate it.
    1. What is the name of the malicious process, the full path of the process, and the parent process ID?  
    2. What is the IP that the process communicates with, and the family name of the malware?

## WriteUP

### Memory Dump

- This was my first **Forensics** CTF, and the description called for investigating a **memory dump**. The first step was selecting a tool suited to this context.
    - I found this GitHub repository that enumerates great **memory forensics tools**:
        - [Awesome Memory Forensics](https://github.com/digitalisx/awesome-memory-forensics)
    - The tool that best suited the challenge was **Volatility3**, a robust framework for memory analysis.
        - [Volatility3](https://github.com/volatilityfoundation/volatility3)

- With Volatility3 selected, I began analyzing the memory dump.

### Processes

- I referred to **Volatility3's** documentation and determined that examining the **process list** for anomalies would be a key initial step. I found `psscan` particularly helpful, as it organizes processes by **hierarchy** (showing parent-child relationships).
    ```bash
    vol -f win10.raw windows.psscan > psscan.txt
    ```
- The output columns included essential process details:
    1. `PID`: Process ID
    2. `PPID`: Parent Process ID
    3. `ImageFileName`: Name of the executable file
    4. `Offset(V)`: Virtual offset
    5. `Threads`: Number of threads
    6. `Handles`: Number of handles
    7. `SessionId`: Session ID
    8. `Wow64`: Indicates if the process is running under WOW64
    9. `CreateTime`: Process creation time
    10. `ExitTime`: Process exit time
    11. `Audit`: Audit information
    12. `Cmd`: Command line
    13. `Path`: Full path of the executable file

- One **process** stood out:
    ```bash
    *** 2220	264	dlIhost.exe	0xb50e42a43080	9	-	0	False	2024-08-22 11:57:21.000000 	N/A	\Device\HarddiskVolume3\Users\m4shl3\AppData\Roaming\DLL\dlIhost.exe	-	-
    ```
- This process raised suspicions for several reasons:
    - **Location**: System processes are rarely located in `AppData\Roaming`.
    - **Naming**: Windows uses `dllhost.exe` as a legitimate system process, but here it was slightly altered to **dlIhost.exe** (substituting an 'I' for 'l').
- This subtle change suggested the process might be **malicious**, using a near-identical name to evade detection.

### Malware

- Next, I checked for **memory regions** with potentially **injected code** using Volatility3's `malfind` command.
    ```bash
    vol -f win10.raw windows.malfind > malfind
    ```

- The output validated my hypothesis:
    ```bash
    2220	dlIhost.exe	0x203f2b00000	0x203f2b1ffff	VadS	PAGE_EXECUTE_READWRITE	32	1 Disabled	N/A	
    ```
- The **dlIhost.exe process had injected code**, confirming it as potentially malicious. Notable flags included:
    - **PAGE_EXECUTE_READWRITE**: This memory protection allows the memory region to be read, written, and executed—ideal for malware looking to execute malicious code within an unsuspecting process’s memory space.

### Network

- With `dlIhost.exe` confirmed as suspicious, I examined **network activity** to identify potential connections to external IPs.
    ```bash
    vol -f win10.raw windows.netscan > netscan
    ```
- The output columns provided details on network connections:
    1. `Offset`: Memory offset
    2. `Proto`: Protocol used (e.g., TCP, UDP)
    3. `LocalAddr`: Local IP address
    4. `LocalPort`: Local port number
    5. `ForeignAddr`: Remote IP address
    6. `ForeignPort`: Remote port number
    7. `State`: Connection state (e.g., ESTABLISHED, LISTENING)
    8. `PID`: Process ID
    9. `Owner`: Owner of the process
    10. `Created`: Creation time of the connection

- Our target process had an **active connection** with the following entry:
    ```bash
    0xb50e40f53260	TCPv4	192.168.253.128	49720	45.77.240.51	6198	ESTABLISHED	2220	dlIhost.exe	2024-08-22 11:58:04.000000 
    ```
- This showed **dlIhost.exe** communicating with **45.77.240.51**.
    - I conducted **OSINT** on this IP through [VIRUS TOTAL](https://www.virustotal.com/gui/ip-address/45.77.240.51), which flagged it as associated with known malware activity, further confirming this process as malicious.

### Dumping

- To confirm the **malware family**, I decided to dump **dlIhost.exe** using Volatility3's `dumpfiles` command. This captures the **.dll** and **.exe** files associated with the process.
    ```bash
    vol -f win10.raw -o ./dump windows.dumpfiles --pid 2220
    ```
- With the file dumped, I uploaded it to [VIRUS TOTAL](https://www.virustotal.com/) for analysis. Virus Total categorized it as **harminer**:
    - **Harminer**: A Trojan commonly used as a **cryptocurrency miner** to mine Monero (XMR) on infected systems.

### Solution

- **Answers based on the information gathered**:
    1. **Name of the malicious process:** dlIhost.exe  
       **Full path of the process:** `C:\Users\m4shl3\AppData\Roaming\DLL\dlIhost.exe`  
       **Parent process ID:** 264

    2. **IP that the process communicates with:** 45.77.240.51  
       **Family name of the malware:** harminer

    - **Flag format:** ISITDTU{processName-FullPath-ID_ip-FamilyName} 

- **Flag:** `ISITDTU{dlIhost.exe-C:\Users\m4shl3\AppData\Roaming\DLL\dlIhost.exe-264_45.77.240.51-harminer}`