# MemLabs Lab 1 — Complete Walkthrough

**Date:** 2026-11-13

A full solution for all three flags in MemLabs Lab 1 (Beginner's Luck), a Windows 7 memory forensics CTF challenge involving console output analysis, paint canvas recovery, and RAR archive extraction.

## Challenge Overview

**Description:** My sister's computer crashed. We were told that there was some important stuff on her system. She's a creative person and she was working on something before the crash happened. Please help her to recover her decrypted important files and data.

The challenge contains **3 flags** hidden across different forensic artifacts.

**Key hints from the description:**

- "Computer crashed" — a memory dump was taken at the moment of the crash
- "Creative person" and "working on something" — hints at **mspaint.exe** (drawing application)
- "Important stuff" and "decrypted important files" — hints at encrypted archives

**Tools used:**

- Volatility 2 (Python 2) for memory analysis (`imageinfo`, `pslist`, `consoles`, `filescan`, `dumpfiles`, `hashdump`)
- `strings`, `grep`, `base64` for string searching and decoding
- GIMP or similar image editor for reconstructing the mspaint canvas
- `unrar` for extracting password-protected RAR archives

**Memory dump:** `MemoryDump_Lab1.raw` (1,073,676,288 bytes / ~1 GB), a Windows 7 SP1 x64 VirtualBox VM.

## Reconnaissance

### Identify the OS profile

```
$ volatility -f MemoryDump_Lab1.raw imageinfo

Suggested Profile(s): Win7SP1x64, Win7SP0x64, Win2008R2SP0x64, Win2008R2SP1x64
AS Layer1: WindowsAMD64PagedMemory (Kernel DTB 0x187000L)
AS Layer2: FileAddressSpace (/home/kali/MemLabs/Lab1/MemoryDump_Lab1.raw)
PAE type: No PAE
DTB: 0x187000L
KDBG: 0xf800028100a0L
Image date and time: 2019-12-11 14:38:00 UTC+0000
```

The profile is **Win7SP1x64**.

### Process list

```
$ volatility -f MemoryDump_Lab1.raw --profile Win7SP1x64 pslist
```

Key processes of interest (48 total):

| PID | Process | Session | PPID | Notes |
| --- | --- | --- | --- | --- |
| 1984 | cmd.exe | 1 | 604 (explorer.exe) | Running St4G3$1.bat — Flag 1 |
| 2424 | mspaint.exe | 1 | 604 (explorer.exe) | Drawing application — Flag 2 |
| 1512 | WinRAR.exe | 2 | 2504 (explorer.exe) | Viewing Important.rar — Flag 3 |
| 604 | explorer.exe | 1 | — | Windows shell (user SmartNet) |
| 2504 | explorer.exe | 2 | — | Windows shell (user Alissa Simpson) |
| 796 | DumpIt.exe | 1 | 604 | Memory acquisition tool |

Three suspicious processes immediately stand out: cmd.exe, mspaint.exe, and WinRAR.exe. Each contains one flag.

## Flag 1 — Console Output (cmd.exe / St4G3$1.bat)

The `consoles` plugin recovers the full text visible in console windows, including command history and screen output.

### Step 1: Dump console output

```
$ volatility -f MemoryDump_Lab1.raw --profile Win7SP1x64 consoles
```

Output for cmd.exe (PID 1984):

```
ConsoleProcess: conhost.exe Pid: 2692
OriginalTitle: %SystemRoot%\system32\cmd.exe
Title: C:\Windows\system32\cmd.exe - St4G3$1

CommandHistory: Application: cmd.exe
Cmd #0 at 0x1de3c0: St4G3$1

Screen Dump:
Microsoft Windows [Version 6.1.7601]
Copyright (c) 2009 Microsoft Corporation.  All rights reserved.

C:\Users\SmartNet>St4G3$1
ZmxhZ3t0aDFzXzFzX3RoM18xc3Rfc3Q0ZzMhIX0=
Press any key to continue . . .
```

The console title shows `cmd.exe - St4G3$1`, meaning a batch file `St4G3$1.bat` was executed. Its output is a Base64-encoded string.

### Step 2: Decode the Base64

```
$ echo 'ZmxhZ3t0aDFzXzFzX3RoM18xc3Rfc3Q0ZzMhIX0=' | base64 -d
flag{th1s_1s_th3_1st_st4g3!!}
```

**Flag 1:** `flag{th1s_1s_th3_1st_st4g3!!}`

## Flag 2 — Mspaint Canvas (mspaint.exe)

The challenge description says the user was "creative" and "working on something." Mspaint.exe (PID 2424) was running — the flag is drawn on the canvas.

### Step 1: Dump the mspaint process memory

```
$ volatility -f MemoryDump_Lab1.raw --profile Win7SP1x64 memdump -p 2424 -D output/
```

This produces `2424.dmp` (~286 MB), which contains the full virtual address space of the mspaint process.

### Step 2: Extract the canvas bitmap

Mspaint stores the canvas as a raw bitmap in memory. The pixel data is stored in BGRX format (4 bytes per pixel: Blue, Green, Red, Alpha/padding).

**Method A — Rename and open in GIMP:**

1. Rename the dump: `mv 2424.dmp 2424.data`
2. Open in GIMP: File → Open, select `2424.data`
3. Set image type to **Raw image data**
4. Set pixel format to **RGBA** (4 bytes/pixel)
5. Try different widths until the image aligns. Common mspaint canvas widths: **819**, 1024, 1280
6. At width **819**, the handwritten flag text becomes visible

**Method B — Automated extraction:**

Search the dump for large regions of pixel data (bytes matching BGRX patterns with alpha channel = 0x00), then render them as an image using Python with PIL/Pillow.

### Step 3: Read the flag

The canvas contains handwritten text (drawn with the brush tool) that reads:

**Flag 2:** `flag{Good_Boy_good_girl_}`

**Note:** The mspaint bitmap extraction can be tricky. The key is finding the correct canvas width (819 pixels in this case). The image may appear mirrored or upside-down depending on the BMP storage order — flip/rotate as needed.

## Flag 3 — WinRAR Archive (Important.rar)

WinRAR.exe (PID 1512) was running under user Alissa Simpson (Session 2), with the command line showing it had `Important.rar` open.

### Step 1: Locate and dump the RAR file

```
$ volatility -f MemoryDump_Lab1.raw --profile Win7SP1x64 filescan | grep -i important

0x000000003fa3ebc0     2      0 R--r-d \Device\HarddiskVolume2\Users\Alissa Simpson\Documents\Important.rar
```

Dump the file:

```
$ volatility -f MemoryDump_Lab1.raw --profile Win7SP1x64 dumpfiles -Q 0x000000003fa3ebc0 -D output/
```

This extracts a 45,056-byte RAR v5 archive.

### Step 2: Check the archive

```
$ unrar l Important.rar

Archive comment:
  Password is NTLM hash(in uppercase) of Alissa's account passwd.

Archive: Important.rar
Name             Size   Packed  Ratio  Date     Time   Attr
flag3.png       43942    43650   99%  2019-12-11 19:29  .....A
```

The archive comment tells us the password is the **NTLM hash (uppercase)** of Alissa Simpson's Windows account password.

### Step 3: Extract the NTLM hash

```
$ volatility -f MemoryDump_Lab1.raw --profile Win7SP1x64 hashdump

Administrator:500:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
SmartNet:1001:aad3b435b51404eeaad3b435b51404ee:4943abb39473a6f32c11301f4987e7e0:::
Alissa Simpson:1003:aad3b435b51404eeaad3b435b51404ee:f4ff64c8baac57d22f22edc681055ba6:::
```

Alissa Simpson's NTLM hash: `f4ff64c8baac57d22f22edc681055ba6`

The archive comment says to use it **in uppercase**: `F4FF64C8BAAC57D22F22EDC681055BA6`

### Step 4: Extract the RAR

```
$ unrar x -pF4FF64C8BAAC57D22F22EDC681055BA6 Important.rar
```

This extracts `flag3.png`, an image containing:

**Flag 3:** `flag{w3ll_3rd_stage_was_easy}`

## Summary

| Stage | Flag | Artifact | Technique |
| --- | --- | --- | --- |
| 1 | `flag{th1s_1s_th3_1st_st4g3!!}` | cmd.exe console (St4G3$1.bat) | `consoles` plugin + Base64 decode |
| 2 | `flag{Good_Boy_good_girl_}` | mspaint.exe canvas bitmap | `memdump` + raw pixel rendering at width 819 |
| 3 | `flag{w3ll_3rd_stage_was_easy}` | Important.rar (WinRAR) | `filescan` + `dumpfiles` + `hashdump` for NTLM password |

### Key Techniques

- **Console output recovery** — the `consoles` plugin is more informative than `cmdscan`; it recovers the full screen buffer including command output, not just the commands typed
- **Raw bitmap extraction** — mspaint stores canvas data as uncompressed BGRX pixels in process memory; dumping the process and opening the raw data in GIMP at the correct width reveals the drawing
- **NTLM hash extraction** — `hashdump` reads the SAM database from the registry hives cached in memory; the hash itself (not the cracked password) was the archive password
- **File carving** — `filescan` + `dumpfiles` can recover files that were open or cached at the time of the memory dump

### Pitfalls

- **Mspaint canvas width** — the raw pixel data has no header specifying dimensions; you must guess the width by trial and error (819 pixels here); wrong widths produce garbled diagonal lines
- **NTLM hash case sensitivity** — the RAR comment specifies "in uppercase"; `f4ff...` will fail, `F4FF...` works
- **RAR version** — some older `unrar` builds may not support RAR v5 format; use a current version
- **Two user sessions** — Flags 1 and 2 are in Session 1 (user SmartNet), Flag 3 is in Session 2 (user Alissa Simpson); both explorer.exe instances (PID 604 and 2504) are worth investigating

### Cross-Challenge Note

Flag 3's value (`flag{w3ll_3rd_stage_was_easy}`) is referenced in **MemLabs Lab 2**, where the SHA1 hash of this flag is used as the password for `Important.zip`:

```
$ echo -n 'flag{w3ll_3rd_stage_was_easy}' | sha1sum
6045dd90029719a039fd2d2ebcca718439dd100a
```
