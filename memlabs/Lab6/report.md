# MemLabs Lab 6 — The Reckoning

**Memory Forensics CTF Walkthrough**  
**Profile:** Win7SP1x64  
**Dump date:** 2019-08-19

---

## Scenario

FBI arrested gangster David Benjamin. A memory dump was taken from one of his workers' machines. The worker was instructed to encrypt David's internet communications, but perhaps that wasn't followed to the letter. Our goal: reconstruct David's secrets from the memory image.

**1 flag, split into 2 parts** — format: `inctf{s0me_l33t_Str1ng}`

**Complete Flag:** `inctf{thi5_cH4LL3Ng3_!s_g0nn4_b3_aN_Am4zINg_!_i_gU3Ss???_}`

---

## Contents

1. [System Reconnaissance](#1-system-reconnaissance)
2. [Process Analysis](#2-process-analysis)
3. [Browser Artifact Extraction](#3-browser-artifact-extraction)
4. [Gmail & Mega Key Recovery](#4-gmail--mega-key-recovery)
5. [Flag Part 1: Mega Download & PNG Repair](#5-flag-part-1-mega-download--png-repair)
6. [Flag Part 2: Encrypted RAR Recovery](#6-flag-part-2-encrypted-rar-recovery)
7. [Evidence Chain](#7-evidence-chain)
8. [Complete Flag](#8-complete-flag)
9. [Extracted Artifacts](#9-extracted-artifacts)
10. [Tools & Techniques](#10-tools--techniques)

---

## 1. System Reconnaissance

### Identify the memory profile

First step in any Volatility analysis: determine the OS profile so all subsequent plugins parse structures correctly.

```
$ vol.py -f MemoryDump_Lab6.raw imageinfo

Suggested Profile(s): Win7SP1x64, Win7SP0x64, Win2008R2SP0x64, Win2008R2SP1x64
                 AS Layer1: WindowsAMD64PagedMemory (Kernel AS)
                 AS Layer2: FileAddressSpace (/home/kali/MemLabs/Lab6/MemoryDump_Lab6.raw)
                      KDBG: 0xf80002c4a0a0L
                       DTB: 0x187000L
                  KPCR #0 : 0xfffff80002c45d00L
              Image date/time: 2019-08-19 14:54:28 UTC+0000
```

**Profile:** `Win7SP1x64` — Windows 7 Service Pack 1, 64-bit. All further Volatility 2 commands use `--profile=Win7SP1x64`.

---

## 2. Process Analysis

### Process tree

The `pstree` plugin reveals the parent-child process hierarchy. Three processes under `explorer.exe` are immediately interesting:

```
$ vol.py -f MemoryDump_Lab6.raw --profile=Win7SP1x64 pstree

Name                 Pid   PPid
...
. explorer.exe       1944  1916
.. chrome.exe        2124  1944   <- Google Chrome (main process)
... chrome.exe       2132  2124       7 child renderer/GPU processes
... chrome.exe       2168  2124
... chrome.exe       2340  2124
... chrome.exe       2440  2124
... chrome.exe       2452  2124
... chrome.exe       2940  2124
.. firefox.exe       2968  1944   <- Mozilla Firefox
... firefox.exe      3000  2968
... firefox.exe      3048  2968
.. WinRAR.exe        3716  1944   <- WinRAR archive viewer
.. cmd.exe           ...   1944
```

The user "Jaffa" on machine "VIRUS-PC" had two browsers and WinRAR open simultaneously.

### Command lines

The `cmdline` plugin shows exactly what arguments each process was launched with:

```
$ vol.py -f MemoryDump_Lab6.raw --profile=Win7SP1x64 cmdline -p 3716

WinRAR.exe pid: 3716
Command line: "C:\Program Files\WinRAR\WinRAR.exe" "C:\Users\Jaffa\Desktop\pr0t3ct3d\flag.rar"
```

**Finding:** WinRAR (PID 3716) was launched to open `C:\Users\Jaffa\Desktop\pr0t3ct3d\flag.rar`. The directory name `pr0t3ct3d` ("protected" in leet speak) suggests this is a hidden/encrypted file.

### Environment variables

The `envars` plugin dumps all environment variables for a process. Checking WinRAR's environment reveals something that should never be stored in an env var:

```
$ vol.py -f MemoryDump_Lab6.raw --profile=Win7SP1x64 envars -p 3716

Pid   Name         Value
3716  COMPUTERNAME  VIRUS-PC
3716  USERDOMAIN    VIRUS-PC
3716  USERNAME      Jaffa
3716  RAR password  easypeasyvirus
```

**Critical finding:** The RAR archive password is stored in plaintext as an environment variable: `RAR password = easypeasyvirus`

This is a major operational security failure — passwords should never be stored in environment variables, where any process or memory forensic tool can read them.

---

## 3. Browser Artifact Extraction

With two browsers open, browser history databases are prime targets. Both Chrome and Firefox store history in SQLite databases that can be dumped from the cached file system.

### Locate browser databases with filescan

```
$ vol.py -f MemoryDump_Lab6.raw --profile=Win7SP1x64 filescan | grep -iE "History|places.sqlite"

Offset(P)          Name
0x000000005da5a610 \Users\Jaffa\AppData\Local\Google\Chrome\User Data\Default\History
0x00000000053fd070 \Users\Jaffa\...\Firefox\Profiles\84kisw0a.default-release\places.sqlite
```

### Dump the Chrome History database

```
$ vol.py -f MemoryDump_Lab6.raw --profile=Win7SP1x64 dumpfiles \
    -Q 0x000000005da5a610 -D artifacts/chrome_history/ -n
```

Query the extracted SQLite database for visited URLs:

```
$ sqlite3 artifacts/chrome_history/file.dat \
    "SELECT url, title, visit_count, last_visit_time FROM urls ORDER BY last_visit_time DESC"

https://pastebin.com/RSGSi1hk          | Private Paste ID: RSGSi1hk     | 1
https://docs.google.com/document/d/    | (Google Docs)                   | 2
  1lptcksPt1l_w7Y29V4o6vkEnHToAPqiCkgNNZfS9rCk/edit
https://mega.nz/...                    | MEGA                            | 1
https://mail.google.com/               | Gmail                           | 5
https://www.google.com/search?q=...    | (various searches)              | ...
```

**Key URLs identified:**

- **Pastebin** (`RSGSi1hk`) — A private paste, likely containing a link
- **Google Docs** (`1lptcksPt1l_...rCk`) — A shared document with the Mega download link
- **Mega.nz** — File hosting, used to share an encrypted file
- **Gmail** — Logged in as `davidbenjamin939@gmail.com`

### Dump the Firefox places.sqlite

```
$ vol.py -f MemoryDump_Lab6.raw --profile=Win7SP1x64 dumpfiles \
    -Q 0x00000000053fd070 -D artifacts/firefox_places/ -n

$ sqlite3 artifacts/firefox_places/file.vacb \
    "SELECT url, title, visit_count FROM moz_places WHERE visit_count > 0"
```

Firefox corroborated the same browsing pattern: Gmail, the Google Docs document, and various Google searches.

### Trace the communication chain

Searching raw memory strings for the Pastebin URL reveals it was shared via Google Hangouts (Google's chat service):

```
$ strings -el MemoryDump_Lab6.raw | grep "RSGSi1hk"

https://www.google.com/url?q=https://pastebin.com/RSGSi1hk
    &sa=D&source=hangouts&ust=1566312093252000
    &usg=AFQjCNG5h1xB6JduLnMZwp7a3M5aHYO4fw
```

**Communication path reconstructed:** An associate shared the Pastebin link through Google Hangouts -> the Pastebin contained a link to a Google Docs document -> the Docs document contained a Mega.nz download URL.

---

## 4. Gmail & Mega Key Recovery

Gmail caches email data as JSON structures in the browser's memory. By searching for keywords related to the Mega download, we can find the decryption key that was emailed separately:

```
$ strings -el MemoryDump_Lab6.raw | grep -B2 -A2 "Mega"

...cached Gmail JSON structure...
Subject: "Mega Drive Key"
From:    danielbenjamin683@gmail.com
To:      davidbenjamin939@gmail.com
Body:    "THE KEY IS zyWxCjCYYSEMA-hZe552qWVXiPwa5TecODbjnsscMIU"
```

**Mega.nz Decryption Key:** `zyWxCjCYYSEMA-hZe552qWVXiPwa5TecODbjnsscMIU`

Sent by Daniel Benjamin to David Benjamin's Gmail account. Mega.nz encrypts files client-side; without this key, the download is useless.

The Mega file ID `SrxQxYTQ` was found in browser history/cache data. Combined with the emailed key, the full download URL is:

```
https://mega.nz/#!SrxQxYTQ!zyWxCjCYYSEMA-hZe552qWVXiPwa5TecODbjnsscMIU
```

---

## 5. Flag Part 1: Mega Download & PNG Repair

### Download the file

```
$ megadl "https://mega.nz/#!SrxQxYTQ!zyWxCjCYYSEMA-hZe552qWVXiPwa5TecODbjnsscMIU" \
    --path=artifacts/

$ ls -la artifacts/flag_.png
-rw-rw-r-- 1 kali kali 41037 Aug 18  2019 artifacts/flag_.png

$ file artifacts/flag_.png
artifacts/flag_.png: data
```

The file is 41,037 bytes but `file` doesn't recognize it as a PNG. Something is wrong with the header.

### Diagnose the corruption

```python
$ python3 -c "
data = open('artifacts/flag_.png','rb').read()
print('PNG magic:', data[:8].hex())    # 89504e470d0a1a0a  (correct)
print('IHDR type:', data[12:16])       # b'iHDR' (WRONG - should be b'IHDR')
print('Byte 0x0C:', hex(data[0x0C]))   # 0x69 ('i') instead of 0x49 ('I')
"
```

The PNG signature (first 8 bytes) is correct, but the IHDR chunk type at offset `0x0C` has a lowercase `i` (`0x69`) instead of uppercase `I` (`0x49`). This single-byte corruption makes the PNG unreadable by any image viewer.

### Fix the IHDR byte and CRC

```python
import struct, zlib

with open('artifacts/flag_.png', 'rb') as f:
    data = bytearray(f.read())

# Fix the corrupted byte
data[0x0C] = 0x49  # 'i' (0x69) -> 'I' (0x49)

# Recalculate IHDR chunk CRC (covers type + data, bytes 12-28)
ihdr_crc = zlib.crc32(bytes(data[12:29])) & 0xFFFFFFFF
struct.pack_into('>I', data, 29, ihdr_crc)

with open('artifacts/flag1_fixed.png', 'wb') as f:
    f.write(data)
```

```
$ file artifacts/flag1_fixed.png
artifacts/flag1_fixed.png: PNG image data, 500 x 500, 8-bit/color RGBA, non-interlaced
```

**Flag Part 1 — flag1_fixed.png (500x500 RGBA)**

The repaired image displays text on a cyan background:

> `inctf{thi5_cH4LL3Ng3_!s_g0nn4_b3_?_`

Reads as: *"this challenge is gonna be ?_"* — the sentence clearly continues in Flag Part 2.

---

## 6. Flag Part 2: Encrypted RAR Recovery

### What we already know

| Item | Value | Source |
|------|-------|--------|
| File Path | `C:\Users\Jaffa\Desktop\pr0t3ct3d\flag.rar` | `cmdline` (PID 3716) |
| Password | `easypeasyvirus` | `envars` (PID 3716) |

### Locate and dump the RAR file

Search `filescan` for the flag.rar FILE_OBJECT:

```
$ vol.py -f MemoryDump_Lab6.raw --profile=Win7SP1x64 filescan | grep -i "flag"

Offset(P)          Name
0x000000005d8edbe0 \Users\Jaffa\Desktop\pr0t3ct3d          <- directory only
```

The `pr0t3ct3d` directory object exists, but `flag.rar` itself does not appear in filescan. The FILE_OBJECT was closed/deallocated before the memory dump. Use `dumpfiles` to recover it from the system cache:

```
$ vol.py -f MemoryDump_Lab6.raw --profile=Win7SP1x64 dumpfiles \
    -Q 0x000000005fcfc4b0 -D artifacts/rar_dump/ -n
```

### Verify and extract the RAR

```
$ unrar l artifacts/rar_dump/flag.rar

UNRAR 5.71
Archive: flag.rar
Details: RAR 5, encrypted headers

 Attributes      Size     Date    Time   Name
----------- ---------  ---------- -----  ----
    ..A....    358256   2019-08-18 21:43  flag2.png
----------- ---------  ---------- -----  ----
               358256                     1
```

The archive contains a single encrypted file: `flag2.png` (358,256 bytes). Extract using the recovered password:

```
$ unrar x -p'easypeasyvirus' artifacts/rar_dump/flag.rar artifacts/

Extracting  flag2.png                                          OK
```

**Flag Part 2 — flag2.png (500x500 RGBA)**

The decrypted image displays text completing the flag:

> `aN_Am4zINg_!_i_gU3Ss???_}`

Reads as: *"an amazing! i guess???"*

### Recovery notes

> **Alternative recovery via carving:** If the `dumpfiles` offset is not found in your run of the dump (FILE_OBJECT addresses can vary), the RAR can also be carved from raw memory by searching for the RAR5 magic bytes (`52 61 72 21 1a 07 01 00`). Multiple RAR5 signatures exist in the dump; the candidate at physical offset `0x200a1000` lists `flag2.png`. However, because the encrypted data spans non-contiguous physical pages, carving typically yields a corrupted archive with AES checksum errors. In that case, recovering the complete RAR requires the `dumpfiles` approach with the correct FILE_OBJECT address, or additional techniques like MFT data run reconstruction.

**MFT data runs (from mftparser):**

The MFT entry at offset `0x535f2000` maps flag.rar's on-disk location:

- Cluster 35,947 — 1 cluster (4,096 bytes)
- Cluster 332,806 — 64 clusters (262,144 bytes)
- Cluster 297,214 — 23 clusters (94,208 bytes)

Total: 88 clusters = 360,448 bytes allocated, 359,192 bytes real size.

---

## 7. Evidence Chain

The complete communication flow reconstructed from memory artifacts:

1. **Google Hangouts -> Pastebin link** — An associate shared the URL `https://pastebin.com/RSGSi1hk` via Google Hangouts (found in Chrome's cached URL redirects with `&source=hangouts` parameter).

2. **Pastebin -> Google Docs document** — The private paste linked to a Google Docs document (`1lptcksPt1l_w7Y29V4o6vkEnHToAPqiCkgNNZfS9rCk`) that contained the Mega.nz download URL for flag1.

3. **Gmail: Mega decryption key sent separately** — Daniel Benjamin (`danielbenjamin683@gmail.com`) emailed the Mega decryption key to David Benjamin (`davidbenjamin939@gmail.com`). Subject: "Mega Drive Key". The key and the download link were never in the same message — a rudimentary attempt at operational security.

4. **Mega.nz download -> flag_.png (Flag Part 1)** — File `flag_.png` downloaded from Mega (41,037 bytes). Intentional IHDR corruption at byte `0x0C`: `0x69` -> `0x49`. After repair + CRC recalculation, the image reveals the first half of the flag.

5. **Desktop: flag.rar (Flag Part 2)** — WinRAR (PID 3716) had `C:\Users\Jaffa\Desktop\pr0t3ct3d\flag.rar` open. RAR5 encrypted archive containing `flag2.png` (358,256 bytes). Password `easypeasyvirus` recovered from WinRAR's environment variables.

6. **flag1 + flag2 = complete flag** — The two PNG images each contain half the flag text, which concatenates into the complete `inctf{...}` flag.

---

## 8. Complete Flag

| Part | Source | Text | Decoded |
|------|--------|------|---------|
| Part 1 | flag1.png from Mega | `inctf{thi5_cH4LL3Ng3_!s_g0nn4_b3_?_` | "this challenge is gonna be ?_" |
| Part 2 | flag2.png from flag.rar | `aN_Am4zINg_!_i_gU3Ss???_}` | "an amazing! i guess???" |

**Complete flag:**

```
inctf{thi5_cH4LL3Ng3_!s_g0nn4_b3_aN_Am4zINg_!_i_gU3Ss???_}
```

*"this challenge is gonna be an amazing! i guess???"*

---

## 9. Extracted Artifacts

| Artifact | Description | Size | Status |
|----------|-------------|------|--------|
| `MemoryDump_Lab6.raw` | Source memory image (Win7SP1x64) | 1.5 GB | Source |
| `flag1_fixed.png` | Repaired PNG from Mega download (Flag Part 1) | 41 KB | Recovered |
| `flag_.png` | Original corrupted PNG from Mega (IHDR byte wrong) | 41 KB | Corrupted |
| `flag2.png` | Decrypted image from flag.rar (Flag Part 2) | 358 KB | Recovered |
| `chrome_history/` | Chrome History SQLite database + SharedCacheMap | 459 KB | Recovered |
| `firefox_places/` | Firefox places.sqlite (history + bookmarks) | 1.3 MB | Recovered |
| `flag.rar` | RAR5 encrypted archive from pr0t3ct3d directory | 359 KB | Recovered |
| `winrar_memdump/3716.dmp` | Full process memory dump of WinRAR.exe | 272 MB | Recovered |
| `mft_body.txt` | MFT timeline (mactime body format) | varies | Recovered |

---

## 10. Tools & Techniques

**Volatility 2 Plugins:** `imageinfo`, `pslist`, `pstree`, `cmdline`, `envars`, `filescan`, `dumpfiles`, `handles`, `clipboard`, `mftparser`, `memdump`, `screenshot`

**Volatility 3 Plugins:** `windows.pslist`, `windows.dumpfiles`

**External Tools:** `strings` (ASCII + UTF-16LE), `sqlite3`, `unrar`, `megadl`, `python3` (PIL, struct, zlib), `binwalk`, `grep`

**Key Techniques:** Browser SQLite database extraction, Gmail JSON cache parsing from memory strings, Mega.nz link reconstruction (file ID + decryption key), PNG IHDR chunk repair with CRC32 recalculation, RAR5 carving by magic bytes, MFT data run analysis, Process environment variable harvesting

---

*MemLabs Lab 6 — The Reckoning | Challenge by `stuxnet999` | Walkthrough by Duckbill Security*
