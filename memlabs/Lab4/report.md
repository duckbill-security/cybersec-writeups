# MemLabs Lab 4 -- "Obsession"

## Challenge Overview

| Field           | Value                                      |
|-----------------|--------------------------------------------|
| Challenge       | MemLabs Lab 4 -- Obsession                 |
| Flags           | 1                                          |
| Flag format     | `inctf{s0me_l33t_Str1ng}`                  |
| Memory dump     | `MemoryDump_Lab4.raw` (1,073,676,288 bytes)|
| MD5 (dump)      | `d2bc2f671bcc9281de5f73993de04df3`          |

**Scenario:** A user's system was compromised. The attacker stole data and also deleted an important file from the system. The only evidence available is a memory dump. The objective is to recover the deleted file.

---

## Phase 1: Initial Triage

### 1.1 Profile Identification

Every Volatility 2 analysis begins with identifying the operating system profile so the framework can correctly interpret kernel structures.

```
$ volatility -f MemoryDump_Lab4.raw imageinfo
```

```
Suggested Profile(s) : Win7SP1x64, Win7SP0x64, Win2008R2SP0x64, ...
                 DTB : 0x187000L
                KDBG : 0xf800027f60a0L
    Number of Processors : 1
 Image Type (Service Pack) : 1
   Image date and time : 2019-06-29 07:30:00 UTC+0000
   Image local date and time : 2019-06-29 13:00:00 +0530
```

**Selected profile:** `Win7SP1x64` (Windows 7 Service Pack 1, 64-bit). The IST timezone (+0530) suggests the user is in India, consistent with the `inctf` flag prefix (InCTF is an Indian CTF competition).

### 1.2 Process Listing

```
$ volatility -f MemoryDump_Lab4.raw --profile=Win7SP1x64 pslist
```

```
Offset(V)          Name                 PID   PPID  Sess  Start
------------------ -------------------- ----- ----- ----- ------------------------------
0xfffffa8000ca0040 System                  4     0    ---  2019-06-29 07:28:07
0xfffffa80014af950 smss.exe              256     4    ---  2019-06-29 07:28:07
0xfffffa8001c57b30 csrss.exe             328   320     0   2019-06-29 07:28:14
0xfffffa8000ca8960 csrss.exe             376   368     1   2019-06-29 07:28:15
0xfffffa8001c6f760 wininit.exe           384   320     0   2019-06-29 07:28:15
0xfffffa8001c751f0 winlogon.exe          412   368     1   2019-06-29 07:28:15
0xfffffa8001bc1b30 services.exe          472   384     0   2019-06-29 07:28:17
0xfffffa8001cb5940 lsass.exe             480   384     0   2019-06-29 07:28:17
0xfffffa8001cc1b30 lsm.exe              488    384     0   2019-06-29 07:28:17
0xfffffa8001d02b30 svchost.exe           580   472     0   2019-06-29 07:28:21
0xfffffa8001d30b30 VBoxService.ex        640   472     0   2019-06-29 07:28:21
...
0xfffffa80020f7b30 explorer.exe         1944  1872     1   2019-06-29 07:28:44
0xfffffa80021abab0 VBoxTray.exe         1592  1944     1   2019-06-29 07:28:53
0xfffffa80022f0610 GoogleCrashHan       2272  2008     0   2019-06-29 07:29:08
0xfffffa80022f6b30 GoogleCrashHan       2284  2008     0   2019-06-29 07:29:08
0xfffffa80020a4420 DumpIt.exe           2624  1944     1   2019-06-29 07:29:25
0xfffffa8002320350 conhost.exe          2636   376     1   2019-06-29 07:29:25
0xfffffa8001cac460 csrss.exe            2700  2692     2   2019-06-29 07:29:30
0xfffffa8002330060 winlogon.exe         2728  2692     2   2019-06-29 07:29:30
0xfffffa8000e54b30 taskhost.exe         2976   472     2   2019-06-29 07:29:36
0xfffffa8000e62b30 dwm.exe             3000   840     2   2019-06-29 07:29:36
0xfffffa8000eaeb30 explorer.exe         3012  2992     2   2019-06-29 07:29:36
0xfffffa8000eeeb30 VBoxTray.exe         2384  3012     2   2019-06-29 07:29:37
0xfffffa8000f18b30 StikyNot.exe         2432  3012     2   2019-06-29 07:29:37
```

**Observations:**

- The system is a **VirtualBox VM** (VBoxService.exe, VBoxTray.exe).
- There are **two interactive user sessions**:
  - **Session 1** -- explorer.exe (PID 1944), which spawned DumpIt.exe (PID 2624). The `cmdline` plugin shows DumpIt ran from `C:\Users\eminem\Desktop\DumpIt\`, identifying this session as user **eminem**.
  - **Session 2** -- explorer.exe (PID 3012), which spawned **StikyNot.exe** (PID 2432, Windows Sticky Notes). This is user **SlimShady** (identified from file paths below).
- **No Notepad.exe, cmd.exe, or browser processes are running.** This means any previously-open documents were closed before the dump.
- **StikyNot.exe** is notable -- Sticky Notes may contain user-written content that could be relevant.

### 1.3 Command-Line Arguments

```
$ volatility -f MemoryDump_Lab4.raw --profile=Win7SP1x64 cmdline
```

Key entries:

```
DumpIt.exe pid: 2624
Command line : "C:\Users\eminem\Desktop\DumpIt\DumpIt.exe"

StikyNot.exe pid: 2432
Command line : "C:\Windows\System32\StikyNot.exe"
```

The DumpIt output file in filescan is `2PAC-20190629-072925.raw`, revealing the computer name as **2PAC**.

---

## Phase 2: File System Reconnaissance

### 2.1 Full File Scan

```
$ volatility -f MemoryDump_Lab4.raw --profile=Win7SP1x64 filescan
```

Filtering the thousands of results for user-created content on desktops, documents, and recently accessed files:

**User eminem's files:**

```
0x3e8ad250  R--r--  \Users\eminem\Desktop\galf.jpeg
0x3e8d19e0  R--r--  \Users\eminem\Desktop\Screenshot1.png
0x3e8da630  R--rwd  \Users\eminem\Desktop\DumpIt
0x3e912190  R--r-d  \Users\eminem\Desktop\DumpIt\DumpIt.exe
0x3ebe2a20  RW-rw-  \Users\eminem\Desktop\DumpIt\2PAC-20190629-072925.raw
0x3e8a85b0  RW-rw-  \Users\eminem\...\Recent\Flag not here.lnk
0x3e8d1c80  RW-rw-  \Users\eminem\...\Recent\galf.lnk
0x3e8e5ba0  RW-rw-  \Users\eminem\...\Recent\Screenshot1.lnk
```

**User SlimShady's files:**

```
0x3fc398d0  R--rw-  \Users\SlimShady\Desktop\Important.txt
0x3f939720  RW-rw-  \Users\SlimShady\...\Recent\Important.lnk
0x3fcb0070  -W-rw-  \Users\SLIMSH~1\AppData\Local\Temp\FXSAPIDebugLogFile.txt
```

**Other notable entries:**

```
0x3eb96870  R--rwd  \$Recycle.Bin\S-1-5-21-410795266-795571449-2132107757-1000\desktop.ini
```

**Analysis of the files:**

| File | Observations |
|------|-------------|
| `galf.jpeg` | Filename is "flag" spelled backwards. Deliberate, likely a planted clue or decoy. Recently accessed (`galf.lnk` exists). |
| `Screenshot1.png` | A screenshot taken by the user. Recently accessed. |
| `Flag not here.lnk` | A shortcut in the Recent folder. The name is an obvious taunt -- probable red herring. |
| `Important.txt` | On SlimShady's Desktop. Per the challenge description, the attacker "deleted an important file" -- this is almost certainly the target. Its `.lnk` in the Recent folder confirms it was recently accessed. |

---

## Phase 3: Investigating Each Lead

### 3.1 Dumping Files from Memory

Volatility's `dumpfiles` plugin extracts cached file content from the Windows memory manager. Files are identified by the physical offset of their `_FILE_OBJECT` structure.

```
$ volatility -f MemoryDump_Lab4.raw --profile=Win7SP1x64 dumpfiles \
    -Q 0x3e8ad250 -D output/    # galf.jpeg

DataSectionObject 0x3e8ad250  \Users\eminem\Desktop\galf.jpeg
  -> file.None.0xfffffa80022ad0f0.dat  (229,376 bytes)

$ volatility -f MemoryDump_Lab4.raw --profile=Win7SP1x64 dumpfiles \
    -Q 0x3e8d19e0 -D output/    # Screenshot1.png

DataSectionObject 0x3e8d19e0  \Users\eminem\Desktop\Screenshot1.png
  -> file.None.0xfffffa80022d1670.dat  (57,344 bytes)

$ volatility -f MemoryDump_Lab4.raw --profile=Win7SP1x64 dumpfiles \
    -Q 0x3fc398d0 -D output/    # Important.txt

DataSectionObject 0x3fc398d0  None  \Users\SlimShady\Desktop\Important.txt
  -> (no output file created)
```

**Critical finding:** `galf.jpeg` and `Screenshot1.png` were successfully dumped. **`Important.txt` failed** -- the `DataSectionObject` exists (the file metadata is in the object manager) but the actual data pages are no longer in the memory manager's cache. This is consistent with a deleted file whose cached pages have been reclaimed.

### 3.2 Screenshot1.png -- Google Homepage

```
$ file Screenshot1.png
PNG image data, 1366 x 334, 8-bit/color RGBA, non-interlaced
```

Visual inspection reveals a screenshot of the Google homepage in a web browser. The search bar is partially visible at the bottom edge but no query text is discernible. There is nothing hidden in the image metadata or pixel data.

**Verdict: Red herring.**

### 3.3 galf.jpeg -- Steganography Analysis

```
$ file galf.jpeg
JPEG image data, JFIF standard 1.01, baseline, precision 8, 1500x844
```

The image shows a stylized illustration of the Joker (Heath Ledger's version from The Dark Knight). The reversed filename ("galf" = "flag") strongly suggests hidden content.

#### Steghide Analysis

```
$ steghide info galf.jpeg
"galf.jpeg":
  format: jpeg
  capacity: 10.5 KB
  embedded file "LMAO.txt":
    size: 38.0 Byte
    encrypted: rijndael-128, cbc
    compressed: yes
```

Steghide confirms an embedded file named **"LMAO.txt"** (38 bytes), encrypted with AES-128-CBC. Testing with an empty passphrase:

```
$ steghide extract -sf galf.jpeg -p ""
wrote extracted data to "LMAO.txt".

$ cat LMAO.txt
Move on bro, there is nothing here :)
```

The embedded file is a troll message from the challenge author. The empty passphrase, the "LMAO" filename, and the Joker image all reinforce that this is a deliberate misdirection.

**Verdict: Red herring (steganography decoy).**

### 3.4 "Flag not here.lnk" -- Self-Evident Decoy

The shortcut name literally says the flag is not here. Combined with the other decoys, this is part of the challenge's pattern of misdirection.

**Verdict: Red herring.**

### 3.5 Sticky Notes (StikyNot.exe, PID 2432)

Windows 7 Sticky Notes stores content in Rich Text Format within the process memory and in a `.snt` (structured storage) file. No `.snt` file appeared in the filescan, so the content must be extracted from the process memory directly.

```
$ volatility -f MemoryDump_Lab4.raw --profile=Win7SP1x64 memdump \
    -p 2432 -D output/
Writing StikyNot.exe [2432] to 2432.dmp
```

Searching the dumped process memory for relevant strings:

```
$ strings 2432.dmp | grep -i flag
The clipboard plugin works well but it doesn't give the flag :P
The flag passed is not correct.
```

The first string is the actual Sticky Notes content (found in RTF context):

```
$ strings 2432.dmp | grep "generator Msftedit"
{\*\generator Msftedit 5.41.21.2510;}\viewkind4\uc1\pard\...\highlight0\f0\fs22
The clipboard plugin works well but it doesn't give the flag :P\lang9\f1\par
```

This is the complete RTF content of the Sticky Note. It tells us two things:
1. The Sticky Note itself is not the flag -- it's a hint.
2. The **clipboard plugin** (`volatility clipboard`) is a dead end.

### 3.6 Clipboard -- Confirmed Empty

Following up on the Sticky Note's hint:

```
$ volatility -f MemoryDump_Lab4.raw --profile=Win7SP1x64 clipboard
```

```
Session  WindowStation  Format          Handle  Object              Data
-------  ------------- ---------------  ------  ------------------  ----
      2  WinSta0       CF_UNICODETEXT      0x0  ------------------
      2  WinSta0       CF_TEXT             0x1  ------------------
      1  WinSta0       CF_UNICODETEXT      0x0  ------------------
      1  WinSta0       CF_TEXT             0x1  ------------------
```

All clipboard entries are empty on both sessions.

**Verdict: Dead end (as warned by the Sticky Note).**

---

## Phase 4: Recovering the Deleted File

### 4.1 Why dumpfiles Failed

At this point all leads except `Important.txt` have been eliminated. The `dumpfiles` plugin failed because:

- When Windows deletes a file, the memory manager may release the file's cached data pages back to the free pool.
- The `_FILE_OBJECT` and its `_SECTION_OBJECT_POINTERS` still exist in memory (which is why `filescan` found it), but the `DataSectionObject`'s `_CONTROL_AREA` no longer maps to valid page table entries.
- The file was only 153 bytes -- too small for its pages to linger in the standby list.

### 4.2 The NTFS Master File Table (MFT) Approach

In NTFS, every file has a record in the **Master File Table (MFT)**. Each MFT record is typically 1024 bytes and contains the file's attributes:

- `$STANDARD_INFORMATION` (0x10) -- timestamps, permissions
- `$FILE_NAME` (0x30) -- the filename and parent directory reference
- `$DATA` (0x80) -- the file's actual content

For small files (roughly under 700 bytes depending on attribute overhead), NTFS stores the file content **directly inside the MFT record** as a "resident" `$DATA` attribute. This is an optimization that avoids allocating a separate cluster on disk. The key insight is: **even if the file's cached pages are gone from the memory manager, the MFT record itself (which contains the resident data) may still be present in the memory dump.**

### 4.3 Locating the MFT Record

```
$ volatility -f MemoryDump_Lab4.raw --profile=Win7SP1x64 mftparser --output=body \
    --output-file=mft_body.txt
```

Searching the body-format output for Important.txt:

```
$ grep -i "important" mft_body.txt

0|[MFT FILE_NAME] Users\SlimShady\Desktop\Important.txt
    (Offset: 0x3bd8ac00)|60583|---a------|0|0|0|
    1561641253|1561641253|1561641253|1561641253

0|[MFT FILE_NAME] Users\SLIMSH~1\AppData\Roaming\MICROS~1\
    Windows\Recent\Important.lnk
    (Offset: 0x23afc400)|22977|---a------|0|0|0|
    1561793383|1561793383|1561793383|1561550543
```

The MFT record for `Important.txt` exists at **physical offset `0x3bd8ac00`** in the memory dump. The timestamps (Unix epoch 1561641253 = 2019-06-27 14:14:13 UTC) show the file was created on June 27, two days before the memory dump was taken on June 29.

### 4.4 Parsing the MFT Record

Extract the 1024-byte MFT record from the raw memory image and parse its NTFS attribute structure:

```python
import struct

offset = 0x3bd8ac00
with open('MemoryDump_Lab4.raw', 'rb') as f:
    f.seek(offset)
    record = f.read(1024)

# Verify MFT signature
assert record[:4] == b'FILE', "Not a valid MFT record"

# MFT record header
first_attr = struct.unpack_from('<H', record, 20)[0]  # Offset to first attribute
flags      = struct.unpack_from('<H', record, 22)[0]   # Record flags

print(f"First attribute offset: {first_attr}")
print(f"Flags: {flags:#x}  (in-use: {bool(flags & 1)}, directory: {bool(flags & 2)})")
```

Output:
```
First attribute offset: 56
Flags: 0x1  (in-use: True, directory: False)
```

The record is marked as **in-use** (not deleted at the MFT level) and is a **file** (not a directory).

Walking the attribute chain starting at byte 56:

```
Attribute 0x10 ($STANDARD_INFORMATION), length 96, resident
Attribute 0x30 ($FILE_NAME), length 120, resident
Attribute 0x30 ($FILE_NAME), length 120, resident    [short 8.3 name]
Attribute 0x40 ($OBJECT_ID), length 40, resident
Attribute 0x80 ($DATA), length 184, **resident**
  -> Content size: 153 bytes
  -> Content offset: 24 (relative to attribute start)
End of attributes (0xFFFFFFFF sentinel)
```

**The `$DATA` attribute is resident** -- the file's content is stored directly inside this MFT record.

### 4.5 Extracting the Resident Data

The 153 bytes of resident data from the `$DATA` attribute:

```
Raw bytes (hex):
69 0d 0a 0d 0a 0d 0a 6e 0d 0a 0d 0a 0d 0a 63 74
0d 0a 0d 0a 0d 0a 0d 0a 66 7b 31 0d 0a 0d 0a 0d
0a 5f 69 73 0d 0a 0d 0a 0d 0a 5f 6e 30 74 0d 0a
0d 0a 0d 0a 0d 0a 5f 45 51 75 34 6c 0d 0a 0d 0a
0d 0a 0d 0a 5f 37 6f 5f 32 5f 62 55 74 0d 0a 0d
0a 0d 0a 0d 0a 0d 0a 0d 0a 0d 0a 5f 74 68 31 73
5f 64 30 73 33 6e 74 0d 0a 0d 0a 0d 0a 0d 0a 5f
6d 34 6b 65 0d 0a 0d 0a 0d 0a 5f 73 33 6e 0d 0a
0d 0a 0d 0a 0d 0a 73 33 7d 0d 0a 0d 0a 47 6f 6f
64 20 77 6f 72 6b 20 3a 50
```

Decoded as ASCII text:

```
i\r\n\r\n\r\n
n\r\n\r\n\r\n
ct\r\n\r\n\r\n\r\n
f{1\r\n\r\n\r\n
_is\r\n\r\n\r\n
_n0t\r\n\r\n\r\n\r\n
_EQu4l\r\n\r\n\r\n\r\n
_7o_2_bUt\r\n\r\n\r\n\r\n\r\n\r\n\r\n
_th1s_d0s3nt\r\n\r\n\r\n\r\n
_m4ke\r\n\r\n\r\n
_s3n\r\n\r\n\r\n\r\n
s3}\r\n\r\n
Good work :P
```

The flag was deliberately split across many lines with excessive blank lines (`\r\n` = Windows line endings) to make it harder to identify via simple string searches. This is why `strings -el MemoryDump_Lab4.raw | grep "inctf{"` returned nothing -- the flag is never contiguous in memory.

### 4.6 Reassembly

Stripping all carriage returns and newlines and removing the congratulatory message:

```python
raw = b'i\r\n\r\n\r\nn\r\n\r\n\r\nct\r\n\r\n\r\n\r\nf{1\r\n\r\n\r\n...'
flag = raw.replace(b'\r', b'').replace(b'\n', b'').decode()
# -> "inctf{1_is_n0t_EQu4l_7o_2_bUt_th1s_d0s3nt_m4ke_s3ns3}Good work :P"
```

---

## Flag

```
inctf{1_is_n0t_EQu4l_7o_2_bUt_th1s_d0s3nt_m4ke_s3ns3}
```

**Decoded (leet-speak to English):** *"1 is not equal to 2 but this doesn't make sense"*

---

## Timeline of Events

| Timestamp (UTC)          | Event                                                    |
|--------------------------|----------------------------------------------------------|
| 2019-06-27 14:14:13      | `Important.txt` created on SlimShady's Desktop           |
| 2019-06-29 07:28:07      | System boot                                              |
| 2019-06-29 07:28:44      | eminem logs in (Session 1, explorer.exe PID 1944)        |
| 2019-06-29 07:29:25      | DumpIt.exe launched from eminem's Desktop                |
| 2019-06-29 07:29:30      | SlimShady logs in (Session 2, csrss/winlogon PID 2700/2728) |
| 2019-06-29 07:29:36      | SlimShady's desktop initializes (explorer.exe PID 3012)  |
| 2019-06-29 07:29:37      | StikyNot.exe + VBoxTray.exe start in Session 2           |
| 2019-06-29 07:30:00      | Memory image captured                                    |

The Important.txt was created two days before the dump. SlimShady's session started just seconds before the dump was taken -- the file may have been deleted between sessions.

---

## Summary of All Artifacts

| Artifact | Location | Type | Finding |
|----------|----------|------|---------|
| `Important.txt` | SlimShady's Desktop | Deleted text file | **Contains the flag** (recovered via MFT resident data) |
| `galf.jpeg` | eminem's Desktop | JPEG with steghide | Decoy -- embedded "LMAO.txt" says "Move on bro" |
| `LMAO.txt` | Embedded in galf.jpeg | Steghide payload | Troll message, no flag |
| `Screenshot1.png` | eminem's Desktop | PNG screenshot | Google homepage, no useful content |
| `Flag not here.lnk` | eminem's Recent | Windows shortcut | Self-explanatory decoy name |
| Sticky Note | StikyNot.exe memory | RTF in process memory | "The clipboard plugin works well but it doesn't give the flag :P" |
| Clipboard | Sessions 1 & 2 | Clipboard data | Empty on both sessions |

---

## Techniques and Concepts

### MFT Resident Data Recovery

This is the core technique for this challenge. In NTFS:

- Every file and directory has an entry in the MFT, a database at the start of the NTFS volume.
- Each MFT record is fixed-size (usually 1024 bytes) and stores attributes as a linked list.
- The `$DATA` attribute (type `0x80`) holds the file content. When the content fits within the MFT record (after accounting for other attributes), it is stored **resident** -- directly inside the record, with no separate disk clusters allocated.
- For a typical MFT record with standard attributes, files up to ~700 bytes can be resident.
- When analyzing a memory dump, the MFT pages that were cached by Windows will be present in the dump. Volatility's `mftparser` plugin scans physical memory for valid MFT record signatures (`FILE`) and parses their attributes.
- Even when `dumpfiles` fails (because the memory manager has released the file's data pages), the MFT record may survive because it is part of the `$MFT` file itself, which is always open and whose pages tend to remain cached.

### Why Standard String Searches Failed

The flag was split across many lines with `\r\n` separators between each fragment:

```
i[blank lines]n[blank lines]ct[blank lines]f{1[blank lines]_is...
```

This means:
- `strings | grep "inctf{"` fails because the string "inctf{" never appears contiguously.
- `strings -el | grep "inctf{"` (UTF-16 search) also fails for the same reason.
- The only way to recover the flag is to extract the complete file content from the MFT record and strip the whitespace.

### Red Herring Identification

The challenge deliberately placed multiple decoys to consume analyst time:

1. **galf.jpeg** -- The reversed "flag" name and successful steghide extraction make it feel like a genuine finding. The challenge author even embedded an AES-encrypted payload to make it seem more significant. Only the content ("Move on bro") reveals the decoy.

2. **Sticky Notes** -- StikyNot.exe running in the compromised user's session draws attention. The RTF content in process memory is recoverable but contains only a hint about the clipboard.

3. **Clipboard** -- After the Sticky Note mentions it, analysts may spend time trying different clipboard extraction techniques (clipboard, editbox, consoles). All are empty.

4. **"Flag not here" shortcut** -- An obvious but effective time-waster for completionist analysts who try to trace where the shortcut pointed.

### Multi-User Session Analysis

The system had two concurrent user sessions:
- **eminem** (Session 1, SID `S-1-5-21-410795266-795571449-2132107757-1000`) -- ran DumpIt, had decoy files on desktop.
- **SlimShady** (Session 2, SID `S-1-5-21-410795266-795571449-2132107757-1001`) -- had the Important.txt and Sticky Notes.

Recognizing that evidence spans multiple user profiles prevents tunnel vision on a single user's artifacts.

---

## Tools Used

| Tool | Purpose |
|------|---------|
| Volatility 2.6.1 `imageinfo` | OS profile identification |
| Volatility 2.6.1 `pslist` | Process enumeration |
| Volatility 2.6.1 `cmdline` | Process command-line arguments |
| Volatility 2.6.1 `filescan` | Open file handle enumeration |
| Volatility 2.6.1 `dumpfiles` | File content extraction from cache |
| Volatility 2.6.1 `clipboard` | Clipboard content extraction |
| Volatility 2.6.1 `memdump` | Full process memory dump |
| Volatility 2.6.1 `mftparser` | MFT record scanning and parsing |
| `steghide` | JPEG steganography detection and extraction |
| `strings` | String extraction from binary data |
| Python `struct` | Manual MFT record attribute parsing |
