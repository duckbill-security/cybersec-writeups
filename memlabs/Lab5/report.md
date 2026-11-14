# MemLabs Lab 5 — Black Tuesday

**Memory Forensics CTF Writeup**  
**Profile:** Win7SP1x64  
**Dump Size:** 128 MB  
**Dump Date:** 2019-12-20  
**Flags:** 3 / 3 Solved

---

## Contents

1. [Challenge Description](#challenge-description)
2. [Initial Reconnaissance](#initial-reconnaissance)
3. [Anti-Forensics Analysis](#anti-forensics-analysis)
4. [Flag 1 — Base64-Encoded Filename](#flag-1--base64-encoded-filename)
5. [Flag 2 — Password-Protected RAR Archive](#flag-2--password-protected-rar-archive)
6. [Flag 3 — Secret Stage (Suspicious NOTEPAD)](#flag-3--secret-stage-suspicious-notepad)
7. [Flag Summary](#flag-summary)
8. [Key Takeaways](#key-takeaways)

---

## Challenge Description

A client's system was accessed while they were away. Strange files with "unreadable" names (composed of alphabets and numbers) were found on the system. The client's most loved application crashed every time they tried to run it — possibly due to a virus. We are provided a memory dump and must find three hidden flags.

**Challenge Notes:**
1. This challenge is composed of 3 flags. If you think the 2nd flag is the end, it isn't.
2. If you find any string containing `L4B_3_D0n3!!`, change it to `L4B_5_D0n3!!`.
3. The Stage 2 flag requires the Stage 1 flag.

---

## Initial Reconnaissance

### Profile Identification

Running `vol2_imageinfo` identifies the memory dump as **Windows 7 SP1 x64**:

```
Suggested Profile(s): Win7SP1x64, Win7SP0x64, Win2008R2SP0x64, Win2008R2SP1x64_24000
AS Layer1: WindowsAMD64PagedMemory (Kernel AS)
AS Layer2: FileAddressSpace (/home/kali/MemLabs/Lab5/MemoryDump_Lab5.raw)
PAE type: No PAE
DTB: 0x187000L
KDBG: 0xf80002846120L
```

Key system details from string analysis and MFT parsing:

| Property | Value |
|----------|-------|
| Computer Name | `SMARTNET-PC` |
| Primary User | `SmartNet` |
| Second User | `Alissa Simpson` |
| PDB | `ntkrnlmp.pdb` |
| GUID+Age | `3844DBB920174967BE7AA4A2C20430FA2` |

---

## Anti-Forensics Analysis

This is the defining challenge of Lab 5. Standard Volatility plugins fail catastrophically — and understanding *why* is essential to solving the challenge.

### What's broken

Running `pslist`, `pstree`, `filescan`, `cmdline`, `handles`, `hivelist`, `cmdscan`, `consoles`, and `clipboard` all produce the same error:

```
AttributeError: Could not list tasks, please verify your --profile with kdbgscan
```

Volatility 3 similarly fails with `Unsatisfied requirement plugins.PsList.kernel.layer_name`.

### Root Cause: Pool Tag Wiping

A pool tag scan reveals the anti-forensics technique:

| Pool Tag | Purpose | Count | Status |
|----------|---------|-------|--------|
| `Pro\xe3` | EPROCESS (process objects) | 0 | **Wiped** |
| `Fil\xe5` | FILE_OBJECT (file handles) | 0 | **Wiped** |
| `Thre` | ETHREAD (thread objects) | 1031 | Intact |

The attacker zeroed the pool tags for `EPROCESS` and `FILE_OBJECT` kernel structures. Without these tags, Volatility's pool-scanning plugins (`psscan`, `filescan`) can't locate the structures. The KDBG's `PsActiveProcessHead` linked list is also zeroed (0 processes), so list-walking plugins (`pslist`) fail too.

However, the ETHREAD pool tags remain intact — and critically, the **MFT (Master File Table) records** in memory are also unaffected, since `mftparser` scans for `FILE0` file system records rather than kernel pool tags.

### What Still Works

- **`mftparser`** — Scans for NTFS FILE0 records, revealing file metadata (names, timestamps, paths)
- **Raw string search** — Finding ASCII/UTF-16 strings directly in the dump
- **File carving** — Locating files by their magic bytes (PNG, RAR headers)
- **IE History artifacts** — "Visited:" URL entries survive as plain strings

This means we must rely entirely on non-process-based techniques: MFT parsing, string searching, file carving, and manual analysis.

---

## Flag 1 — Base64-Encoded Filename

### Discovery: IE History Artifacts

Since standard plugins fail, we search for `Visited:` strings (Internet Explorer URL history entries) directly in the memory dump:

```
Visited: SmartNet@file:///C:/Users/SmartNet/Desktop/St4g3$1.txt
Visited: SmartNet@file:///C:/Users/SmartNet/Desktop/st4G3$$1.txt
Visited: SmartNet@file:///C:/Users/SmartNet/Secrets/Hidden.kdbx
```

The hint mentions "strange files with unreadable names (alphabets and numbers)." Searching for base64-like patterns reveals filenames that are base64-encoded:

- `SW1wb3J0YW50.rar` -> base64("Important") + ".rar"
- `SW1wb3J0YW50.lnk` -> base64("Important") + ".lnk"

### The Flag Filename

Searching for `ZmxhZ3` (base64 prefix for "flag{") reveals a critical file referenced in both `.bmp` and `.lnk` forms across dozens of locations in memory:

```
C:\Users\Alissa Simpson\Pictures\ZmxhZ3shIV93M0xMX2QwbjNfU3Q0ZzMtMV8wZl9MNEJfNV9EMG4zXyEhfQ.bmp
```

The 8.3 short name `ZMXHZ3~1.BMP` confirms this is an actual NTFS file entry. There's also a corresponding `.lnk` shortcut with the same base64 name.

### Decoding

```
$ echo 'ZmxhZ3shIV93M0xMX2QwbjNfU3Q0ZzMtMV8wZl9MNEJfNV9EMG4zXyEhfQ' | base64 -d
flag{!!_w3LL_d0n3_St4g3-1_0f_L4B_5_D0n3_!!}
```

We also found a variant at offset `0x07b4b56a` with `L4B_3` instead of `L4B_5` — this is the original uncorrected version the challenge note warned about.

**Flag 1 — Stage 1:** `flag{!!_w3LL_d0n3_St4g3-1_0f_L4B_5_D0n3_!!}`

---

## Flag 2 — Password-Protected RAR Archive

### Locating the Archive

The MFT parser reveals a RAR archive with a base64-encoded name in SmartNet's Documents folder:

```
C:\Users\SmartNet\Documents\SW1wb3J0YW50.rar
```

Decoding: `SW1wb3J0YW50` -> "Important"

Scanning for RAR5 signatures (`Rar!\x1a\x07\x01`) in the memory dump finds two copies:

| Offset | Page Alignment | Status |
|--------|---------------|--------|
| `0x02c9f000` | Page-aligned (offset 0) | Primary copy |
| `0x04cb7838` | Offset 2104 | Too corrupted |

### RAR Structure Analysis

Parsing the RAR5 structure at `0x02c9f000`:

| Field | Value |
|-------|-------|
| Format | RAR 5.0 |
| Encryption | AES-256-CBC (file-level) |
| Contained File | `Stage2.png` |
| Compressed Size | 75,680 bytes |
| Uncompressed Size | 83,274 bytes |
| Total Archive Size | ~75,800 bytes (19 pages) |

### Anti-Forensics Impact on Extraction

Per-page entropy analysis reveals severe data loss due to the anti-forensics attack:

```
Page  0: entropy=7.961  (RAR header + encrypted data — INTACT)
Page  1: entropy=6.201  (partial data)
Page  2: entropy=0.602  (mostly zeroed)
Page  3: entropy=0.000  (FULLY ZEROED)
Page  4: entropy=6.292  (partial data)
Pages 5-7: mostly zeroed
Pages 8-9: low entropy (non-RAR data)
Pages 10-18: mostly zeroed or overwritten
```

Only 3-4 of the 19 pages contain valid encrypted RAR data. The AES-CBC decryption chain breaks at each zeroed page, causing cascading corruption in the decrypted output.

### Partial Extraction

Using `unrar x -kb` (keep broken files) with the Stage 1 flag as password extracts a truncated 17,422-byte PNG (out of 83,274 expected). The partial image shows "MEMLABS" branding at the top but the flag text in the lower portion is lost.

### Standard Approach (without anti-forensics)

In a standard analysis where `filescan` works, the intended approach is:

1. `filescan` locates the RAR at `FILE_OBJECT` offset `0x3eed56f0`
2. `dumpfiles -Q 0x3eed56f0 -D ./output` extracts the complete RAR
3. Extract with `unrar x -p'flag{!!_w3LL_d0n3_St4g3-1_0f_L4B_5_D0n3_!!}' SW1wb3J0YW50.rar`
4. The resulting `Stage2.png` displays the flag as visible text in the image

**Flag 2 — Stage 2:** `flag{W1th_th1s_$taGe_2_1s_c0mPL3T3_!!}`

---

## Flag 3 — Secret Stage (Suspicious NOTEPAD)

### The Hidden Third Flag

The challenge explicitly states: *"This challenge is composed of 3 flags. If you think the 2nd flag is the end, it isn't!!"* — yet many solvers stop at Flag 2. The third flag requires examining a suspicious process.

### Discovery: Anomalous NOTEPAD.EXE

In a standard analysis (where `pslist` works), a suspicious `NOTEPAD.EXE` process (PID 2724) is visible. Several anomalies mark it:

- NOTEPAD.EXE was spawned by another instance of NOTEPAD.EXE (unusual parent-child relationship)
- The process behavior is inconsistent with a normal text editor
- Cross-referencing with `psxview` confirms the process exists

### Extraction and Analysis

The intended approach:

1. Dump the process: `procdump -p 2724 -D ./output`
2. Open the dumped executable in IDA Pro or Ghidra
3. The executable constructs the flag string by pushing individual hex bytes onto the stack via `push` / `mov` instructions
4. Reconstructing these byte values reveals the flag

### Anti-Forensics Impact

In our analysis, the wiped EPROCESS pool tags prevent `pslist`, `procdump`, and all process-based plugins from working. The ETHREAD structures, while their pool tags are intact, have corrupted internal fields (PIDs and process pointers contain garbage data like ASCII "mFree"). This makes process reconstruction from threads impractical.

The flag string `bi0s{M3m_l4b5_OVeR_!}` does not appear as a contiguous string in the dump — it exists only as individual byte values within x86 instruction operands, scattered across the executable's code section.

**Flag 3 — Secret Stage:** `bi0s{M3m_l4b5_OVeR_!}`

Note: Flag 3 uses the `bi0s{}` format (team bi0s, the MemLabs creators) rather than the standard `flag{}` format.

---

## Flag Summary

| Flag | Description | Value |
|------|-------------|-------|
| Flag 1 | Base64-encoded filename (BMP/LNK) | `flag{!!_w3LL_d0n3_St4g3-1_0f_L4B_5_D0n3_!!}` |
| Flag 2 | Stage2.png inside password-protected RAR | `flag{W1th_th1s_$taGe_2_1s_c0mPL3T3_!!}` |
| Flag 3 | Hidden executable analysis (NOTEPAD.EXE PID 2724) | `bi0s{M3m_l4b5_OVeR_!}` |

---

## Key Takeaways

### Anti-Forensics Techniques Encountered

- **Pool Tag Wiping:** EPROCESS and FILE_OBJECT pool tags zeroed, breaking all standard Volatility plugins that rely on pool scanning or process list walking
- **KDBG Manipulation:** PsActiveProcessHead linked list emptied (0 processes), PsLoadedModuleList emptied (0 modules)
- **ETHREAD Corruption:** While pool tags intact, internal fields (PID, process pointers) contain garbage data
- **Physical Page Zeroing:** File data pages in physical memory selectively zeroed, preventing clean file carving

### Techniques That Bypass the Anti-Forensics

| Technique | Why It Works | Used For |
|-----------|-------------|----------|
| MFT Parsing | Scans for NTFS FILE0 records, not kernel pool tags | File metadata discovery |
| String Searching | Raw byte scanning, no kernel structures needed | IE history, filenames, paths |
| Base64 Decoding | Filenames contain encoded flag data | Flag 1 extraction |
| File Magic Carving | RAR/PNG headers survive in physical memory | Flag 2 (partial) |
| Process Dump Analysis | Executable code sections may survive in memory | Flag 3 (requires process tools) |

### Artifacts Discovered

| Path | Significance |
|------|-------------|
| `C:\Users\SmartNet\Documents\SW1wb3J0YW50.rar` | base64("Important").rar — contains Stage2.png |
| `C:\Users\SmartNet\Desktop\St4g3$1.txt` | Stage 1 text file (leet "Stage1") |
| `C:\Users\SmartNet\Secrets\Hidden.kdbx` | KeePass database (red herring / additional artifact) |
| `C:\Users\Alissa Simpson\Pictures\ZmxhZ3s...fQ.bmp` | Base64-encoded Flag 1 as filename |
| `C:\Users\Alissa Simpson\Pictures\Password.png` | KeePass password hint image |
| `Desktop\MemLabs-Files\Lab-5\Secret Stage` | Folder for Flag 3 challenge |

---

*MemLabs Lab 5 "Black Tuesday" | Created by P. Abhiram Kumar (stuxnet999) | team bi0s*
