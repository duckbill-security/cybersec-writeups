# MemLabs Lab 2 — Complete Walkthrough

Nov 13, 2026 · @David

A full solution for all three flags in MemLabs Lab 2, a Windows 7 memory forensics CTF challenge involving environment variables, KeePass password recovery, and browser history analysis.

## Challenge Overview

**Description:** One of the clients of our company lost access to his system due to an unknown error. He is supposedly a very popular "environmental" activist. As a part of the investigation, he told us that his go-to applications are browsers, his password managers, etc. We hope that you can dig into this memory dump and find his important stuff and give it back to us.

The challenge contains **3 flags** hidden across different forensic artifacts.

**Key hints from the description:**

- "Environmental" (in quotes) hints at **environment variables**
- "Browsers" hints at **Chrome browsing history**
- "Password managers" hints at **KeePass**

**Tools used:**

- Volatility 2 (Python 2) for memory analysis
- `strings`, `grep`, `base64` for string searching and decoding
- `keepass2john` and `john` for password hash verification
- Python 3 with `pycryptodome` for manual KDBX decryption
- `megatools` for downloading from MEGA cloud storage
- `7z` for extracting password-protected ZIP files

**Memory dump:** `MemoryDump_Lab2.raw` (1,073,676,288 bytes / \~1 GB), a Windows 7 SP1 x64 VirtualBox VM.

## Reconnaissance

### Identify the OS profile

```
$ volatility -f MemoryDump_Lab2.raw imageinfo

Suggested Profile(s): Win7SP1x64, Win7SP0x64, Win2008R2SP0x64, Win2008R2SP1x64
AS Layer1: WindowsAMD64PagedMemory (Kernel DTB 0x187000L)
AS Layer2: FileAddressSpace (/home/kali/MemLabs/Lab2/MemoryDump_Lab2.raw)
PAE type: No PAE
DTB: 0x187000L
KDBG: 0xf800027f20a0L
```

The profile is **Win7SP1x64**.

### Process list

```
$ volatility -f MemoryDump_Lab2.raw --profile Win7SP1x64 pslist
```

Key processes of interest (54 total):

| PID | Process | Notes |
| --- | --- | --- |
| 3008 | KeePass.exe | Password manager (Session 1, user: Alissa Simpson) |
| 3260 | notepad.exe | Had Hidden.kdbx open |
| 2984 | chrome.exe | Browser with multiple child processes |
| 1064 | explorer.exe | Windows shell |
| 320 | csrss.exe | Contains environment variables |

The presence of KeePass, Chrome, and notepad immediately aligns with the challenge description about browsers and password managers.

## Flag 1 — Environment Variable (Base64)

The quoted word "environmental" in the challenge description is the hint. Run the `envars` plugin to list environment variables across all processes:

```
$ volatility -f MemoryDump_Lab2.raw --profile Win7SP1x64 envars | grep NEW_TMP

320  csrss.exe     0x0000000000481320  NEW_TMP  C:\Windows\ZmxhZ3t3M2xjMG0zX1QwXyRUNGczXyFfT2ZfTDRCXzJ9
424  wininit.exe   0x000000000030a600  NEW_TMP  C:\Windows\ZmxhZ3t3M2xjMG0zX1QwXyRUNGczXyFfT2ZfTDRCXzJ9
812  svchost.exe   0x0000000000221320  NEW_TMP  C:\Windows\ZmxhZ3t3M2xjMG0zX1QwXyRUNGczXyFfT2ZfTDRCXzJ9
```

A custom environment variable `NEW_TMP` appears in every process with a value that looks like Base64 appended to `C:\Windows\`. Decode it:

```
$ echo 'ZmxhZ3t3M2xjMG0zX1QwXyRUNGczXyFfT2ZfTDRCXzJ9' | base64 -d
flag{w3lc0m3_T0_$T4g3_!_Of_L4B_2}
```

**Flag 1:** `flag{w3lc0m3_T0_$T4g3_!_Of_L4B_2}`

## Flag 2 — KeePass Password Database

This is the most involved flag. The challenge mentions "password managers" and we saw KeePass.exe (PID 3008) in the process list.

### Step 1: Locate the KeePass database

KeePass stores passwords in `.kdbx` files. Scan for it:

```
$ volatility -f MemoryDump_Lab2.raw --profile Win7SP1x64 filescan | grep .kdbx

0x000000003fb112a0  16  0  R--r--  \Device\HarddiskVolume2\Users\SmartNet\Secrets\Hidden.kdbx
```

### Step 2: Dump the KDBX file

```
$ volatility -f MemoryDump_Lab2.raw --profile Win7SP1x64 dumpfiles -Q 0x000000003fb112a0 -D output/

DataSectionObject 0x3fb112a0  None  \Device\HarddiskVolume2\Users\SmartNet\Secrets\Hidden.kdbx
```

The extracted file is only **4,096 bytes** (a single memory page). The full KDBX would be larger, but only one page was resident in the memory dump's section object. This is enough — it contains the complete KDBX header.

### Step 3: Find the master password

The KeePass database needs a master password. Scan for password-related files:

```
$ volatility -f MemoryDump_Lab2.raw --profile Win7SP1x64 filescan | grep -i password

0x000000003fce1c70  1  0  R--r-d  \Device\HarddiskVolume2\Users\Alissa Simpson\Pictures\Password.png
```

Dump it:

```
$ volatility -f MemoryDump_Lab2.raw --profile Win7SP1x64 dumpfiles -Q 0x000000003fce1c70 -D output/
```

The image says "WOW! YOU ARE HERE!! BUT THE FLAG IS NOT HERE!! :P" but in the **bottom-right corner**, in small text:

> Psst!! password is **P4SSw0rd\_123**

### Step 4: Verify the password

Even though the KDBX is truncated, the header is intact. Extract the hash and verify:

```
$ keepass2john Hidden.kdbx
Hidden.kdbx:$keepass$*2*60000*0*03459735f8d3...2a68c087e896...

$ echo 'P4SSw0rd_123' | john --stdin keepass_hash.txt
P4SSw0rd_123  (Hidden.kdbx)
```

Password confirmed.

### Step 5: Decrypt the truncated KDBX manually

Since `pykeepass` cannot open a truncated file, we decrypt manually:

1. **Parse the KDBX header** (222 bytes): extract MasterSeed, TransformSeed, TransformRounds (60,000), EncryptionIV, ProtectedStreamKey, and StreamStartBytes
2. **Derive the master key:**
   - Composite key = SHA256(SHA256("P4SSw0rd\_123"))
   - AES-ECB encrypt the composite key with TransformSeed for 60,000 rounds
   - Final key = SHA256(MasterSeed + SHA256(transformed\_key))
3. **Decrypt the payload** (3,872 bytes after alignment) with AES-256-CBC using the derived key and IV
4. **Verify:** first 32 decrypted bytes match StreamStartBytes — confirms correct decryption
5. **Decompress:** the remaining data is a HashedBlockStream containing gzip-compressed XML (19,546 bytes decompressed)
6. **Decrypt protected fields:** KeePass uses Salsa20 with key = SHA256(ProtectedStreamKey) and nonce `0xE830094B97205D2A` to encrypt password values in the XML. Decrypt them in document order.

### Step 6: Read the entries

The decrypted XML reveals multiple entries, including decoy entries:

| Title | UserName | Password |
| --- | --- | --- |
| fake | stuxn3t | nothing here bro |
| fake again | R3x | not here bro :) |
| oh not again! | s0rc3r3r | your princess is in another castle |
| why God!! | f4lc0n | boom boom :) |
| **Sabka Baap** | **Flag** | **flag{w0w\_th1s\_1s\_Th3\_SeC0nD\_ST4g3\_!!}** |
| **The\_FLag\_Man** | **Flag** | **flag{w0w\_th1s\_1s\_Th3\_SeC0nD\_ST4g3\_!!}** |

The last two entries both contain the real flag.

**Flag 2:** `flag{w0w_th1s_1s_Th3_SeC0nD_ST4g3_!!}`

**Alternate approach:** If the KDBX file dumps completely (all pages resident), you can open it directly in KeePass or with `pykeepass` using password `P4SSw0rd_123` and copy the password from the entry.

## Flag 3 — Chrome History and MEGA Download

The challenge description mentions "browsers." Chrome (PID 2984) was running.

### Step 1: Extract Chrome browsing history

Use the `chromehistory` Volatility plugin (from the [Volatility-Plugins](https://github.com/superponible/volatility-plugins) repository):

```
$ volatility --plugins=plugins/ -f MemoryDump_Lab2.raw --profile Win7SP1x64 chromehistory
```

Among the browsing history, a MEGA cloud storage link appears:

```
https://mega.nz/#F!TrgSQQTS!H0ZrUzF0B-ZKNM3y9E76lg
```

The MEGA folder is named **MemLabs\_Lab2\_Stage3** and contains a single file: `Important.zip`.

### Step 2: Download from MEGA

```
$ megadl 'https://mega.nz/#F!TrgSQQTS!H0ZrUzF0B-ZKNM3y9E76lg'
```

This downloads `Important.zip`, which is password-protected (AES-256 encryption, method 99).

### Step 3: Determine the ZIP password

The standard `unzip` tool does not support AES encryption. Use `7z` instead. The password is the **SHA1 hash of the Lab 1 Stage 3 flag**:

```
$ echo -n 'flag{w3ll_3rd_stage_was_easy}' | sha1sum
6045dd90029719a039fd2d2ebcca718439dd100a
```

### Step 4: Extract and read the flag

```
$ 7z x Important.zip -p6045dd90029719a039fd2d2ebcca718439dd100a
```

This extracts `Important.png`, an image containing:

**Flag 3:** `flag{oK_So_Now_St4g3_3_is_DoNE!!}`

## Summary

| Stage | Flag | Artifact | Technique |
| --- | --- | --- | --- |
| 1 | `flag{w3lc0m3_T0_$T4g3_!_Of_L4B_2}` | `NEW_TMP` env var | `envars` plugin + Base64 decode |
| 2 | `flag{w0w_th1s_1s_Th3_SeC0nD_ST4g3_!!}` | Hidden.kdbx (KeePass) | `filescan` + `dumpfiles` + Password.png + manual AES/Salsa20 decryption |
| 3 | `flag{oK_So_Now_St4g3_3_is_DoNE!!}` | Important.zip (MEGA) | `chromehistory` plugin + `megadl` + SHA1 password + `7z` extraction |

### Key Techniques

- **Environment variable analysis** — the `envars` plugin reveals system-wide variables; custom or unusual names are worth investigating
- **File carving from memory** — `filescan` + `dumpfiles` extracts files cached in memory, even if only partially resident (the KDBX had only 1 of its pages in RAM)
- **Manual cryptographic recovery** — when tools fail on truncated files, understanding the file format (KDBX header → AES key derivation → CBC decryption → gzip decompression → Salsa20 stream cipher for protected fields) lets you recover data from partial extractions
- **Browser history analysis** — Chrome history plugins reveal URLs visited, including cloud storage links containing evidence
- **Cross-challenge dependencies** — Flag 3's ZIP password is the SHA1 of a flag from Lab 1, rewarding solvers who completed earlier challenges

### Pitfalls

- **Truncated memory dumps** — always verify the dump file size matches the expected uncompressed size; a partial extraction causes every Volatility plugin to return empty results
- **Password.png misdirection** — the image's main text says "THE FLAG IS NOT HERE" but the actual password (`P4SSw0rd_123`) is hidden in tiny text in the bottom-right corner
- **NTLM hash red herring** — cracking user NTLM hashes (Alissa Simpson's `goodmorningindia`) does not give the KeePass master password; the password is in the PNG image instead
- **AES-encrypted ZIPs** — standard `unzip` cannot handle AES (method 99); use `7z` instead
