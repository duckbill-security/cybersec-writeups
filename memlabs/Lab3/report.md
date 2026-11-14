# MemLabs Lab 3 — Complete Walkthrough

**Date:** 2026-11-13

A full solution for MemLabs Lab 3 (The Evil's Den), a Windows 7 memory forensics CTF challenge involving a Python XOR/Base64 encryption script and JPEG steganography.

## Challenge Overview

**Description:** A malicious script encrypted a very secret piece of information I had on my system. Can you recover the information for me please?

The challenge contains **1 flag** split into **2 parts**. The first half is needed to unlock the second half.

**Key hints from the description:**

- "Malicious script encrypted" — look for a script that performs encryption
- "Secret piece of information" — encrypted data stored on the system
- The challenge README states **steganography** tools (specifically steghide) are needed
- Flag format: `inctf{s0me_l33t_Str1ng}`

**Tools used:**

- Volatility 2 (Python 2) for memory analysis (`imageinfo`, `pslist`, `cmdline`, `filescan`, `dumpfiles`)
- `base64` for Base64 decoding
- Python for XOR decryption
- `steghide` for extracting hidden data from JPEG images

**Memory dump:** `MemoryDump_Lab3.raw` (~1 GB), a Windows 7 SP1 x86 VirtualBox VM.

## Reconnaissance

### Identify the OS profile

```
$ volatility -f MemoryDump_Lab3.raw imageinfo

Suggested Profile(s): Win7SP1x86_23418, Win7SP0x86, Win7SP1x86
AS Layer1: IA32PagedMemoryPae (Kernel DTB 0x185000L)
AS Layer2: FileAddressSpace (/home/kali/MemLabs/Lab3/MemoryDump_Lab3.raw)
PAE type: PAE
DTB: 0x185000L
```

The profile is **Win7SP1x86_23418** — notably, this is a **32-bit** system (x86), unlike Labs 1 and 2 which were 64-bit.

### Process list

```
$ volatility -f MemoryDump_Lab3.raw --profile Win7SP1x86_23418 pslist
```

Key processes of interest (41 total):

| PID | Process | Session | PPID | Notes |
| --- | --- | --- | --- | --- |
| 5300 | explorer.exe | 1 | 5128 | Windows shell (user: hello) |
| 3736 | notepad.exe | 1 | 5300 (explorer) | Editing evilscript.py |
| 3432 | notepad.exe | 1 | 5300 (explorer) | Editing vip.txt |
| 4116 | DumpIt.exe | 1 | 5300 (explorer) | Memory acquisition tool |

Two notepad.exe processes stand out immediately — both launched from explorer.exe by user "hello."

### Identify what the notepad processes have open

```
$ volatility -f MemoryDump_Lab3.raw --profile Win7SP1x86_23418 cmdline -p 3736,3432

notepad.exe pid:   3736
Command line : "C:\Windows\system32\NOTEPAD.EXE" C:\Users\hello\Desktop\evilscript.py

notepad.exe pid:   3432
Command line : "C:\Windows\system32\NOTEPAD.EXE" C:\Users\hello\Desktop\vip.txt
```

- **PID 3736** is editing `evilscript.py` — the "malicious script" from the challenge description
- **PID 3432** is editing `vip.txt` — the encrypted output ("very important" secret)

## Flag Part 1 — Reversing the Evil Script

### Step 1: Locate the files in memory

```
$ volatility -f MemoryDump_Lab3.raw --profile Win7SP1x86_23418 filescan | grep -E "evilscript|vip\.txt|suspision"

0x0000000004f34148      2      0 RW---- \Device\HarddiskVolume2\Users\hello\Desktop\suspision1.jpeg
0x000000003de1b5f0      8      0 R--rw- \Device\HarddiskVolume2\Users\hello\Desktop\evilscript.py.py
0x000000003e727e50      8      0 -W-rw- \Device\HarddiskVolume2\Users\hello\Desktop\vip.txt
```

Three important files on the Desktop:

| File | Physical Offset | Notes |
| --- | --- | --- |
| `evilscript.py.py` | 0x3de1b5f0 | The encryption script (double `.py` extension) |
| `vip.txt` | 0x3e727e50 | The encrypted output |
| `suspision1.jpeg` | 0x04f34148 | Suspicious JPEG — steghide target |

**Note:** The file on disk is `evilscript.py.py` (double extension), but notepad's command line references `evilscript.py`. This is a common Windows quirk when file extensions are hidden — the user may have named it `evilscript.py` not realizing `.py` was already appended.

### Step 2: Dump the files

```
$ volatility -f MemoryDump_Lab3.raw --profile Win7SP1x86_23418 dumpfiles -Q 0x000000003de1b5f0 -D output/
DataSectionObject 0x3de1b5f0   None   \Device\HarddiskVolume2\Users\hello\Desktop\evilscript.py.py

$ volatility -f MemoryDump_Lab3.raw --profile Win7SP1x86_23418 dumpfiles -Q 0x000000003e727e50 -D output/
DataSectionObject 0x3e727e50   None   \Device\HarddiskVolume2\Users\hello\Desktop\vip.txt

$ volatility -f MemoryDump_Lab3.raw --profile Win7SP1x86_23418 dumpfiles -Q 0x0000000004f34148 -D output/
DataSectionObject 0x04f34148   None   \Device\HarddiskVolume2\Users\hello\Desktop\suspision1.jpeg
```

### Step 3: Analyze the evil script

The contents of `evilscript.py.py`:

```python
import sys
import string

def xor(s):
	a = ''.join(chr(ord(i)^3) for i in s)
	return a

def encoder(x):
	return x.encode("base64")

if __name__ == "__main__":
	f = open("C:\\Users\\hello\\Desktop\\vip.txt", "w")
	arr = sys.argv[1]
	arr = encoder(xor(arr))
	f.write(arr)
	f.close()
```

The script does two things to its command-line argument:

1. **XOR each character with 3** — a simple single-byte XOR cipher
2. **Base64 encode the result** — standard encoding

The output is written to `vip.txt`.

### Step 4: Read the encrypted output

Contents of `vip.txt`:

```
am1gd2V4M20wXGs3b2U=
```

### Step 5: Reverse the encryption

To recover the original plaintext, reverse the operations in the opposite order:

1. **Base64 decode** the string
2. **XOR each byte with 3** (XOR is its own inverse)

```python
import base64

encoded = 'am1gd2V4M20wXGs3b2U='
decoded = base64.b64decode(encoded)       # b'jm`wex3m0\\k7oe'
original = ''.join(chr(b ^ 3) for b in decoded)
print(original)  # inctf{0n3_h4lf
```

Or as a one-liner:

```bash
$ echo 'am1gd2V4M20wXGs3b2U=' | base64 -d | python3 -c "import sys; print(''.join(chr(b^3) for b in sys.stdin.buffer.read()))"
inctf{0n3_h4lf
```

**Flag Part 1:** `inctf{0n3_h4lf`

The flag is incomplete — no closing `}`. The challenge description said the flag is split into two parts, and steghide is needed for the second half.

## Flag Part 2 — Steganography

### Step 1: Examine the suspicious JPEG

The filescan revealed `suspision1.jpeg` on the Desktop. After dumping it (Step 2 above), we can verify it's a valid JPEG:

```
$ file suspision1.jpeg
suspision1.jpeg: JPEG image data, JFIF standard 1.01, aspect ratio, density 1x1,
segment length 16, baseline, precision 8, 256x197, components 3
```

A 256x197 pixel JPEG image — small, but with room for steganographic data.

### Step 2: Extract with steghide

The challenge hints say steghide is required. The passphrase is the first half of the flag — a common CTF pattern where solving one part unlocks the next.

```
$ steghide info suspision1.jpeg
"suspision1.jpeg":
  format: jpeg
  capacity: 581.0 Byte
Try to get information about embedded data? (y/n) y
Enter passphrase: inctf{0n3_h4lf
  embedded file "secret text":
    size: 16.0 Byte
    encrypted: rijndael-128, cbc
    compressed: yes
```

The JPEG contains an embedded file called "secret text" (16 bytes), encrypted with AES-128-CBC and compressed.

```
$ steghide extract -sf suspision1.jpeg -p "inctf{0n3_h4lf"
wrote extracted data to "secret text"

$ cat "secret text"
_1s_n0t_3n0ugh}
```

**Flag Part 2:** `_1s_n0t_3n0ugh}`

## Complete Flag

Combining both parts:

**Flag: `inctf{0n3_h4lf_1s_n0t_3n0ugh}`**

*Translation: "One half is not enough"*

## Summary

| Part | Value | Artifact | Technique |
| --- | --- | --- | --- |
| 1 | `inctf{0n3_h4lf` | evilscript.py.py + vip.txt | `filescan` + `dumpfiles` → reverse XOR(3) + Base64 |
| 2 | `_1s_n0t_3n0ugh}` | suspision1.jpeg | `steghide extract` with Part 1 as passphrase |

**Complete flag:** `inctf{0n3_h4lf_1s_n0t_3n0ugh}`

### Key Techniques

- **File carving from memory** — `filescan` + `dumpfiles` recovered the Python script, the encrypted text file, and the JPEG image from the memory dump
- **Script reverse engineering** — understanding what the encryption script does (XOR then Base64) to reverse the process and recover the plaintext
- **XOR cipher reversal** — XOR is a symmetric operation; XORing the ciphertext with the same key (3) recovers the plaintext
- **Steganography extraction** — `steghide` extracts data hidden in JPEG files using a passphrase; the first flag half was the key to unlocking the second

### Pitfalls

- **Double file extension** — the script appears as `evilscript.py.py` in the filesystem but notepad's cmdline shows `evilscript.py`; this is because Windows hides known extensions by default, so the user likely named it `evilscript.py` while the `.py` extension was already appended
- **32-bit profile** — Lab 3 uses Win7SP1x86_23418 (32-bit), unlike Labs 1 and 2 which are 64-bit; using the wrong profile produces no results
- **steghide passphrase** — the passphrase is the incomplete first half of the flag (`inctf{0n3_h4lf`), not the full flag; trying common passwords or empty passphrases will fail
- **File naming** — the JPEG is misspelled as "suspision1.jpeg" (not "suspicion"); searching for "suspicion" in filescan would miss it
- **Flag format** — Lab 3 uses `inctf{...}` format, not `flag{...}` like Labs 1 and 2; this is because the challenge was originally from InCTF

### Attack Chain Reconstruction

1. The user "hello" wrote `evilscript.py.py` — a simple Python 2 script that XORs a string with the key byte `3` and Base64 encodes the result
2. They ran the script with the first half of their secret as the argument: `python evilscript.py.py "inctf{0n3_h4lf"`
3. The script wrote the encrypted output to `vip.txt` on the Desktop
4. The second half of the secret (`_1s_n0t_3n0ugh}`) was hidden inside `suspision1.jpeg` using steghide, with the first half as the passphrase
5. At the time of the memory dump, the user had both `evilscript.py` and `vip.txt` open in separate notepad windows, and the JPEG was accessible on the Desktop
