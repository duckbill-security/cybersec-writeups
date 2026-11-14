# Cybersec Writeups

DFIR challenge writeups and forensic analysis reports.

## MemLabs — Memory Forensics

| Lab | Title | Profile | Flags |
|-----|-------|---------|-------|
| [Lab 1](memlabs/Lab1/report.md) | Beginner's Luck | Win7SP1x86 | 3/3 |
| [Lab 2](memlabs/Lab2/report.md) | A New World | Win7SP1x64 | 3/3 |
| [Lab 3](memlabs/Lab3/report.md) | The Evil's Den | Win7SP1x86 | 3/3 |
| [Lab 4](memlabs/Lab4/report.md) | Obsession | Win7SP1x64 | 3/3 |
| [Lab 5](memlabs/Lab5/report.md) | Black Tuesday | Win7SP1x64 | 3/3 |
| [Lab 6](memlabs/Lab6/report.md) | The Reckoning | Win7SP1x64 | 3/3 |

## Malware Traffic Analysis

| Exercise | Date | Report |
|----------|------|--------|
| [The Lucky Turkey](malware-traffic-analysis/2026-11-10-The-Lucky-Turkey/report.md) | 2026-11-10 | Traffic analysis |

## Structure

Each challenge has a `report.md` writeup and an `artifacts/` folder with key evidence (flag images, screenshots, extracted files). Source memory dumps and pcap files are not included — they are available from the original challenge pages.

## Tools

Analysis performed with the [DFIR MCP toolkit](https://github.com/anthropics/claude-code) using Volatility 2/3, tshark, The Sleuth Kit, steghide, and related forensic tools.
