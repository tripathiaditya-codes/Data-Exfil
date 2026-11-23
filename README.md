# Incident Report: Malicious PE Disguised as imgpaper.png

**Classification:** Malware infection with domain controller compromise (PCAP-based analysis) **Malware family (assessed):** Trickbot-associated banking trojan / information stealer **Severity:** Critical **Analyst:** \[Your name\] **Tools used:** Wireshark, VirusTotal **Capture date (from DHCP lease data):** approx. 28 May 2020

## 1. Executive Summary

A Windows 7 workstation (`CAT-BOMB-W7-PC`, 10.5.28.229, user `phillip.ghent`) downloaded an executable disguised as an image file named `imgpaper.png` over plain HTTP from 162.216.0.163. VirusTotal flags the file as malicious (59/71 vendors). The sample is a loader/packer that decrypts and runs shellcode in memory.

In the same capture, the host sent system reconnaissance data and harvested credential data (POP3 mail, OpenVPN, OpenSSH keys) to external servers by HTTP POST. A second POST in the same format originated from the domain controller `Catbomber-DC` (10.5.28.8) under the `Administrator` account, which indicates the malware also ran on the DC. This must be treated as a **full domain compromise**, not a single-host infection.

## 2. Scope and Data Sources

| Source | Used for |
| --- | --- |
| Network capture (PCAP) | HTTP object extraction, stream reconstruction, POST bodies |
| VirusTotal report for SHA256 `934c8452...bcc79a` | Detection ratio, vendor labels, code insights |

## 3. Investigation Method

1. Opened **File > Export Objects > HTTP** and noticed `imgpaper.png`. Reasoning: the name hides the real file type, and it is served as `application/octet-stream` at about 503 kB, which is not normal for a PNG.
2. Applied the display filter `frame contains "imgpaper"`, which returned one frame: **frame 4030**, `GET /images/imgpaper.png` from 10.5.28.229 to 162.216.0.163.
3. Used **Follow TCP Stream** (`tcp.stream eq 52`, 504 kB, 1 client packet, 372 server packets). The response began with the `MZ` header and the string "This program cannot be run in DOS mode", which confirms a Windows PE executable, not an image.
4. Applied `frame contains "DOS mode"`, which returned two frames from 162.216.0.163 to 10.5.28.229: **frame 4032** (first data segment of `imgpaper.png`) and **frame 9238** (start of a second PE-sized download, `cursor.png`, in a different stream).
5. Ran `sha256sum imgpaper.png` on the exported object. The hash matched the VirusTotal entry, and the file size (503,808 bytes) matched the HTTP Content-Length.
6. Reviewed the POST streams: `tcp.stream eq 21` (workstation) and `tcp.stream eq 86` (domain controller).

&#91;image: Figure 1\]

*Figure 1. File > Export Objects > HTTP list: `imgpaper.png` (packet 4585) and `cursor.png` (packet 9771) from 162.216.0.163.*

&#91;image: Figure 2\]

*Figure 2. The filter `frame contains "imgpaper"` returns the GET request in frame 4030.*

&#91;image: Figure 3\]

*Figure 3. Follow TCP Stream (stream 52): GET request, response headers and the `MZ` header.*

&#91;image: Figure 4\]

*Figure 4. The filter `frame contains "DOS mode"` returns frames 4032 and 9238 from 162.216.0.163.*

## 4. Findings

### 4.1 Payload delivery and masquerading

- The server 162.216.0.163 delivered a PE file named `imgpaper.png` to 10.5.28.229 over HTTP.
- The `.png` name is used to look harmless. The file contents are an executable.
- Size: 492 KB. VirusTotal tags: `peexe`, `spreader`, `persistence`, `direct-cpu-clock-access`, `checks-user-input`, `runtime-modules`.

HTTP transfer details for `imgpaper.png` (stream 52):

| Field | Value |
| --- | --- |
| Request | `GET /images/imgpaper.png HTTP/1.1` (frame 4030) |
| Host | 162.216.0.163 |
| User-Agent | `WinHTTP loader/1.0` |
| Server | nginx/1.6.2 |
| Date | Thu, 28 May 2020 18:12:02 GMT |
| Content-Type | `application/octet-stream` |
| Content-Length | 503808 (same as the file size) |
| PE compile time (VirusTotal) | 2020-05-28 10:57:59 UTC, the same day as delivery |
| First submission to VirusTotal | 2020-06-01 |

The generic `WinHTTP loader/1.0` User-Agent is a useful hunting pivot for this download.

&#91;image: Figure 5\]

*Figure 5. VirusTotal basic properties: hashes, size 503,808 bytes and compile time 2020-05-28 10:57:59 UTC.*

### 4.2 Malware behavior (VirusTotal code insights)

VirusTotal describes the binary as a malicious loader/packer disguised as a legitimate MFC application. It:

1. Extracts an encrypted payload from resource ID `0x8c35`.
2. Resolves memory allocation APIs dynamically by hash from `kernel32.dll`.
3. Allocates `PAGE_EXECUTE_READWRITE` memory.
4. Decrypts the payload with a modified stream cipher using a hardcoded key.
5. Executes the decrypted shellcode immediately.

This is consistent with a packer stage that hides the real payload from static scanning.

&#91;image: Figure 6\]

*Figure 6. VirusTotal detection (59/71) and code insights for the sample.*

### 4.3 Detection summary

| Item | Value |
| --- | --- |
| Detection ratio | 59 / 71 |
| Trickbot-related labels | Antiy-AVL `Trojan/Win32.Trickpak`, DrWeb `Trojan.Trick.46644`, Alibaba `Trojan:Win32/Mansabo` |
| Emotet-labeled detections | AliCloud `Trojan:Win/Emotet.AE`, Fortinet `W32/Emotet.CHWJ!tr` |
| Generic labels | `Trojan.Agent.ERPH` (BitDefender, Emsisoft, eScan, GData, ALYac, Arcabit), Avast/AVG `MalwareX-gen`, Avira `TR/W32.MalwareX` |
| Behavioral/ML | CrowdStrike `malicious_confidence_100%`, Cynet `Malicious (score: 100)`, DeepInstinct `MALICIOUS`, Elastic `Malicious (high confidence)` |

&#91;image: Figure 7\]

*Figure 7. VirusTotal vendor detections, including the Trickpak and Trick labels.*

**Family assessment.** The Trickbot-linked labels (Trickpak, Trick) together with the observed behavior point to Trickbot. Emotet and Trickbot were frequently delivered together in this period, which would explain the Emotet labels, though the labels could also simply be loose heuristics. Confidence: **moderate to high** for "Trickbot-associated", low for any claim of a specific Emotet component. Family attribution should be confirmed with sandbox or YARA analysis.

### 4.4 Data exfiltration

The malware sent multipart/form-data HTTP POST requests with the boundary `----WebKitFormBoundary7MA4YWxkTrZu0gW` (the default Postman boundary) and the following fields:

| Field | Content |
| --- | --- |
| `proclist` | Running process list |
| `sysinfo` | `ipconfig /all`, `net config workstation`, `net view /all`, `nltest /domain_trusts`, plus domain, user and computer details |

The value `proclisttest` and the Postman boundary suggest the operator's server-side handler was still being tested during this campaign.

Additional markers in the traffic show credential collection:

- Exported **POP3 credentials** for the mail server (`mail.catbomber.net:995`) with the username `phillip.ghent` and a password (redacted here: `gh3n****`).
- **OpenVPN** passwords and configs.
- **OpenSSH private keys**.

The HTTP response header `Server: cowboy` was observed from the receiving server and is useful as a hunting fingerprint.

&#91;image: Figure 8\]

*Figure 8. Workstation POST (stream 21): multipart boundary, `proclist` field and a process list that includes `wermgr.exe`.*

&#91;image: Figure 9\]

*Figure 9. Workstation `sysinfo`: `ipconfig /all` output for `Cat-Bomb-W7-PC` (10.5.28.229).*

&#91;image: Figure 10\]

*Figure 10. Workstation `nltest /domain_trusts` output and LOCAL\_MACHINE\_DATA (stream 21, packet 2254).*

### 4.5 Victim system information

| Property | Workstation | Domain Controller |
| --- | --- | --- |
| Hostname | `CAT-BOMB-W7-PC` | `Catbomber-DC` |
| IP | 10.5.28.229 (DHCP) | 10.5.28.8 (static) |
| OS | Windows 7 Professional | Windows Server 2008 R2 Standard |
| Executing user | `phillip.ghent` | `Administrator` |
| Domain | `catbomber.net` | `catbomber.net` |
| MAC | 00-08-02-1C-47-AE | A4-1F-72-C2-09-6A |

Domain accounts enumerated: `Administrator`, `Guest`, `krbtgt`, `timothy.sizemore`, `phillip.ghent`. Other domain machines seen: `CAT-BOMB-W10-PC`.

Process-list observations:

- Workstation list includes `wermgr.exe`, a process commonly used as an injection target by Trickbot. This is an indicator, not proof of injection.
- DC list shows AD services (`Microsoft.ActiveDirectory.WebServices.exe`, `dns.exe`, `dfsrs.exe`, `ismserv.exe`), confirming the host is the domain controller.

&#91;image: Figure 11\]

*Figure 11. Workstation `net config workstation`: user `phillip.ghent`, Windows 7 Professional.*

### 4.6 Domain controller compromise

The second POST body reports `User name: Administrator` and `Computer name: \\CATBOMBER-DC`. This shows the malware (or its module) executed on the DC with administrator rights and sent the same style of report. **How** the attacker reached the DC is not established by the evidence reviewed so far (see section 8).

&#91;image: Figure 12\]

*Figure 12. Domain controller POST (stream 86): `ipconfig /all` for `Catbomber-DC` (10.5.28.8).*

&#91;image: Figure 13\]

*Figure 13. Domain controller `net config workstation`: user `Administrator`, Windows Server 2008 R2 Standard.*

### 4.7 Additional findings from the HTTP object list and POST streams

The HTTP object list shows the workstation's activity in packet order. The external IP lookups and the first POSTs come **before** the `imgpaper.png` download, so `imgpaper.png` is not shown to be the first malicious execution (see section 8, item 3).

| Packet | Host | Object | Size | Assessment |
| --- | --- | --- | --- | --- |
| 22 | api.ipify.org | text/plain | 15 B | External IP lookup. 15 bytes matches the length of `173.166.146.112`, so that address is most likely the victim's public IP, not a C2 server |
| 1561, 1600, 1665, 1686 | 36.89.106.69 | multipart/form-data | 210-282 B | Small POSTs (content not reviewed yet) |
| 2256 | 203.176.135.102:8082 | multipart/form-data | 4,362 B | Workstation report (`proclist` + `sysinfo`, stream 21, pkts 2252-2254) |
| 2835, 2975 | 162.216.0.163 | `VidT6cErs` | 106 kB, 105 kB | Two downloads before `imgpaper.png`; not hashed yet |
| 3036, 3047 | wtfismyip.com, icanhazip.com | text/plain | 16 B each | More public IP lookups (16 B = IP + newline) |
| 4585 | 162.216.0.163 | `imgpaper.png` | 503 kB | The PE under analysis (stream 52) |
| 9771 | 162.216.0.163 | `cursor.png` | 503 kB | Second PE-sized download (frame 9238); hash not compared yet |
| 12886 | 203.176.135.102:8082 | multipart/form-data | 4,343 B | DC report (stream 86, pkts 12882-12884) |

In the stream 21 screenshots the process list contains `wermgr.exe`, and the sysinfo block names `Cat-Bomb-W7-PC`, `phillip.ghent` and Windows 7 Professional. In stream 86 the report names `Catbomber-DC`, user `Administrator` and Windows Server 2008 R2 Standard. The DC report comes after the `cursor.png` download in packet order.

Both reports appear to go to `203.176.135.102:8082`, based on the object list sizes; confirm the destination in each packet's IP header.

## 5. Timeline

| Packet | Event | Evidence |
| --- | --- | --- |
| 22 | Workstation looks up its public IP via api.ipify.org (more lookups at pkts 3036 and 3047) | HTTP object list |
| 1561-1688 | Small multipart POSTs to 36.89.106.69 | HTTP object list |
| 2252-2256 | Workstation sends `proclist` and `sysinfo` to an external server (4,362 B) | Stream 21, object list |
| 2835, 2975 | `VidT6cErs` (106 kB and 105 kB) downloaded from 162.216.0.163 | HTTP object list |
| 4030-4585 | `GET /images/imgpaper.png`; PE returned, 503,808 bytes, at 909.6 s (about 18:12 GMT, 28 May 2020) | Stream 52 |
| 9238-9771 | Second PE-sized download, `cursor.png`, at 1078.5 s (about 18:15 GMT) | `DOS mode` filter, object list |
| 12882-12886 | Domain controller sends the same type of report as `Administrator` at 1285.6 s (about 18:18 GMT) | Stream 86 |

*Times are Wireshark capture-relative seconds. The approximate GMT values are derived from the server's HTTP Date header (18:12:02 GMT at about 909.8 s), so treat them as estimates. Times for packets before 4030 were not recorded.*

## 6. Indicators of Compromise (IOCs)

| Type | Value | Notes |
| --- | --- | --- |
| SHA256 | `934c84524389ecfb3b1dfcb28f9697a2b52ea0ebcaa510469f0d2d9086bcc79a` | `imgpaper.png` (PE) |
| MD5 | `25f283843378702ebc360e54ab37ed2e` | `imgpaper.png` |
| SHA-1 | `6135e409197758c60cd46c14d2c70f38b23eea96` | `imgpaper.png` |
| Imphash | `63d656bce327d52100cd4b1fdda09ce5` | `imgpaper.png` |
| File names | `imgpaper.png`, `cursor.png`, `VidT6cErs` | PE masquerading as images; `VidT6cErs` unknown |
| IP | 162.216.0.163 | Payload hosting (nginx/1.6.2) |
| IP:port | 203.176.135.102:8082 | Receives the large `proclist`/`sysinfo` POSTs |
| IP | 36.89.106.69 | Receives small multipart POSTs (to be reviewed) |
| IP | 173.166.146.112 | Most likely the victim's public IP (api.ipify.org reply), not C2 |
| Domains | api.ipify.org, wtfismyip.com, icanhazip.com | Legitimate IP lookup services, used by the malware for external IP discovery |
| User-Agent | `WinHTTP loader/1.0` | Seen on the `imgpaper.png` download |
| HTTP header | `Server: cowboy` | Server fingerprint noted during analysis; confirm which host returned it |
| Multipart boundary | `----WebKitFormBoundary7MA4YWxkTrZu0gW` | Detection pivot (also used by legitimate Postman traffic, so combine with other fields) |
| Field names | `proclist`, `sysinfo`, value `proclisttest` | Exfil format |
| Hardcoded key | `Y%olT5sKZd@\|~R4cXWitr{` | From VirusTotal code insights |
| Internal hosts | 10.5.28.229, 10.5.28.8 | Compromised |
| Accounts | `phillip.ghent`, `Administrator` | Compromised |

## 7. MITRE ATT&CK Mapping

| Tactic | Technique | Basis |
| --- | --- | --- |
| Initial Access / Execution | T1204.002 User Execution: Malicious File | Victim downloaded and ran the file (assumed from resulting traffic) |
| Defense Evasion | T1036.008 Masquerade File Type | PE named `.png` |
| Defense Evasion | T1027 Obfuscated Files or Information | Encrypted resource payload |
| Defense Evasion | T1055 Process Injection | Shellcode execution, `wermgr.exe` (likely) |
| Discovery | T1082, T1016, T1033, T1482 | sysinfo, ipconfig, user, domain trusts |
| Discovery | T1057 Process Discovery | `proclist` |
| Credential Access | T1555, T1552.004 | POP3/VPN credentials, SSH private keys |
| Command and Control | T1071.001 Web Protocols | HTTP POST |
| Exfiltration | T1041 Exfiltration Over C2 Channel | POST bodies |

## 8. Gaps and Items to Verify

1. **`cursor.png` vs `imgpaper.png`:** export packet 9771, run `sha256sum`, and compare with `934c8452...bcc79a`. A different hash means a second-stage file to check on VirusTotal.
2. **`VidT6cErs` (packets 2835 and 2975):** save both objects under different names, then hash them, run `file`, and search the hashes on VirusTotal. They arrive before `imgpaper.png` and may belong to an earlier stage.
3. **Initial infection vector:** the IP lookups and POSTs (packets 22 to 2256) come before the `imgpaper.png` download. Review the frames before packet 22 (DNS, HTTP, SMTP, TLS) to find how the workstation was first infected, or confirm the capture started after infection.
4. **Lateral movement path to the DC:** filter `smb || smb2 || dcerpc` and `ip.src==10.5.28.229 && ip.dst==10.5.28.8`, focusing on the window between 1078 s and 1285 s.
5. **Exfil destinations:** confirm the destination IP of packets 2256 and 12886 from the IP header, and read the small POSTs to 36.89.106.69 (packets 1561 to 1688) plus their URIs and User-Agent.
6. **DNS activity:** run the `dns` filter to see which domains resolved to the external IPs.
7. **Execution confirmation:** the PCAP shows the downloads and the later outbound traffic, but not the user action that launched the file.

Useful Wireshark filters:

```
http.request.method == "POST" && ip.addr == 10.5.28.229
frame contains "proclist"
ip.addr == 162.216.0.163
smb || smb2 || dcerpc
dns
```

## 9. Recommendations

### Immediate containment

- Isolate `CAT-BOMB-W7-PC` and `Catbomber-DC` from the network.
- Block the IOCs above at the firewall, proxy and EDR.
- Treat the domain as compromised; investigate other hosts such as `CAT-BOMB-W10-PC`.

### Eradication and recovery

- Rebuild the compromised hosts from known-good media; do not rely on cleaning.
- Reset all domain account passwords and reset `krbtgt` **twice**, with the required wait between resets.
- Revoke and reissue the user's POP3 mail credentials, VPN credentials and SSH keys.
- Review accounts and scheduled tasks on the DC for persistence.

### Detection and prevention

- Alert on executables served with image extensions or MIME types, and on `MZ` content in `.png` downloads.
- Alert on HTTP POST requests containing `proclist` / `sysinfo` and on the Postman boundary string.
- Hunt for `wermgr.exe` with unusual network activity.
- Block executable downloads over plain HTTP at the proxy, and restrict outbound traffic from servers.
- Replace end-of-life systems (Windows 7, Server 2008 R2).
- Limit administrator logons to the DC from workstations; use tiered administration.

## 10. Conclusion

The evidence shows a malicious PE disguised as an image (`imgpaper.png`, and a second download named `cursor.png`), served over HTTP by 162.216.0.163 to a workstation that was already sending system data to external servers. A matching report later comes from the domain controller as `Administrator`, which points to domain-level compromise. The sample is assessed as Trickbot-associated with moderate to high confidence. The initial infection vector, the role of `VidT6cErs` and `cursor.png`, and the path to the DC are still open and are listed in section 8.

*Note: all credentials in this report are redacted. Do not store plaintext passwords in incident documentation.*
