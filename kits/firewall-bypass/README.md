# firewall-bypass v1.0

Firewall bypass extreme toolkit buat authorized pentest.

## Perintah

```bash
python3 fw_bypass.py method --target 10.0.0.1
python3 fw_bypass.py tunnel --type dns --server 8.8.8.8
python3 fw_bypass.py evasion --target 10.0.0.1
python3 fw_bypass.py protocol --proto icmp
python3 fw_bypass.py test --target 10.0.0.1 --port 80
```

## Bypass Methods

| Method | Keterangan |
|---|---|
| Fragmentation | IP fragmentasi, split packet kecil |
| Decoy | Decoy scan, samarkan sumber |
| Source Port | Source port spoof (DNS 53) |
| MAC Spoof | MAC address spoof |
| Badsum | Bad checksum, bypass stateless FW |
| Data Length | Data length manipulation |
| TTL | TTL manipulation |
| Window Size | TCP window size manipulation |

## Tunneling

| Type | Tools |
|---|---|
| DNS | iodine, dnscat2, dns2tcp |
| ICMP | ptunnel, icmptunnel |
| HTTP | reGeorg, reDuh, Squid |
| SSH | ssh -L, ssh -R, ssh -D |

## Evasion

- IP fragmentation
- TCP flags (NULL, Xmas, FIN)
- TTL manipulation
- TCP window size
- Source port spoof
- MAC spoof
- Bad checksum
- Data length
- Decoy

## Protocol Abuse

- DNS: tunnel, exfiltration, cache poisoning, rebinding
- ICMP: tunnel, exfiltration, ping sweep
- HTTP: tunnel, smuggling, parameter pollution, cache poisoning
- SMTP: tunnel, exfiltration, relay abuse

## Aturan pakai

- **Wajib** otorisasi tertulis / CTF scope
- Jangan produksi tanpa izin
- Tunneling = teknik advanced, hati-hati
- Output = attack artifact
