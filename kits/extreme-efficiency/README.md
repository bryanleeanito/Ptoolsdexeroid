# extreme-efficiency v1.0

Mode Extreme Efficiency — optimize semua kit buat maksimal performa minimal resource.

## Perintah

```bash
python3 extreme_mode.py parallel --tools "nmap,httpx,ffuf" --target 10.0.0.1
python3 extreme_mode.py cache --tool nmap --args "-sV 10.0.0.1" --ttl 3600
python3 extreme_mode.py auto --chain "subfinder -> httpx -> ffuf -> nuclei"
python3 extreme_mode.py minimize --tool nuclei --templates-cpu 1
python3 extreme_mode.py monitor --pid 1234
python3 extreme_mode.py schedule --tool "nmap -sV" --cron "0 2 * * *"
```

## Fitur

| Perintah | Fungsi |
|---|---|
| `parallel` | Jalankan multi-tool secara paralel |
| `cache` | Cache hasil tool biar tidak repeat |
| `auto` | Auto-chain tool (output 1 = input lain) |
| `minimize` | Minimize resource (RAM, CPU, network) |
| `monitor` | Monitor resource usage |
| `schedule` | Schedule tool execution |

## Optimizations

### CPU
- `-T2` (nmap timing)
- `-c 1` (nuclei concurrency)
- `-t 10` (ffuf threads)
- `nice -n 19` (lowest priority)

### RAM
- `ulimit -v 500000` (500MB limit)
- `-timeout 5` (network timeout)
- `--max-retries 1` (minimize retries)

### Network
- `--max-rate 100` (nmap)
- `-rl 50` (nuclei rate limit)
- `--timeout 5` (ffuf)

## Auto Chain Example

```
subfinder -> httpx -> ffuf -> nuclei
```

1. `subfinder -d target.com` → subdomain list
2. `httpx -l subdomains.txt` → live hosts
3. `ffuf -w wordlist.txt -u https://target/FUZZ` → directory brute
4. `nuclei -l live.txt -t templates/` → vulnerability scan

## Aturan pakai

- Extreme efficiency = minimal resource, maksimal output
- Cache biar tidak repeat kerja
- Parallel biar cepat
- Schedule biar otomatis
