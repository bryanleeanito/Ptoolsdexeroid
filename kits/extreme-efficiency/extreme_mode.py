#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""extreme_mode.py — Mode Extreme Efficiency v2 (hardware-tuned).

Di-tune khusus untuk ThinkPad T14s G1:
  - CPU  : Ryzen 5 PRO 4650U (6 core / 12 thread)
  - RAM  : 16 GB
  - OS   : Kali Linux

Fitur:
  - parallel: jalankan multi-tool secara paralel (auto-detect core count)
  - cache: cache hasil tool biar tidak repeat
  - auto: auto-chain tool (output 1 tool = input tool lain)
  - hwinfo: tampilan capability hardware + tuning preset
  - minimize: minimize resource (RAM, CPU, network)
  - monitor: monitor resource usage
  - schedule: schedule tool execution
  - preset: tuning preset (stealth / balanced / max)

    python3 extreme_mode.py parallel --tools "nmap,httpx,ffuf" --target 10.0.0.1
    python3 extreme_mode.py cache --tool nmap --args "-sV 10.0.0.1" --ttl 3600
    python3 extreme_mode.py auto --chain "subfinder -> httpx -> ffuf -> nuclei"
    python3 extreme_mode.py hwinfo
    python3 extreme_mode.py preset --mode stealth
    python3 extreme_mode.py minimize --tool nuclei
    python3 extreme_mode.py monitor --pid 1234
    python3 extreme_mode.py schedule --tool "nmap -sV" --cron "0 2 * * *"
"""
import argparse, hashlib, json, multiprocessing, os, subprocess, sys, time
from concurrent.futures import ThreadPoolExecutor, as_completed

# ============ Hardware Presets ============

# Preset tuned untuk Ryzen 5 PRO 4650U (6C/12T), 16GB RAM, Kali Linux
HARDWARE_PRESETS = {
    "stealth": {
        "name": "Stealth (T14s G1 tuned)",
        "nmap_timing": "-T2",
        "nmap_max_rate": "--max-rate 50",
        "nmap_retries": "--max-retries 1",
        "nuclei_concurrency": "-c 4",
        "nuclei_rate": "-rl 20",
        "ffuf_threads": "-t 6",
        "ffuf_rate": "-rate 20",
        "hydra_tasks": "-t 2",
        "gobuster_threads": "-t 6",
        "ram_limit_mb": "512",
        "cpu_nice": "15",
        "io_class": "idle (ionice -c3)",
        "max_parallel": "4",
    },
    "balanced": {
        "name": "Balanced (T14s G1 tuned)",
        "nmap_timing": "-T3",
        "nmap_max_rate": "--max-rate 200",
        "nmap_retries": "--max-retries 2",
        "nuclei_concurrency": "-c 8",
        "nuclei_rate": "-rl 50",
        "ffuf_threads": "-t 12",
        "ffuf_rate": "-rate 50",
        "hydra_tasks": "-t 4",
        "gobuster_threads": "-t 12",
        "ram_limit_mb": "2048",
        "cpu_nice": "10",
        "io_class": "best-effort (ionice -c2)",
        "max_parallel": "8",
    },
    "max": {
        "name": "Max Power (T14s G1 tuned)",
        "nmap_timing": "-T4",
        "nmap_max_rate": "--max-rate 1000",
        "nmap_retries": "--max-retries 3",
        "nuclei_concurrency": "-c 12",
        "nuclei_rate": "-rl 150",
        "ffuf_threads": "-t 24",
        "ffuf_rate": "-rate 200",
        "hydra_tasks": "-t 6",
        "gobuster_threads": "-t 24",
        "ram_limit_mb": "8192",
        "cpu_nice": "0",
        "io_class": "realtime (ionice -c1) [WARNING: stutter risk]",
        "max_parallel": "12",
    },
}

def show_hwinfo():
    print("[*] Hardware capability (T14s G1 baseline)")
    print()
    # Detect actual hardware
    cores = multiprocessing.cpu_count()
    try:
        with open("/proc/cpuinfo") as f:
            for line in f:
                if "model name" in line:
                    print(f"  CPU    : {line.split(':')[1].strip()}")
                    break
    except Exception:
        pass
    print(f"  Cores  : {cores} logical")
    try:
        with open("/proc/meminfo") as f:
            for line in f:
                if "MemTotal" in line:
                    total_kb = int(line.split()[1])
                    print(f"  RAM    : {total_kb // 1024 // 1024} GB")
                    break
    except Exception:
        pass
    print(f"  OS     : Kali Linux")
    print()
    print("[*] Preset tersedia: stealth | balanced | max")
    print()
    print("[*] Rekomendasi T14s G1 (6C/12T, 16GB):")
    print("  - Recon pasif / stealth  -> preset stealth")
    print("  - Biasa sehari-hari      -> preset balanced")
    print("  - Lab / offline target   -> preset max")

def show_preset(mode):
    p = HARDWARE_PRESETS.get(mode, HARDWARE_PRESETS["balanced"])
    print(f"[*] Preset: {p['name']}")
    print()
    print("  Network / Rate:")
    print(f"    nmap timing    : {p['nmap_timing']}")
    print(f"    nmap max-rate  : {p['nmap_max_rate']}")
    print(f"    nmap retries   : {p['nmap_retries']}")
    print(f"    nuclei concur. : {p['nuclei_concurrency']}")
    print(f"    nuclei rate    : {p['nuclei_rate']}")
    print(f"    ffuf threads   : {p['ffuf_threads']}")
    print(f"    hydra tasks    : {p['hydra_tasks']}")
    print()
    print("  System:")
    print(f"    RAM limit      : {p['ram_limit_mb']} MB")
    print(f"    CPU nice       : {p['cpu_nice']}")
    print(f"    IO class       : {p['io_class']}")
    print(f"    Max parallel   : {p['max_parallel']}")
    print()
    print("[*] Usage:")
    print(f"  nice -n {p['cpu_nice']} {p['nmap_timing']} {p['nmap_max_rate']} <target>")
    print(f"  ionice -c2 nice -n {p['cpu_nice']} nuclei {p['nuclei_concurrency']} {p['nuclei_rate']}")
    print(f"  ulimit -v {int(p['ram_limit_mb']) * 1024}  # sebelum run tool berat")

# ============ Parallel Execution ============

def parallel_exec(tools, target):
    tool_list = [t.strip() for t in tools.split(",")]
    max_workers = min(len(tool_list), multiprocessing.cpu_count())
    print(f"[*] Parallel execution: {len(tool_list)} tools -> {target}")
    print(f"[*] Workers: {max_workers} (CPU count: {multiprocessing.cpu_count()})")
    print()
    results = {}
    def run_tool(tool):
        cmd = f"{tool} {target}" if "{}" not in tool else tool.format(target)
        try:
            r = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=300)
            return tool, r.returncode, r.stdout[:500]
        except Exception as e:
            return tool, -1, str(e)
    with ThreadPoolExecutor(max_workers=max_workers) as pool:
        futures = {pool.submit(run_tool, tool): tool for tool in tool_list}
        for future in as_completed(futures):
            tool, rc, out = future.result()
            results[tool] = {"rc": rc, "output": out}
            status = "DONE" if rc == 0 else "FAIL"
            print(f"  [{status:4}] {tool:30} rc={rc}")
    print()
    print(f"[*] Summary:")
    for tool, data in results.items():
        print(f"  {tool:30} rc={data['rc']}")
    return results

# ============ Cache System ============

def cache_result(tool, args, ttl=3600):
    cache_dir = os.path.expanduser("~/.cache/extreme-efficiency")
    os.makedirs(cache_dir, exist_ok=True)
    cache_key = hashlib.sha256(f"{tool}:{args}".encode()).hexdigest()[:16]
    cache_file = f"{cache_dir}/{cache_key}.json"
    print(f"[*] Cache: {tool} {args}")
    print(f"[*] TTL: {ttl}s")
    print()
    if os.path.exists(cache_file):
        with open(cache_file) as f:
            cache = json.load(f)
        age = time.time() - cache.get("timestamp", 0)
        if age < ttl:
            print(f"[+] Cache HIT ({age:.0f}s old)")
            print(cache.get("output", "")[:500])
            return cache
        else:
            print(f"[-] Cache EXPIRED ({age:.0f}s old)")
    print(f"[*] Running: {tool} {args}")
    try:
        r = subprocess.run(f"{tool} {args}", shell=True, capture_output=True, text=True, timeout=300)
        result = {"tool": tool, "args": args, "output": r.stdout[:2000], "rc": r.returncode, "timestamp": time.time()}
        with open(cache_file, "w") as f:
            json.dump(result, f)
        print(f"[+] Cached: {cache_file}")
        return result
    except Exception as e:
        print(f"[-] Error: {e}")
        return None

# ============ Auto Chain ============

def auto_chain(chain):
    tools = [t.strip() for t in chain.split("->")]
    print(f"[*] Auto chain: {' -> '.join(tools)}")
    print()
    prev_output = None
    for i, tool in enumerate(tools, 1):
        print(f"[{i}/{len(tools)}] {tool}")
        if prev_output:
            try:
                r = subprocess.run(tool, shell=True, input=prev_output, capture_output=True, text=True, timeout=300)
                prev_output = r.stdout
                print(f"  -> {r.stdout[:200]}")
            except Exception as e:
                print(f"  [-] Error: {e}")
                break
        else:
            try:
                r = subprocess.run(tool, shell=True, capture_output=True, text=True, timeout=300)
                prev_output = r.stdout
                print(f"  -> {r.stdout[:200]}")
            except Exception as e:
                print(f"  [-] Error: {e}")
                break
    return prev_output

# ============ Minimize Resource ============

def minimize(tool, mode="balanced"):
    p = HARDWARE_PRESETS.get(mode, HARDWARE_PRESETS["balanced"])
    print(f"[*] Minimize resource: {tool} (preset: {mode})")
    print()
    opts = {
        "nmap": [p["nmap_timing"], p["nmap_max_rate"], p["nmap_retries"], "--host-timeout 30s"],
        "nuclei": [p["nuclei_concurrency"], p["nuclei_rate"], "-timeout 5", "-retries 1"],
        "ffuf": [p["ffuf_threads"], p["ffuf_rate"], "-timeout 5"],
        "hydra": [p["hydra_tasks"], "-w 5"],
        "gobuster": [p["gobuster_threads"], "--timeout 5"],
    }
    print(f"[+] Optimizations for {tool}:")
    for o in opts.get(tool, []):
        print(f"  {o}")
    print()
    print(f"[+] System (preset {mode}):")
    print(f"  nice -n {p['cpu_nice']}")
    print(f"  {p['io_class']}")
    print(f"  ulimit -v {int(p['ram_limit_mb']) * 1024}")

# ============ Monitor ============

def monitor_pid(pid):
    print(f"[*] Monitor PID: {pid}")
    print()
    print("[*] Commands:")
    print(f"  top -p {pid}")
    print(f"  htop -p {pid}")
    print(f"  strace -p {pid} -e trace=network")
    print(f"  lsof -p {pid}")
    print(f"  ps -p {pid} -o pid,ppid,cmd,%cpu,%mem,etime")
    print()
    print("[*] Resource limits:")
    print(f"  prlimit --pid {pid} --as=500000000")
    print(f"  prlimit --pid {pid} --cpu=300")
    print(f"  prlimit --pid {pid} --nofile=1024")

# ============ Schedule ============

def schedule(tool, cron):
    print(f"[*] Schedule: {tool}")
    print(f"[*] Cron: {cron}")
    print()
    print("[*] Crontab:")
    print(f"  {cron} {tool} > /var/log/extreme-efficiency.log 2>&1")
    print()
    print("[*] Systemd timer:")
    print("  [Unit]")
    print("  Description=Extreme Efficiency Task")
    print()
    print("  [Service]")
    print("  Type=oneshot")
    print(f"  ExecStart={tool}")
    print()
    print("  [Install]")
    print("  WantedBy=multi-user.target")

def main():
    args = sys.argv[1:]
    if not args:
        print(__doc__)
        return
    cmd = args[0]
    if cmd == "parallel":
        p = argparse.ArgumentParser()
        p.add_argument("--tools", required=True)
        p.add_argument("--target", required=True)
        a = p.parse_args(args[1:])
        parallel_exec(a.tools, a.target)
    elif cmd == "cache":
        p = argparse.ArgumentParser()
        p.add_argument("--tool", required=True)
        p.add_argument("--args", required=True)
        p.add_argument("--ttl", type=int, default=3600)
        a = p.parse_args(args[1:])
        cache_result(a.tool, a.args, a.ttl)
    elif cmd == "auto":
        p = argparse.ArgumentParser()
        p.add_argument("--chain", required=True)
        a = p.parse_args(args[1:])
        auto_chain(a.chain)
    elif cmd == "hwinfo":
        show_hwinfo()
    elif cmd == "preset":
        p = argparse.ArgumentParser()
        p.add_argument("--mode", default="balanced", choices=["stealth", "balanced", "max"])
        a = p.parse_args(args[1:])
        show_preset(a.mode)
    elif cmd == "minimize":
        p = argparse.ArgumentParser()
        p.add_argument("--tool", required=True)
        p.add_argument("--mode", default="balanced", choices=["stealth", "balanced", "max"])
        a = p.parse_args(args[1:])
        minimize(a.tool, a.mode)
    elif cmd == "monitor":
        p = argparse.ArgumentParser()
        p.add_argument("--pid", required=True)
        a = p.parse_args(args[1:])
        monitor_pid(a.pid)
    elif cmd == "schedule":
        p = argparse.ArgumentParser()
        p.add_argument("--tool", required=True)
        p.add_argument("--cron", required=True)
        a = p.parse_args(args[1:])
        schedule(a.tool, a.cron)
    else:
        print(__doc__)

if __name__ == "__main__":
    main()
