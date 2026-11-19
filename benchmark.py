import csv
from modules.username_recon import run_username_recon
from modules.domain_recon import run_domain_recon

REAL_HANDLES = ["torvalds", "gvanrossum", "octocat", "defunkt", "mojombo"]
FAKE_HANDLES = [
    "osint_fake_user_991122",
    "zxq_nonexistent_884422",
    "null_handle_test_775533",
    "fake_recon_id_664411",
    "no_such_acct_553300",
]
DOMAINS = ["github.com", "kernel.org", "python.org", "wikipedia.org", "cloudflare.com"]

print("=" * 65)
print("CHAPTER 4 AUTOMATED OSINT BENCHMARK SUITE")
print("=" * 65)

# 1. Concurrency Benchmark (1 worker vs 10 workers)
print("\n[1/4] Testing Sequential (1 thread) vs Concurrent (10 threads)...")
seq = run_username_recon("torvalds", max_workers=1)
con = run_username_recon("torvalds", max_workers=10)
speedup = round(seq["execution_time_sec"] / max(con["execution_time_sec"], 0.01), 2)
print(f"  Sequential (1 thread)   : {seq['execution_time_sec']}s")
print(f"  Concurrent (10 threads) : {con['execution_time_sec']}s")
print(f"  Speedup Factor          : {speedup}x faster")

rows = []

# 2. Real Public Handles
print("\n[2/4] Benchmarking 5 Real Public Handles...")
real_times = []
for u in REAL_HANDLES:
    res = run_username_recon(u, max_workers=10)
    real_times.append(res["execution_time_sec"])
    print(f"  @{u:<14} -> Found: {res['accounts_found']}/18 | Errors: {res['errors_count']} | Time: {res['execution_time_sec']}s")
    rows.append(["Real Username", u, res["platforms_checked"], res["accounts_found"], res["errors_count"], res["execution_time_sec"]])

# 3. Negative Control (False Positive Rate)
print("\n[3/4] Benchmarking 5 Non-Existent Handles (False-Positive Test)...")
total_checks = 0
total_fp = 0
fake_times = []
for u in FAKE_HANDLES:
    res = run_username_recon(u, max_workers=10)
    fake_times.append(res["execution_time_sec"])
    total_checks += (res["platforms_checked"] - res["errors_count"])
    total_fp += res["accounts_found"]
    print(f"  @{u:<24} -> False Positives: {res['accounts_found']} | Errors: {res['errors_count']} | Time: {res['execution_time_sec']}s")
    rows.append(["Negative Control", u, res["platforms_checked"], res["accounts_found"], res["errors_count"], res["execution_time_sec"]])

fpr = round((total_fp / max(total_checks, 1)) * 100, 2)

# 4. Domain Infrastructure Recon
print("\n[4/4] Benchmarking 5 Public Domains...")
dom_times = []
for d in DOMAINS:
    res = run_domain_recon(d)
    dom_times.append(res["execution_time_sec"])
    es = res["email_security"]
    whois_ok = "error" not in res["whois"]
    print(f"  {d:<16} -> IP: {res['ip_address']:<15} | WHOIS: {whois_ok} | SPF:{es['has_spf']} DMARC:{es['has_dmarc']} | Time: {res['execution_time_sec']}s")
    rows.append(["Domain Recon", d, "DNS/WHOIS/HTTP", f"WHOIS={whois_ok}", 0, res["execution_time_sec"]])

# Export CSV for Excel / Google Sheets charts
with open("chapter4_benchmark_results.csv", "w", newline="", encoding="utf-8") as f:
    writer = csv.writer(f)
    writer.writerow(["Test Category", "Target", "Checks", "Detected/Status", "Errors", "Time_Sec"])
    writer.writerows(rows)

print("\n" + "=" * 65)
print("SUMMARY METRICS FOR CHAPTER 4")
print("=" * 65)
print(f"  Concurrency Speedup        : {speedup}x ({seq['execution_time_sec']}s -> {con['execution_time_sec']}s)")
print(f"  Avg Real Handle Scan Time  : {round(sum(real_times)/len(real_times), 2)}s")
print(f"  Avg Fake Handle Scan Time  : {round(sum(fake_times)/len(fake_times), 2)}s")
print(f"  Measured False-Positive %  : {fpr}% ({total_fp}/{total_checks} checks)")
print(f"  Avg Domain Recon Time      : {round(sum(dom_times)/len(dom_times), 2)}s")
print("  Saved CSV                  : chapter4_benchmark_results.csv")
print("=" * 65)
