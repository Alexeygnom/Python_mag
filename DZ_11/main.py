import pandas as pd
import numpy as np

import matplotlib.pyplot as plt
import seaborn as sns

# Обработка данных
raw = pd.read_json(PATH) 

events = pd.json_normalize(raw["result"])
events["offset"] = raw.get("offset", pd.Series([np.nan] * len(raw)))

if "EventCode" in events.columns:
    events["EventCode"] = events["EventCode"].astype("string")

if "_time" in events.columns:
    events["_time"] = pd.to_datetime(events["_time"], errors="coerce")

events["sourcetype"] = events.get("sourcetype", pd.Series([pd.NA] * len(events))).astype("string")

win_df = events[events["sourcetype"].eq("WinEventLog:Security")].copy()
dns_df = events[events["sourcetype"].str.contains("dns", case=False, na=False)].copy()

dns_query_candidates = ["query", "Query", "query_name", "QueryName", "rrname", "domain", "Domain", "dns_query"]
dns_query_col = next((c for c in dns_query_candidates if c in dns_df.columns), None)

if dns_query_col is None:
    dns_df["query"] = pd.NA
    dns_query_col = "query"

dns_df["dns_query"] = dns_df[dns_query_col].astype("string")

win_df = win_df.dropna(subset=["EventCode"]).drop_duplicates()
dns_df = dns_df.dropna(subset=["dns_query"]).drop_duplicates()

print("events:", events.shape)
print("win_df:", win_df.shape)
print("dns_df:", dns_df.shape)
print("dns_query_col used:", dns_query_col)


# Анализ
suspicious_codes = {
    "4625",  # failed logon
    "4672",  # special privileges assigned
    "4688",  # process creation
    "4703",  # user right adjusted
    "4720",  # user account created
    "4728",  # member added to security-enabled global group
    "4732",  # member added to security-enabled local group
    "4768",  # Kerberos TGT requested
    "4769",  # Kerberos service ticket requested
}

win_susp = win_df[win_df["EventCode"].isin(list(suspicious_codes))].copy()

top10_win = (
    win_susp["EventCode"]
    .value_counts()
    .head(10)
)

dns_work = dns_df.copy()
dns_work["dns_query"] = dns_work["dns_query"].str.strip().str.lower()

dns_work["q_len"] = dns_work["dns_query"].str.len()

q_freq = dns_work["dns_query"].value_counts(dropna=True)
dns_work["q_freq"] = dns_work["dns_query"].map(q_freq).fillna(0).astype(int)

src_col_candidates = ["src", "src_ip", "client_ip", "Src", "source_ip"]
src_col = next((c for c in src_col_candidates if c in dns_work.columns), None)

if src_col is None:
    dns_work["src_norm"] = "unknown"
else:
    dns_work["src_norm"] = dns_work[src_col].astype("string").fillna("unknown")

src_q_counts = dns_work.groupby(["src_norm", "dns_query"]).size().rename("src_q_cnt").reset_index()
dns_work = dns_work.merge(src_q_counts, on=["src_norm", "dns_query"], how="left")

dns_work["is_rare"] = dns_work["q_freq"] <= 2
dns_work["is_long"] = dns_work["q_len"] >= 40
dns_work["is_burst_src"] = dns_work["src_q_cnt"] >= 30

dns_work["susp_score"] = (
    dns_work["is_rare"].astype(int) * 2 +
    dns_work["is_long"].astype(int) * 2 +
    dns_work["is_burst_src"].astype(int) * 1
)

dns_susp = dns_work[dns_work["susp_score"] > 0].copy()

top10_dns = (
    dns_susp["dns_query"]
    .value_counts()
    .head(10)
)

print("Top-10 suspicious WinEventLog EventCode:")
print(top10_win)

print("\nTop-10 suspicious DNS queries:")
print(top10_dns)

sample_dns = dns_susp.sort_values(["susp_score", "q_freq", "q_len"], ascending=False).head(20)
sample_dns[["dns_query", "susp_score", "q_freq", "q_len", "src_norm", "src_q_cnt"]].head(20)


# Визуализация
plt.figure(figsize=(10, 6))
sns.barplot(x=top10_win.values, y=top10_win.index)
plt.title("Top-10 suspicious WinEventLog events (by EventCode)")
plt.xlabel("Count")
plt.ylabel("EventCode")
plt.tight_layout()
plt.show()

plt.figure(figsize=(10, 6))
sns.barplot(x=top10_dns.values, y=top10_dns.index)
plt.title("Top-10 suspicious DNS queries")
plt.xlabel("Count")
plt.ylabel("DNS query")
plt.tight_layout()
plt.show()
