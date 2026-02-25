import pyshark
import pandas as pd
import matplotlib.pyplot as plt
from collections import Counter
from datetime import datetime


# Анализ
pcap_file = "dhcp.pcapng"
capture = pyshark.FileCapture(pcap_file)

ips = []
dns_queries = []
timestamps = []
dhcp_types = []

print("Обработка пакетов...")

for packet in capture:
    try:
        timestamps.append(float(packet.sniff_timestamp))

        if hasattr(packet, 'ip'):
            ips.append(packet.ip.src)
            ips.append(packet.ip.dst)

        if hasattr(packet, 'dns') and hasattr(packet.dns, 'qry_name'):
            dns_queries.append(str(packet.dns.qry_name))

        if hasattr(packet, 'dhcp') and hasattr(packet.dhcp, 'option_dhcp'):
            dhcp_types.append(str(packet.dhcp.option_dhcp))

    except Exception:
        continue

capture.close()

top_ips = ip_counter.most_common(10)

print("\nТОП-10 IP-адресов:")
for ip, count in top_ips:
    print(ip, count)

    dns_counter = Counter(dns_queries)
    print("\nDNS-запросы:")
    for domain, count in dns_counter.most_common(10):
        print(domain, count)
else:
    print("\nDNS-запросов не найдено.")

if dhcp_types:
    dhcp_counter = Counter(dhcp_types)
    print("\nDHCP типы сообщений:")
    for t, count in dhcp_counter.most_common():
        print(t, count)
else:
    print("\nDHCP сообщений не найдено (или поле option_dhcp недоступно).")


# Визуализация
if top_ips:
    df_ips = pd.DataFrame(top_ips, columns=["IP", "Count"]).set_index("IP")

    plt.figure()
    df_ips["Count"].plot(kind="bar")
    plt.title("")
    plt.xlabel("IP")
    plt.ylabel("")
    plt.xticks(rotation=45, ha="right")
    plt.tight_layout()
    plt.show()

if dhcp_types:
    df_dhcp = pd.DataFrame(dhcp_counter.most_common(), columns=["Type", "Count"]).set_index("Type")

    plt.figure()
    df_dhcp["Count"].plot(kind="bar")
    plt.title("")
    plt.xlabel("Тип DHCP")
    plt.ylabel("")
    plt.xticks(rotation=45, ha="right")
    plt.tight_layout()
    plt.show()

print("\nАнализ завершён.")
