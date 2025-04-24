import os
import gzip
import zipfile
import tempfile
from scapy.all import rdpcap, IP, TCP, UDP
from collections import defaultdict, Counter
import math
import matplotlib.pyplot as plt
import datetime
import csv
import warnings

INTERVALS = [5 * 60, 10 * 60, 15 * 60]  # in seconds
PORT_RANGES = {'system': (0, 1023), 'user': (1024, 49151)}
K_VALUES = [3, 4, 5, 6]  # for IP prefix grouping

def entropy(counter):
    total = sum(counter.values())
    if total == 0:
        return 0
    return -sum((count / total) * math.log2(count / total) for count in counter.values())

def port_category(port):
    if port <= PORT_RANGES['system'][1]:
        return 'system'
    elif port <= PORT_RANGES['user'][1]:
        return 'user'
    else:
        return None  # Ignore ephemeral

def ip_prefix(ip, k):
    parts = list(map(int, ip.split('.')))
    binary = ''.join(f'{p:08b}' for p in parts)
    return binary[:k]

def process_packets(packets, interval, k):
    start_time = None
    results = []
    tables = defaultdict(lambda: defaultdict(Counter))  # interval_id -> feature -> Counter

    for pkt in packets:
        if IP not in pkt:
            continue
        ts = float(pkt.time)
        if start_time is None:
            start_time = ts

        index = int((ts - start_time) // interval)

        size = len(pkt)
        s_ip = pkt[IP].src
        d_ip = pkt[IP].dst

        s_prefix = ip_prefix(s_ip, k)
        d_prefix = ip_prefix(d_ip, k)

        tables[index][f'saddr_pkt'][s_prefix] += 1
        tables[index][f'daddr_pkt'][d_prefix] += 1
        tables[index][f'saddr_size'][s_prefix] += size
        tables[index][f'daddr_size'][d_prefix] += size

        if TCP in pkt or UDP in pkt:
            sport = pkt.sport
            dport = pkt.dport

            sport_cat = port_category(sport)
            dport_cat = port_category(dport)

            if sport_cat:
                tables[index]['sport_pkt'][sport_cat] += 1
                tables[index]['sport_size'][sport_cat] += size
            if dport_cat:
                tables[index]['dport_pkt'][dport_cat] += 1
                tables[index]['dport_size'][dport_cat] += size

    for index in sorted(tables):
        interval_start = index * interval
        result = {'interval': interval_start}
        for key in tables[index]:
            result[key] = entropy(tables[index][key])
        results.append(result)

    return results

def extract_pcap(file_path, temp_dir):
    if file_path.endswith('.pcap'):
        return file_path
    elif file_path.endswith('.pcap.gz'):
        output_path = os.path.join(temp_dir, os.path.basename(file_path[:-3]))
        with gzip.open(file_path, 'rb') as f_in, open(output_path, 'wb') as f_out:
            f_out.write(f_in.read())
        return output_path
    elif file_path.endswith('.zip'):
        with zipfile.ZipFile(file_path, 'r') as zip_ref:
            zip_ref.extractall(temp_dir)
            for name in zip_ref.namelist():
                if name.endswith('.pcap'):
                    return os.path.join(temp_dir, name)
    return None

def plot_entropy(results, field, interval, k):
    try:
        times = [r['interval'] for r in results]
        time_labels = [str(datetime.timedelta(seconds=t)) for t in times]
        values = [r.get(field, 0) for r in results]
        plt.figure(figsize=(10, 4))
        plt.plot(time_labels, values, label=field)
        plt.xlabel('Time')
        plt.ylabel('Entropy')
        plt.title(f'{field} entropy over time (interval={interval // 60} min, k={k})')
        plt.xticks(rotation=45)
        plt.grid(True)
        plt.tight_layout()
        filename = f'entropy_{field}_int{interval}_k{k}.png'
        plt.savefig(filename)
        plt.close()
        print(f'📊 Saved plot: {filename}')
    except Exception as e:
        warnings.warn(f"⚠️ Failed to generate/save plot for {field} (int={interval}, k={k}): {e}")

def write_csv(results, interval, k):
    if not results:
        return
    fields = sorted(results[0].keys())
    filename = f'entropy_data_int{interval}_k{k}.csv'
    with open(filename, 'w', newline='') as csvfile:
        writer = csv.DictWriter(csvfile, fieldnames=fields)
        writer.writeheader()
        for row in results:
            writer.writerow(row)
    print(f'📄 Saved CSV: {filename}')

def main():
    pcap_folder = r'C:\Users\jstou\OneDrive\Desktop\54700 projects\PCAP-20181103 (1)\PCAP-20181103'
    print(f"📂 Scanning folder: {pcap_folder}")

    if not os.path.exists(pcap_folder):
        print("❌ Folder not found.")
        return

    files = os.listdir(pcap_folder)

    with tempfile.TemporaryDirectory() as temp_dir:
        for file in files:
            path = os.path.join(pcap_folder, file)
            print(f"🧹 Processing: {file}")
            pcap_path = extract_pcap(path, temp_dir)
            if not pcap_path:
                print(f"⚠️ Skipped (no valid PCAP): {file}")
                continue

            try:
                packets = rdpcap(pcap_path)
                print(f"✅ Read {len(packets)} packets")

                for interval in INTERVALS:
                    for k in K_VALUES:
                        results = process_packets(packets, interval, k)
                        for field in ['sport_pkt', 'dport_pkt', 'sport_size', 'dport_size',
                                      'saddr_pkt', 'daddr_pkt', 'saddr_size', 'daddr_size']:
                            plot_entropy(results, field, interval, k)
                        write_csv(results, interval, k)

            except Exception as e:
                print(f"❌ Failed to process {file}: {e}")

if __name__ == "__main__":
    print("🚀 Starting entropy analysis...")
    main()
