
import os
import gzip
import datetime
from collections import defaultdict
import matplotlib.pyplot as plt
from scapy.all import rdpcap
from scapy.layers.inet import IP

# --- CONFIG ---
PCAP_DIR = r'C:\Users\jstou\OneDrive\Desktop\54700 projects\PCAP-20181103 (1)\PCAP-20181103'
QUANTUMS = [300, 600]  # 1 min, 5 min, 10 min in seconds
PLOT_OUTPUT_DIR = 'charts'

os.makedirs(PLOT_OUTPUT_DIR, exist_ok=True)

def read_pcap_gz(file_path):
    try:
        with gzip.open(file_path, 'rb') as f:
            packets = rdpcap(f)
        return packets
    except Exception as e:
        print(f"Error reading {file_path}: {e}")
        return []

def get_quantum_start(ts, quantum_secs):
    return ts - (ts % quantum_secs)

def process_pcap_files(directory, quantum_secs):
    stats = defaultdict(lambda: {'count': 0, 'volume': 0})
    files = sorted(f for f in os.listdir(directory) if f.endswith('.pcap.gz'))
    
    for filename in files:
        full_path = os.path.join(directory, filename)
        print(f"Processing: {filename}")
        packets = read_pcap_gz(full_path)
        
        for pkt in packets:
            if IP in pkt:
                ts = int(pkt.time)
                size = len(pkt)
                q_start = get_quantum_start(ts, quantum_secs)
                stats[q_start]['count'] += 1
                stats[q_start]['volume'] += size

    return stats

def plot_stats(stats, quantum_secs):
    times = sorted(stats.keys())
    counts = [stats[t]['count'] for t in times]
    volumes = [stats[t]['volume'] for t in times]
    avg_sizes = [vol / cnt if cnt > 0 else 0 for cnt, vol in zip(counts, volumes)]
    readable_times = [datetime.datetime.fromtimestamp(t) for t in times]

    label = f'{quantum_secs // 60}min'
    
    # Plot packet count
    plt.figure(figsize=(12, 4))
    plt.plot(readable_times, counts, label='Packet Count')
    plt.title(f'Packet Count ({label} interval)')
    plt.xlabel('Time')
    plt.ylabel('Count')
    plt.xticks(rotation=45)
    plt.tight_layout()
    plt.savefig(f'{PLOT_OUTPUT_DIR}/packet_count_{label}.png')
    plt.close()

    # Plot volume
    plt.figure(figsize=(12, 4))
    plt.plot(readable_times, volumes, label='Volume (bytes)', color='orange')
    plt.title(f'Packet Volume ({label} interval)')
    plt.xlabel('Time')
    plt.ylabel('Bytes')
    plt.xticks(rotation=45)
    plt.tight_layout()
    plt.savefig(f'{PLOT_OUTPUT_DIR}/volume_{label}.png')
    plt.close()

    # Plot average packet size
    plt.figure(figsize=(12, 4))
    plt.plot(readable_times, avg_sizes, label='Average Packet Size (bytes)', color='green')
    plt.title(f'Average Packet Size ({label} interval)')
    plt.xlabel('Time')
    plt.ylabel('Avg Size (bytes)')
    plt.xticks(rotation=45)
    plt.tight_layout()
    plt.savefig(f'{PLOT_OUTPUT_DIR}/avg_size_{label}.png')
    plt.close()

def main():
    for quantum in QUANTUMS:
        print(f'\nAnalyzing with quantum = {quantum} seconds...')
        stats = process_pcap_files(PCAP_DIR, quantum)
        plot_stats(stats, quantum)
    print("\n✅ All plots saved to 'charts' folder.")

if __name__ == '__main__':
    main()
