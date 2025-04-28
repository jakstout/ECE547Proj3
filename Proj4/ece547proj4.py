import gzip
import datetime
import math
import os
from collections import defaultdict, Counter
import concurrent.futures
import numpy as np
import matplotlib.pyplot as plt
from scapy.all import PcapReader, IP, TCP, UDP
from tqdm import tqdm
import warnings
import time
import psutil

# --- CONFIG ---
PCAP_DIR = r'C:\Users\jstou\OneDrive\Desktop\54700 projects\PCAP-20181103 (1)\PCAP-20181103'
QUANTUMS = [300, 600, 900]  # Time windows in seconds (5/10/15 mins)
PLOT_OUTPUT_DIR = 'charts'
MAX_WORKERS = min(4, os.cpu_count() - 1)  # Conservative parallel processing
MEMORY_LIMIT_MB = 4000  # Set memory limit (adjust based on your system)

# --- Setup ---
os.makedirs(PLOT_OUTPUT_DIR, exist_ok=True)
warnings.filterwarnings('ignore', category=RuntimeWarning)  # Suppress numpy warnings

def check_system_limits():
    """System resource check compatible with Windows"""
    print("\n" + "="*60)
    print("System Resource Check")
    print("="*60)
    
    avail_mem = psutil.virtual_memory().available / (1024**2)
    print(f"Available memory: {avail_mem:.0f} MB")
    if avail_mem < MEMORY_LIMIT_MB:
        print(f"⚠️ Warning: Only {avail_mem:.0f} MB available - consider reducing MEMORY_LIMIT_MB")
    
    print("Note: File descriptor limits not checked on Windows")

def process_single_packet(pkt):
    """Process a single packet and return its info"""
    if IP in pkt:
        ip_layer = pkt[IP]
        ts = int(pkt.time)
        src_ip = ip_layer.src
        dst_ip = ip_layer.dst
        proto = ip_layer.proto
        sport = dport = None
        
        if TCP in pkt:
            transport = pkt[TCP]
            sport, dport = transport.sport, transport.dport
        elif UDP in pkt:
            transport = pkt[UDP]
            sport, dport = transport.sport, transport.dport
        
        return (ts, src_ip, dst_ip, sport, dport, proto)
    return None

def process_pcap_file(file_path):
    """Process a single PCAP file and return all packets as a list"""
    filename = os.path.basename(file_path)
    print(f"📖 Reading {filename}...")
    start_time = time.time()
    packet_info = []
    
    try:
        with gzip.open(file_path, 'rb') as f:
            for pkt in PcapReader(f):
                result = process_single_packet(pkt)
                if result:
                    packet_info.append(result)
        
        elapsed = time.time() - start_time
        print(f"✅ Processed {filename} ({len(packet_info)} packets, {elapsed:.2f}s)")
        return packet_info
        
    except Exception as e:
        print(f"\n⚠️ Failed to process {filename}: {str(e)}")
        return []

def process_all_packets(directory):
    """Process all PCAP files with parallel processing"""
    files = sorted(
        os.path.join(directory, f) 
        for f in os.listdir(directory) 
        if f.endswith('.pcap.gz')
    )
    
    if not files:
        print("No PCAP files found in directory!")
        return []
    
    print(f"\nFound {len(files)} PCAP files to process")
    
    # Process files with parallel execution
    with concurrent.futures.ProcessPoolExecutor(max_workers=MAX_WORKERS) as executor:
        futures = [executor.submit(process_pcap_file, file_path) for file_path in files]
        
        results = []
        for future in tqdm(concurrent.futures.as_completed(futures), total=len(files), desc="Processing PCAPs"):
            try:
                results.extend(future.result())
            except Exception as e:
                print(f"\n⚠️ Processing error: {str(e)}")
    
    return results

def get_quantum_start(ts, quantum_secs):
    """Calculate time window start timestamp"""
    return ts - (ts % quantum_secs)

def entropy(counter):
    """Optimized entropy calculation using numpy"""
    counts = np.array(list(counter.values()))
    probs = counts / counts.sum()
    return -np.sum(probs * np.log2(probs + 1e-10))  # Add small epsilon to avoid log(0)

def build_entropy_stats(packet_list, quantum_secs=300):
    """Build entropy statistics from packet list"""
    print(f"\n🔍 Building entropy stats for {quantum_secs}s intervals...")
    stats = defaultdict(lambda: {
        'saddr': Counter(),
        'daddr': Counter(),
        'sport': Counter(),
        'dport': Counter(),
        'proto': Counter()
    })
    
    for ts, src_ip, dst_ip, sport, dport, proto in tqdm(packet_list, desc="Processing packets"):
        q_start = get_quantum_start(ts, quantum_secs)
        
        stats[q_start]['saddr'][src_ip] += 1
        stats[q_start]['daddr'][dst_ip] += 1
        stats[q_start]['proto'][proto] += 1
        if sport: stats[q_start]['sport'][sport] += 1
        if dport: stats[q_start]['dport'][dport] += 1
    
    return stats

def plot_entropy(stats, quantum_secs):
    """Generate entropy plots"""
    print(f"\n📈 Generating plots for {quantum_secs}s intervals...")
    times = sorted(stats.keys())
    if not times:
        print("⚠️ No data to plot")
        return
        
    readable_times = [datetime.datetime.fromtimestamp(t) for t in times]
    label = f'{quantum_secs//60}min'
    attributes = ['saddr', 'daddr', 'sport', 'dport', 'proto']
    
    for attr in tqdm(attributes, desc="Generating plots"):
        plt.figure(figsize=(12, 4))
        entropies = [entropy(stats[t][attr]) for t in times]
        
        plt.plot(readable_times, entropies, marker='o', markersize=3, linewidth=1)
        plt.title(f'Entropy of {attr.upper()} ({label} interval)')
        plt.xlabel('Time')
        plt.ylabel('Entropy (bits)')
        plt.grid(True, alpha=0.3)
        plt.xticks(rotation=45, ha='right')
        
        output_path = f'{PLOT_OUTPUT_DIR}/entropy_{attr}_{label}.png'
        plt.tight_layout()
        plt.savefig(output_path, dpi=150, bbox_inches='tight')
        plt.close()
        print(f"💾 Saved {output_path}")

def main():
    print("\n" + "="*60)
    print("PCAP ENTROPY ANALYZER (Optimized for Windows)")
    print("="*60)
    print(f"Directory: {PCAP_DIR}")
    print(f"Time windows: {[f'{q//60}min' for q in QUANTUMS]}")
    print(f"Parallel workers: {MAX_WORKERS}")
    print("="*60 + "\n")
    
    check_system_limits()
    start_time = time.time()
    
    # Process all PCAP files
    packet_list = process_all_packets(PCAP_DIR)
    print(f"\n📊 Loaded {len(packet_list):,} packets total")
    
    # Analyze for each time window
    for quantum in QUANTUMS:
        print("\n" + "="*40)
        print(f"ANALYZING {quantum//60} MINUTE WINDOWS")
        print("="*40)
        
        stats = build_entropy_stats(packet_list, quantum)
        plot_entropy(stats, quantum)
    
    total_time = time.time() - start_time
    print("\n" + "="*60)
    print(f"✅ Analysis completed in {total_time//60:.0f}m {total_time%60:.0f}s")
    print(f"📊 Results saved to: {os.path.abspath(PLOT_OUTPUT_DIR)}")
    print("="*60)

if __name__ == '__main__':
    main()
