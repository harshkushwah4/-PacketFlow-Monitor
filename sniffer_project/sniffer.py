from scapy.all import *
import signal, sys, time
from collections import Counter
from datetime import datetime

iface = r"\Device\NPF_{71F26EE8-164D-4399-B2FE-8631B2371C8C}"
count = 0
protocols = Counter()
top_ips = Counter()
azure_hits = 0
video_streams = 0
large_transfers = 0
packets = []

def handle_packet(pkt):
    global count, azure_hits, video_streams, large_transfers
    count += 1
    
    if pkt.haslayer(IP):
        src = pkt[IP].src
        dst = pkt[IP].dst
        protocols[pkt[IP].proto] += 1
        top_ips[src] += 1
        
        # Azure family detection (20.0.0.0/8, 52.0.0.0/8, 104.0.0.0/8)
        azure_nets = ['20.', '52.', '104.']
        if any(net in src for net in azure_nets) or any(net in dst for net in azure_nets):
            azure_hits += 1
        
        # Video streaming (YouTube/Netflix ports + large payloads)
        if pkt.haslayer(TCP) and pkt[TCP].dport in [443, 80] and len(pkt) > 1400:
            video_streams += 1
            large_transfers += 1
    
    packets.append(pkt)
    
    if count % 200 == 0:
        print(f"\r🎥 LIVE: {count} pkts | Azure:{azure_hits} | Video:{video_streams} | Top:{top_ips.most_common(2)}", end="")

def signal_handler(sig, frame):
    print(f"\n{'='*100}")
    print(f"🎉 HARSH'S ULTIMATE SNIFFER: {count:,} PACKETS MASTERED!")
    print(f"☁️  AZURE FAMILY: {azure_hits}")
    print(f"🎬 VIDEO STREAMS: {video_streams}")
    print(f"📦 LARGE Xfers: {large_transfers}")
    print(f"🔝 PROTOCOLS: {dict(protocols.most_common())}")
    print(f"🌐 TOP 5 IPS: {dict(top_ips.most_common(5))}")
    
    ts = datetime.now().strftime('%Y%m%d_%H%M')
    wrpcap(f"master_capture_{ts}.pcap", packets[-5000:])  # Last 5k packets
    print(f"💾 MASTER FILES: master_capture_{ts}.pcap | master_stats_{ts}.csv")
    print('🏆 YOU ARE NOW NETWORK PROFESSIONAL!')
    sys.exit(0)

print("🏆 HARSH'S ULTIMATE SNIFFER v7.0")
print("🎯 Azure + Video Stream Detection")
print("💡 YouTube/Netflix/Office → Ctrl+C")
print("="*80)

signal.signal(signal.SIGINT, signal_handler)
sniff(iface=iface, prn=handle_packet, store=0)
