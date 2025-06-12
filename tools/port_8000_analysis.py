#!/usr/bin/env python3
"""
Targeted analysis of port 8000 HTTP traffic
"""

import json
from collections import defaultdict, Counter
from pathlib import Path
import sys

from scapy.all import TCP, IP, Raw, rdpcap
from scapy.layers.http import HTTP, HTTPRequest, HTTPResponse


def analyze_port_8000_traffic(filename):
    """Analyze HTTP traffic specifically on port 8000."""
    print(f"🔍 PORT 8000 ANALYSIS: {filename}")
    print("=" * 80)
    
    try:
        # Load more packets to ensure we capture the traffic
        packets = rdpcap(filename, count=5000)
        print(f"📦 Loaded {len(packets)} packets")
        
        # Filter for port 8000 traffic
        port_8000_packets = []
        for pkt in packets:
            if TCP in pkt and (pkt[TCP].sport == 8000 or pkt[TCP].dport == 8000):
                port_8000_packets.append(pkt)
        
        print(f"🎯 Found {len(port_8000_packets)} packets on port 8000")
        
        if not port_8000_packets:
            print("❌ No port 8000 traffic found")
            return
        
        # Analyze the port 8000 packets
        http_packets = []
        raw_packets = []
        
        for pkt in port_8000_packets:
            if HTTP in pkt:
                http_packets.append(pkt)
            elif Raw in pkt:
                raw_packets.append(pkt)
        
        print(f"📊 Port 8000 breakdown:")
        print(f"  • HTTP packets (detected by Scapy): {len(http_packets)}")
        print(f"  • Raw data packets: {len(raw_packets)}")
        
        # Analyze raw packets for HTTP patterns
        print(f"\n🔍 ANALYZING RAW PACKETS FOR HTTP PATTERNS:")
        
        http_like_packets = []
        streaming_packets = []
        
        for i, pkt in enumerate(raw_packets[:50]):  # Check first 50 raw packets
            if Raw in pkt:
                raw_data = bytes(pkt[Raw])
                
                try:
                    text = raw_data.decode('utf-8', errors='ignore')
                    text_lower = text.lower()
                    
                    # Check for HTTP patterns
                    is_http_request = any(method in text_lower for method in ['get ', 'post ', 'put ', 'delete '])
                    is_http_response = 'http/' in text_lower
                    is_json = text.strip().startswith('{') or text.strip().startswith('[')
                    is_sse = 'data:' in text and '\n' in text
                    has_headers = 'content-type:' in text_lower or 'transfer-encoding:' in text_lower
                    
                    if is_http_request or is_http_response or has_headers:
                        http_like_packets.append({
                            'packet_num': i,
                            'size': len(raw_data),
                            'direction': f"{pkt[IP].src}:{pkt[TCP].sport} -> {pkt[IP].dst}:{pkt[TCP].dport}",
                            'is_request': is_http_request,
                            'is_response': is_http_response,
                            'has_headers': has_headers,
                            'preview': repr(text[:300])
                        })
                    
                    if is_json or is_sse:
                        streaming_packets.append({
                            'packet_num': i,
                            'size': len(raw_data),
                            'direction': f"{pkt[IP].src}:{pkt[TCP].sport} -> {pkt[IP].dst}:{pkt[TCP].dport}",
                            'is_json': is_json,
                            'is_sse': is_sse,
                            'preview': repr(text[:200])
                        })
                        
                except UnicodeDecodeError:
                    # Binary data - might be compressed or encoded
                    pass
        
        print(f"  • HTTP-like packets found: {len(http_like_packets)}")
        print(f"  • Streaming-like packets found: {len(streaming_packets)}")
        
        # Show HTTP-like packets
        if http_like_packets:
            print(f"\n📝 HTTP-LIKE PACKETS:")
            for pkt_info in http_like_packets[:5]:
                print(f"  Packet {pkt_info['packet_num']} ({pkt_info['direction']}, {pkt_info['size']} bytes):")
                print(f"    Request: {pkt_info['is_request']}, Response: {pkt_info['is_response']}, Headers: {pkt_info['has_headers']}")
                print(f"    Preview: {pkt_info['preview']}")
                print()
        
        # Show streaming packets
        if streaming_packets:
            print(f"\n🌊 STREAMING-LIKE PACKETS:")
            for pkt_info in streaming_packets[:5]:
                print(f"  Packet {pkt_info['packet_num']} ({pkt_info['direction']}, {pkt_info['size']} bytes):")
                print(f"    JSON: {pkt_info['is_json']}, SSE: {pkt_info['is_sse']}")
                print(f"    Preview: {pkt_info['preview']}")
                print()
        
        # Connection analysis
        print(f"\n🔗 CONNECTION ANALYSIS:")
        connections = defaultdict(list)
        for pkt in port_8000_packets:
            if IP in pkt and TCP in pkt:
                conn_key = f"{pkt[IP].src}:{pkt[TCP].sport} <-> {pkt[IP].dst}:{pkt[TCP].dport}"
                connections[conn_key].append(pkt)
        
        print(f"  • Total connections involving port 8000: {len(connections)}")
        for conn_key, conn_packets in list(connections.items())[:5]:
            raw_count = sum(1 for p in conn_packets if Raw in p)
            print(f"    {conn_key}: {len(conn_packets)} packets ({raw_count} with data)")
        
        # Test our parser on this specific traffic
        print(f"\n🧪 TESTING OUR PARSER:")
        
        # Import our parser
        import sys
        sys.path.append('.')
        from llmshark.parser import HTTPStreamReassembler
        
        reassembler = HTTPStreamReassembler()
        
        # Try to parse the port 8000 packets
        sessions_found = 0
        for pkt in port_8000_packets:
            if Raw in pkt and IP in pkt and TCP in pkt:
                try:
                    # Create a minimal packet info for our parser
                    packet_info = {
                        'src_ip': pkt[IP].src,
                        'dst_ip': pkt[IP].dst,
                        'src_port': pkt[TCP].sport,
                        'dst_port': pkt[TCP].dport,
                        'data': bytes(pkt[Raw])
                    }
                    
                    # Try to identify if this looks like HTTP
                    data_str = packet_info['data'].decode('utf-8', errors='ignore')
                    if any(pattern in data_str.lower() for pattern in ['http/', 'content-type:', 'post ', 'get ']):
                        print(f"    Found potential HTTP packet: {packet_info['src_ip']}:{packet_info['src_port']} -> {packet_info['dst_ip']}:{packet_info['dst_port']}")
                        print(f"    Data preview: {repr(data_str[:150])}")
                        
                        # Try our reassembler
                        result = reassembler.process_packet(packet_info)
                        if result:
                            sessions_found += 1
                            print(f"    ✅ Parser accepted this packet!")
                        else:
                            print(f"    ❌ Parser rejected this packet")
                        
                except Exception as e:
                    pass
        
        print(f"  • Sessions found by our parser: {sessions_found}")
        
        return {
            'total_port_8000_packets': len(port_8000_packets),
            'http_packets': len(http_packets),
            'raw_packets': len(raw_packets),
            'http_like_packets': len(http_like_packets),
            'streaming_packets': len(streaming_packets),
            'sessions_found': sessions_found
        }
        
    except Exception as e:
        print(f"❌ Error analyzing {filename}: {e}")
        import traceback
        traceback.print_exc()
        return None


if __name__ == "__main__":
    analyze_port_8000_traffic(sys.argv[1]) 