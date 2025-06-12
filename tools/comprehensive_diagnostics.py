#!/usr/bin/env python3
"""
Comprehensive diagnostics for PCAP files to identify why streaming sessions aren't detected.
"""

import json
from collections import defaultdict, Counter
from pathlib import Path
import sys

from scapy.all import TCP, IP, Raw, rdpcap
from scapy.layers.http import HTTP, HTTPRequest, HTTPResponse


def analyze_pcap_comprehensive(filename):
    """Comprehensive analysis of PCAP file structure."""
    print(f"🔍 COMPREHENSIVE DIAGNOSTICS: {filename}")
    print("=" * 80)
    
    try:
        # Load packets
        packets = rdpcap(filename, count=2000)  # More packets for analysis
        print(f"📦 Loaded {len(packets)} packets")
        
        # Basic packet analysis
        packet_types = Counter()
        ports = Counter()
        ips = set()
        
        for pkt in packets:
            # Count packet types
            if IP in pkt:
                ips.add(pkt[IP].src)
                ips.add(pkt[IP].dst)
                
            if TCP in pkt:
                packet_types['TCP'] += 1
                ports[pkt[TCP].sport] += 1
                ports[pkt[TCP].dport] += 1
                
            if HTTP in pkt:
                packet_types['HTTP'] += 1
                
            if Raw in pkt:
                packet_types['Raw Data'] += 1
        
        print(f"\n📊 BASIC STATISTICS:")
        print(f"  • Unique IPs: {len(ips)}")
        print(f"  • Packet types: {dict(packet_types)}")
        print(f"  • Top ports: {dict(ports.most_common(10))}")
        
        # Analyze potential HTTP traffic patterns
        print(f"\n🔍 HTTP DETECTION ANALYSIS:")
        
        # Look for HTTP-like patterns in raw data
        http_indicators = {
            'GET requests': 0,
            'POST requests': 0,
            'HTTP responses': 0,
            'JSON content': 0,
            'SSE data': 0,
            'Chunked encoding': 0,
            'Content-Type headers': 0,
            'HTTPS/TLS': 0
        }
        
        sample_data = []
        
        for pkt in packets[:500]:  # Check first 500 packets
            if Raw in pkt:
                raw_data = bytes(pkt[Raw])
                
                if len(raw_data) > 20:  # Meaningful data
                    try:
                        text = raw_data.decode('utf-8', errors='ignore')
                        text_lower = text.lower()
                        
                        # Check for HTTP indicators
                        if 'get /' in text_lower or 'get http' in text_lower:
                            http_indicators['GET requests'] += 1
                        if 'post /' in text_lower or 'post http' in text_lower:
                            http_indicators['POST requests'] += 1
                        if 'http/1.' in text_lower or 'http/2' in text_lower:
                            http_indicators['HTTP responses'] += 1
                        if 'content-type:' in text_lower:
                            http_indicators['Content-Type headers'] += 1
                        if 'transfer-encoding: chunked' in text_lower:
                            http_indicators['Chunked encoding'] += 1
                        if 'data:' in text and '\n' in text:
                            http_indicators['SSE data'] += 1
                        if text.strip().startswith('{') and text.strip().endswith('}'):
                            http_indicators['JSON content'] += 1
                            
                        # Store sample for analysis
                        if len(sample_data) < 5 and len(text.strip()) > 50:
                            sample_data.append({
                                'size': len(raw_data),
                                'preview': repr(text[:200]),
                                'packet_info': f"TCP {pkt[TCP].sport}->{pkt[TCP].dport}" if TCP in pkt else "Unknown"
                            })
                            
                    except UnicodeDecodeError:
                        # Check for TLS/binary patterns
                        if raw_data.startswith(b'\x16\x03'):  # TLS handshake
                            http_indicators['HTTPS/TLS'] += 1
        
        for indicator, count in http_indicators.items():
            print(f"  • {indicator}: {count}")
            
        # Show sample data
        if sample_data:
            print(f"\n📝 SAMPLE DATA PACKETS:")
            for i, sample in enumerate(sample_data, 1):
                print(f"  Sample {i} ({sample['packet_info']}, {sample['size']} bytes):")
                print(f"    {sample['preview']}")
        
        # Port analysis for common web services
        print(f"\n🌐 PORT ANALYSIS:")
        web_ports = {80: 'HTTP', 443: 'HTTPS', 8080: 'HTTP-Alt', 8443: 'HTTPS-Alt', 
                    3000: 'Dev-HTTP', 5000: 'Dev-HTTP', 8000: 'Dev-HTTP'}
        
        found_web_ports = {}
        for port, count in ports.most_common(20):
            if port in web_ports:
                found_web_ports[port] = f"{web_ports[port]} ({count} packets)"
        
        if found_web_ports:
            print(f"  • Web service ports found:")
            for port, info in found_web_ports.items():
                print(f"    Port {port}: {info}")
        else:
            print(f"  • No standard web ports detected")
            print(f"  • Top ports: {list(ports.most_common(5))}")
        
        # TLS/Encryption detection
        print(f"\n🔒 ENCRYPTION ANALYSIS:")
        if http_indicators['HTTPS/TLS'] > 0:
            print(f"  ⚠️  Detected {http_indicators['HTTPS/TLS']} TLS packets")
            print(f"     This traffic is encrypted and cannot be analyzed")
        else:
            print(f"  ✅ No obvious TLS encryption detected")
        
        # Streaming pattern analysis
        print(f"\n🌊 STREAMING PATTERN ANALYSIS:")
        
        # Look for streaming-like patterns
        streaming_indicators = {
            'Long connections': 0,
            'Frequent small packets': 0,
            'JSON streaming patterns': 0,
            'SSE patterns': 0,
            'Large data transfers': 0
        }
        
        # Group packets by connection
        connections = defaultdict(list)
        for pkt in packets:
            if TCP in pkt and IP in pkt:
                conn_key = f"{pkt[IP].src}:{pkt[TCP].sport}-{pkt[IP].dst}:{pkt[TCP].dport}"
                connections[conn_key].append(pkt)
        
        for conn_key, conn_packets in connections.items():
            if len(conn_packets) > 50:  # Long connection
                streaming_indicators['Long connections'] += 1
                
            small_packets = [p for p in conn_packets if Raw in p and 10 < len(bytes(p[Raw])) < 200]
            if len(small_packets) > 20:
                streaming_indicators['Frequent small packets'] += 1
        
        for indicator, count in streaming_indicators.items():
            print(f"  • {indicator}: {count}")
        
        # Final diagnosis
        print(f"\n🎯 DIAGNOSIS:")
        
        if http_indicators['HTTPS/TLS'] > 10:
            print(f"  ❌ ISSUE: Traffic is encrypted (HTTPS/TLS)")
            print(f"     SOLUTION: Cannot analyze encrypted traffic")
        elif http_indicators['HTTP responses'] == 0 and http_indicators['GET requests'] == 0:
            print(f"  ❌ ISSUE: No HTTP traffic detected")
            print(f"     SOLUTION: Check if this contains web traffic at all")
        elif http_indicators['HTTP responses'] > 0 and http_indicators['SSE data'] == 0:
            print(f"  ⚠️  ISSUE: HTTP detected but no streaming patterns")
            print(f"     SOLUTION: May need different streaming detection logic")
        else:
            print(f"  ✅ Traffic looks analyzable - may need parser improvements")
            
        return {
            'total_packets': len(packets),
            'http_indicators': http_indicators,
            'streaming_indicators': streaming_indicators,
            'sample_data': sample_data,
            'ports': dict(ports.most_common(10))
        }
        
    except Exception as e:
        print(f"❌ Error analyzing {filename}: {e}")
        return None


def compare_pcap_files(working_file, problematic_file):
    """Compare two PCAP files to identify differences."""
    print(f"\n" + "=" * 80)
    print(f"🔄 COMPARATIVE ANALYSIS")
    print(f"=" * 80)
    
    print(f"Working file: {working_file}")
    working_stats = analyze_pcap_comprehensive(working_file)
    
    print(f"\nProblematic file: {problematic_file}")
    problem_stats = analyze_pcap_comprehensive(problematic_file)
    
    if working_stats and problem_stats:
        print(f"\n📊 COMPARISON SUMMARY:")
        print(f"  Working file - HTTP responses: {working_stats['http_indicators']['HTTP responses']}")
        print(f"  Problem file - HTTP responses: {problem_stats['http_indicators']['HTTP responses']}")
        
        print(f"  Working file - TLS packets: {working_stats['http_indicators']['HTTPS/TLS']}")
        print(f"  Problem file - TLS packets: {problem_stats['http_indicators']['HTTPS/TLS']}")


if __name__ == "__main__":
    # Analyze the problematic file
    analyze_pcap_comprehensive(sys.argv[1])
    
    # Compare with working file if it exists
    if len(sys.argv) > 2:
        working_file = sys.argv[2]
        if Path(working_file).exists():
            compare_pcap_files(working_file, sys.argv[1]) 