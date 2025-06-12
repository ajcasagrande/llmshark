#!/usr/bin/env python3
"""
Script to examine PCAP packet structure and understand streaming format.
"""

import json

from scapy.all import TCP, Raw, rdpcap
from scapy.layers.http import HTTP, HTTPRequest, HTTPResponse


def examine_pcap(filename):
    """Examine PCAP file structure."""
    print(f"🔍 Examining {filename}")
    
    # Load more packets to see full conversations
    packets = rdpcap(filename, count=1000)  # More packets
    http_packets = [p for p in packets if HTTP in p]
    
    print(f"📦 Total packets examined: {len(packets)}")
    print(f"📦 HTTP packets: {len(http_packets)}")
    
    # Examine requests and responses
    requests = [p for p in http_packets if HTTPRequest in p]
    responses = [p for p in http_packets if HTTPResponse in p]
    
    print(f"📤 HTTP Requests: {len(requests)}")
    print(f"📥 HTTP Responses: {len(responses)}")
    
    # Now examine the actual HTTP responses we found
    if responses:
        print(f"\n🔍 Examining HTTP Responses:")
        
        for i, pkt in enumerate(responses[:3]):  # First 3 responses
            resp = pkt[HTTPResponse]
            print(f"\n  Response {i+1}:")
            print(f"    Status: {getattr(resp, 'Status_Code', 'Unknown')}")
            
            # Check response headers
            if hasattr(resp, 'fields'):
                print(f"    Headers:")
                for field, value in resp.fields.items():
                    print(f"      {field}: {value}")
            
            # Check for streaming data in response
            if Raw in pkt:
                raw_data = bytes(pkt[Raw])
                if len(raw_data) > 0:
                    print(f"    Data size: {len(raw_data)} bytes")
                    try:
                        text = raw_data.decode('utf-8', errors='ignore')
                        print(f"    Data preview: {repr(text[:200])}")
                        
                        # Analyze streaming format
                        if 'data:' in text:
                            print("    🌊 Format: Server-Sent Events (SSE)")
                            data_lines = [line for line in text.split('\n') if line.startswith('data:')]
                            print(f"    SSE data lines: {len(data_lines)}")
                        
                        elif text.count('{"') > 1:
                            print("    🌊 Format: Multiple JSON objects (streaming)")
                            json_count = text.count('{"')
                            print(f"    JSON objects: ~{json_count}")
                        
                        elif '"object"' in text and '"delta"' in text:
                            print("    🌊 Format: OpenAI-style streaming JSON")
                            
                        else:
                            print("    📄 Format: Single response or unknown")
                            
                    except Exception as e:
                        print(f"    ❌ Could not decode data: {e}")
                else:
                    print(f"    📭 No data payload")
    
    # Also examine the request to understand what's being asked for
    if requests:
        print(f"\n📤 Examining HTTP Request:")
        req_pkt = requests[0]
        req = req_pkt[HTTPRequest]
        
        print(f"  Method: {getattr(req, 'Method', 'Unknown')}")
        print(f"  Path: {getattr(req, 'Path', 'Unknown')}")
        print(f"  Host: {getattr(req, 'Host', 'Unknown')}")
        
        # Check request headers
        if hasattr(req, 'fields'):
            print(f"  Request headers:")
            for field, value in req.fields.items():
                print(f"    {field}: {value}")
        
        # Check request body
        if Raw in req_pkt:
            req_data = bytes(req_pkt[Raw])
            if len(req_data) > 0:
                req_text = req_data.decode('utf-8', errors='ignore')
                print(f"  Request body ({len(req_data)} bytes):")
                print(f"    {repr(req_text[:300])}")
                
                # Check if it's requesting streaming
                if 'stream' in req_text.lower():
                    print("    ✅ Request includes streaming parameter")
                    
                    # Try to parse as JSON to see the request structure
                    try:
                        req_json = json.loads(req_text)
                        if 'stream' in req_json:
                            print(f"    Stream parameter: {req_json['stream']}")
                        if 'model' in req_json:
                            print(f"    Model: {req_json['model']}")
                    except:
                        print("    ❓ Could not parse request as JSON")
                else:
                    print("    ❓ No obvious streaming parameter in request")
    
    # Summary
    print(f"\n📊 Summary:")
    print(f"  • Found {len(requests)} HTTP requests")
    print(f"  • Found {len(responses)} HTTP responses") 
    print(f"  • Each response should be a streaming session")
    
    # Check if responses have substantial data
    data_responses = [r for r in responses if Raw in r and len(bytes(r[Raw])) > 100]
    print(f"  • {len(data_responses)} responses with substantial data (>100 bytes)")
    
    if len(data_responses) == len(responses):
        print("  ✅ All responses contain data - this looks like successful streaming!")
    else:
        print("  ⚠️  Some responses may be empty or incomplete")


if __name__ == "__main__":
    examine_pcap("captures/genai-perf.pcap") 