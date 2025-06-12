"""
PCAP file parser for extracting HTTP/SSE streaming data.

This module handles parsing of Wireshark capture files (.pcap) to extract
HTTP sessions and SSE streaming data for analysis.
"""

import gzip
import json
import re
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple

from scapy.all import TCP, IP, Raw, rdpcap
from scapy.layers.http import HTTP, HTTPRequest, HTTPResponse

from .models import (
    EventType,
    HTTPHeaders,
    ProtocolVersion,
    StreamChunk,
    StreamSession,
)


class PCAPParseError(Exception):
    """Raised when there's an error parsing a PCAP file."""

    pass


class HTTPStreamReassembler:
    """Reassembles HTTP streams from TCP packets."""

    def __init__(self) -> None:
        self.streams: Dict[str, Dict[str, any]] = {}
        self.completed_sessions: List[StreamSession] = []

    def get_stream_key(self, packet: any) -> str:
        """Generate unique key for a TCP stream."""
        if IP in packet and TCP in packet:
            src_ip = packet[IP].src
            dst_ip = packet[IP].dst
            src_port = packet[TCP].sport
            dst_port = packet[TCP].dport

            # Normalize stream direction (client->server)
            if src_port > dst_port:
                return f"{dst_ip}:{dst_port}-{src_ip}:{src_port}"
            else:
                return f"{src_ip}:{src_port}-{dst_ip}:{dst_port}"
        return ""

    def add_packet(self, packet: any, timestamp: datetime) -> None:
        """Add a packet to the appropriate stream."""
        stream_key = self.get_stream_key(packet)
        if not stream_key:
            return

        if stream_key not in self.streams:
            self.streams[stream_key] = {
                "packets": [],
                "http_data": b"",
                "direction_map": {},
                "timestamps": [],
            }

        self.streams[stream_key]["packets"].append(packet)
        self.streams[stream_key]["timestamps"].append(timestamp)

        # Track packet direction
        if IP in packet and TCP in packet:
            src_ip = packet[IP].src
            dst_ip = packet[IP].dst
            src_port = packet[TCP].sport
            dst_port = packet[TCP].dport

            direction = (
                "client_to_server" if src_port > dst_port else "server_to_client"
            )
            seq = packet[TCP].seq

            self.streams[stream_key]["direction_map"][seq] = {
                "direction": direction,
                "timestamp": timestamp,
                "src_ip": src_ip,
                "dst_ip": dst_ip,
                "src_port": src_port,
                "dst_port": dst_port,
            }

    def process_streams(self) -> List[StreamSession]:
        """Process all collected streams to extract HTTP sessions."""
        sessions = []

        for stream_key, stream_data in self.streams.items():
            try:
                session = self._process_single_stream(stream_key, stream_data)
                if session:
                    sessions.append(session)
            except Exception as e:
                # Log error but continue processing other streams
                print(f"Error processing stream {stream_key}: {e}")
                continue

        return sessions

    def _process_single_stream(
        self, stream_key: str, stream_data: Dict
    ) -> Optional[StreamSession]:
        """Process a single HTTP stream."""
        packets = stream_data["packets"]
        timestamps = stream_data["timestamps"]

        if not packets:
            return None

        # Find HTTP request and response
        http_request = None
        http_response = None
        request_timestamp = None
        response_timestamp = None

        for i, packet in enumerate(packets):
            if HTTPRequest in packet:
                http_request = packet[HTTPRequest]
                request_timestamp = timestamps[i]
            elif HTTPResponse in packet:
                http_response = packet[HTTPResponse]
                response_timestamp = timestamps[i]

        if not (http_request and http_response):
            return None

        # Extract basic session info
        first_packet = packets[0]
        session_id = f"{stream_key}_{int(timestamps[0].timestamp())}"

        ip_layer = first_packet[IP]
        tcp_layer = first_packet[TCP]

        # Determine client vs server
        is_client_to_server = tcp_layer.sport > tcp_layer.dport
        if is_client_to_server:
            source_ip, dest_ip = ip_layer.src, ip_layer.dst
            source_port, dest_port = tcp_layer.sport, tcp_layer.dport
        else:
            source_ip, dest_ip = ip_layer.dst, ip_layer.src
            source_port, dest_port = tcp_layer.dport, tcp_layer.sport

        # Parse HTTP headers
        request_headers = self._parse_http_headers(http_request)
        response_headers = self._parse_http_headers(http_response)

        # Check if this is an SSE stream
        content_type = response_headers.content_type or ""
        if "text/event-stream" not in content_type.lower():
            # Not an SSE stream, skip
            return None

        # Extract streaming chunks
        chunks = self._extract_sse_chunks(
            packets, timestamps, stream_data["direction_map"]
        )

        if not chunks:
            return None

        # Create session
        session = StreamSession(
            session_id=session_id,
            source_ip=source_ip,
            dest_ip=dest_ip,
            source_port=source_port,
            dest_port=dest_port,
            protocol_version=self._detect_http_version(http_request),
            connection_start=timestamps[0],
            request_sent=request_timestamp or timestamps[0],
            response_start=response_timestamp or timestamps[0],
            first_chunk=chunks[0].timestamp if chunks else None,
            last_chunk=chunks[-1].timestamp if chunks else None,
            connection_end=timestamps[-1] if len(timestamps) > 1 else None,
            request_method=getattr(http_request, "Method", b"GET").decode(
                "utf-8", errors="ignore"
            ),
            request_path=getattr(http_request, "Path", b"/").decode(
                "utf-8", errors="ignore"
            ),
            request_headers=request_headers,
            response_status=int(getattr(http_response, "Status_Code", b"200")),
            response_headers=response_headers,
            chunks=chunks,
            total_bytes=sum(chunk.size_bytes for chunk in chunks),
        )

        return session

    def _parse_http_headers(self, http_layer: any) -> HTTPHeaders:
        """Parse HTTP headers from scapy HTTP layer."""
        headers = HTTPHeaders()

        if hasattr(http_layer, "fields"):
            raw_headers = {}
            for field, value in http_layer.fields.items():
                if isinstance(value, bytes):
                    value = value.decode("utf-8", errors="ignore")
                raw_headers[field] = str(value)

            headers.raw_headers = raw_headers

            # Extract common headers
            headers.content_type = raw_headers.get("Content-Type")
            headers.content_length = self._safe_int(raw_headers.get("Content-Length"))
            headers.transfer_encoding = raw_headers.get("Transfer-Encoding")
            headers.content_encoding = raw_headers.get("Content-Encoding")
            headers.cache_control = raw_headers.get("Cache-Control")
            headers.connection = raw_headers.get("Connection")
            headers.user_agent = raw_headers.get("User-Agent")
            headers.server = raw_headers.get("Server")

        return headers

    def _safe_int(self, value: Optional[str]) -> Optional[int]:
        """Safely convert string to int."""
        if value is None:
            return None
        try:
            return int(value)
        except (ValueError, TypeError):
            return None

    def _detect_http_version(self, http_request: any) -> ProtocolVersion:
        """Detect HTTP version from request."""
        version = getattr(http_request, "Http_Version", b"HTTP/1.1")
        if isinstance(version, bytes):
            version = version.decode("utf-8", errors="ignore")

        version_map = {
            "HTTP/1.0": ProtocolVersion.HTTP_1_0,
            "HTTP/1.1": ProtocolVersion.HTTP_1_1,
            "HTTP/2": ProtocolVersion.HTTP_2,
            "HTTP/3": ProtocolVersion.HTTP_3,
        }

        return version_map.get(version, ProtocolVersion.HTTP_1_1)

    def _extract_sse_chunks(
        self, packets: List[any], timestamps: List[datetime], direction_map: Dict
    ) -> List[StreamChunk]:
        """Extract SSE chunks from HTTP response packets."""
        chunks = []
        chunk_buffer = b""
        sequence_number = 0

        for i, packet in enumerate(packets):
            if Raw in packet and TCP in packet:
                # Check if this is server-to-client data
                seq = packet[TCP].seq
                direction_info = direction_map.get(seq, {})

                if direction_info.get("direction") == "server_to_client":
                    payload = bytes(packet[Raw])
                    chunk_buffer += payload

                    # Try to parse SSE chunks from buffer
                    new_chunks = self._parse_sse_buffer(
                        chunk_buffer, timestamps[i], sequence_number
                    )
                    chunks.extend(new_chunks)
                    sequence_number += len(new_chunks)

                    # Keep remaining unparsed data in buffer
                    if new_chunks:
                        # Remove parsed data from buffer (simplified)
                        chunk_buffer = b""

        # Mark first and last chunks
        if chunks:
            chunks[0].is_first_token = True
            chunks[-1].is_last_token = True

        return chunks

    def _parse_sse_buffer(
        self, buffer: bytes, timestamp: datetime, start_sequence: int
    ) -> List[StreamChunk]:
        """Parse SSE data from buffer."""
        chunks = []

        try:
            # Decode buffer
            text = buffer.decode("utf-8", errors="ignore")

            # Split by SSE chunk boundaries
            sse_pattern = r"data:\s*(.+?)(?=\n\n|\r\n\r\n|$)"
            matches = re.findall(sse_pattern, text, re.DOTALL)

            for i, match in enumerate(matches):
                content = match.strip()
                if content and content != "[DONE]":  # Skip SSE termination marker
                    try:
                        # Try to parse as JSON (common for LLM streams)
                        json.loads(content)
                        chunk_content = content
                    except json.JSONDecodeError:
                        # Not JSON, use raw content
                        chunk_content = content

                    chunk = StreamChunk(
                        timestamp=timestamp,
                        sequence_number=start_sequence + i,
                        size_bytes=len(chunk_content.encode("utf-8")),
                        content=chunk_content,
                        event_type=None,  # Could be enhanced to parse SSE event types
                        event_id=None,
                    )
                    chunks.append(chunk)

        except Exception as e:
            # If parsing fails, create a single chunk with raw data
            if buffer:
                chunk = StreamChunk(
                    timestamp=timestamp,
                    sequence_number=start_sequence,
                    size_bytes=len(buffer),
                    content=buffer.decode("utf-8", errors="ignore"),
                    parse_errors=[str(e)],
                )
                chunks.append(chunk)

        return chunks


class PCAPParser:
    """Main PCAP parser class."""

    def __init__(self) -> None:
        self.sessions: List[StreamSession] = []
        self.parse_errors: List[str] = []

    def parse_file(self, pcap_file: Path) -> List[StreamSession]:
        """Parse a single PCAP file."""
        if not pcap_file.exists():
            raise PCAPParseError(f"PCAP file does not exist: {pcap_file}")

        try:
            # Read PCAP file using scapy
            packets = rdpcap(str(pcap_file))

            if not packets:
                raise PCAPParseError(f"No packets found in PCAP file: {pcap_file}")

            # Use stream reassembler to process packets
            reassembler = HTTPStreamReassembler()

            for packet in packets:
                # Convert scapy timestamp to datetime
                timestamp = datetime.fromtimestamp(float(packet.time))
                reassembler.add_packet(packet, timestamp)

            # Process streams to extract sessions
            sessions = reassembler.process_streams()

            # Add capture file metadata
            for session in sessions:
                session.capture_file = pcap_file

            return sessions

        except Exception as e:
            error_msg = f"Error parsing PCAP file {pcap_file}: {str(e)}"
            self.parse_errors.append(error_msg)
            raise PCAPParseError(error_msg) from e

    def parse_files(self, pcap_files: List[Path]) -> List[StreamSession]:
        """Parse multiple PCAP files."""
        all_sessions = []

        for pcap_file in pcap_files:
            try:
                sessions = self.parse_file(pcap_file)
                all_sessions.extend(sessions)
            except PCAPParseError as e:
                print(f"Warning: {e}")
                continue

        return all_sessions

    def validate_pcap_file(self, pcap_file: Path) -> bool:
        """Validate that a file is a valid PCAP file."""
        if not pcap_file.exists():
            return False

        if not pcap_file.suffix.lower() in [".pcap", ".pcapng", ".cap"]:
            return False

        try:
            # Try to read just the first few packets
            packets = rdpcap(str(pcap_file), count=10)
            return len(packets) > 0
        except:
            return False

    def get_pcap_info(self, pcap_file: Path) -> Dict[str, any]:
        """Get basic information about a PCAP file."""
        if not self.validate_pcap_file(pcap_file):
            return {}

        try:
            packets = rdpcap(str(pcap_file))

            info = {
                "file_path": pcap_file,
                "file_size_bytes": pcap_file.stat().st_size,
                "packet_count": len(packets),
                "http_packet_count": sum(1 for p in packets if HTTP in p),
                "tcp_packet_count": sum(1 for p in packets if TCP in p),
                "capture_duration_seconds": 0.0,
                "start_time": None,
                "end_time": None,
            }

            if packets:
                start_time = datetime.fromtimestamp(float(packets[0].time))
                end_time = datetime.fromtimestamp(float(packets[-1].time))
                info["start_time"] = start_time
                info["end_time"] = end_time
                info["capture_duration_seconds"] = (
                    end_time - start_time
                ).total_seconds()

            return info

        except Exception as e:
            self.parse_errors.append(f"Error getting PCAP info for {pcap_file}: {e}")
            return {}


def find_pcap_files(directory: Path, recursive: bool = True) -> List[Path]:
    """Find all PCAP files in a directory."""
    pcap_extensions = [".pcap", ".pcapng", ".cap"]
    pcap_files = []

    if recursive:
        for ext in pcap_extensions:
            pcap_files.extend(directory.rglob(f"*{ext}"))
    else:
        for ext in pcap_extensions:
            pcap_files.extend(directory.glob(f"*{ext}"))

    return sorted(pcap_files)
