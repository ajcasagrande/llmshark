"""
PCAP file parser for extracting HTTP/SSE streaming data.

This module handles parsing of Wireshark capture files (.pcap) to extract
HTTP sessions and SSE streaming data for analysis.
"""

import json
import re
import time
from collections.abc import Callable
from datetime import datetime
from pathlib import Path

from scapy.all import IP, TCP, Raw, rdpcap
from scapy.layers.http import HTTP, HTTPRequest, HTTPResponse

from .models import (
    HTTPHeaders,
    ProtocolVersion,
    StreamChunk,
    StreamSession,
)


class PCAPParseError(Exception):
    """Raised when there's an error parsing a PCAP file."""



class ParseProgress:
    """Progress tracking for PCAP parsing."""

    def __init__(self):
        self.total_packets = 0
        self.processed_packets = 0
        self.total_bytes = 0
        self.processed_bytes = 0
        self.start_time = time.time()
        self.http_packets_found = 0
        self.sse_streams_found = 0

    def update(self, packet_count: int = 1, bytes_processed: int = 0, http_found: bool = False, sse_found: bool = False):
        """Update progress counters."""
        self.processed_packets += packet_count
        self.processed_bytes += bytes_processed
        if http_found:
            self.http_packets_found += 1
        if sse_found:
            self.sse_streams_found += 1

    @property
    def elapsed_time(self) -> float:
        """Get elapsed time in seconds."""
        return time.time() - self.start_time

    @property
    def progress_ratio(self) -> float:
        """Get progress as ratio (0.0 to 1.0)."""
        if self.total_packets == 0:
            return 0.0
        return min(self.processed_packets / self.total_packets, 1.0)

    @property
    def eta_seconds(self) -> float | None:
        """Estimate time remaining in seconds."""
        if self.progress_ratio <= 0:
            return None

        remaining_ratio = 1.0 - self.progress_ratio
        if remaining_ratio <= 0:
            return 0.0

        return (self.elapsed_time / self.progress_ratio) * remaining_ratio

    @property
    def packets_per_second(self) -> float:
        """Get processing rate in packets per second."""
        if self.elapsed_time <= 0:
            return 0.0
        return self.processed_packets / self.elapsed_time

    @property
    def mbytes_per_second(self) -> float:
        """Get processing rate in MB per second."""
        if self.elapsed_time <= 0:
            return 0.0
        return (self.processed_bytes / (1024 * 1024)) / self.elapsed_time


class HTTPStreamReassembler:
    """Reassembles HTTP streams from TCP packets."""

    def __init__(self, progress_callback: Callable[[ParseProgress], None] | None = None) -> None:
        self.streams: dict[str, dict[str, any]] = {}
        self.completed_sessions: list[StreamSession] = []
        self.progress_callback = progress_callback
        self.progress = ParseProgress()

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

        # Update progress
        packet_size = len(bytes(packet)) if packet else 0
        is_http = HTTP in packet
        self.progress.update(packet_count=1, bytes_processed=packet_size, http_found=is_http)

        # Call progress callback if provided
        if self.progress_callback:
            self.progress_callback(self.progress)

    def set_total_packets(self, total: int) -> None:
        """Set total packet count for progress tracking."""
        self.progress.total_packets = total

    def process_streams(self) -> list[StreamSession]:
        """Process all collected streams to extract HTTP sessions."""
        sessions = []

        for stream_key, stream_data in self.streams.items():
            try:
                session = self._process_single_stream(stream_key, stream_data)
                if session:
                    sessions.append(session)
                    self.progress.update(sse_found=True)
            except Exception as e:
                # Log error but continue processing other streams
                print(f"Error processing stream {stream_key}: {e}")
                continue

        return sessions

    def _process_single_stream(
        self, stream_key: str, stream_data: dict
    ) -> StreamSession | None:
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

        # If Scapy didn't detect HTTP layers, try to parse raw HTTP data
        if not (http_request and http_response):
            parsed_http = self._parse_raw_http_data(packets, timestamps)
            if parsed_http:
                http_request = parsed_http["request"]
                http_response = parsed_http["response"]
                request_timestamp = parsed_http["request_timestamp"]
                response_timestamp = parsed_http["response_timestamp"]

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

        # Check if this could be an SSE/streaming response
        # Accept multiple content types and check for streaming indicators
        content_type = response_headers.content_type or ""
        transfer_encoding = response_headers.transfer_encoding or ""

        # More permissive check for streaming content
        is_streaming = (
            "text/event-stream" in content_type.lower() or
            "application/json" in content_type.lower() or
            "chunked" in transfer_encoding.lower() or
            "stream" in content_type.lower()
        )

        if not is_streaming:
            # Still try to extract data if there are multiple data packets
            data_packets = [p for p in packets if Raw in p and len(bytes(p[Raw])) > 0]
            if len(data_packets) < 2:  # Not enough data packets to be streaming
                return None

        # Extract streaming chunks with improved detection
        chunks = self._extract_streaming_chunks(
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
            request_method=self._get_http_field(http_request, "Method", b"GET").decode(
                "utf-8", errors="ignore"
            ),
            request_path=self._get_http_field(http_request, "Path", b"/").decode(
                "utf-8", errors="ignore"
            ),
            request_headers=request_headers,
            response_status=int(self._get_http_field(http_response, "Status_Code", b"200")),
            response_headers=response_headers,
            chunks=chunks,
            total_bytes=sum(chunk.size_bytes for chunk in chunks),
        )

        return session

    def _parse_http_headers(self, http_layer: any) -> HTTPHeaders:
        """Parse HTTP headers from scapy HTTP layer or mock HTTP object."""
        headers = HTTPHeaders()

        # Handle both Scapy HTTP layers and our mock HTTP objects
        if hasattr(http_layer, "fields") or isinstance(http_layer, dict):
            raw_headers = {}

            # Get fields from either Scapy object or our mock dict
            fields = http_layer.fields if hasattr(http_layer, "fields") else http_layer.get("fields", {})

            for field, value in fields.items():
                if isinstance(value, bytes):
                    value = value.decode("utf-8", errors="ignore")
                raw_headers[field] = str(value)

            headers.raw_headers = raw_headers

            # Extract common headers
            headers.content_type = raw_headers.get("Content-Type") or raw_headers.get("content-type")
            headers.content_length = self._safe_int(raw_headers.get("Content-Length") or raw_headers.get("content-length"))
            headers.transfer_encoding = raw_headers.get("Transfer-Encoding") or raw_headers.get("transfer-encoding")
            headers.content_encoding = raw_headers.get("Content-Encoding") or raw_headers.get("content-encoding")
            headers.cache_control = raw_headers.get("Cache-Control") or raw_headers.get("cache-control")
            headers.connection = raw_headers.get("Connection") or raw_headers.get("connection")
            headers.user_agent = raw_headers.get("User-Agent") or raw_headers.get("user-agent")
            headers.server = raw_headers.get("Server") or raw_headers.get("server")

        return headers

    def _safe_int(self, value: str | None) -> int | None:
        """Safely convert string to int."""
        if value is None:
            return None
        try:
            return int(value)
        except (ValueError, TypeError):
            return None

    def _parse_raw_http_data(self, packets: list[any], timestamps: list[datetime]) -> dict | None:
        """Parse HTTP data from raw TCP packets when Scapy doesn't detect HTTP layers."""
        request_data = None
        response_data = None
        request_timestamp = None
        response_timestamp = None

        for i, packet in enumerate(packets):
            if Raw in packet and TCP in packet:
                try:
                    raw_data = bytes(packet[Raw])
                    text_data = raw_data.decode('utf-8', errors='ignore')

                    # Check for HTTP request
                    if text_data.startswith(('GET ', 'POST ', 'PUT ', 'DELETE ', 'HEAD ', 'OPTIONS ', 'PATCH ')):
                        request_data = self._create_mock_http_request(text_data)
                        request_timestamp = timestamps[i]

                    # Check for HTTP response
                    elif text_data.startswith('HTTP/'):
                        response_data = self._create_mock_http_response(text_data)
                        response_timestamp = timestamps[i]

                except (UnicodeDecodeError, AttributeError):
                    continue

        if request_data and response_data:
            return {
                "request": request_data,
                "response": response_data,
                "request_timestamp": request_timestamp,
                "response_timestamp": response_timestamp
            }

        return None

    def _create_mock_http_request(self, text_data: str) -> dict:
        """Create a mock HTTP request object from raw text data."""
        lines = text_data.split('\r\n')
        if not lines:
            return None

        # Parse request line
        request_line = lines[0]
        parts = request_line.split(' ')
        if len(parts) < 3:
            return None

        method = parts[0]
        path = parts[1]
        version = parts[2]

        # Parse headers
        headers = {}
        for line in lines[1:]:
            if ':' in line:
                key, value = line.split(':', 1)
                headers[key.strip()] = value.strip()
            elif line.strip() == '':
                break

        return {
            'Method': method.encode('utf-8'),
            'Path': path.encode('utf-8'),
            'Http_Version': version.encode('utf-8'),
            'fields': headers
        }

    def _create_mock_http_response(self, text_data: str) -> dict:
        """Create a mock HTTP response object from raw text data."""
        lines = text_data.split('\r\n')
        if not lines:
            return None

        # Parse status line
        status_line = lines[0]
        parts = status_line.split(' ')
        if len(parts) < 3:
            return None

        version = parts[0]
        status_code = parts[1]
        reason_phrase = ' '.join(parts[2:])

        # Parse headers
        headers = {}
        for line in lines[1:]:
            if ':' in line:
                key, value = line.split(':', 1)
                headers[key.strip()] = value.strip()
            elif line.strip() == '':
                break

        return {
            'Http_Version': version.encode('utf-8'),
            'Status_Code': status_code.encode('utf-8'),
            'Reason_Phrase': reason_phrase.encode('utf-8'),
            'fields': headers
        }

    def _get_http_field(self, http_obj: any, field_name: str, default: any = None) -> any:
        """Get field from HTTP object (Scapy or mock)."""
        if isinstance(http_obj, dict):
            return http_obj.get(field_name, default)
        else:
            return getattr(http_obj, field_name, default)

    def _detect_http_version(self, http_request: any) -> ProtocolVersion:
        """Detect HTTP version from request."""
        version = self._get_http_field(http_request, "Http_Version", b"HTTP/1.1")
        if isinstance(version, bytes):
            version = version.decode("utf-8", errors="ignore")

        version_map = {
            "HTTP/1.0": ProtocolVersion.HTTP_1_0,
            "HTTP/1.1": ProtocolVersion.HTTP_1_1,
            "HTTP/2": ProtocolVersion.HTTP_2,
            "HTTP/3": ProtocolVersion.HTTP_3,
        }

        return version_map.get(version, ProtocolVersion.HTTP_1_1)

    def _extract_streaming_chunks(
        self, packets: list[any], timestamps: list[datetime], direction_map: dict
    ) -> list[StreamChunk]:
        """Extract streaming chunks from HTTP response packets with improved detection."""
        chunks = []
        chunk_buffer = b""
        sequence_number = 0

        # Find all server-to-client data packets
        data_packets = []
        for i, packet in enumerate(packets):
            if Raw in packet and TCP in packet:
                seq = packet[TCP].seq
                direction_info = direction_map.get(seq, {})

                if direction_info.get("direction") == "server_to_client":
                    payload = bytes(packet[Raw])
                    if len(payload) > 0:  # Only include packets with actual data
                        data_packets.append((i, packet, payload, timestamps[i]))

        if len(data_packets) < 1:
            return []

        # Process each data packet
        for packet_idx, packet, payload, timestamp in data_packets:
            chunk_buffer += payload

            # Try multiple parsing strategies
            new_chunks = []

            # Strategy 1: SSE format (data: ...)
            sse_chunks = self._parse_sse_buffer(chunk_buffer, timestamp, sequence_number)
            if sse_chunks:
                new_chunks.extend(sse_chunks)

            # Strategy 2: JSON streaming (each line is JSON)
            if not new_chunks:
                json_chunks = self._parse_json_stream_buffer(chunk_buffer, timestamp, sequence_number)
                if json_chunks:
                    new_chunks.extend(json_chunks)

            # Strategy 3: Chunked HTTP data
            if not new_chunks:
                chunked_data = self._parse_chunked_buffer(chunk_buffer, timestamp, sequence_number)
                if chunked_data:
                    new_chunks.extend(chunked_data)

            # Strategy 4: Fallback - treat each packet as a chunk
            if not new_chunks and len(payload) > 10:  # Minimum size to be meaningful
                fallback_chunk = self._create_fallback_chunk(payload, timestamp, sequence_number)
                if fallback_chunk:
                    new_chunks.append(fallback_chunk)

            if new_chunks:
                chunks.extend(new_chunks)
                sequence_number += len(new_chunks)
                # Keep some buffer for potential multi-packet chunks
                if len(chunk_buffer) > 8192:  # Reset if buffer gets too large
                    chunk_buffer = b""

        # Mark first and last chunks
        if chunks:
            chunks[0].is_first_token = True
            chunks[-1].is_last_token = True

        return chunks

    def _parse_sse_buffer(
        self, buffer: bytes, timestamp: datetime, start_sequence: int
    ) -> list[StreamChunk]:
        """Parse SSE data from buffer."""
        chunks = []

        try:
            # Decode buffer
            text = buffer.decode("utf-8", errors="ignore")

            # More comprehensive SSE patterns
            patterns = [
                r"data:\s*(.+?)(?=\n\n|\r\n\r\n|$)",  # Standard SSE
                r"data:\s*(.+?)(?=\ndata:|\n\n|\r\n\r\n|$)",  # Multiple data lines
                r"event:\s*\w+\ndata:\s*(.+?)(?=\n\n|\r\n\r\n|$)",  # With event type
            ]

            all_matches = []
            for pattern in patterns:
                matches = re.findall(pattern, text, re.DOTALL | re.MULTILINE)
                all_matches.extend(matches)

            for i, match in enumerate(all_matches):
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

        except Exception:
            # If parsing fails, don't create fallback chunks here
            pass

        return chunks

    def _parse_json_stream_buffer(
        self, buffer: bytes, timestamp: datetime, start_sequence: int
    ) -> list[StreamChunk]:
        """Parse JSON streaming data (newline-delimited JSON)."""
        chunks = []

        try:
            text = buffer.decode("utf-8", errors="ignore")

            # Split by newlines and try to parse each line as JSON
            lines = text.split('\n')

            for i, line in enumerate(lines):
                line = line.strip()
                if line and len(line) > 2:  # Minimum length for valid JSON
                    try:
                        # Try to parse as JSON
                        json.loads(line)
                        chunk = StreamChunk(
                            timestamp=timestamp,
                            sequence_number=start_sequence + i,
                            size_bytes=len(line.encode("utf-8")),
                            content=line,
                            event_type=None,
                            event_id=None,
                        )
                        chunks.append(chunk)
                    except json.JSONDecodeError:
                        continue

        except Exception:
            pass

        return chunks

    def _parse_chunked_buffer(
        self, buffer: bytes, timestamp: datetime, start_sequence: int
    ) -> list[StreamChunk]:
        """Parse HTTP chunked transfer encoding."""
        chunks = []

        try:
            text = buffer.decode("utf-8", errors="ignore")

            # Look for chunked encoding pattern: size\r\ndata\r\n
            chunk_pattern = r"([0-9a-fA-F]+)\r?\n(.+?)(?=\r?\n[0-9a-fA-F]+|\r?\n0\r?\n|$)"
            matches = re.findall(chunk_pattern, text, re.DOTALL)

            for i, (size_hex, data) in enumerate(matches):
                try:
                    expected_size = int(size_hex, 16)
                    if expected_size > 0 and len(data.encode('utf-8')) >= expected_size // 2:  # Rough size check
                        chunk = StreamChunk(
                            timestamp=timestamp,
                            sequence_number=start_sequence + i,
                            size_bytes=len(data.encode("utf-8")),
                            content=data.strip(),
                            event_type=None,
                            event_id=None,
                        )
                        chunks.append(chunk)
                except ValueError:
                    continue

        except Exception:
            pass

        return chunks

    def _create_fallback_chunk(
        self, payload: bytes, timestamp: datetime, sequence_number: int
    ) -> StreamChunk | None:
        """Create a fallback chunk from raw payload."""
        try:
            content = payload.decode("utf-8", errors="ignore").strip()
            if len(content) > 0:
                return StreamChunk(
                    timestamp=timestamp,
                    sequence_number=sequence_number,
                    size_bytes=len(payload),
                    content=content,
                    event_type=None,
                    event_id=None,
                )
        except Exception:
            pass
        return None


class PCAPParser:
    """Main PCAP parser class."""

    def __init__(self) -> None:
        self.sessions: list[StreamSession] = []
        self.parse_errors: list[str] = []

    def parse_file(self, pcap_file: Path, progress_callback: Callable[[ParseProgress], None] | None = None) -> list[StreamSession]:
        """Parse a single PCAP file with optional progress callback."""
        if not pcap_file.exists():
            raise PCAPParseError(f"PCAP file does not exist: {pcap_file}")

        try:
            # Read PCAP file using scapy
            packets = rdpcap(str(pcap_file))

            if not packets:
                raise PCAPParseError(f"No packets found in PCAP file: {pcap_file}")

            # Use stream reassembler to process packets
            reassembler = HTTPStreamReassembler(progress_callback)
            reassembler.set_total_packets(len(packets))

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

    def parse_files(self, pcap_files: list[Path], progress_callback: Callable[[ParseProgress], None] | None = None) -> list[StreamSession]:
        """Parse multiple PCAP files with optional progress callback."""
        all_sessions = []

        for pcap_file in pcap_files:
            try:
                sessions = self.parse_file(pcap_file, progress_callback)
                all_sessions.extend(sessions)
            except PCAPParseError as e:
                print(f"Warning: {e}")
                continue

        return all_sessions

    def validate_pcap_file(self, pcap_file: Path) -> bool:
        """Validate that a file is a valid PCAP file."""
        if not pcap_file.exists():
            return False

        if pcap_file.suffix.lower() not in [".pcap", ".pcapng", ".cap"]:
            return False

        try:
            # Try to read just the first few packets
            packets = rdpcap(str(pcap_file), count=10)
            return len(packets) > 0
        except:
            return False

    def get_pcap_info(self, pcap_file: Path) -> dict[str, any]:
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


def find_pcap_files(directory: Path, recursive: bool = True) -> list[Path]:
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
