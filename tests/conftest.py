"""
Pytest configuration and shared fixtures for LLMShark tests.
"""

from datetime import datetime, timedelta
from pathlib import Path
from typing import List
import tempfile

import pytest

from llmshark.models import (
    HTTPHeaders,
    ProtocolVersion,
    StreamChunk,
    StreamSession,
    TimingStats,
)


@pytest.fixture
def sample_http_headers() -> HTTPHeaders:
    """Sample HTTP headers for testing."""
    return HTTPHeaders(
        content_type="text/event-stream",
        content_length=None,
        transfer_encoding="chunked",
        content_encoding=None,
        cache_control="no-cache",
        connection="keep-alive",
        raw_headers={
            "Content-Type": "text/event-stream",
            "Transfer-Encoding": "chunked",
            "Cache-Control": "no-cache",
            "Connection": "keep-alive",
        },
    )


@pytest.fixture
def sample_stream_chunks() -> List[StreamChunk]:
    """Sample stream chunks for testing."""
    base_time = datetime.now()
    chunks = []

    for i in range(10):
        chunk = StreamChunk(
            timestamp=base_time + timedelta(milliseconds=i * 100),
            sequence_number=i,
            size_bytes=50 + i * 10,
            content=f'{{"chunk": {i}, "data": "token_{i}"}}',
            event_type="data",
            is_first_token=(i == 0),
            is_last_token=(i == 9),
        )
        chunks.append(chunk)

    return chunks


@pytest.fixture
def sample_stream_session(
    sample_http_headers: HTTPHeaders, sample_stream_chunks: List[StreamChunk]
) -> StreamSession:
    """Sample stream session for testing."""
    base_time = datetime.now()

    return StreamSession(
        session_id="test_session_001",
        source_ip="192.168.1.100",
        dest_ip="10.0.0.1",
        source_port=54321,
        dest_port=443,
        protocol_version=ProtocolVersion.HTTP_1_1,
        connection_start=base_time,
        request_sent=base_time + timedelta(milliseconds=10),
        response_start=base_time + timedelta(milliseconds=50),
        first_chunk=sample_stream_chunks[0].timestamp,
        last_chunk=sample_stream_chunks[-1].timestamp,
        connection_end=base_time + timedelta(seconds=2),
        request_method="POST",
        request_path="/v1/chat/completions",
        request_headers=sample_http_headers,
        response_status=200,
        response_headers=sample_http_headers,
        chunks=sample_stream_chunks,
        total_bytes=sum(chunk.size_bytes for chunk in sample_stream_chunks),
    )


@pytest.fixture
def sample_timing_stats() -> TimingStats:
    """Sample timing statistics for testing."""
    itl_values = [50.0, 75.0, 60.0, 80.0, 55.0, 70.0, 65.0, 85.0, 90.0]

    return TimingStats(
        ttft_seconds=0.5,
        ttft_ms=500.0,
        mean_itl_ms=71.1,
        median_itl_ms=70.0,
        p95_itl_ms=88.0,
        p99_itl_ms=89.5,
        std_itl_ms=13.6,
        min_itl_ms=50.0,
        max_itl_ms=90.0,
        mean_chunk_interval_ms=100.0,
        median_chunk_interval_ms=100.0,
        tokens_per_second=14.1,
        bytes_per_second=550.0,
        itl_values_ms=itl_values,
        chunk_intervals_ms=[100.0] * 9,
    )


@pytest.fixture
def temp_pcap_file() -> Path:
    """Create a temporary PCAP file for testing."""
    with tempfile.NamedTemporaryFile(suffix=".pcap", delete=False) as f:
        # Write minimal PCAP header (simplified for testing)
        pcap_header = b"\xd4\xc3\xb2\xa1\x02\x00\x04\x00\x00\x00\x00\x00\x00\x00\x00\x00\xff\xff\x00\x00\x01\x00\x00\x00"
        f.write(pcap_header)
        temp_path = Path(f.name)

    yield temp_path

    # Cleanup
    if temp_path.exists():
        temp_path.unlink()


@pytest.fixture
def temp_output_dir() -> Path:
    """Create a temporary output directory for testing."""
    with tempfile.TemporaryDirectory() as temp_dir:
        yield Path(temp_dir)


@pytest.fixture
def multiple_sessions(sample_http_headers: HTTPHeaders) -> List[StreamSession]:
    """Multiple stream sessions for comparison testing."""
    sessions = []
    base_time = datetime.now()

    for session_id in range(3):
        chunks = []
        for i in range(5):
            chunk = StreamChunk(
                timestamp=base_time
                + timedelta(milliseconds=session_id * 1000 + i * 200),
                sequence_number=i,
                size_bytes=40 + i * 5,
                content=f'{{"session": {session_id}, "chunk": {i}}}',
                event_type="data",
                is_first_token=(i == 0),
                is_last_token=(i == 4),
            )
            chunks.append(chunk)

        session = StreamSession(
            session_id=f"test_session_{session_id:03d}",
            source_ip="192.168.1.100",
            dest_ip="10.0.0.1",
            source_port=54321 + session_id,
            dest_port=443,
            protocol_version=ProtocolVersion.HTTP_1_1,
            connection_start=base_time + timedelta(milliseconds=session_id * 1000),
            request_sent=base_time + timedelta(milliseconds=session_id * 1000 + 10),
            response_start=base_time + timedelta(milliseconds=session_id * 1000 + 50),
            first_chunk=chunks[0].timestamp,
            last_chunk=chunks[-1].timestamp,
            connection_end=base_time + timedelta(milliseconds=session_id * 1000 + 1200),
            request_method="POST",
            request_path="/v1/chat/completions",
            request_headers=sample_http_headers,
            response_status=200,
            response_headers=sample_http_headers,
            chunks=chunks,
            total_bytes=sum(chunk.size_bytes for chunk in chunks),
        )
        sessions.append(session)

    return sessions


# Pytest configuration
def pytest_configure(config):
    """Configure pytest with custom markers."""
    config.addinivalue_line("markers", "unit: marks tests as unit tests")
    config.addinivalue_line("markers", "integration: marks tests as integration tests")
    config.addinivalue_line("markers", "slow: marks tests as slow running")
