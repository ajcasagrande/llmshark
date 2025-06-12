"""
Unit tests for LLMShark models.
"""

import pytest
from datetime import datetime, timedelta
from typing import List

from llmshark.models import (
    CompressionType,
    EventType,
    HTTPHeaders,
    ProtocolVersion,
    StreamChunk,
    StreamSession,
    TimingStats,
    AnalysisResult,
    AnomalyDetection,
    SessionComparison,
    ComparisonReport,
)


@pytest.mark.unit
class TestStreamChunk:
    """Test StreamChunk model."""

    def test_create_basic_chunk(self):
        """Test creating a basic chunk."""
        timestamp = datetime.now()
        chunk = StreamChunk(
            timestamp=timestamp,
            sequence_number=1,
            size_bytes=100,
            content='{"data": "test"}',
        )

        assert chunk.timestamp == timestamp
        assert chunk.sequence_number == 1
        assert chunk.size_bytes == 100
        assert chunk.content == '{"data": "test"}'
        assert chunk.event_type is None
        assert chunk.event_id is None
        assert not chunk.is_first_token
        assert not chunk.is_last_token
        assert chunk.parse_errors == []

    def test_tokens_extracted(self):
        """Test token extraction from chunk content."""
        chunk = StreamChunk(
            timestamp=datetime.now(),
            sequence_number=1,
            size_bytes=20,
            content="hello world test",
        )

        assert chunk.tokens_extracted == ["hello", "world", "test"]
        assert chunk.token_count == 3

    def test_empty_content_tokens(self):
        """Test token extraction with empty content."""
        chunk = StreamChunk(
            timestamp=datetime.now(),
            sequence_number=1,
            size_bytes=0,
            content="",
        )

        assert chunk.tokens_extracted == []
        assert chunk.token_count == 0

    def test_chunk_with_parse_errors(self):
        """Test chunk with parse errors."""
        chunk = StreamChunk(
            timestamp=datetime.now(),
            sequence_number=1,
            size_bytes=10,
            content="invalid",
            parse_errors=["JSON decode error"],
        )

        assert len(chunk.parse_errors) == 1
        assert "JSON decode error" in chunk.parse_errors


@pytest.mark.unit
class TestHTTPHeaders:
    """Test HTTPHeaders model."""

    def test_create_headers(self):
        """Test creating HTTP headers."""
        headers = HTTPHeaders(
            content_type="application/json",
            content_length=1024,
            transfer_encoding="chunked",
            raw_headers={"Custom-Header": "value"},
        )

        assert headers.content_type == "application/json"
        assert headers.content_length == 1024
        assert headers.transfer_encoding == "chunked"
        assert headers.raw_headers["Custom-Header"] == "value"

    def test_compression_type_detection(self):
        """Test compression type detection."""
        # No compression
        headers = HTTPHeaders()
        assert headers.compression_type == CompressionType.NONE

        # GZIP compression
        headers = HTTPHeaders(content_encoding="gzip")
        assert headers.compression_type == CompressionType.GZIP

        # Deflate compression
        headers = HTTPHeaders(content_encoding="deflate")
        assert headers.compression_type == CompressionType.DEFLATE

        # Brotli compression
        headers = HTTPHeaders(content_encoding="br")
        assert headers.compression_type == CompressionType.BROTLI

    def test_case_insensitive_compression(self):
        """Test case-insensitive compression detection."""
        headers = HTTPHeaders(content_encoding="GZIP")
        assert headers.compression_type == CompressionType.GZIP


@pytest.mark.unit
class TestStreamSession:
    """Test StreamSession model."""

    def test_create_session(self, sample_stream_session: StreamSession):
        """Test creating a stream session."""
        session = sample_stream_session

        assert session.session_id == "test_session_001"
        assert session.source_ip == "192.168.1.100"
        assert session.dest_ip == "10.0.0.1"
        assert session.source_port == 54321
        assert session.dest_port == 443
        assert session.protocol_version == ProtocolVersion.HTTP_1_1
        assert session.request_method == "POST"
        assert session.request_path == "/v1/chat/completions"
        assert session.response_status == 200
        assert len(session.chunks) == 10
        assert session.total_bytes > 0

    def test_duration_calculation(self, sample_stream_session: StreamSession):
        """Test session duration calculation."""
        session = sample_stream_session
        duration = session.duration_seconds

        assert duration is not None
        assert duration > 0
        assert duration < 10  # Should be a few seconds

    def test_streaming_duration(self, sample_stream_session: StreamSession):
        """Test streaming duration calculation."""
        session = sample_stream_session
        streaming_duration = session.streaming_duration_seconds

        assert streaming_duration is not None
        assert streaming_duration > 0
        assert streaming_duration < session.duration_seconds

    def test_total_tokens(self, sample_stream_session: StreamSession):
        """Test total tokens calculation."""
        session = sample_stream_session

        # Each chunk has content like '{"chunk": 0, "data": "token_0"}'
        # which should extract several tokens
        assert session.total_tokens > 0
        assert session.chunk_count == 10

    def test_session_without_chunks(self):
        """Test session without chunks."""
        session = StreamSession(
            session_id="empty",
            source_ip="127.0.0.1",
            dest_ip="127.0.0.1",
            source_port=8080,
            dest_port=80,
            protocol_version=ProtocolVersion.HTTP_1_1,
            connection_start=datetime.now(),
            request_sent=datetime.now(),
            response_start=datetime.now(),
            request_method="GET",
            request_path="/",
            request_headers=HTTPHeaders(),
            response_status=200,
            response_headers=HTTPHeaders(),
        )

        assert session.total_tokens == 0
        assert session.chunk_count == 0
        assert session.streaming_duration_seconds is None


@pytest.mark.unit
class TestTimingStats:
    """Test TimingStats model."""

    def test_create_timing_stats(self, sample_timing_stats: TimingStats):
        """Test creating timing statistics."""
        stats = sample_timing_stats

        assert stats.ttft_seconds == 0.5
        assert stats.ttft_ms == 500.0
        assert stats.mean_itl_ms == 71.1
        assert stats.median_itl_ms == 70.0
        assert stats.p95_itl_ms == 88.0
        assert stats.p99_itl_ms == 89.5
        assert stats.std_itl_ms == 13.6
        assert stats.min_itl_ms == 50.0
        assert stats.max_itl_ms == 90.0
        assert len(stats.itl_values_ms) == 9

    def test_ttft_ms_computed_from_seconds(self):
        """Test TTFT ms computation from seconds."""
        stats = TimingStats(ttft_seconds=1.5)
        assert stats.ttft_ms == 1500.0

    def test_empty_timing_stats(self):
        """Test empty timing statistics."""
        stats = TimingStats()

        assert stats.ttft_seconds is None
        assert stats.ttft_ms is None
        assert stats.mean_itl_ms is None
        assert stats.tokens_per_second is None
        assert stats.itl_values_ms == []


@pytest.mark.unit
class TestAnalysisResult:
    """Test AnalysisResult model."""

    def test_create_analysis_result(self, multiple_sessions: List[StreamSession]):
        """Test creating analysis result."""
        result = AnalysisResult(
            input_files=[],
            analysis_duration_seconds=1.5,
            sessions=multiple_sessions,
            session_count=len(multiple_sessions),
            total_bytes_analyzed=1000,
            total_tokens_analyzed=500,
            total_duration_seconds=10.0,
            overall_timing_stats=TimingStats(),
        )

        assert result.session_count == 3
        assert result.total_bytes_analyzed == 1000
        assert result.total_tokens_analyzed == 500
        assert result.analysis_duration_seconds == 1.5
        assert len(result.sessions) == 3

    def test_average_tokens_per_second(self):
        """Test average tokens per second calculation."""
        result = AnalysisResult(
            input_files=[],
            analysis_duration_seconds=1.0,
            sessions=[],
            session_count=0,
            total_bytes_analyzed=0,
            total_tokens_analyzed=1000,
            total_duration_seconds=10.0,
            overall_timing_stats=TimingStats(),
        )

        assert result.average_tokens_per_second == 100.0

    def test_sessions_by_performance_empty(self):
        """Test sessions by performance with empty data."""
        result = AnalysisResult(
            input_files=[],
            analysis_duration_seconds=1.0,
            sessions=[],
            session_count=0,
            overall_timing_stats=TimingStats(),
        )

        assert result.sessions_by_performance == []


@pytest.mark.unit
class TestAnomalyDetection:
    """Test AnomalyDetection model."""

    def test_create_anomaly_detection(self):
        """Test creating anomaly detection result."""
        anomalies = AnomalyDetection(
            large_gaps=[{"session_id": "test", "gap_ms": 5000}],
            outlier_chunks=[1, 5, 9],
            unusual_patterns=["High variance detected"],
            silence_periods=[{"duration_ms": 3000}],
            gap_threshold_ms=4000.0,
            outlier_threshold_std=2.5,
        )

        assert len(anomalies.large_gaps) == 1
        assert len(anomalies.outlier_chunks) == 3
        assert len(anomalies.unusual_patterns) == 1
        assert len(anomalies.silence_periods) == 1
        assert anomalies.gap_threshold_ms == 4000.0
        assert anomalies.outlier_threshold_std == 2.5

    def test_default_anomaly_detection(self):
        """Test default anomaly detection values."""
        anomalies = AnomalyDetection()

        assert anomalies.large_gaps == []
        assert anomalies.outlier_chunks == []
        assert anomalies.unusual_patterns == []
        assert anomalies.silence_periods == []
        assert anomalies.gap_threshold_ms == 5000.0
        assert anomalies.outlier_threshold_std == 3.0


@pytest.mark.unit
class TestSessionComparison:
    """Test SessionComparison model."""

    def test_create_session_comparison(self):
        """Test creating session comparison."""
        comparison = SessionComparison(
            session_a_id="session_a",
            session_b_id="session_b",
            ttft_diff_ms=100.0,
            ttft_diff_percent=20.0,
            mean_itl_diff_ms=15.0,
            mean_itl_diff_percent=10.0,
            itl_statistical_significance=True,
            p_value=0.01,
            which_session_better="session_a",
        )

        assert comparison.session_a_id == "session_a"
        assert comparison.session_b_id == "session_b"
        assert comparison.ttft_diff_ms == 100.0
        assert comparison.ttft_diff_percent == 20.0
        assert comparison.mean_itl_diff_ms == 15.0
        assert comparison.mean_itl_diff_percent == 10.0
        assert comparison.itl_statistical_significance is True
        assert comparison.p_value == 0.01
        assert comparison.which_session_better == "session_a"

    def test_empty_session_comparison(self):
        """Test empty session comparison."""
        comparison = SessionComparison(
            session_a_id="a",
            session_b_id="b",
        )

        assert comparison.ttft_diff_ms is None
        assert comparison.mean_itl_diff_ms is None
        assert comparison.itl_statistical_significance is None
        assert comparison.which_session_better is None
        assert comparison.pattern_differences == []
        assert comparison.improvement_suggestions == []


@pytest.mark.unit
class TestComparisonReport:
    """Test ComparisonReport model."""

    def test_create_comparison_report(self):
        """Test creating comparison report."""
        # Create mock analysis results
        result1 = AnalysisResult(
            input_files=[],
            analysis_duration_seconds=1.0,
            sessions=[],
            session_count=1,
            overall_timing_stats=TimingStats(),
        )

        result2 = AnalysisResult(
            input_files=[],
            analysis_duration_seconds=2.0,
            sessions=[],
            session_count=2,
            overall_timing_stats=TimingStats(),
        )

        report = ComparisonReport(
            captures=[result1, result2],
            best_capture_index=0,
            performance_rankings=[0, 1],
            common_patterns=["Both show good performance"],
            improvement_opportunities=["Reduce latency"],
            performance_variance=0.1,
            consistency_score=0.85,
        )

        assert len(report.captures) == 2
        assert report.best_capture_index == 0
        assert report.performance_rankings == [0, 1]
        assert len(report.common_patterns) == 1
        assert len(report.improvement_opportunities) == 1
        assert report.performance_variance == 0.1
        assert report.consistency_score == 0.85

    def test_comparison_report_defaults(self):
        """Test comparison report with default values."""
        report = ComparisonReport(captures=[])

        assert report.captures == []
        assert report.best_capture_index is None
        assert report.performance_rankings == []
        assert report.common_patterns == []
        assert report.unique_patterns == {}
        assert report.improvement_opportunities == []
        assert report.performance_variance is None
        assert report.consistency_score is None


@pytest.mark.unit
class TestEnums:
    """Test enum classes."""

    def test_event_type_enum(self):
        """Test EventType enum."""
        assert EventType.HTTP_REQUEST == "http_request"
        assert EventType.SSE_CHUNK == "sse_chunk"
        assert EventType.CONNECTION_START == "connection_start"

    def test_compression_type_enum(self):
        """Test CompressionType enum."""
        assert CompressionType.NONE == "none"
        assert CompressionType.GZIP == "gzip"
        assert CompressionType.DEFLATE == "deflate"
        assert CompressionType.BROTLI == "br"

    def test_protocol_version_enum(self):
        """Test ProtocolVersion enum."""
        assert ProtocolVersion.HTTP_1_0 == "HTTP/1.0"
        assert ProtocolVersion.HTTP_1_1 == "HTTP/1.1"
        assert ProtocolVersion.HTTP_2 == "HTTP/2"
        assert ProtocolVersion.HTTP_3 == "HTTP/3"


@pytest.mark.unit
class TestModelValidation:
    """Test model validation rules."""

    def test_stream_chunk_validation(self):
        """Test StreamChunk validation."""
        # Valid chunk
        chunk = StreamChunk(
            timestamp=datetime.now(),
            sequence_number=0,
            size_bytes=100,
            content="test",
        )
        assert chunk.size_bytes == 100

        # Test negative size_bytes should be caught by Pydantic
        with pytest.raises(ValueError):
            StreamChunk(
                timestamp=datetime.now(),
                sequence_number=0,
                size_bytes=-1,
                content="test",
            )

    def test_stream_session_port_validation(self):
        """Test StreamSession port validation."""
        # Valid ports
        session = StreamSession(
            session_id="test",
            source_ip="127.0.0.1",
            dest_ip="127.0.0.1",
            source_port=8080,
            dest_port=80,
            protocol_version=ProtocolVersion.HTTP_1_1,
            connection_start=datetime.now(),
            request_sent=datetime.now(),
            response_start=datetime.now(),
            request_method="GET",
            request_path="/",
            request_headers=HTTPHeaders(),
            response_status=200,
            response_headers=HTTPHeaders(),
        )
        assert session.source_port == 8080
        assert session.dest_port == 80

        # Invalid port (too high)
        with pytest.raises(ValueError):
            StreamSession(
                session_id="test",
                source_ip="127.0.0.1",
                dest_ip="127.0.0.1",
                source_port=99999,  # Too high
                dest_port=80,
                protocol_version=ProtocolVersion.HTTP_1_1,
                connection_start=datetime.now(),
                request_sent=datetime.now(),
                response_start=datetime.now(),
                request_method="GET",
                request_path="/",
                request_headers=HTTPHeaders(),
                response_status=200,
                response_headers=HTTPHeaders(),
            )

    def test_response_status_validation(self):
        """Test HTTP response status validation."""
        # Valid status codes
        for status in [200, 404, 500]:
            session = StreamSession(
                session_id="test",
                source_ip="127.0.0.1",
                dest_ip="127.0.0.1",
                source_port=8080,
                dest_port=80,
                protocol_version=ProtocolVersion.HTTP_1_1,
                connection_start=datetime.now(),
                request_sent=datetime.now(),
                response_start=datetime.now(),
                request_method="GET",
                request_path="/",
                request_headers=HTTPHeaders(),
                response_status=status,
                response_headers=HTTPHeaders(),
            )
            assert session.response_status == status

        # Invalid status code
        with pytest.raises(ValueError):
            StreamSession(
                session_id="test",
                source_ip="127.0.0.1",
                dest_ip="127.0.0.1",
                source_port=8080,
                dest_port=80,
                protocol_version=ProtocolVersion.HTTP_1_1,
                connection_start=datetime.now(),
                request_sent=datetime.now(),
                response_start=datetime.now(),
                request_method="GET",
                request_path="/",
                request_headers=HTTPHeaders(),
                response_status=999,  # Invalid
                response_headers=HTTPHeaders(),
            )
