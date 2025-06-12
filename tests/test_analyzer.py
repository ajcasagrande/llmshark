"""
Unit tests for LLMShark stream analyzer.
"""

import pytest
from datetime import datetime, timedelta
from typing import List

from llmshark.analyzer import StreamAnalyzer
from llmshark.models import StreamSession, TimingStats, AnalysisResult


@pytest.mark.unit
class TestStreamAnalyzer:
    """Test StreamAnalyzer functionality."""

    def test_analyze_empty_sessions(self):
        """Test analyzing empty session list."""
        analyzer = StreamAnalyzer()
        result = analyzer.analyze_sessions([])

        assert result.session_count == 0
        assert result.total_tokens_analyzed == 0
        assert result.total_bytes_analyzed == 0
        assert len(result.key_insights) > 0
        assert "No streaming sessions found" in result.key_insights[0]

    def test_analyze_single_session(self, sample_stream_session: StreamSession):
        """Test analyzing a single session."""
        analyzer = StreamAnalyzer()
        result = analyzer.analyze_sessions([sample_stream_session])

        assert result.session_count == 1
        assert result.total_tokens_analyzed > 0
        assert result.total_bytes_analyzed > 0
        assert len(result.sessions) == 1
        assert sample_stream_session.session_id in result.per_session_timing

        # Check timing stats were calculated
        timing = result.per_session_timing[sample_stream_session.session_id]
        assert timing.ttft_ms is not None
        assert timing.mean_itl_ms is not None

    def test_analyze_multiple_sessions(self, multiple_sessions: List[StreamSession]):
        """Test analyzing multiple sessions."""
        analyzer = StreamAnalyzer()
        result = analyzer.analyze_sessions(multiple_sessions)

        assert result.session_count == 3
        assert len(result.sessions) == 3
        assert len(result.per_session_timing) == 3

        # Should have overall timing stats
        assert result.overall_timing_stats.ttft_ms is not None
        assert result.overall_timing_stats.mean_itl_ms is not None

    def test_anomaly_detection_enabled(self, sample_stream_session: StreamSession):
        """Test analysis with anomaly detection enabled."""
        analyzer = StreamAnalyzer()
        result = analyzer.analyze_sessions(
            [sample_stream_session], detect_anomalies=True
        )

        # Should have anomaly detection results (even if empty)
        assert result.anomalies is not None
        assert hasattr(result.anomalies, "large_gaps")
        assert hasattr(result.anomalies, "silence_periods")
        assert hasattr(result.anomalies, "unusual_patterns")

    def test_anomaly_detection_disabled(self, sample_stream_session: StreamSession):
        """Test analysis with anomaly detection disabled."""
        analyzer = StreamAnalyzer()
        result = analyzer.analyze_sessions(
            [sample_stream_session], detect_anomalies=False
        )

        # Should still have anomaly object but with default values
        assert result.anomalies is not None
        assert len(result.anomalies.large_gaps) == 0
        assert len(result.anomalies.silence_periods) == 0
        assert len(result.anomalies.unusual_patterns) == 0

    def test_session_ranking(self, multiple_sessions: List[StreamSession]):
        """Test session ranking functionality."""
        analyzer = StreamAnalyzer()
        result = analyzer.analyze_sessions(multiple_sessions)

        assert result.best_session_id is not None
        assert result.worst_session_id is not None
        assert result.best_session_id != result.worst_session_id

        # Best session should be in our sessions
        best_session_ids = [s.session_id for s in result.sessions]
        assert result.best_session_id in best_session_ids
        assert result.worst_session_id in best_session_ids

    def test_insights_generation(self, sample_stream_session: StreamSession):
        """Test that insights are generated."""
        analyzer = StreamAnalyzer()
        result = analyzer.analyze_sessions([sample_stream_session])

        assert len(result.key_insights) > 0
        assert len(result.recommendations) > 0

        # Check for expected insight patterns
        insights_text = " ".join(result.key_insights)
        assert "session" in insights_text.lower()
        assert "token" in insights_text.lower()

    def test_timing_calculation_accuracy(self, sample_stream_session: StreamSession):
        """Test accuracy of timing calculations."""
        analyzer = StreamAnalyzer()
        result = analyzer.analyze_sessions([sample_stream_session])

        session_timing = result.per_session_timing[sample_stream_session.session_id]

        # TTFT should be positive and reasonable
        assert session_timing.ttft_ms > 0
        assert session_timing.ttft_ms < 10000  # Less than 10 seconds

        # ITL should be positive and reasonable
        assert session_timing.mean_itl_ms > 0
        assert session_timing.mean_itl_ms < 5000  # Less than 5 seconds

        # Check that percentiles are ordered correctly
        assert session_timing.min_itl_ms <= session_timing.median_itl_ms
        assert session_timing.median_itl_ms <= session_timing.p95_itl_ms
        assert session_timing.p95_itl_ms <= session_timing.p99_itl_ms
        assert session_timing.p99_itl_ms <= session_timing.max_itl_ms

    def test_throughput_calculation(self, sample_stream_session: StreamSession):
        """Test throughput calculations."""
        analyzer = StreamAnalyzer()
        result = analyzer.analyze_sessions([sample_stream_session])

        session_timing = result.per_session_timing[sample_stream_session.session_id]

        # Should have positive throughput
        assert session_timing.tokens_per_second > 0
        assert session_timing.bytes_per_second > 0

        # Tokens per second should be reasonable for LLM streaming
        assert session_timing.tokens_per_second < 1000  # Very fast would be < 1000 tps

    def test_aggregate_timing_calculation(self, multiple_sessions: List[StreamSession]):
        """Test aggregate timing calculations across sessions."""
        analyzer = StreamAnalyzer()
        result = analyzer.analyze_sessions(multiple_sessions)

        overall = result.overall_timing_stats

        # Should have aggregate values
        assert overall.ttft_ms is not None
        assert overall.mean_itl_ms is not None
        assert overall.median_itl_ms is not None

        # Overall ITL values should include all sessions
        total_expected_itl_values = sum(
            len(timing.itl_values_ms)
            for timing in result.per_session_timing.values()
            if timing.itl_values_ms
        )
        assert len(overall.itl_values_ms) == total_expected_itl_values


@pytest.mark.unit
class TestAnalyzerAnomalyDetection:
    """Test anomaly detection functionality."""

    def test_large_gap_detection(self):
        """Test detection of large gaps between chunks."""
        # Create session with large gap
        base_time = datetime.now()
        chunks = []

        # Normal chunks
        for i in range(3):
            from llmshark.models import StreamChunk

            chunk = StreamChunk(
                timestamp=base_time + timedelta(milliseconds=i * 100),
                sequence_number=i,
                size_bytes=50,
                content=f"chunk {i}",
            )
            chunks.append(chunk)

        # Add chunk with large gap (10 seconds later)
        large_gap_chunk = StreamChunk(
            timestamp=base_time + timedelta(seconds=10),
            sequence_number=3,
            size_bytes=50,
            content="delayed chunk",
        )
        chunks.append(large_gap_chunk)

        # Create session
        from llmshark.models import StreamSession, HTTPHeaders, ProtocolVersion

        session = StreamSession(
            session_id="gap_test",
            source_ip="127.0.0.1",
            dest_ip="127.0.0.1",
            source_port=8080,
            dest_port=80,
            protocol_version=ProtocolVersion.HTTP_1_1,
            connection_start=base_time,
            request_sent=base_time,
            response_start=base_time,
            request_method="GET",
            request_path="/",
            request_headers=HTTPHeaders(),
            response_status=200,
            response_headers=HTTPHeaders(),
            chunks=chunks,
        )

        analyzer = StreamAnalyzer()
        analyzer.gap_threshold_ms = 5000.0  # 5 second threshold
        result = analyzer.analyze_sessions([session], detect_anomalies=True)

        # Should detect the large gap
        assert len(result.anomalies.large_gaps) > 0
        assert result.anomalies.large_gaps[0]["gap_ms"] > 5000

    def test_silence_period_detection(self):
        """Test detection of silence periods."""
        # Create session with silence period
        base_time = datetime.now()
        chunks = []

        # First batch of chunks
        for i in range(2):
            from llmshark.models import StreamChunk

            chunk = StreamChunk(
                timestamp=base_time + timedelta(milliseconds=i * 100),
                sequence_number=i,
                size_bytes=50,
                content=f"chunk {i}",
            )
            chunks.append(chunk)

        # Add chunk after silence period
        silence_chunk = StreamChunk(
            timestamp=base_time + timedelta(seconds=3),  # 3 second gap
            sequence_number=2,
            size_bytes=50,
            content="after silence",
        )
        chunks.append(silence_chunk)

        # Create session
        from llmshark.models import StreamSession, HTTPHeaders, ProtocolVersion

        session = StreamSession(
            session_id="silence_test",
            source_ip="127.0.0.1",
            dest_ip="127.0.0.1",
            source_port=8080,
            dest_port=80,
            protocol_version=ProtocolVersion.HTTP_1_1,
            connection_start=base_time,
            request_sent=base_time,
            response_start=base_time,
            request_method="GET",
            request_path="/",
            request_headers=HTTPHeaders(),
            response_status=200,
            response_headers=HTTPHeaders(),
            chunks=chunks,
        )

        analyzer = StreamAnalyzer()
        analyzer.silence_threshold_ms = 2000.0  # 2 second threshold
        result = analyzer.analyze_sessions([session], detect_anomalies=True)

        # Should detect the silence period
        assert len(result.anomalies.silence_periods) > 0
        assert result.anomalies.silence_periods[0]["duration_ms"] > 2000

    def test_no_anomalies_in_normal_session(self, sample_stream_session: StreamSession):
        """Test that normal sessions don't trigger anomalies."""
        analyzer = StreamAnalyzer()
        # Set high thresholds so normal session won't trigger
        analyzer.gap_threshold_ms = 10000.0
        analyzer.silence_threshold_ms = 10000.0
        analyzer.anomaly_threshold_std = 5.0

        result = analyzer.analyze_sessions(
            [sample_stream_session], detect_anomalies=True
        )

        # Should not detect anomalies with high thresholds
        assert len(result.anomalies.large_gaps) == 0
        assert len(result.anomalies.silence_periods) == 0


@pytest.mark.unit
class TestAnalyzerConfiguration:
    """Test analyzer configuration options."""

    def test_custom_thresholds(self):
        """Test setting custom thresholds."""
        analyzer = StreamAnalyzer()

        # Set custom thresholds
        analyzer.anomaly_threshold_std = 2.5
        analyzer.gap_threshold_ms = 3000.0
        analyzer.silence_threshold_ms = 1500.0

        assert analyzer.anomaly_threshold_std == 2.5
        assert analyzer.gap_threshold_ms == 3000.0
        assert analyzer.silence_threshold_ms == 1500.0

    def test_analysis_timing(self, sample_stream_session: StreamSession):
        """Test that analysis timing is recorded."""
        analyzer = StreamAnalyzer()
        result = analyzer.analyze_sessions([sample_stream_session])

        assert result.analysis_duration_seconds > 0
        assert result.analysis_duration_seconds < 10  # Should be fast
