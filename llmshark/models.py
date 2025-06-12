"""
Data models for LLM streaming analysis using Pydantic.

This module defines all the core data structures used throughout the application,
including stream sessions, chunks, timing statistics, and analysis results.
"""

from __future__ import annotations

from datetime import datetime
from enum import Enum
from pathlib import Path
from typing import Any

from pydantic import BaseModel, Field, computed_field, validator


class EventType(str, Enum):
    """Types of HTTP/SSE events."""

    HTTP_REQUEST = "http_request"
    HTTP_RESPONSE = "http_response"
    SSE_CHUNK = "sse_chunk"
    CONNECTION_START = "connection_start"
    CONNECTION_END = "connection_end"


class CompressionType(str, Enum):
    """HTTP compression types."""

    NONE = "none"
    GZIP = "gzip"
    DEFLATE = "deflate"
    BROTLI = "br"


class ProtocolVersion(str, Enum):
    """HTTP protocol versions."""

    HTTP_1_0 = "HTTP/1.0"
    HTTP_1_1 = "HTTP/1.1"
    HTTP_2 = "HTTP/2"
    HTTP_3 = "HTTP/3"


class StreamChunk(BaseModel):
    """Represents a single chunk of data in an SSE stream."""

    timestamp: datetime = Field(description="When the chunk was received")
    sequence_number: int = Field(description="Order of this chunk in the stream")
    size_bytes: int = Field(ge=0, description="Size of the chunk in bytes")
    content: str = Field(description="Raw content of the chunk")
    event_type: str | None = Field(None, description="SSE event type if specified")
    event_id: str | None = Field(None, description="SSE event ID if specified")
    is_first_token: bool = Field(False, description="Whether this is the first token")
    is_last_token: bool = Field(False, description="Whether this is the last token")
    parse_errors: list[str] = Field(
        default_factory=list, description="Any parsing errors"
    )

    @computed_field
    @property
    def tokens_extracted(self) -> list[str]:
        """Extract tokens from the chunk content."""
        # Simple token extraction - can be enhanced based on LLM format
        return self.content.split() if self.content else []

    @computed_field
    @property
    def token_count(self) -> int:
        """Number of tokens in this chunk."""
        return len(self.tokens_extracted)


class HTTPHeaders(BaseModel):
    """HTTP headers with common fields extracted."""

    content_type: str | None = Field(None, description="Content-Type header")
    content_length: int | None = Field(None, description="Content-Length header")
    transfer_encoding: str | None = Field(
        None, description="Transfer-Encoding header"
    )
    content_encoding: str | None = Field(None, description="Content-Encoding header")
    cache_control: str | None = Field(None, description="Cache-Control header")
    connection: str | None = Field(None, description="Connection header")
    user_agent: str | None = Field(None, description="User-Agent header")
    server: str | None = Field(None, description="Server header")
    raw_headers: dict[str, str] = Field(default_factory=dict, description="All headers")

    @computed_field
    @property
    def compression_type(self) -> CompressionType:
        """Detected compression type."""
        encoding = (self.content_encoding or "").lower()
        if "gzip" in encoding:
            return CompressionType.GZIP
        elif "deflate" in encoding:
            return CompressionType.DEFLATE
        elif "br" in encoding:
            return CompressionType.BROTLI
        return CompressionType.NONE


class StreamSession(BaseModel):
    """Represents a complete HTTP streaming session."""

    session_id: str = Field(description="Unique identifier for this session")
    source_ip: str = Field(description="Client IP address")
    dest_ip: str = Field(description="Server IP address")
    source_port: int = Field(ge=1, le=65535, description="Client port")
    dest_port: int = Field(ge=1, le=65535, description="Server port")
    protocol_version: ProtocolVersion = Field(description="HTTP protocol version")

    # Timing information
    connection_start: datetime = Field(
        description="When the connection was established"
    )
    request_sent: datetime = Field(description="When the HTTP request was sent")
    response_start: datetime = Field(description="When the response started")
    first_chunk: datetime | None = Field(
        None, description="When the first chunk arrived"
    )
    last_chunk: datetime | None = Field(
        None, description="When the last chunk arrived"
    )
    connection_end: datetime | None = Field(
        None, description="When connection closed"
    )

    # HTTP details
    request_method: str = Field(description="HTTP method (GET, POST, etc.)")
    request_path: str = Field(description="Request path/URL")
    request_headers: HTTPHeaders = Field(description="Request headers")
    response_status: int = Field(
        ge=100, le=599, description="HTTP response status code"
    )
    response_headers: HTTPHeaders = Field(description="Response headers")

    # Stream data
    chunks: list[StreamChunk] = Field(
        default_factory=list, description="All chunks in order"
    )
    total_bytes: int = Field(0, ge=0, description="Total bytes received")

    # Metadata
    capture_file: Path | None = Field(None, description="Source PCAP file")
    analysis_timestamp: datetime = Field(default_factory=datetime.now)

    @computed_field
    @property
    def duration_seconds(self) -> float | None:
        """Total session duration in seconds."""
        if self.connection_end:
            return (self.connection_end - self.connection_start).total_seconds()
        elif self.last_chunk:
            return (self.last_chunk - self.connection_start).total_seconds()
        return None

    @computed_field
    @property
    def streaming_duration_seconds(self) -> float | None:
        """Duration of the streaming portion in seconds."""
        if self.first_chunk and self.last_chunk:
            return (self.last_chunk - self.first_chunk).total_seconds()
        return None

    @computed_field
    @property
    def total_tokens(self) -> int:
        """Total number of tokens across all chunks."""
        return sum(chunk.token_count for chunk in self.chunks)

    @computed_field
    @property
    def chunk_count(self) -> int:
        """Number of chunks in this session."""
        return len(self.chunks)


class TimingStats(BaseModel):
    """Statistical analysis of timing data."""

    # Time to First Token (TTFT)
    ttft_seconds: float | None = Field(
        None, description="Time to first token in seconds"
    )
    ttft_ms: float | None = Field(
        None, description="Time to first token in milliseconds"
    )

    # Inter-Token Latency (ITL)
    mean_itl_ms: float | None = Field(
        None, description="Mean inter-token latency in ms"
    )
    median_itl_ms: float | None = Field(
        None, description="Median inter-token latency in ms"
    )
    p95_itl_ms: float | None = Field(None, description="95th percentile ITL in ms")
    p99_itl_ms: float | None = Field(None, description="99th percentile ITL in ms")
    std_itl_ms: float | None = Field(
        None, description="Standard deviation of ITL in ms"
    )
    min_itl_ms: float | None = Field(None, description="Minimum ITL in ms")
    max_itl_ms: float | None = Field(None, description="Maximum ITL in ms")

    # Chunk timing
    mean_chunk_interval_ms: float | None = Field(
        None, description="Mean time between chunks"
    )
    median_chunk_interval_ms: float | None = Field(
        None, description="Median time between chunks"
    )

    # Throughput
    tokens_per_second: float | None = Field(
        None, description="Overall tokens per second"
    )
    bytes_per_second: float | None = Field(
        None, description="Overall bytes per second"
    )

    # Raw timing arrays for detailed analysis
    itl_values_ms: list[float] = Field(
        default_factory=list, description="All ITL values"
    )
    chunk_intervals_ms: list[float] = Field(
        default_factory=list, description="Chunk intervals"
    )

    @validator("ttft_ms", pre=True)
    def compute_ttft_ms(
        cls, v: float | None, values: dict[str, Any]
    ) -> float | None:
        """Compute TTFT in milliseconds from seconds."""
        ttft_seconds = values.get("ttft_seconds")
        if ttft_seconds is not None:
            return ttft_seconds * 1000
        return v


class AnomalyDetection(BaseModel):
    """Results of anomaly detection analysis."""

    large_gaps: list[dict[str, Any]] = Field(
        default_factory=list, description="Detected large gaps"
    )
    outlier_chunks: list[int] = Field(
        default_factory=list, description="Chunk indices with outlier timing"
    )
    unusual_patterns: list[str] = Field(
        default_factory=list, description="Detected unusual patterns"
    )
    silence_periods: list[dict[str, Any]] = Field(
        default_factory=list, description="Periods with no activity"
    )

    # Thresholds used for detection
    gap_threshold_ms: float = Field(
        5000.0, description="Threshold for large gap detection"
    )
    outlier_threshold_std: float = Field(
        3.0, description="Standard deviations for outlier detection"
    )


class SessionComparison(BaseModel):
    """Comparison results between sessions."""

    session_a_id: str = Field(description="ID of first session")
    session_b_id: str = Field(description="ID of second session")

    # Timing comparisons
    ttft_diff_ms: float | None = Field(
        None, description="TTFT difference in ms (B - A)"
    )
    ttft_diff_percent: float | None = Field(
        None, description="TTFT difference as percentage"
    )

    mean_itl_diff_ms: float | None = Field(
        None, description="Mean ITL difference in ms"
    )
    mean_itl_diff_percent: float | None = Field(
        None, description="Mean ITL difference as percentage"
    )

    # Statistical tests
    itl_statistical_significance: bool | None = Field(
        None, description="Whether ITL difference is significant"
    )
    p_value: float | None = Field(None, description="P-value of statistical test")

    # Pattern differences
    pattern_differences: list[str] = Field(
        default_factory=list, description="Detected pattern differences"
    )

    # Quality assessment
    which_session_better: str | None = Field(
        None, description="Which session performed better"
    )
    improvement_suggestions: list[str] = Field(
        default_factory=list, description="Suggestions for improvement"
    )


class AnalysisResult(BaseModel):
    """Complete analysis results for one or more PCAP files."""

    # Input information
    input_files: list[Path] = Field(description="PCAP files analyzed")
    analysis_timestamp: datetime = Field(default_factory=datetime.now)
    analysis_duration_seconds: float = Field(description="How long the analysis took")

    # Sessions found
    sessions: list[StreamSession] = Field(description="All streaming sessions found")
    session_count: int = Field(description="Total number of sessions")

    # Aggregate statistics
    total_bytes_analyzed: int = Field(0, description="Total bytes across all sessions")
    total_tokens_analyzed: int = Field(
        0, description="Total tokens across all sessions"
    )
    total_duration_seconds: float = Field(
        0.0, description="Total duration of all sessions"
    )

    # Timing analysis
    overall_timing_stats: TimingStats = Field(description="Aggregate timing statistics")
    per_session_timing: dict[str, TimingStats] = Field(default_factory=dict)

    # Anomaly detection
    anomalies: AnomalyDetection = Field(description="Detected anomalies")

    # Comparisons (if multiple sessions)
    session_comparisons: list[SessionComparison] = Field(default_factory=list)

    # Quality metrics
    best_session_id: str | None = Field(
        None, description="ID of best performing session"
    )
    worst_session_id: str | None = Field(
        None, description="ID of worst performing session"
    )

    # Summary insights
    key_insights: list[str] = Field(
        default_factory=list, description="Key insights from analysis"
    )
    recommendations: list[str] = Field(
        default_factory=list, description="Recommendations"
    )

    @computed_field
    @property
    def average_tokens_per_second(self) -> float | None:
        """Average tokens per second across all sessions."""
        if self.total_duration_seconds > 0 and self.total_tokens_analyzed > 0:
            return self.total_tokens_analyzed / self.total_duration_seconds
        return None

    @computed_field
    @property
    def sessions_by_performance(self) -> list[str]:
        """Session IDs ordered by performance (best first)."""
        session_scores = []
        for session in self.sessions:
            timing = self.per_session_timing.get(session.session_id)
            if (
                timing
                and timing.ttft_seconds is not None
                and timing.mean_itl_ms is not None
            ):
                # Lower TTFT and ITL = better performance
                score = timing.ttft_seconds + (timing.mean_itl_ms / 1000)
                session_scores.append((session.session_id, score))

        # Sort by score (lower is better)
        session_scores.sort(key=lambda x: x[1])
        return [session_id for session_id, _ in session_scores]


class ComparisonReport(BaseModel):
    """Comprehensive comparison report for multiple captures."""

    captures: list[AnalysisResult] = Field(
        description="Analysis results for each capture"
    )
    comparison_timestamp: datetime = Field(default_factory=datetime.now)

    # Cross-capture statistics
    best_capture_index: int | None = Field(
        None, description="Index of best performing capture"
    )
    performance_rankings: list[int] = Field(
        default_factory=list, description="Capture indices by performance"
    )

    # Aggregate insights
    common_patterns: list[str] = Field(
        default_factory=list, description="Patterns common across captures"
    )
    unique_patterns: dict[int, list[str]] = Field(
        default_factory=dict, description="Unique patterns per capture"
    )

    improvement_opportunities: list[str] = Field(
        default_factory=list, description="Areas for improvement"
    )

    # Statistical summary
    performance_variance: float | None = Field(
        None, description="Variance in performance across captures"
    )
    consistency_score: float | None = Field(
        None, description="How consistent performance was (0-1)"
    )
