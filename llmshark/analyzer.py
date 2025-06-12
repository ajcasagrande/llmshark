"""
Stream analysis engine for LLM streaming traffic.

This module performs comprehensive analysis of HTTP/SSE streaming sessions,
calculating timing statistics, detecting anomalies, and generating insights.
"""

import json
import statistics
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Tuple

import numpy as np
from scipy import stats

from .models import (
    AnalysisResult,
    AnomalyDetection,
    StreamSession,
    TimingStats,
)


class StreamAnalyzer:
    """Main analyzer for streaming sessions."""

    def __init__(self) -> None:
        self.analysis_start_time: Optional[datetime] = None
        self.anomaly_threshold_std = 3.0
        self.gap_threshold_ms = 5000.0
        self.silence_threshold_ms = 2000.0

    def analyze_sessions(
        self, sessions: List[StreamSession], detect_anomalies: bool = True
    ) -> AnalysisResult:
        """Perform comprehensive analysis of streaming sessions."""
        self.analysis_start_time = datetime.now()

        if not sessions:
            return self._create_empty_result()

        # Calculate per-session timing statistics
        per_session_timing = {}
        for session in sessions:
            timing_stats = self._calculate_session_timing(session)
            per_session_timing[session.session_id] = timing_stats

        # Calculate overall timing statistics
        overall_timing = self._calculate_overall_timing(sessions, per_session_timing)

        # Detect anomalies if requested
        anomalies = AnomalyDetection()
        if detect_anomalies:
            anomalies = self._detect_anomalies(sessions, per_session_timing)

        # Generate insights and recommendations
        key_insights = self._generate_insights(sessions, per_session_timing, anomalies)
        recommendations = self._generate_recommendations(
            sessions, per_session_timing, anomalies
        )

        # Identify best and worst performing sessions
        best_session_id, worst_session_id = self._rank_sessions(
            sessions, per_session_timing
        )

        # Calculate aggregate statistics
        total_bytes = sum(session.total_bytes for session in sessions)
        total_tokens = sum(session.total_tokens for session in sessions)
        total_duration = sum(session.duration_seconds or 0.0 for session in sessions)

        analysis_duration = (datetime.now() - self.analysis_start_time).total_seconds()

        return AnalysisResult(
            input_files=[
                session.capture_file for session in sessions if session.capture_file
            ],
            analysis_duration_seconds=analysis_duration,
            sessions=sessions,
            session_count=len(sessions),
            total_bytes_analyzed=total_bytes,
            total_tokens_analyzed=total_tokens,
            total_duration_seconds=total_duration,
            overall_timing_stats=overall_timing,
            per_session_timing=per_session_timing,
            anomalies=anomalies,
            best_session_id=best_session_id,
            worst_session_id=worst_session_id,
            key_insights=key_insights,
            recommendations=recommendations,
        )

    def _create_empty_result(self) -> AnalysisResult:
        """Create an empty analysis result."""
        analysis_duration = 0.0
        if self.analysis_start_time:
            analysis_duration = (
                datetime.now() - self.analysis_start_time
            ).total_seconds()

        return AnalysisResult(
            input_files=[],
            analysis_duration_seconds=analysis_duration,
            sessions=[],
            session_count=0,
            overall_timing_stats=TimingStats(),
            key_insights=["No streaming sessions found in the provided PCAP files."],
            recommendations=["Ensure PCAP files contain HTTP/SSE streaming traffic."],
        )

    def _calculate_session_timing(self, session: StreamSession) -> TimingStats:
        """Calculate timing statistics for a single session."""
        timing_stats = TimingStats()

        if not session.chunks:
            return timing_stats

        # Calculate Time to First Token (TTFT)
        if session.response_start and session.first_chunk:
            ttft_seconds = (
                session.first_chunk - session.response_start
            ).total_seconds()
            timing_stats.ttft_seconds = ttft_seconds
            timing_stats.ttft_ms = ttft_seconds * 1000

        # Calculate Inter-Token Latency (ITL) and chunk intervals
        if len(session.chunks) > 1:
            itl_values = []
            chunk_intervals = []

            for i in range(1, len(session.chunks)):
                prev_chunk = session.chunks[i - 1]
                curr_chunk = session.chunks[i]

                interval_ms = (
                    curr_chunk.timestamp - prev_chunk.timestamp
                ).total_seconds() * 1000
                chunk_intervals.append(interval_ms)

                # ITL is based on tokens, not just chunks
                if prev_chunk.token_count > 0 and curr_chunk.token_count > 0:
                    # Simplified ITL calculation - can be enhanced
                    itl_ms = interval_ms / max(curr_chunk.token_count, 1)
                    itl_values.append(itl_ms)

            if itl_values:
                timing_stats.itl_values_ms = itl_values
                timing_stats.mean_itl_ms = statistics.mean(itl_values)
                timing_stats.median_itl_ms = statistics.median(itl_values)
                timing_stats.std_itl_ms = (
                    statistics.stdev(itl_values) if len(itl_values) > 1 else 0.0
                )
                timing_stats.min_itl_ms = min(itl_values)
                timing_stats.max_itl_ms = max(itl_values)

                # Calculate percentiles
                timing_stats.p95_itl_ms = np.percentile(itl_values, 95)
                timing_stats.p99_itl_ms = np.percentile(itl_values, 99)

            if chunk_intervals:
                timing_stats.chunk_intervals_ms = chunk_intervals
                timing_stats.mean_chunk_interval_ms = statistics.mean(chunk_intervals)
                timing_stats.median_chunk_interval_ms = statistics.median(
                    chunk_intervals
                )

        # Calculate throughput
        duration = session.streaming_duration_seconds or session.duration_seconds
        if duration and duration > 0:
            timing_stats.tokens_per_second = session.total_tokens / duration
            timing_stats.bytes_per_second = session.total_bytes / duration

        return timing_stats

    def _calculate_overall_timing(
        self, sessions: List[StreamSession], per_session_timing: Dict[str, TimingStats]
    ) -> TimingStats:
        """Calculate aggregate timing statistics across all sessions."""
        overall_stats = TimingStats()

        # Collect all values across sessions
        all_ttft_values = []
        all_itl_values = []
        all_chunk_intervals = []
        total_tokens = 0
        total_bytes = 0
        total_duration = 0.0

        for session in sessions:
            timing = per_session_timing.get(session.session_id)
            if not timing:
                continue

            if timing.ttft_ms is not None:
                all_ttft_values.append(timing.ttft_ms)

            if timing.itl_values_ms:
                all_itl_values.extend(timing.itl_values_ms)

            if timing.chunk_intervals_ms:
                all_chunk_intervals.extend(timing.chunk_intervals_ms)

            total_tokens += session.total_tokens
            total_bytes += session.total_bytes

            duration = (
                session.streaming_duration_seconds or session.duration_seconds or 0.0
            )
            total_duration += duration

        # Calculate aggregate TTFT statistics
        if all_ttft_values:
            overall_stats.ttft_ms = statistics.mean(all_ttft_values)
            overall_stats.ttft_seconds = overall_stats.ttft_ms / 1000

        # Calculate aggregate ITL statistics
        if all_itl_values:
            overall_stats.itl_values_ms = all_itl_values
            overall_stats.mean_itl_ms = statistics.mean(all_itl_values)
            overall_stats.median_itl_ms = statistics.median(all_itl_values)
            overall_stats.std_itl_ms = (
                statistics.stdev(all_itl_values) if len(all_itl_values) > 1 else 0.0
            )
            overall_stats.min_itl_ms = min(all_itl_values)
            overall_stats.max_itl_ms = max(all_itl_values)
            overall_stats.p95_itl_ms = np.percentile(all_itl_values, 95)
            overall_stats.p99_itl_ms = np.percentile(all_itl_values, 99)

        # Calculate aggregate chunk interval statistics
        if all_chunk_intervals:
            overall_stats.chunk_intervals_ms = all_chunk_intervals
            overall_stats.mean_chunk_interval_ms = statistics.mean(all_chunk_intervals)
            overall_stats.median_chunk_interval_ms = statistics.median(
                all_chunk_intervals
            )

        # Calculate overall throughput
        if total_duration > 0:
            overall_stats.tokens_per_second = total_tokens / total_duration
            overall_stats.bytes_per_second = total_bytes / total_duration

        return overall_stats

    def _detect_anomalies(
        self, sessions: List[StreamSession], per_session_timing: Dict[str, TimingStats]
    ) -> AnomalyDetection:
        """Detect anomalies in streaming sessions."""
        anomalies = AnomalyDetection(
            gap_threshold_ms=self.gap_threshold_ms,
            outlier_threshold_std=self.anomaly_threshold_std,
        )

        # Detect large gaps in streaming
        for session in sessions:
            large_gaps = self._detect_large_gaps(session)
            anomalies.large_gaps.extend(large_gaps)

        # Detect outliers in timing
        all_itl_values = []
        session_itl_map = {}

        for session_id, timing in per_session_timing.items():
            if timing.itl_values_ms:
                for i, itl in enumerate(timing.itl_values_ms):
                    all_itl_values.append(itl)
                    session_itl_map[len(all_itl_values) - 1] = (session_id, i)

        if all_itl_values and len(all_itl_values) > 10:
            outliers = self._detect_statistical_outliers(all_itl_values)
            for outlier_idx in outliers:
                if outlier_idx in session_itl_map:
                    session_id, chunk_idx = session_itl_map[outlier_idx]
                    anomalies.outlier_chunks.append(chunk_idx)

        # Detect silence periods
        for session in sessions:
            silence_periods = self._detect_silence_periods(session)
            anomalies.silence_periods.extend(silence_periods)

        # Detect unusual patterns
        unusual_patterns = self._detect_unusual_patterns(sessions, per_session_timing)
        anomalies.unusual_patterns.extend(unusual_patterns)

        return anomalies

    def _detect_large_gaps(self, session: StreamSession) -> List[Dict[str, any]]:
        """Detect large gaps between chunks in a session."""
        large_gaps = []

        if len(session.chunks) < 2:
            return large_gaps

        for i in range(1, len(session.chunks)):
            prev_chunk = session.chunks[i - 1]
            curr_chunk = session.chunks[i]

            gap_ms = (
                curr_chunk.timestamp - prev_chunk.timestamp
            ).total_seconds() * 1000

            if gap_ms > self.gap_threshold_ms:
                large_gaps.append(
                    {
                        "session_id": session.session_id,
                        "chunk_before": i - 1,
                        "chunk_after": i,
                        "gap_ms": gap_ms,
                        "timestamp": prev_chunk.timestamp,
                    }
                )

        return large_gaps

    def _detect_statistical_outliers(self, values: List[float]) -> List[int]:
        """Detect statistical outliers using Z-score method."""
        if len(values) < 10:
            return []

        z_scores = np.abs(stats.zscore(values))
        outlier_indices = np.where(z_scores > self.anomaly_threshold_std)[0]

        return outlier_indices.tolist()

    def _detect_silence_periods(self, session: StreamSession) -> List[Dict[str, any]]:
        """Detect periods of silence (no chunks) in a session."""
        silence_periods = []

        if len(session.chunks) < 2:
            return silence_periods

        for i in range(1, len(session.chunks)):
            prev_chunk = session.chunks[i - 1]
            curr_chunk = session.chunks[i]

            silence_ms = (
                curr_chunk.timestamp - prev_chunk.timestamp
            ).total_seconds() * 1000

            if silence_ms > self.silence_threshold_ms:
                silence_periods.append(
                    {
                        "session_id": session.session_id,
                        "start_chunk": i - 1,
                        "end_chunk": i,
                        "duration_ms": silence_ms,
                        "start_time": prev_chunk.timestamp,
                        "end_time": curr_chunk.timestamp,
                    }
                )

        return silence_periods

    def _detect_unusual_patterns(
        self, sessions: List[StreamSession], per_session_timing: Dict[str, TimingStats]
    ) -> List[str]:
        """Detect unusual patterns in the streaming data."""
        patterns = []

        # Check for sessions with very high variance
        high_variance_sessions = []
        for session_id, timing in per_session_timing.items():
            if timing.std_itl_ms and timing.mean_itl_ms:
                cv = timing.std_itl_ms / timing.mean_itl_ms  # Coefficient of variation
                if cv > 1.0:  # High variance
                    high_variance_sessions.append(session_id)

        if high_variance_sessions:
            patterns.append(
                f"High variance in timing detected in {len(high_variance_sessions)} sessions"
            )

        # Check for bimodal distributions
        all_chunk_sizes = []
        for session in sessions:
            chunk_sizes = [chunk.size_bytes for chunk in session.chunks]
            all_chunk_sizes.extend(chunk_sizes)

        if all_chunk_sizes and len(set(all_chunk_sizes)) > 10:
            # Simple bimodal detection
            hist, _ = np.histogram(all_chunk_sizes, bins=20)
            peaks = self._find_peaks(hist)
            if len(peaks) >= 2:
                patterns.append("Bimodal distribution detected in chunk sizes")

        # Check for periodic patterns
        for session in sessions:
            if len(session.chunks) > 10:
                intervals = []
                for i in range(1, len(session.chunks)):
                    interval = (
                        session.chunks[i].timestamp - session.chunks[i - 1].timestamp
                    ).total_seconds()
                    intervals.append(interval)

                if intervals:
                    # Check for periodicity using autocorrelation
                    if self._has_periodic_pattern(intervals):
                        patterns.append(
                            f"Periodic pattern detected in session {session.session_id}"
                        )

        return patterns

    def _find_peaks(self, data: np.ndarray, min_height: float = 0.1) -> List[int]:
        """Simple peak detection in histogram data."""
        peaks = []

        for i in range(1, len(data) - 1):
            if (
                data[i] > data[i - 1]
                and data[i] > data[i + 1]
                and data[i] > min_height * max(data)
            ):
                peaks.append(i)

        return peaks

    def _has_periodic_pattern(
        self, intervals: List[float], threshold: float = 0.3
    ) -> bool:
        """Check if intervals show periodic pattern using simple autocorrelation."""
        if len(intervals) < 10:
            return False

        # Simple autocorrelation check
        intervals_array = np.array(intervals)
        autocorr = np.correlate(intervals_array, intervals_array, mode="full")
        autocorr = autocorr[autocorr.size // 2 :]

        # Look for significant peaks in autocorrelation
        if len(autocorr) > 2:
            normalized_autocorr = (
                autocorr / autocorr[0] if autocorr[0] != 0 else autocorr
            )
            return any(
                val > threshold for val in normalized_autocorr[1 : len(autocorr) // 2]
            )

        return False

    def _rank_sessions(
        self, sessions: List[StreamSession], per_session_timing: Dict[str, TimingStats]
    ) -> Tuple[Optional[str], Optional[str]]:
        """Rank sessions by performance."""
        if not sessions:
            return None, None

        session_scores = []

        for session in sessions:
            timing = per_session_timing.get(session.session_id)
            if not timing:
                continue

            # Calculate performance score (lower is better)
            score = 0.0
            factors = 0

            if timing.ttft_ms is not None:
                score += timing.ttft_ms / 1000  # Convert to seconds for scoring
                factors += 1

            if timing.mean_itl_ms is not None:
                score += timing.mean_itl_ms / 1000  # Convert to seconds for scoring
                factors += 1

            if factors > 0:
                score /= factors  # Average score
                session_scores.append((session.session_id, score))

        if not session_scores:
            return None, None

        # Sort by score (lower is better)
        session_scores.sort(key=lambda x: x[1])

        best_session_id = session_scores[0][0]
        worst_session_id = session_scores[-1][0]

        return best_session_id, worst_session_id

    def _generate_insights(
        self,
        sessions: List[StreamSession],
        per_session_timing: Dict[str, TimingStats],
        anomalies: AnomalyDetection,
    ) -> List[str]:
        """Generate key insights from the analysis."""
        insights = []

        if not sessions:
            return ["No streaming sessions found."]

        # Basic statistics insights
        insights.append(f"Analyzed {len(sessions)} streaming session(s)")

        total_tokens = sum(session.total_tokens for session in sessions)
        total_bytes = sum(session.total_bytes for session in sessions)
        insights.append(f"Total tokens processed: {total_tokens:,}")
        insights.append(f"Total bytes transferred: {total_bytes:,}")

        # TTFT insights
        ttft_values = [
            timing.ttft_ms
            for timing in per_session_timing.values()
            if timing.ttft_ms is not None
        ]
        if ttft_values:
            avg_ttft = statistics.mean(ttft_values)
            insights.append(f"Average Time to First Token: {avg_ttft:.1f}ms")

            if avg_ttft < 500:
                insights.append("Excellent TTFT performance (< 500ms)")
            elif avg_ttft < 1000:
                insights.append("Good TTFT performance (< 1s)")
            elif avg_ttft < 2000:
                insights.append("Moderate TTFT performance (< 2s)")
            else:
                insights.append("Slow TTFT performance (> 2s)")

        # ITL insights
        all_itl_values = []
        for timing in per_session_timing.values():
            if timing.itl_values_ms:
                all_itl_values.extend(timing.itl_values_ms)

        if all_itl_values:
            avg_itl = statistics.mean(all_itl_values)
            insights.append(f"Average Inter-Token Latency: {avg_itl:.1f}ms")

            if avg_itl < 50:
                insights.append("Excellent ITL performance (< 50ms)")
            elif avg_itl < 100:
                insights.append("Good ITL performance (< 100ms)")
            elif avg_itl < 200:
                insights.append("Moderate ITL performance (< 200ms)")
            else:
                insights.append("Slow ITL performance (> 200ms)")

        # Anomaly insights
        if anomalies.large_gaps:
            insights.append(f"Detected {len(anomalies.large_gaps)} large timing gaps")

        if anomalies.silence_periods:
            insights.append(
                f"Detected {len(anomalies.silence_periods)} silence periods"
            )

        if anomalies.unusual_patterns:
            insights.append("Unusual patterns detected in streaming behavior")

        return insights

    def _generate_recommendations(
        self,
        sessions: List[StreamSession],
        per_session_timing: Dict[str, TimingStats],
        anomalies: AnomalyDetection,
    ) -> List[str]:
        """Generate recommendations based on analysis."""
        recommendations = []

        if not sessions:
            return ["Capture more streaming sessions for analysis."]

        # TTFT recommendations
        ttft_values = [
            timing.ttft_ms
            for timing in per_session_timing.values()
            if timing.ttft_ms is not None
        ]
        if ttft_values:
            avg_ttft = statistics.mean(ttft_values)
            if avg_ttft > 1000:
                recommendations.append(
                    "Consider optimizing server response time to reduce TTFT"
                )
                recommendations.append(
                    "Implement response streaming to reduce perceived latency"
                )

        # ITL recommendations
        all_itl_values = []
        for timing in per_session_timing.values():
            if timing.itl_values_ms:
                all_itl_values.extend(timing.itl_values_ms)

        if all_itl_values:
            avg_itl = statistics.mean(all_itl_values)
            std_itl = statistics.stdev(all_itl_values) if len(all_itl_values) > 1 else 0

            if avg_itl > 200:
                recommendations.append("Consider optimizing token generation speed")
                recommendations.append(
                    "Implement batching to reduce per-token overhead"
                )

            if std_itl > avg_itl:
                recommendations.append(
                    "High variance in ITL detected - investigate inconsistent performance"
                )

        # Anomaly-based recommendations
        if anomalies.large_gaps:
            recommendations.append(
                "Investigate causes of large timing gaps in streaming"
            )
            recommendations.append("Consider implementing keep-alive mechanisms")

        if anomalies.silence_periods:
            recommendations.append(
                "Reduce silence periods with more consistent streaming"
            )

        # Session consistency recommendations
        if len(sessions) > 1:
            session_performances = []
            for session in sessions:
                timing = per_session_timing.get(session.session_id)
                if (
                    timing
                    and timing.ttft_ms is not None
                    and timing.mean_itl_ms is not None
                ):
                    score = timing.ttft_ms + timing.mean_itl_ms
                    session_performances.append(score)

            if session_performances and len(session_performances) > 1:
                cv = statistics.stdev(session_performances) / statistics.mean(
                    session_performances
                )
                if cv > 0.3:  # High coefficient of variation
                    recommendations.append(
                        "High variability between sessions - investigate consistency issues"
                    )

        return recommendations
