"""
Capture comparison module for analyzing multiple PCAP files.

This module provides functionality to compare analysis results from multiple
captures, identify performance differences, and generate comprehensive reports.
"""

import statistics

from scipy import stats

from .models import (
    AnalysisResult,
    ComparisonReport,
    SessionComparison,
    TimingStats,
)


class CaptureComparator:
    """Compare multiple capture analysis results."""

    def __init__(self) -> None:
        self.significance_threshold = (
            0.05  # p-value threshold for statistical significance
        )

    def compare_captures(self, results: list[AnalysisResult]) -> ComparisonReport:
        """Compare multiple capture analysis results."""
        if len(results) < 2:
            return self._create_single_capture_report(results)

        # Rank captures by performance
        performance_rankings = self._rank_captures_by_performance(results)
        best_capture_index = performance_rankings[0] if performance_rankings else None

        # Find common and unique patterns
        common_patterns = self._find_common_patterns(results)
        unique_patterns = self._find_unique_patterns(results)

        # Generate improvement opportunities
        improvement_opportunities = self._identify_improvement_opportunities(results)

        # Calculate performance variance and consistency
        performance_variance = self._calculate_performance_variance(results)
        consistency_score = self._calculate_consistency_score(results)

        return ComparisonReport(
            captures=results,
            best_capture_index=best_capture_index,
            performance_rankings=performance_rankings,
            common_patterns=common_patterns,
            unique_patterns=unique_patterns,
            improvement_opportunities=improvement_opportunities,
            performance_variance=performance_variance,
            consistency_score=consistency_score,
        )

    def compare_sessions(
        self,
        session_a_id: str,
        session_b_id: str,
        timing_a: TimingStats,
        timing_b: TimingStats,
    ) -> SessionComparison:
        """Compare two individual sessions."""
        comparison = SessionComparison(
            session_a_id=session_a_id, session_b_id=session_b_id
        )

        # Compare TTFT
        if timing_a.ttft_ms is not None and timing_b.ttft_ms is not None:
            comparison.ttft_diff_ms = timing_b.ttft_ms - timing_a.ttft_ms
            if timing_a.ttft_ms > 0:
                comparison.ttft_diff_percent = (
                    comparison.ttft_diff_ms / timing_a.ttft_ms
                ) * 100

        # Compare ITL
        if timing_a.mean_itl_ms is not None and timing_b.mean_itl_ms is not None:
            comparison.mean_itl_diff_ms = timing_b.mean_itl_ms - timing_a.mean_itl_ms
            if timing_a.mean_itl_ms > 0:
                comparison.mean_itl_diff_percent = (
                    comparison.mean_itl_diff_ms / timing_a.mean_itl_ms
                ) * 100

        # Statistical significance test for ITL
        if (
            timing_a.itl_values_ms
            and timing_b.itl_values_ms
            and len(timing_a.itl_values_ms) > 5
            and len(timing_b.itl_values_ms) > 5
        ):

            try:
                statistic, p_value = stats.ttest_ind(
                    timing_a.itl_values_ms, timing_b.itl_values_ms
                )
                comparison.p_value = p_value
                comparison.itl_statistical_significance = (
                    p_value < self.significance_threshold
                )
            except Exception:
                comparison.itl_statistical_significance = None

        # Determine which session performed better
        comparison.which_session_better = self._determine_better_session(
            timing_a, timing_b
        )

        # Generate pattern differences
        comparison.pattern_differences = self._compare_session_patterns(
            timing_a, timing_b
        )

        # Generate improvement suggestions
        comparison.improvement_suggestions = self._generate_session_improvements(
            timing_a, timing_b, comparison.which_session_better
        )

        return comparison

    def _create_single_capture_report(
        self, results: list[AnalysisResult]
    ) -> ComparisonReport:
        """Create report for single capture (no comparison possible)."""
        return ComparisonReport(
            captures=results,
            best_capture_index=0 if results else None,
            performance_rankings=[0] if results else [],
            common_patterns=["Only one capture provided - no comparison possible"],
            improvement_opportunities=[
                "Capture additional sessions for comparison analysis"
            ],
        )

    def _rank_captures_by_performance(self, results: list[AnalysisResult]) -> list[int]:
        """Rank captures by overall performance."""
        capture_scores = []

        for i, result in enumerate(results):
            score = self._calculate_capture_performance_score(result)
            capture_scores.append((i, score))

        # Sort by score (lower is better)
        capture_scores.sort(key=lambda x: x[1])

        return [index for index, _ in capture_scores]

    def _calculate_capture_performance_score(self, result: AnalysisResult) -> float:
        """Calculate overall performance score for a capture."""
        timing = result.overall_timing_stats
        score = 0.0
        factors = 0

        # TTFT contribution (weight: 0.4)
        if timing.ttft_ms is not None:
            score += (timing.ttft_ms / 1000) * 0.4
            factors += 0.4

        # Mean ITL contribution (weight: 0.4)
        if timing.mean_itl_ms is not None:
            score += (timing.mean_itl_ms / 1000) * 0.4
            factors += 0.4

        # Consistency contribution (weight: 0.2)
        if (
            timing.std_itl_ms is not None
            and timing.mean_itl_ms is not None
            and timing.mean_itl_ms > 0
        ):
            cv = timing.std_itl_ms / timing.mean_itl_ms  # Coefficient of variation
            score += cv * 0.2
            factors += 0.2

        # Normalize by factors used
        if factors > 0:
            score /= factors

        return score

    def _find_common_patterns(self, results: list[AnalysisResult]) -> list[str]:
        """Find patterns common across multiple captures."""
        common_patterns = []

        if len(results) < 2:
            return common_patterns

        # Check for common TTFT performance levels
        ttft_categories = []
        for result in results:
            if result.overall_timing_stats.ttft_ms is not None:
                ttft_ms = result.overall_timing_stats.ttft_ms
                if ttft_ms < 500:
                    ttft_categories.append("excellent")
                elif ttft_ms < 1000:
                    ttft_categories.append("good")
                elif ttft_ms < 2000:
                    ttft_categories.append("moderate")
                else:
                    ttft_categories.append("slow")

        if ttft_categories and len(set(ttft_categories)) == 1:
            common_patterns.append(
                f"All captures show {ttft_categories[0]} TTFT performance"
            )

        # Check for common ITL performance levels
        itl_categories = []
        for result in results:
            if result.overall_timing_stats.mean_itl_ms is not None:
                itl_ms = result.overall_timing_stats.mean_itl_ms
                if itl_ms < 50:
                    itl_categories.append("excellent")
                elif itl_ms < 100:
                    itl_categories.append("good")
                elif itl_ms < 200:
                    itl_categories.append("moderate")
                else:
                    itl_categories.append("slow")

        if itl_categories and len(set(itl_categories)) == 1:
            common_patterns.append(
                f"All captures show {itl_categories[0]} ITL performance"
            )

        # Check for common anomaly patterns
        anomaly_types = []
        for result in results:
            if result.anomalies.large_gaps:
                anomaly_types.append("large_gaps")
            if result.anomalies.silence_periods:
                anomaly_types.append("silence_periods")
            if result.anomalies.unusual_patterns:
                anomaly_types.append("unusual_patterns")

        anomaly_counts = {}
        for anomaly_type in anomaly_types:
            anomaly_counts[anomaly_type] = anomaly_counts.get(anomaly_type, 0) + 1

        for anomaly_type, count in anomaly_counts.items():
            if count == len(results):  # Present in all captures
                common_patterns.append(
                    f"All captures show {anomaly_type.replace('_', ' ')}"
                )

        # Check for similar session counts
        session_counts = [result.session_count for result in results]
        if len(set(session_counts)) == 1:
            common_patterns.append(
                f"All captures contain {session_counts[0]} session(s)"
            )

        return common_patterns

    def _find_unique_patterns(
        self, results: list[AnalysisResult]
    ) -> dict[int, list[str]]:
        """Find patterns unique to specific captures."""
        unique_patterns = {}

        for i, result in enumerate(results):
            patterns = []

            # Check for unique performance characteristics
            timing = result.overall_timing_stats

            if timing.ttft_ms is not None:
                # Compare with other captures
                other_ttft_values = []
                for j, other_result in enumerate(results):
                    if i != j and other_result.overall_timing_stats.ttft_ms is not None:
                        other_ttft_values.append(
                            other_result.overall_timing_stats.ttft_ms
                        )

                if other_ttft_values:
                    avg_other_ttft = statistics.mean(other_ttft_values)
                    if timing.ttft_ms < avg_other_ttft * 0.8:
                        patterns.append("Significantly faster TTFT than other captures")
                    elif timing.ttft_ms > avg_other_ttft * 1.2:
                        patterns.append("Significantly slower TTFT than other captures")

            # Check for unique anomalies
            unique_anomaly_count = 0
            if result.anomalies.large_gaps:
                unique_anomaly_count += 1
            if result.anomalies.silence_periods:
                unique_anomaly_count += 1
            if result.anomalies.unusual_patterns:
                unique_anomaly_count += 1

            other_anomaly_counts = []
            for j, other_result in enumerate(results):
                if i != j:
                    count = 0
                    if other_result.anomalies.large_gaps:
                        count += 1
                    if other_result.anomalies.silence_periods:
                        count += 1
                    if other_result.anomalies.unusual_patterns:
                        count += 1
                    other_anomaly_counts.append(count)

            if other_anomaly_counts and unique_anomaly_count > max(
                other_anomaly_counts
            ):
                patterns.append("More anomalies detected than other captures")
            elif other_anomaly_counts and unique_anomaly_count < min(
                other_anomaly_counts
            ):
                patterns.append("Fewer anomalies detected than other captures")

            # Check for unique session characteristics
            if result.session_count > 0:
                avg_tokens_per_session = (
                    result.total_tokens_analyzed / result.session_count
                )

                other_avg_tokens = []
                for j, other_result in enumerate(results):
                    if i != j and other_result.session_count > 0:
                        other_avg = (
                            other_result.total_tokens_analyzed
                            / other_result.session_count
                        )
                        other_avg_tokens.append(other_avg)

                if other_avg_tokens:
                    overall_avg = statistics.mean(other_avg_tokens)
                    if avg_tokens_per_session > overall_avg * 1.5:
                        patterns.append(
                            "Sessions contain significantly more tokens than other captures"
                        )
                    elif avg_tokens_per_session < overall_avg * 0.5:
                        patterns.append(
                            "Sessions contain significantly fewer tokens than other captures"
                        )

            if patterns:
                unique_patterns[i] = patterns

        return unique_patterns

    def _identify_improvement_opportunities(
        self, results: list[AnalysisResult]
    ) -> list[str]:
        """Identify opportunities for improvement across captures."""
        opportunities = []

        if not results:
            return opportunities

        # Find best performing capture for reference
        rankings = self._rank_captures_by_performance(results)
        if not rankings:
            return opportunities

        best_result = results[rankings[0]]
        best_timing = best_result.overall_timing_stats

        # TTFT improvement opportunities
        ttft_values = [
            r.overall_timing_stats.ttft_ms
            for r in results
            if r.overall_timing_stats.ttft_ms is not None
        ]

        if ttft_values and len(ttft_values) > 1:
            avg_ttft = statistics.mean(ttft_values)
            min_ttft = min(ttft_values)

            if avg_ttft > min_ttft * 1.2:
                improvement_ms = avg_ttft - min_ttft
                opportunities.append(
                    f"TTFT could be improved by {improvement_ms:.1f}ms on average "
                    f"(best performance already achieved in one capture)"
                )

        # ITL improvement opportunities
        itl_values = [
            r.overall_timing_stats.mean_itl_ms
            for r in results
            if r.overall_timing_stats.mean_itl_ms is not None
        ]

        if itl_values and len(itl_values) > 1:
            avg_itl = statistics.mean(itl_values)
            min_itl = min(itl_values)

            if avg_itl > min_itl * 1.2:
                improvement_ms = avg_itl - min_itl
                opportunities.append(
                    f"ITL could be improved by {improvement_ms:.1f}ms on average "
                    f"(best performance already achieved in one capture)"
                )

        # Consistency improvement opportunities
        consistency_scores = []
        for result in results:
            if (
                result.overall_timing_stats.std_itl_ms is not None
                and result.overall_timing_stats.mean_itl_ms is not None
            ):
                if result.overall_timing_stats.mean_itl_ms > 0:
                    cv = (
                        result.overall_timing_stats.std_itl_ms
                        / result.overall_timing_stats.mean_itl_ms
                    )
                    consistency_scores.append(cv)

        if consistency_scores and len(consistency_scores) > 1:
            avg_cv = statistics.mean(consistency_scores)
            best_cv = min(consistency_scores)

            if avg_cv > best_cv * 1.5:
                opportunities.append(
                    "Timing consistency could be improved across captures"
                )

        # Anomaly reduction opportunities
        total_anomalies = sum(
            len(r.anomalies.large_gaps)
            + len(r.anomalies.silence_periods)
            + len(r.anomalies.unusual_patterns)
            for r in results
        )

        if total_anomalies > 0:
            opportunities.append(
                f"Reduce {total_anomalies} detected anomalies across all captures"
            )

        return opportunities

    def _calculate_performance_variance(
        self, results: list[AnalysisResult]
    ) -> float | None:
        """Calculate variance in performance across captures."""
        scores = []

        for result in results:
            score = self._calculate_capture_performance_score(result)
            if score > 0:  # Valid score
                scores.append(score)

        if len(scores) > 1:
            return statistics.variance(scores)

        return None

    def _calculate_consistency_score(
        self, results: list[AnalysisResult]
    ) -> float | None:
        """Calculate consistency score (0-1, higher is more consistent)."""
        if len(results) < 2:
            return 1.0  # Single capture is perfectly consistent with itself

        # Calculate consistency based on coefficient of variation of performance scores
        scores = []
        for result in results:
            score = self._calculate_capture_performance_score(result)
            if score > 0:
                scores.append(score)

        if len(scores) < 2:
            return None

        mean_score = statistics.mean(scores)
        if mean_score == 0:
            return 1.0

        cv = statistics.stdev(scores) / mean_score

        # Convert CV to consistency score (lower CV = higher consistency)
        # CV of 0 = consistency of 1.0, CV of 1 = consistency of 0.5, etc.
        consistency = 1.0 / (1.0 + cv)

        return consistency

    def _determine_better_session(
        self, timing_a: TimingStats, timing_b: TimingStats
    ) -> str | None:
        """Determine which session performed better."""
        score_a = 0.0
        score_b = 0.0
        factors = 0

        # TTFT comparison
        if timing_a.ttft_ms is not None and timing_b.ttft_ms is not None:
            if timing_a.ttft_ms < timing_b.ttft_ms:
                score_a += 1
            elif timing_b.ttft_ms < timing_a.ttft_ms:
                score_b += 1
            factors += 1

        # ITL comparison
        if timing_a.mean_itl_ms is not None and timing_b.mean_itl_ms is not None:
            if timing_a.mean_itl_ms < timing_b.mean_itl_ms:
                score_a += 1
            elif timing_b.mean_itl_ms < timing_a.mean_itl_ms:
                score_b += 1
            factors += 1

        # Consistency comparison
        if (
            timing_a.std_itl_ms is not None
            and timing_b.std_itl_ms is not None
            and timing_a.mean_itl_ms is not None
            and timing_b.mean_itl_ms is not None
        ):

            cv_a = (
                timing_a.std_itl_ms / timing_a.mean_itl_ms
                if timing_a.mean_itl_ms > 0
                else float("inf")
            )
            cv_b = (
                timing_b.std_itl_ms / timing_b.mean_itl_ms
                if timing_b.mean_itl_ms > 0
                else float("inf")
            )

            if cv_a < cv_b:
                score_a += 0.5  # Consistency has less weight
            elif cv_b < cv_a:
                score_b += 0.5
            factors += 0.5

        if factors == 0:
            return None

        if score_a > score_b:
            return "session_a"
        elif score_b > score_a:
            return "session_b"
        else:
            return "tie"

    def _compare_session_patterns(
        self, timing_a: TimingStats, timing_b: TimingStats
    ) -> list[str]:
        """Compare patterns between two sessions."""
        differences = []

        # Compare ITL distributions
        if timing_a.itl_values_ms and timing_b.itl_values_ms:
            # Check for different distribution shapes
            if len(timing_a.itl_values_ms) > 10 and len(timing_b.itl_values_ms) > 10:
                try:
                    # Kolmogorov-Smirnov test for distribution differences
                    ks_stat, ks_p = stats.ks_2samp(
                        timing_a.itl_values_ms, timing_b.itl_values_ms
                    )
                    if ks_p < 0.05:
                        differences.append(
                            "ITL distributions are significantly different"
                        )
                except Exception:
                    pass

        # Compare variability patterns
        if (
            timing_a.std_itl_ms is not None
            and timing_b.std_itl_ms is not None
            and timing_a.mean_itl_ms is not None
            and timing_b.mean_itl_ms is not None
        ):

            cv_a = (
                timing_a.std_itl_ms / timing_a.mean_itl_ms
                if timing_a.mean_itl_ms > 0
                else 0
            )
            cv_b = (
                timing_b.std_itl_ms / timing_b.mean_itl_ms
                if timing_b.mean_itl_ms > 0
                else 0
            )

            if abs(cv_a - cv_b) > 0.2:
                if cv_a > cv_b:
                    differences.append("Session A shows higher timing variability")
                else:
                    differences.append("Session B shows higher timing variability")

        # Compare throughput patterns
        if (
            timing_a.tokens_per_second is not None
            and timing_b.tokens_per_second is not None
        ):
            ratio = (
                timing_b.tokens_per_second / timing_a.tokens_per_second
                if timing_a.tokens_per_second > 0
                else 1
            )
            if ratio > 1.2:
                differences.append("Session B has significantly higher throughput")
            elif ratio < 0.8:
                differences.append("Session A has significantly higher throughput")

        return differences

    def _generate_session_improvements(
        self,
        timing_a: TimingStats,
        timing_b: TimingStats,
        better_session: str | None,
    ) -> list[str]:
        """Generate improvement suggestions based on session comparison."""
        suggestions = []

        if better_session == "session_a":
            if timing_b.ttft_ms is not None and timing_a.ttft_ms is not None:
                if timing_b.ttft_ms > timing_a.ttft_ms:
                    diff = timing_b.ttft_ms - timing_a.ttft_ms
                    suggestions.append(
                        f"Reduce TTFT by {diff:.1f}ms (achieve Session A performance)"
                    )

            if timing_b.mean_itl_ms is not None and timing_a.mean_itl_ms is not None:
                if timing_b.mean_itl_ms > timing_a.mean_itl_ms:
                    diff = timing_b.mean_itl_ms - timing_a.mean_itl_ms
                    suggestions.append(
                        f"Reduce mean ITL by {diff:.1f}ms (achieve Session A performance)"
                    )

        elif better_session == "session_b":
            if timing_a.ttft_ms is not None and timing_b.ttft_ms is not None:
                if timing_a.ttft_ms > timing_b.ttft_ms:
                    diff = timing_a.ttft_ms - timing_b.ttft_ms
                    suggestions.append(
                        f"Reduce TTFT by {diff:.1f}ms (achieve Session B performance)"
                    )

            if timing_a.mean_itl_ms is not None and timing_b.mean_itl_ms is not None:
                if timing_a.mean_itl_ms > timing_b.mean_itl_ms:
                    diff = timing_a.mean_itl_ms - timing_b.mean_itl_ms
                    suggestions.append(
                        f"Reduce mean ITL by {diff:.1f}ms (achieve Session B performance)"
                    )

        # General consistency improvements
        if timing_a.std_itl_ms is not None and timing_b.std_itl_ms is not None:
            if timing_a.std_itl_ms > timing_b.std_itl_ms:
                suggestions.append("Improve Session A timing consistency")
            elif timing_b.std_itl_ms > timing_a.std_itl_ms:
                suggestions.append("Improve Session B timing consistency")

        return suggestions
