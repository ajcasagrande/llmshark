"""
Visualization and reporting module for LLMShark.

This module provides functionality to create charts, graphs, and HTML reports
for analysis results and comparisons.
"""

from pathlib import Path

try:
    import matplotlib.pyplot as plt
    import plotly.express as px
    import plotly.graph_objects as go
    import seaborn as sns
    from plotly.subplots import make_subplots

    PLOTTING_AVAILABLE = True
except ImportError:
    PLOTTING_AVAILABLE = False

from .models import AnalysisResult, ComparisonReport


def create_timing_charts(result: AnalysisResult, output_dir: Path) -> list[Path]:
    """Create timing charts for analysis results."""
    if not PLOTTING_AVAILABLE:
        raise ImportError(
            "Plotting libraries not available. Install with: pip install llmshark[viz]"
        )

    chart_files = []

    # ITL distribution chart
    itl_chart = _create_itl_distribution_chart(result)
    if itl_chart:
        itl_file = output_dir / "itl_distribution.html"
        itl_chart.write_html(str(itl_file))
        chart_files.append(itl_file)

    # TTFT comparison chart
    ttft_chart = _create_ttft_comparison_chart(result)
    if ttft_chart:
        ttft_file = output_dir / "ttft_comparison.html"
        ttft_chart.write_html(str(ttft_file))
        chart_files.append(ttft_file)

    # Timeline chart
    timeline_chart = _create_timeline_chart(result)
    if timeline_chart:
        timeline_file = output_dir / "session_timeline.html"
        timeline_chart.write_html(str(timeline_file))
        chart_files.append(timeline_file)

    return chart_files


def create_comparison_charts(report: ComparisonReport, output_dir: Path) -> list[Path]:
    """Create comparison charts for multiple captures."""
    if not PLOTTING_AVAILABLE:
        raise ImportError(
            "Plotting libraries not available. Install with: pip install llmshark[viz]"
        )

    chart_files = []

    # Performance comparison chart
    perf_chart = _create_performance_comparison_chart(report)
    if perf_chart:
        perf_file = output_dir / "performance_comparison.html"
        perf_chart.write_html(str(perf_file))
        chart_files.append(perf_file)

    # Consistency chart
    consistency_chart = _create_consistency_chart(report)
    if consistency_chart:
        consistency_file = output_dir / "consistency_analysis.html"
        consistency_chart.write_html(str(consistency_file))
        chart_files.append(consistency_file)

    return chart_files


def save_html_report(
    result: AnalysisResult, comparison: ComparisonReport | None, output_file: Path
) -> None:
    """Save a comprehensive HTML report."""
    html_content = _generate_html_report(result, comparison)

    with open(output_file, "w", encoding="utf-8") as f:
        f.write(html_content)


def _create_itl_distribution_chart(result: AnalysisResult) -> go.Figure | None:
    """Create ITL distribution chart."""
    if not result.overall_timing_stats.itl_values_ms:
        return None

    fig = go.Figure()

    # Histogram
    fig.add_trace(
        go.Histogram(
            x=result.overall_timing_stats.itl_values_ms,
            nbinsx=50,
            name="ITL Distribution",
            opacity=0.7,
            marker_color="skyblue",
        )
    )

    # Add mean line
    mean_itl = result.overall_timing_stats.mean_itl_ms
    if mean_itl:
        fig.add_vline(
            x=mean_itl,
            line_dash="dash",
            line_color="red",
            annotation_text=f"Mean: {mean_itl:.1f}ms",
        )

    # Add median line
    median_itl = result.overall_timing_stats.median_itl_ms
    if median_itl:
        fig.add_vline(
            x=median_itl,
            line_dash="dash",
            line_color="green",
            annotation_text=f"Median: {median_itl:.1f}ms",
        )

    fig.update_layout(
        title="Inter-Token Latency Distribution",
        xaxis_title="ITL (milliseconds)",
        yaxis_title="Frequency",
        showlegend=False,
    )

    return fig


def _create_ttft_comparison_chart(result: AnalysisResult) -> go.Figure | None:
    """Create TTFT comparison chart across sessions."""
    if not result.per_session_timing:
        return None

    session_ids = []
    ttft_values = []

    for session_id, timing in result.per_session_timing.items():
        if timing.ttft_ms is not None:
            session_ids.append(
                session_id[:20] + "..." if len(session_id) > 20 else session_id
            )
            ttft_values.append(timing.ttft_ms)

    if not ttft_values:
        return None

    fig = go.Figure(
        data=[
            go.Bar(x=session_ids, y=ttft_values, marker_color="lightcoral", name="TTFT")
        ]
    )

    # Add average line
    avg_ttft = sum(ttft_values) / len(ttft_values)
    fig.add_hline(
        y=avg_ttft,
        line_dash="dash",
        line_color="blue",
        annotation_text=f"Average: {avg_ttft:.1f}ms",
    )

    fig.update_layout(
        title="Time to First Token by Session",
        xaxis_title="Session",
        yaxis_title="TTFT (milliseconds)",
        xaxis_tickangle=-45,
    )

    return fig


def _create_timeline_chart(result: AnalysisResult) -> go.Figure | None:
    """Create timeline chart showing chunk arrivals."""
    if not result.sessions or not result.sessions[0].chunks:
        return None

    fig = go.Figure()

    for i, session in enumerate(result.sessions[:5]):  # Show first 5 sessions
        if session.chunks:
            timestamps = [chunk.timestamp for chunk in session.chunks]
            chunk_sizes = [chunk.size_bytes for chunk in session.chunks]

            # Convert timestamps to seconds from start
            start_time = timestamps[0]
            relative_times = [(ts - start_time).total_seconds() for ts in timestamps]

            fig.add_trace(
                go.Scatter(
                    x=relative_times,
                    y=chunk_sizes,
                    mode="markers+lines",
                    name=f"Session {i+1}",
                    marker=dict(size=6),
                    line=dict(width=2),
                )
            )

    fig.update_layout(
        title="Chunk Timeline Analysis",
        xaxis_title="Time (seconds from start)",
        yaxis_title="Chunk Size (bytes)",
        hovermode="x unified",
    )

    return fig


def _create_performance_comparison_chart(
    report: ComparisonReport,
) -> go.Figure | None:
    """Create performance comparison chart."""
    if len(report.captures) < 2:
        return None

    capture_names = [f"Capture {i+1}" for i in range(len(report.captures))]
    ttft_values = []
    itl_values = []

    for capture in report.captures:
        timing = capture.overall_timing_stats
        ttft_values.append(timing.ttft_ms if timing.ttft_ms else 0)
        itl_values.append(timing.mean_itl_ms if timing.mean_itl_ms else 0)

    fig = make_subplots(
        rows=1,
        cols=2,
        subplot_titles=("Time to First Token", "Mean Inter-Token Latency"),
        specs=[[{"secondary_y": False}, {"secondary_y": False}]],
    )

    # TTFT chart
    fig.add_trace(
        go.Bar(x=capture_names, y=ttft_values, name="TTFT", marker_color="lightblue"),
        row=1,
        col=1,
    )

    # ITL chart
    fig.add_trace(
        go.Bar(x=capture_names, y=itl_values, name="ITL", marker_color="lightcoral"),
        row=1,
        col=2,
    )

    fig.update_xaxes(title_text="Capture", row=1, col=1)
    fig.update_xaxes(title_text="Capture", row=1, col=2)
    fig.update_yaxes(title_text="Time (ms)", row=1, col=1)
    fig.update_yaxes(title_text="Time (ms)", row=1, col=2)

    fig.update_layout(
        title_text="Performance Comparison Across Captures", showlegend=False
    )

    return fig


def _create_consistency_chart(report: ComparisonReport) -> go.Figure | None:
    """Create consistency analysis chart."""
    if len(report.captures) < 2:
        return None

    capture_names = [f"Capture {i+1}" for i in range(len(report.captures))]
    cv_values = []  # Coefficient of variation

    for capture in report.captures:
        timing = capture.overall_timing_stats
        if timing.std_itl_ms and timing.mean_itl_ms and timing.mean_itl_ms > 0:
            cv = timing.std_itl_ms / timing.mean_itl_ms
            cv_values.append(cv)
        else:
            cv_values.append(0)

    fig = go.Figure(
        data=[
            go.Bar(
                x=capture_names,
                y=cv_values,
                marker_color="lightgreen",
                name="Coefficient of Variation",
            )
        ]
    )

    fig.update_layout(
        title="Timing Consistency Analysis (Lower is Better)",
        xaxis_title="Capture",
        yaxis_title="Coefficient of Variation",
        annotations=[
            dict(
                x=0.5,
                y=1.05,
                xref="paper",
                yref="paper",
                text="Lower values indicate more consistent timing",
                showarrow=False,
                font=dict(size=12, color="gray"),
            )
        ],
    )

    return fig


def _generate_html_report(
    result: AnalysisResult, comparison: ComparisonReport | None
) -> str:
    """Generate comprehensive HTML report."""

    html_template = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>LLMShark Analysis Report</title>
    <style>
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            line-height: 1.6;
            color: #333;
            max-width: 1200px;
            margin: 0 auto;
            padding: 20px;
            background-color: #f5f5f5;
        }
        .header {
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            padding: 2rem;
            border-radius: 10px;
            margin-bottom: 2rem;
            text-align: center;
        }
        .card {
            background: white;
            border-radius: 10px;
            padding: 1.5rem;
            margin-bottom: 1.5rem;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
        }
        .metric-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 1rem;
            margin-bottom: 2rem;
        }
        .metric-card {
            background: #f8f9fa;
            padding: 1rem;
            border-radius: 8px;
            text-align: center;
            border-left: 4px solid #667eea;
        }
        .metric-value {
            font-size: 2rem;
            font-weight: bold;
            color: #667eea;
        }
        .metric-label {
            color: #666;
            font-size: 0.9rem;
        }
        .insights-list {
            list-style: none;
            padding: 0;
        }
        .insights-list li {
            padding: 0.5rem 0;
            border-bottom: 1px solid #eee;
        }
        .insights-list li:before {
            content: "💡 ";
            margin-right: 0.5rem;
        }
        .recommendations-list {
            list-style: none;
            padding: 0;
        }
        .recommendations-list li {
            padding: 0.5rem 0;
            border-bottom: 1px solid #eee;
        }
        .recommendations-list li:before {
            content: "🎯 ";
            margin-right: 0.5rem;
        }
        .anomaly-warning {
            background: #fff3cd;
            border: 1px solid #ffeaa7;
            border-radius: 5px;
            padding: 1rem;
            margin: 1rem 0;
        }
        .table {
            width: 100%;
            border-collapse: collapse;
            margin-top: 1rem;
        }
        .table th, .table td {
            padding: 0.75rem;
            text-align: left;
            border-bottom: 1px solid #dee2e6;
        }
        .table th {
            background-color: #f8f9fa;
            font-weight: 600;
        }
        .footer {
            text-align: center;
            margin-top: 3rem;
            color: #666;
            font-size: 0.9rem;
        }
    </style>
</head>
<body>
    <div class="header">
        <h1>🦈 LLMShark Analysis Report</h1>
        <p>Generated on {timestamp}</p>
    </div>

    <div class="card">
        <h2>📊 Summary</h2>
        <div class="metric-grid">
            <div class="metric-card">
                <div class="metric-value">{session_count}</div>
                <div class="metric-label">Sessions Analyzed</div>
            </div>
            <div class="metric-card">
                <div class="metric-value">{total_tokens:,}</div>
                <div class="metric-label">Total Tokens</div>
            </div>
            <div class="metric-card">
                <div class="metric-value">{total_bytes:,}</div>
                <div class="metric-label">Total Bytes</div>
            </div>
            <div class="metric-card">
                <div class="metric-value">{avg_tokens_per_sec:.1f}</div>
                <div class="metric-label">Avg Tokens/sec</div>
            </div>
        </div>
    </div>

    <div class="card">
        <h2>⏱️ Timing Statistics</h2>
        <table class="table">
            <tr><th>Metric</th><th>Value</th></tr>
            <tr><td>Time to First Token</td><td>{ttft_ms:.1f} ms</td></tr>
            <tr><td>Mean Inter-Token Latency</td><td>{mean_itl_ms:.1f} ms</td></tr>
            <tr><td>Median ITL</td><td>{median_itl_ms:.1f} ms</td></tr>
            <tr><td>95th Percentile ITL</td><td>{p95_itl_ms:.1f} ms</td></tr>
            <tr><td>99th Percentile ITL</td><td>{p99_itl_ms:.1f} ms</td></tr>
            <tr><td>ITL Standard Deviation</td><td>{std_itl_ms:.1f} ms</td></tr>
        </table>
    </div>

    {anomalies_section}

    <div class="card">
        <h2>💡 Key Insights</h2>
        <ul class="insights-list">
            {insights_html}
        </ul>
    </div>

    <div class="card">
        <h2>🎯 Recommendations</h2>
        <ul class="recommendations-list">
            {recommendations_html}
        </ul>
    </div>

    {comparison_section}

    <div class="footer">
        <p>Generated by LLMShark - LLM Streaming Traffic Analysis Tool</p>
    </div>
</body>
</html>
"""

    # Prepare data
    timing = result.overall_timing_stats

    # Format insights and recommendations
    insights_html = "\n".join(f"<li>{insight}</li>" for insight in result.key_insights)
    recommendations_html = "\n".join(
        f"<li>{rec}</li>" for rec in result.recommendations
    )

    # Anomalies section
    anomalies_section = ""
    if (
        result.anomalies.large_gaps
        or result.anomalies.silence_periods
        or result.anomalies.unusual_patterns
    ):
        anomalies_list = []
        if result.anomalies.large_gaps:
            anomalies_list.append(
                f"{len(result.anomalies.large_gaps)} large timing gaps"
            )
        if result.anomalies.silence_periods:
            anomalies_list.append(
                f"{len(result.anomalies.silence_periods)} silence periods"
            )
        if result.anomalies.unusual_patterns:
            anomalies_list.append(
                f"{len(result.anomalies.unusual_patterns)} unusual patterns"
            )

        anomalies_section = f"""
        <div class="card">
            <h2>🚨 Anomalies Detected</h2>
            <div class="anomaly-warning">
                <ul>
                    {''.join(f'<li>{anomaly}</li>' for anomaly in anomalies_list)}
                </ul>
            </div>
        </div>
        """

    # Comparison section
    comparison_section = ""
    if comparison and len(comparison.captures) > 1:
        comparison_section = f"""
        <div class="card">
            <h2>🔄 Comparison Analysis</h2>
            <p>Performance rankings and insights from comparing multiple captures.</p>
            <h3>Common Patterns</h3>
            <ul>
                {''.join(f'<li>{pattern}</li>' for pattern in comparison.common_patterns)}
            </ul>
            <h3>Improvement Opportunities</h3>
            <ul>
                {''.join(f'<li>{opp}</li>' for opp in comparison.improvement_opportunities)}
            </ul>
        </div>
        """

    # Fill template
    return html_template.format(
        timestamp=result.analysis_timestamp.strftime("%Y-%m-%d %H:%M:%S"),
        session_count=result.session_count,
        total_tokens=result.total_tokens_analyzed,
        total_bytes=result.total_bytes_analyzed,
        avg_tokens_per_sec=result.average_tokens_per_second or 0,
        ttft_ms=timing.ttft_ms or 0,
        mean_itl_ms=timing.mean_itl_ms or 0,
        median_itl_ms=timing.median_itl_ms or 0,
        p95_itl_ms=timing.p95_itl_ms or 0,
        p99_itl_ms=timing.p99_itl_ms or 0,
        std_itl_ms=timing.std_itl_ms or 0,
        anomalies_section=anomalies_section,
        insights_html=insights_html,
        recommendations_html=recommendations_html,
        comparison_section=comparison_section,
    )
