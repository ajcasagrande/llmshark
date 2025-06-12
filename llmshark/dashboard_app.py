"""
Dash-based interactive dashboard for LLMShark analytics.

This module provides a comprehensive web application with advanced interactive
visualizations, real-time updates, and detailed performance analytics.
"""

from __future__ import annotations

import dash
import dash_bootstrap_components as dbc
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
from dash import Input, Output, dcc, html

from .models import AnalysisResult


class LLMSharkDashboard:
    """Advanced Dash-based dashboard for LLM streaming analytics."""

    def __init__(self, result: AnalysisResult):
        self.result = result
        self.app = dash.Dash(
            __name__,
            external_stylesheets=[dbc.themes.BOOTSTRAP, dbc.icons.FONT_AWESOME],
            suppress_callback_exceptions=True
        )
        self._setup_layout()
        self._setup_callbacks()

    def _setup_layout(self) -> None:
        """Setup the dashboard layout."""

        self.app.layout = dbc.Container([
            # Header
            dbc.Row([
                dbc.Col([
                    html.H1([
                        "🦈 LLMShark Analytics Dashboard"
                    ], className="text-primary mb-0"),
                    html.P(
                        "Advanced real-time analysis of LLM streaming performance",
                        className="text-muted lead"
                    )
                ])
            ], className="mb-4"),

            # Key metrics cards
            dbc.Row([
                dbc.Col([
                    self._create_metric_card(
                        "TTFT",
                        f"{self.result.overall_timing_stats.ttft_ms or 0:.1f}ms",
                        "primary"
                    )
                ], width=2),
                dbc.Col([
                    self._create_metric_card(
                        "ITL",
                        f"{self.result.overall_timing_stats.mean_itl_ms or 0:.1f}ms",
                        "info"
                    )
                ], width=2),
                dbc.Col([
                    self._create_metric_card(
                        "Throughput",
                        f"{self.result.overall_timing_stats.tokens_per_second or 0:.1f} tok/s",
                        "success"
                    )
                ], width=2),
                dbc.Col([
                    self._create_metric_card(
                        "Sessions",
                        str(self.result.session_count),
                        "warning"
                    )
                ], width=2),
                dbc.Col([
                    self._create_metric_card(
                        "Anomalies",
                        str(len(self.result.anomalies.large_gaps) + len(self.result.anomalies.outlier_chunks)),
                        "danger"
                    )
                ], width=2),
                dbc.Col([
                    self._create_metric_card(
                        "Quality",
                        f"{self._calculate_quality_score():.0f}/100",
                        "dark"
                    )
                ], width=2)
            ], className="mb-4"),

            # Main content tabs
            dbc.Tabs([
                dbc.Tab(label="📊 Performance Overview", tab_id="performance"),
                dbc.Tab(label="🕒 Timeline Analysis", tab_id="timeline"),
                dbc.Tab(label="📈 Statistical Analysis", tab_id="statistics"),
                dbc.Tab(label="🔍 Anomaly Detection", tab_id="anomalies"),
                dbc.Tab(label="🎯 Advanced Analytics", tab_id="advanced")
            ], id="main-tabs", active_tab="performance"),

            # Tab content
            html.Div(id="tab-content", className="mt-4")

        ], fluid=True, className="px-4 py-3")

    def _create_metric_card(self, title: str, value: str, color: str) -> dbc.Card:
        """Create a metric card component."""

        return dbc.Card([
            dbc.CardBody([
                html.Div([
                    html.H4(value, className="mb-1"),
                    html.P(title, className="text-muted mb-0")
                ], className="text-center")
            ])
        ], className="h-100 shadow-sm")

    def _setup_callbacks(self) -> None:
        """Setup dashboard callbacks."""

        @self.app.callback(
            Output("tab-content", "children"),
            [Input("main-tabs", "active_tab")]
        )
        def update_tab_content(active_tab):
            """Update tab content based on selections."""

            if active_tab == "performance":
                return self._create_performance_content()
            elif active_tab == "timeline":
                return self._create_timeline_content()
            elif active_tab == "statistics":
                return self._create_statistics_content()
            elif active_tab == "anomalies":
                return self._create_anomalies_content()
            elif active_tab == "advanced":
                return self._create_advanced_content()

            return html.Div("Select a tab to view content")

    def _create_performance_content(self) -> html.Div:
        """Create performance overview content."""

        # TTFT Distribution
        ttft_values = [
            timing.ttft_ms for timing in self.result.per_session_timing.values()
            if timing.ttft_ms is not None
        ]

        ttft_fig = px.histogram(
            x=ttft_values,
            nbins=20,
            title="Time to First Token Distribution",
            labels={'x': 'TTFT (ms)', 'y': 'Frequency'},
            template="plotly_white"
        ) if ttft_values else go.Figure()

        # Session Performance
        performance_data = []
        for session_id, timing in self.result.per_session_timing.items():
            if timing.tokens_per_second:
                performance_data.append({
                    'Session': session_id[:10] + '...',
                    'Tokens/sec': timing.tokens_per_second,
                    'TTFT (ms)': timing.ttft_ms or 0,
                    'ITL (ms)': timing.mean_itl_ms or 0
                })

        perf_fig = px.bar(
            pd.DataFrame(performance_data) if performance_data else pd.DataFrame(),
            x='Session',
            y='Tokens/sec',
            title="Throughput by Session",
            color='TTFT (ms)',
            template="plotly_white"
        ) if performance_data else go.Figure()

        return dbc.Row([
            dbc.Col([
                dbc.Card([
                    dbc.CardHeader("TTFT Analysis"),
                    dbc.CardBody([
                        dcc.Graph(figure=ttft_fig)
                    ])
                ])
            ], width=6),
            dbc.Col([
                dbc.Card([
                    dbc.CardHeader("Session Performance"),
                    dbc.CardBody([
                        dcc.Graph(figure=perf_fig)
                    ])
                ])
            ], width=6)
        ])

    def _create_timeline_content(self) -> html.Div:
        """Create timeline analysis content."""

        if not self.result.sessions or not self.result.sessions[0].chunks:
            return html.Div("No timeline data available")

        session = self.result.sessions[0]

        timeline_data = []
        start_time = session.chunks[0].timestamp

        for i, chunk in enumerate(session.chunks):
            relative_time = (chunk.timestamp - start_time).total_seconds()
            timeline_data.append({
                'Time (s)': relative_time,
                'Chunk Size (bytes)': chunk.size_bytes,
                'Token Count': chunk.token_count,
                'Chunk #': i + 1
            })

        df = pd.DataFrame(timeline_data)

        timeline_fig = px.scatter(
            df,
            x='Time (s)',
            y='Chunk Size (bytes)',
            size='Token Count',
            hover_data=['Chunk #'],
            title="Interactive Timeline Analysis",
            template="plotly_white"
        )

        return dbc.Row([
            dbc.Col([
                dbc.Card([
                    dbc.CardHeader("Chunk Timeline"),
                    dbc.CardBody([
                        dcc.Graph(figure=timeline_fig)
                    ])
                ])
            ], width=12)
        ])

    def _create_statistics_content(self) -> html.Div:
        """Create statistical analysis content."""

        metrics_data = self._prepare_metrics_dataframe()

        if metrics_data.empty:
            return html.Div("No statistical data available")

        correlation_matrix = metrics_data.corr()

        corr_fig = px.imshow(
            correlation_matrix,
            text_auto=True,
            aspect="auto",
            title="Performance Metrics Correlation Matrix",
            template="plotly_white"
        )

        return dbc.Row([
            dbc.Col([
                dbc.Card([
                    dbc.CardHeader("Correlation Analysis"),
                    dbc.CardBody([
                        dcc.Graph(figure=corr_fig)
                    ])
                ])
            ], width=12)
        ])

    def _create_anomalies_content(self) -> html.Div:
        """Create anomaly detection content."""

        anomaly_info = []

        if self.result.anomalies.large_gaps:
            anomaly_info.append(
                dbc.Alert([
                    html.H5(f"Found {len(self.result.anomalies.large_gaps)} Large Gaps"),
                    html.P("Significant delays detected between chunks")
                ], color="warning")
            )

        if self.result.anomalies.outlier_chunks:
            anomaly_info.append(
                dbc.Alert([
                    html.H5(f"Found {len(self.result.anomalies.outlier_chunks)} Outlier Chunks"),
                    html.P("Chunks with unusual timing patterns")
                ], color="danger")
            )

        if not anomaly_info:
            anomaly_info.append(
                dbc.Alert([
                    html.H5("No Anomalies Detected"),
                    html.P("All sessions appear to be performing normally")
                ], color="success")
            )

        return html.Div(anomaly_info)

    def _create_advanced_content(self) -> html.Div:
        """Create advanced analytics content."""

        insights_cards = []

        insights_cards.append(
            dbc.Card([
                dbc.CardHeader(html.H5("Key Insights", className="mb-0")),
                dbc.CardBody([
                    html.Ul([
                        html.Li(insight) for insight in self.result.key_insights
                    ])
                ])
            ])
        )

        insights_cards.append(
            dbc.Card([
                dbc.CardHeader(html.H5("Recommendations", className="mb-0")),
                dbc.CardBody([
                    html.Ul([
                        html.Li(rec) for rec in self.result.recommendations
                    ])
                ])
            ], className="mt-3")
        )

        return html.Div(insights_cards)

    def _prepare_metrics_dataframe(self) -> pd.DataFrame:
        """Prepare metrics dataframe for analysis."""

        metrics_data = []

        for session_id, timing in self.result.per_session_timing.items():
            session = next((s for s in self.result.sessions if s.session_id == session_id), None)
            if not session:
                continue

            row = {
                'ttft_ms': timing.ttft_ms,
                'mean_itl_ms': timing.mean_itl_ms,
                'tokens_per_second': timing.tokens_per_second,
                'total_tokens': session.total_tokens,
                'total_bytes': session.total_bytes
            }
            if any(v is not None and v != 0 for v in row.values()):
                metrics_data.append(row)

        return pd.DataFrame(metrics_data)

    def _calculate_quality_score(self) -> float:
        """Calculate overall quality score."""

        if not self.result.per_session_timing:
            return 0.0

        scores = []

        for timing in self.result.per_session_timing.values():
            session_score = 50

            if timing.ttft_ms is not None:
                if timing.ttft_ms < 100:
                    session_score += 20
                elif timing.ttft_ms < 500:
                    session_score += 10
                elif timing.ttft_ms > 2000:
                    session_score -= 10

            if timing.tokens_per_second is not None:
                if timing.tokens_per_second > 50:
                    session_score += 10
                elif timing.tokens_per_second < 10:
                    session_score -= 10

            scores.append(max(0, min(100, session_score)))

        return sum(scores) / len(scores) if scores else 0.0

    def run(self, host: str = "127.0.0.1", port: int = 8050, debug: bool = False) -> None:
        """Run the dashboard server."""

        self.app.run(host=host, port=port, debug=debug)


def launch_dashboard(result: AnalysisResult, port: int = 8050) -> None:
    """Launch the Dash dashboard."""

    dashboard = LLMSharkDashboard(result)
    print(f"🦈 Starting LLMShark Dashboard on http://localhost:{port}")
    dashboard.run(port=port)
