"""
Advanced visualization module for LLMShark with state-of-the-art interactive components.

This module provides modern, interactive dashboards and visualizations for 
comprehensive analysis of LLM streaming performance data.
"""

from __future__ import annotations

import json
import statistics
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import numpy as np
import pandas as pd
import plotly.graph_objects as go
import plotly.express as px
from plotly.subplots import make_subplots
from sklearn.cluster import DBSCAN
from sklearn.decomposition import PCA
from sklearn.preprocessing import StandardScaler
import networkx as nx

from .models import AnalysisResult, ComparisonReport, StreamSession, TimingStats


class AdvancedVisualizer:
    """Advanced visualization engine with state-of-the-art components."""
    
    def __init__(self):
        self.color_palette = {
            'primary': '#667eea',
            'secondary': '#764ba2', 
            'accent': '#f093fb',
            'success': '#4ecdc4',
            'warning': '#ffd93d',
            'danger': '#ff6b6b',
            'info': '#74b9ff',
            'light': '#f8f9fa',
            'dark': '#2d3436'
        }
        
    def create_interactive_dashboard(
        self, 
        result: AnalysisResult, 
        output_dir: Path
    ) -> Path:
        """Create comprehensive interactive dashboard."""
        
        # Create dashboard components
        performance_fig = self._create_performance_overview(result)
        timeline_fig = self._create_advanced_timeline(result)
        distribution_fig = self._create_statistical_distributions(result)
        anomaly_fig = self._create_anomaly_detection_viz(result)
        correlation_fig = self._create_correlation_matrix(result)
        clustering_fig = self._create_performance_clustering(result)
        
        # Create dashboard HTML
        dashboard_html = self._create_dashboard_html([
            ('Performance Overview', performance_fig),
            ('Timeline Analysis', timeline_fig),
            ('Statistical Distributions', distribution_fig),
            ('Anomaly Detection', anomaly_fig),
            ('Correlation Analysis', correlation_fig),
            ('Performance Clustering', clustering_fig)
        ])
        
        dashboard_path = output_dir / "advanced_dashboard.html"
        with open(dashboard_path, 'w', encoding='utf-8') as f:
            f.write(dashboard_html)
            
        return dashboard_path
        
    def _create_performance_overview(self, result: AnalysisResult) -> go.Figure:
        """Create comprehensive performance overview with KPIs."""
        
        # Create subplot structure
        fig = make_subplots(
            rows=2, cols=3,
            subplot_titles=[
                'TTFT Distribution', 'ITL Trends', 'Throughput Analysis',
                'Session Performance', 'Error Rates', 'Quality Score'
            ],
            specs=[
                [{"type": "histogram"}, {"type": "scatter"}, {"type": "bar"}],
                [{"type": "box"}, {"type": "indicator"}, {"type": "bar"}]
            ]
        )
        
        # TTFT Distribution (Top Left)
        ttft_values = [
            timing.ttft_ms for timing in result.per_session_timing.values()
            if timing.ttft_ms is not None
        ]
        if ttft_values:
            fig.add_trace(
                go.Histogram(
                    x=ttft_values,
                    name="TTFT",
                    marker_color=self.color_palette['primary'],
                    opacity=0.7
                ),
                row=1, col=1
            )
        
        # ITL Trends (Top Middle)
        for i, session in enumerate(result.sessions[:5]):  # Top 5 sessions
            if session.chunks:
                timestamps = [(chunk.timestamp - session.chunks[0].timestamp).total_seconds() 
                             for chunk in session.chunks]
                chunk_sizes = [chunk.size_bytes for chunk in session.chunks]
                
                fig.add_trace(
                    go.Scatter(
                        x=timestamps,
                        y=chunk_sizes,
                        mode='lines+markers',
                        name=f'Session {i+1}',
                        line=dict(width=2),
                        marker=dict(size=4)
                    ),
                    row=1, col=2
                )
        
        # Throughput Analysis (Top Right)
        session_ids = []
        throughput_values = []
        for session_id, timing in result.per_session_timing.items():
            if timing.tokens_per_second:
                session_ids.append(session_id[:10] + '...')
                throughput_values.append(timing.tokens_per_second)
        
        if throughput_values:
            fig.add_trace(
                go.Bar(
                    x=session_ids,
                    y=throughput_values,
                    name="Tokens/sec",
                    marker_color=self.color_palette['success']
                ),
                row=1, col=3
            )
        
        # Session Performance Box Plot (Bottom Left)
        itl_data = []
        session_labels = []
        for session_id, timing in result.per_session_timing.items():
            if timing.itl_values_ms:
                itl_data.extend(timing.itl_values_ms)
                session_labels.extend([session_id[:10]] * len(timing.itl_values_ms))
        
        if itl_data:
            fig.add_trace(
                go.Box(
                    y=itl_data,
                    x=session_labels,
                    name="ITL Distribution",
                    marker_color=self.color_palette['accent']
                ),
                row=2, col=1
            )
        
        # Quality Indicator (Bottom Middle)
        quality_score = self._calculate_quality_score(result)
        fig.add_trace(
            go.Indicator(
                mode="gauge+number+delta",
                value=quality_score,
                domain={'x': [0, 1], 'y': [0, 1]},
                title={'text': "Quality Score"},
                gauge={
                    'axis': {'range': [None, 100]},
                    'bar': {'color': self.color_palette['primary']},
                    'steps': [
                        {'range': [0, 50], 'color': self.color_palette['danger']},
                        {'range': [50, 80], 'color': self.color_palette['warning']},
                        {'range': [80, 100], 'color': self.color_palette['success']}
                    ],
                    'threshold': {
                        'line': {'color': "red", 'width': 4},
                        'thickness': 0.75,
                        'value': 90
                    }
                }
            ),
            row=2, col=2
        )
        
        # Quality Breakdown (Bottom Right)
        quality_metrics = ['TTFT', 'ITL', 'Throughput', 'Consistency']
        quality_values = [
            min(100, max(0, 100 - (result.overall_timing_stats.ttft_ms or 500) / 10)),
            min(100, max(0, 100 - (result.overall_timing_stats.mean_itl_ms or 100) / 2)),
            min(100, (result.overall_timing_stats.tokens_per_second or 0) * 2),
            quality_score
        ]
        
        fig.add_trace(
            go.Bar(
                x=quality_metrics,
                y=quality_values,
                name="Quality Breakdown",
                marker_color=self.color_palette['info']
            ),
            row=2, col=3
        )
        
        fig.update_layout(
            height=800,
            title="LLM Streaming Performance Overview",
            showlegend=True,
            template="plotly_white"
        )
        
        return fig
        
    def _create_advanced_timeline(self, result: AnalysisResult) -> go.Figure:
        """Create advanced timeline with interactive features."""
        
        fig = go.Figure()
        
        for i, session in enumerate(result.sessions):
            if not session.chunks:
                continue
                
            # Create timeline data
            timestamps = [chunk.timestamp for chunk in session.chunks]
            chunk_sizes = [chunk.size_bytes for chunk in session.chunks]
            token_counts = [chunk.token_count for chunk in session.chunks]
            
            # Convert to relative time
            start_time = timestamps[0]
            relative_times = [(ts - start_time).total_seconds() for ts in timestamps]
            
            # Main timeline
            fig.add_trace(
                go.Scatter(
                    x=relative_times,
                    y=chunk_sizes,
                    mode='lines+markers',
                    name=f'Session {i+1}',
                    line=dict(width=3),
                    marker=dict(
                        size=[max(4, min(20, tc)) for tc in token_counts],
                        sizemode='diameter',
                        sizeref=1,
                        opacity=0.8
                    ),
                    hovertemplate=(
                        '<b>Session %{fullData.name}</b><br>'
                        'Time: %{x:.2f}s<br>'
                        'Chunk Size: %{y} bytes<br>'
                        'Tokens: %{customdata}<br>'
                        '<extra></extra>'
                    ),
                    customdata=token_counts
                )
            )
            
            # Add anomaly markers
            timing = result.per_session_timing.get(session.session_id)
            if timing and timing.itl_values_ms:
                # Identify outliers
                itl_mean = statistics.mean(timing.itl_values_ms)
                itl_std = statistics.stdev(timing.itl_values_ms) if len(timing.itl_values_ms) > 1 else 0
                threshold = itl_mean + 2 * itl_std
                
                anomaly_times = []
                anomaly_sizes = []
                
                for j, itl in enumerate(timing.itl_values_ms):
                    if itl > threshold and j < len(relative_times):
                        anomaly_times.append(relative_times[j])
                        anomaly_sizes.append(chunk_sizes[j])
                
                if anomaly_times:
                    fig.add_trace(
                        go.Scatter(
                            x=anomaly_times,
                            y=anomaly_sizes,
                            mode='markers',
                            name=f'Anomalies S{i+1}',
                            marker=dict(
                                symbol='x',
                                size=12,
                                color=self.color_palette['danger'],
                                line=dict(width=2)
                            ),
                            showlegend=False
                        )
                    )
        
        # Add interactive elements
        fig.update_layout(
            title="Interactive Timeline Analysis",
            xaxis_title="Time (seconds)",
            yaxis_title="Chunk Size (bytes)",
            hovermode='closest',
            height=600,
            template="plotly_white",
            updatemenus=[
                dict(
                    type="buttons",
                    direction="left",
                    buttons=list([
                        dict(
                            args=[{"visible": [True] * len(fig.data)}],
                            label="Show All",
                            method="update"
                        ),
                        dict(
                            args=[{"visible": [i % 2 == 0 for i in range(len(fig.data))]}],
                            label="Even Sessions",
                            method="update"
                        )
                    ]),
                    pad={"r": 10, "t": 10},
                    showactive=True,
                    x=0.01,
                    xanchor="left",
                    y=1.02,
                    yanchor="top"
                ),
            ]
        )
        
        return fig
        
    def _create_statistical_distributions(self, result: AnalysisResult) -> go.Figure:
        """Create comprehensive statistical distribution analysis."""
        
        fig = make_subplots(
            rows=2, cols=2,
            subplot_titles=[
                'ITL Distribution with Fit', 'TTFT vs Throughput',
                'Chunk Size Distribution', 'Performance Scatter Matrix'
            ]
        )
        
        # ITL Distribution with statistical fitting
        all_itl_values = []
        for timing in result.per_session_timing.values():
            if timing.itl_values_ms:
                all_itl_values.extend(timing.itl_values_ms)
        
        if all_itl_values:
            fig.add_trace(
                go.Histogram(
                    x=all_itl_values,
                    histnorm='probability density',
                    name="ITL Histogram",
                    marker_color=self.color_palette['primary'],
                    opacity=0.7
                ),
                row=1, col=1
            )
            
            # Add normal distribution overlay
            mean_itl = statistics.mean(all_itl_values)
            std_itl = statistics.stdev(all_itl_values) if len(all_itl_values) > 1 else 0
            x_norm = np.linspace(min(all_itl_values), max(all_itl_values), 100)
            y_norm = (1 / (std_itl * np.sqrt(2 * np.pi))) * np.exp(-0.5 * ((x_norm - mean_itl) / std_itl) ** 2)
            
            fig.add_trace(
                go.Scatter(
                    x=x_norm,
                    y=y_norm,
                    mode='lines',
                    name="Normal Fit",
                    line=dict(color=self.color_palette['danger'], width=3)
                ),
                row=1, col=1
            )
        
        # TTFT vs Throughput scatter
        ttft_vals = []
        throughput_vals = []
        for timing in result.per_session_timing.values():
            if timing.ttft_ms is not None and timing.tokens_per_second is not None:
                ttft_vals.append(timing.ttft_ms)
                throughput_vals.append(timing.tokens_per_second)
        
        if ttft_vals and throughput_vals:
            fig.add_trace(
                go.Scatter(
                    x=ttft_vals,
                    y=throughput_vals,
                    mode='markers',
                    name="TTFT vs Throughput",
                    marker=dict(
                        size=10,
                        color=self.color_palette['accent'],
                        opacity=0.7
                    )
                ),
                row=1, col=2
            )
        
        # Chunk size distribution
        all_chunk_sizes = []
        for session in result.sessions:
            all_chunk_sizes.extend([chunk.size_bytes for chunk in session.chunks])
        
        if all_chunk_sizes:
            fig.add_trace(
                go.Histogram(
                    x=all_chunk_sizes,
                    name="Chunk Sizes",
                    marker_color=self.color_palette['success'],
                    opacity=0.7
                ),
                row=2, col=1
            )
        
        fig.update_layout(
            height=800,
            title="Statistical Distribution Analysis",
            template="plotly_white"
        )
        
        return fig
        
    def _create_anomaly_detection_viz(self, result: AnalysisResult) -> go.Figure:
        """Create advanced anomaly detection visualization."""
        
        fig = make_subplots(
            rows=2, cols=2,
            subplot_titles=[
                'Anomaly Timeline', 'Outlier Detection',
                'Pattern Analysis', 'Anomaly Clustering'
            ]
        )
        
        # Anomaly timeline
        for i, session in enumerate(result.sessions[:3]):  # Top 3 sessions
            if not session.chunks:
                continue
                
            timing = result.per_session_timing.get(session.session_id)
            if not timing or not timing.itl_values_ms:
                continue
                
            # Detect anomalies using z-score
            itl_values = np.array(timing.itl_values_ms)
            z_scores = np.abs((itl_values - np.mean(itl_values)) / np.std(itl_values))
            anomaly_threshold = 2.5
            
            timestamps = [(chunk.timestamp - session.chunks[0].timestamp).total_seconds() 
                         for chunk in session.chunks[1:]]
            
            # Normal points
            normal_mask = z_scores <= anomaly_threshold
            fig.add_trace(
                go.Scatter(
                    x=np.array(timestamps)[normal_mask],
                    y=itl_values[normal_mask],
                    mode='markers',
                    name=f'Normal S{i+1}',
                    marker=dict(color=self.color_palette['primary'], size=6)
                ),
                row=1, col=1
            )
            
            # Anomalous points
            anomaly_mask = z_scores > anomaly_threshold
            if np.any(anomaly_mask):
                fig.add_trace(
                    go.Scatter(
                        x=np.array(timestamps)[anomaly_mask],
                        y=itl_values[anomaly_mask],
                        mode='markers',
                        name=f'Anomalies S{i+1}',
                        marker=dict(
                            color=self.color_palette['danger'],
                            size=10,
                            symbol='diamond'
                        )
                    ),
                    row=1, col=1
                )
        
        fig.update_layout(
            height=800,
            title="Advanced Anomaly Detection",
            template="plotly_white"
        )
        
        return fig
        
    def _create_correlation_matrix(self, result: AnalysisResult) -> go.Figure:
        """Create correlation matrix of performance metrics."""
        
        # Prepare data for correlation analysis
        metrics_data = []
        for session_id, timing in result.per_session_timing.items():
            session = next((s for s in result.sessions if s.session_id == session_id), None)
            if not session:
                continue
                
            row = {
                'ttft_ms': timing.ttft_ms or 0,
                'mean_itl_ms': timing.mean_itl_ms or 0,
                'tokens_per_second': timing.tokens_per_second or 0,
                'bytes_per_second': timing.bytes_per_second or 0,
                'total_tokens': session.total_tokens,
                'total_bytes': session.total_bytes,
                'chunk_count': len(session.chunks),
                'duration_seconds': session.duration_seconds or 0
            }
            metrics_data.append(row)
        
        if not metrics_data:
            return go.Figure()
            
        df = pd.DataFrame(metrics_data)
        correlation_matrix = df.corr()
        
        fig = go.Figure(data=go.Heatmap(
            z=correlation_matrix.values,
            x=correlation_matrix.columns,
            y=correlation_matrix.columns,
            colorscale='RdBu',
            zmid=0,
            text=correlation_matrix.round(2).values,
            texttemplate='%{text}',
            textfont={"size": 10},
            hoverongaps=False
        ))
        
        fig.update_layout(
            title="Performance Metrics Correlation Matrix",
            height=600,
            template="plotly_white"
        )
        
        return fig
        
    def _create_performance_clustering(self, result: AnalysisResult) -> go.Figure:
        """Create performance clustering visualization."""
        
        # Prepare data for clustering
        features = []
        session_labels = []
        
        for session_id, timing in result.per_session_timing.items():
            if (timing.ttft_ms is not None and 
                timing.mean_itl_ms is not None and 
                timing.tokens_per_second is not None):
                
                features.append([
                    timing.ttft_ms,
                    timing.mean_itl_ms,
                    timing.tokens_per_second
                ])
                session_labels.append(session_id[:10])
        
        if len(features) < 3:
            return go.Figure()
            
        # Standardize features
        scaler = StandardScaler()
        features_scaled = scaler.fit_transform(features)
        
        # Apply DBSCAN clustering
        clustering = DBSCAN(eps=0.5, min_samples=2)
        cluster_labels = clustering.fit_predict(features_scaled)
        
        # Apply PCA for visualization
        pca = PCA(n_components=2)
        features_pca = pca.fit_transform(features_scaled)
        
        # Create scatter plot
        fig = go.Figure()
        
        unique_labels = set(cluster_labels)
        colors = [self.color_palette['primary'], self.color_palette['accent'], 
                 self.color_palette['success'], self.color_palette['warning']]
        
        for i, label in enumerate(unique_labels):
            mask = cluster_labels == label
            cluster_name = f'Cluster {label}' if label != -1 else 'Outliers'
            color = colors[i % len(colors)] if label != -1 else self.color_palette['danger']
            
            fig.add_trace(
                go.Scatter(
                    x=features_pca[mask, 0],
                    y=features_pca[mask, 1],
                    mode='markers',
                    name=cluster_name,
                    marker=dict(
                        size=10,
                        color=color,
                        opacity=0.7
                    ),
                    text=[session_labels[j] for j in range(len(session_labels)) if mask[j]],
                    hovertemplate='<b>%{text}</b><br>PC1: %{x:.2f}<br>PC2: %{y:.2f}<extra></extra>'
                )
            )
        
        fig.update_layout(
            title="Performance Clustering Analysis",
            xaxis_title=f"PC1 ({pca.explained_variance_ratio_[0]:.1%} variance)",
            yaxis_title=f"PC2 ({pca.explained_variance_ratio_[1]:.1%} variance)",
            height=600,
            template="plotly_white"
        )
        
        return fig
        
    def _calculate_quality_score(self, result: AnalysisResult) -> float:
        """Calculate overall quality score based on performance metrics."""
        
        if not result.per_session_timing:
            return 0.0
            
        scores = []
        
        for timing in result.per_session_timing.values():
            session_score = 50  # Base score
            
            # TTFT score (lower is better)
            if timing.ttft_ms is not None:
                if timing.ttft_ms < 100:
                    session_score += 20
                elif timing.ttft_ms < 500:
                    session_score += 10
                elif timing.ttft_ms > 2000:
                    session_score -= 10
            
            # ITL consistency score
            if timing.std_itl_ms is not None and timing.mean_itl_ms is not None:
                cv = timing.std_itl_ms / timing.mean_itl_ms if timing.mean_itl_ms > 0 else 1
                if cv < 0.2:
                    session_score += 20
                elif cv < 0.5:
                    session_score += 10
                elif cv > 1.0:
                    session_score -= 10
            
            # Throughput score
            if timing.tokens_per_second is not None:
                if timing.tokens_per_second > 50:
                    session_score += 10
                elif timing.tokens_per_second < 10:
                    session_score -= 10
            
            scores.append(max(0, min(100, session_score)))
        
        return statistics.mean(scores) if scores else 0.0
        
    def _create_dashboard_html(self, charts: List[Tuple[str, go.Figure]]) -> str:
        """Create comprehensive HTML dashboard."""
        
        # Convert charts to HTML divs
        chart_divs = []
        for title, fig in charts:
            chart_html = fig.to_html(
                include_plotlyjs='cdn',
                div_id=title.lower().replace(' ', '_'),
                config={'displayModeBar': True, 'responsive': True}
            )
            # Extract just the div content
            div_start = chart_html.find('<div')
            div_end = chart_html.rfind('</div>') + 6
            chart_div = chart_html[div_start:div_end]
            chart_divs.append((title, chart_div))
        
        return f"""
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>LLMShark Advanced Analytics Dashboard</title>
    <script src="https://cdn.plot.ly/plotly-latest.min.js"></script>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.1.3/dist/css/bootstrap.min.css" rel="stylesheet">
    <style>
        body {{
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            min-height: 100vh;
        }}
        .dashboard-container {{
            padding: 2rem;
        }}
        .dashboard-header {{
            background: rgba(255, 255, 255, 0.95);
            backdrop-filter: blur(10px);
            border-radius: 20px;
            padding: 2rem;
            margin-bottom: 2rem;
            text-align: center;
            box-shadow: 0 8px 32px rgba(0,0,0,0.1);
        }}
        .chart-container {{
            background: rgba(255, 255, 255, 0.95);
            backdrop-filter: blur(10px);
            border-radius: 15px;
            padding: 1.5rem;
            margin-bottom: 2rem;
            box-shadow: 0 8px 32px rgba(0,0,0,0.1);
            transition: transform 0.3s ease;
        }}
        .chart-container:hover {{
            transform: translateY(-5px);
        }}
        .chart-title {{
            font-size: 1.5rem;
            font-weight: 600;
            margin-bottom: 1rem;
            color: #2d3436;
        }}
        .nav-tabs {{
            border: none;
            margin-bottom: 2rem;
        }}
        .nav-tabs .nav-link {{
            border: none;
            background: rgba(255, 255, 255, 0.7);
            margin-right: 0.5rem;
            border-radius: 10px;
            color: #2d3436;
            font-weight: 500;
        }}
        .nav-tabs .nav-link.active {{
            background: rgba(255, 255, 255, 0.95);
            color: #667eea;
        }}
    </style>
</head>
<body>
    <div class="dashboard-container">
        <div class="dashboard-header">
            <h1 class="display-4">🦈 LLMShark Advanced Analytics</h1>
            <p class="lead">State-of-the-art visualization dashboard for LLM streaming performance analysis</p>
            <small class="text-muted">Generated on {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</small>
        </div>
        
        <ul class="nav nav-tabs" id="dashboardTabs" role="tablist">
            {"".join([f'''
            <li class="nav-item" role="presentation">
                <button class="nav-link {'active' if i == 0 else ''}" 
                        id="{title.lower().replace(' ', '_')}-tab" 
                        data-bs-toggle="tab" 
                        data-bs-target="#{title.lower().replace(' ', '_')}-pane" 
                        type="button" role="tab">{title}</button>
            </li>
            ''' for i, (title, _) in enumerate(chart_divs)])}
        </ul>
        
        <div class="tab-content" id="dashboardTabContent">
            {"".join([f'''
            <div class="tab-pane fade {'show active' if i == 0 else ''}" 
                 id="{title.lower().replace(' ', '_')}-pane" 
                 role="tabpanel">
                <div class="chart-container">
                    <h3 class="chart-title">{title}</h3>
                    {chart_div}
                </div>
            </div>
            ''' for i, (title, chart_div) in enumerate(chart_divs)])}
        </div>
    </div>
    
    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.1.3/dist/js/bootstrap.bundle.min.js"></script>
    <script>
        // Make charts responsive
        window.addEventListener('resize', function() {{
            Plotly.Plots.resize();
        }});
        
        // Initialize tooltips
        var tooltipTriggerList = [].slice.call(document.querySelectorAll('[data-bs-toggle="tooltip"]'));
        var tooltipList = tooltipTriggerList.map(function (tooltipTriggerEl) {{
            return new bootstrap.Tooltip(tooltipTriggerEl);
        }});
    </script>
</body>
</html>
        """ 