"""
Streamlit dashboard for interactive LLM streaming analysis.

This module provides a web-based dashboard for real-time exploration and analysis
of LLM streaming performance data with interactive controls and filters.
"""

from __future__ import annotations

import asyncio
import json
import statistics
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any, Dict, List, Optional

import numpy as np
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
import streamlit as st
from plotly.subplots import make_subplots
from sklearn.cluster import KMeans
from sklearn.preprocessing import StandardScaler

from .models import AnalysisResult, StreamSession, TimingStats
from .advanced_visualization import AdvancedVisualizer


class StreamlitDashboard:
    """Interactive Streamlit dashboard for LLM streaming analysis."""
    
    def __init__(self):
        self.visualizer = AdvancedVisualizer()
        
    def run_dashboard(self, result: AnalysisResult) -> None:
        """Run the Streamlit dashboard."""
        
        # Configure page
        st.set_page_config(
            page_title="LLMShark Analytics",
            page_icon="🦈",
            layout="wide",
            initial_sidebar_state="expanded"
        )
        
        # Custom CSS
        st.markdown("""
        <style>
        .main > div {
            padding-top: 2rem;
        }
        .stMetric {
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            padding: 1rem;
            border-radius: 10px;
            color: white;
        }
        .stSelectbox > div > div {
            background-color: #f8f9fa;
        }
        </style>
        """, unsafe_allow_html=True)
        
        # Header
        st.title("🦈 LLMShark Analytics Dashboard")
        st.markdown("**Advanced real-time analysis of LLM streaming performance**")
        
        # Sidebar controls
        self._create_sidebar(result)
        
        # Main dashboard
        self._create_main_dashboard(result)
        
    def _create_sidebar(self, result: AnalysisResult) -> None:
        """Create sidebar with controls and filters."""
        
        st.sidebar.title("🔧 Controls")
        
        # File information
        st.sidebar.markdown("### 📁 Analysis Info")
        st.sidebar.info(f"""
        **Sessions Found:** {result.session_count}  
        **Total Bytes:** {result.total_bytes_analyzed:,}  
        **Total Tokens:** {result.total_tokens_analyzed:,}  
        **Analysis Time:** {result.analysis_duration_seconds:.2f}s
        """)
        
        # Session filters
        st.sidebar.markdown("### 🎯 Session Filters")
        
        session_options = ["All Sessions"] + [
            f"Session {i+1} ({session.session_id[:8]}...)"
            for i, session in enumerate(result.sessions)
        ]
        
        selected_sessions = st.sidebar.multiselect(
            "Select Sessions:",
            session_options,
            default=["All Sessions"]
        )
        
        # Performance filters
        st.sidebar.markdown("### 📊 Performance Filters")
        
        if result.overall_timing_stats.ttft_ms:
            ttft_range = st.sidebar.slider(
                "TTFT Range (ms)",
                min_value=0,
                max_value=int(result.overall_timing_stats.ttft_ms * 2),
                value=(0, int(result.overall_timing_stats.ttft_ms * 2)),
                step=50
            )
        
        if result.overall_timing_stats.itl_values_ms:
            itl_percentile = st.sidebar.selectbox(
                "ITL Percentile View",
                ["All", "P50", "P95", "P99"],
                index=0
            )
        
        # Analysis options
        st.sidebar.markdown("### ⚙️ Analysis Options")
        
        show_anomalies = st.sidebar.checkbox("Show Anomalies", value=True)
        enable_clustering = st.sidebar.checkbox("Enable Clustering", value=False)
        real_time_updates = st.sidebar.checkbox("Real-time Updates", value=False)
        
        # Export options
        st.sidebar.markdown("### 💾 Export")
        
        if st.sidebar.button("📊 Generate Report"):
            self._generate_report(result)
            
        if st.sidebar.button("📁 Export Data"):
            self._export_data(result)
    
    def _create_main_dashboard(self, result: AnalysisResult) -> None:
        """Create main dashboard content."""
        
        # Key metrics row
        self._create_metrics_row(result)
        
        # Main visualizations
        tab1, tab2, tab3, tab4 = st.tabs([
            "📈 Performance Overview", 
            "🕒 Timeline Analysis", 
            "📊 Statistical Analysis",
            "🔍 Advanced Analytics"
        ])
        
        with tab1:
            self._create_performance_tab(result)
            
        with tab2:
            self._create_timeline_tab(result)
            
        with tab3:
            self._create_statistical_tab(result)
            
        with tab4:
            self._create_advanced_tab(result)
    
    def _create_metrics_row(self, result: AnalysisResult) -> None:
        """Create key metrics row."""
        
        col1, col2, col3, col4, col5 = st.columns(5)
        
        with col1:
            ttft_value = result.overall_timing_stats.ttft_ms or 0
            st.metric(
                "⏱️ Avg TTFT",
                f"{ttft_value:.1f}ms",
                delta=f"{ttft_value - 500:.1f}ms" if ttft_value > 0 else None
            )
        
        with col2:
            itl_value = result.overall_timing_stats.mean_itl_ms or 0
            st.metric(
                "🔄 Avg ITL",
                f"{itl_value:.1f}ms",
                delta=f"{itl_value - 100:.1f}ms" if itl_value > 0 else None
            )
        
        with col3:
            throughput = result.overall_timing_stats.tokens_per_second or 0
            st.metric(
                "🚀 Throughput",
                f"{throughput:.1f} tok/s",
                delta=f"{throughput - 25:.1f}" if throughput > 0 else None
            )
        
        with col4:
            quality_score = self.visualizer._calculate_quality_score(result)
            st.metric(
                "⭐ Quality Score",
                f"{quality_score:.0f}/100",
                delta=f"{quality_score - 75:.0f}" if quality_score > 0 else None
            )
        
        with col5:
            anomaly_count = len(result.anomalies.large_gaps) + len(result.anomalies.outlier_chunks)
            st.metric(
                "🚨 Anomalies",
                str(anomaly_count),
                delta=f"-{max(0, 5 - anomaly_count)}" if anomaly_count < 5 else f"+{anomaly_count - 5}"
            )
    
    def _create_performance_tab(self, result: AnalysisResult) -> None:
        """Create performance overview tab."""
        
        col1, col2 = st.columns(2)
        
        with col1:
            st.markdown("#### 📊 TTFT Distribution")
            ttft_values = [
                timing.ttft_ms for timing in result.per_session_timing.values()
                if timing.ttft_ms is not None
            ]
            
            if ttft_values:
                fig = px.histogram(
                    x=ttft_values,
                    nbins=20,
                    title="Time to First Token Distribution",
                    labels={'x': 'TTFT (ms)', 'y': 'Frequency'}
                )
                fig.update_layout(
                    template="plotly_white",
                    height=400
                )
                st.plotly_chart(fig, use_container_width=True)
            else:
                st.warning("No TTFT data available")
        
        with col2:
            st.markdown("#### 🎯 Session Performance")
            
            performance_data = []
            for session_id, timing in result.per_session_timing.items():
                if timing.tokens_per_second:
                    performance_data.append({
                        'Session': session_id[:10] + '...',
                        'Tokens/sec': timing.tokens_per_second,
                        'TTFT (ms)': timing.ttft_ms or 0,
                        'Mean ITL (ms)': timing.mean_itl_ms or 0
                    })
            
            if performance_data:
                df = pd.DataFrame(performance_data)
                fig = px.bar(
                    df,
                    x='Session',
                    y='Tokens/sec',
                    title="Throughput by Session",
                    color='TTFT (ms)',
                    color_continuous_scale='RdYlBu_r'
                )
                fig.update_layout(
                    template="plotly_white",
                    height=400
                )
                st.plotly_chart(fig, use_container_width=True)
        
        # ITL Analysis
        st.markdown("#### 🔄 Inter-Token Latency Analysis")
        
        col3, col4 = st.columns(2)
        
        with col3:
            all_itl_values = []
            session_labels = []
            
            for session_id, timing in result.per_session_timing.items():
                if timing.itl_values_ms:
                    all_itl_values.extend(timing.itl_values_ms)
                    session_labels.extend([session_id[:10]] * len(timing.itl_values_ms))
            
            if all_itl_values:
                fig = px.box(
                    x=session_labels,
                    y=all_itl_values,
                    title="ITL Distribution by Session"
                )
                fig.update_layout(
                    template="plotly_white",
                    height=400,
                    xaxis_title="Session",
                    yaxis_title="ITL (ms)"
                )
                st.plotly_chart(fig, use_container_width=True)
        
        with col4:
            if all_itl_values:
                # ITL percentiles
                percentiles = [50, 75, 90, 95, 99]
                percentile_values = [np.percentile(all_itl_values, p) for p in percentiles]
                
                fig = px.bar(
                    x=[f"P{p}" for p in percentiles],
                    y=percentile_values,
                    title="ITL Percentiles",
                    labels={'x': 'Percentile', 'y': 'ITL (ms)'}
                )
                fig.update_layout(
                    template="plotly_white",
                    height=400
                )
                st.plotly_chart(fig, use_container_width=True)
    
    def _create_timeline_tab(self, result: AnalysisResult) -> None:
        """Create timeline analysis tab."""
        
        st.markdown("#### 📅 Session Timeline Analysis")
        
        # Session selector
        session_names = [f"Session {i+1}" for i in range(len(result.sessions))]
        selected_session_idx = st.selectbox(
            "Select Session for Timeline:",
            range(len(result.sessions)),
            format_func=lambda x: session_names[x]
        )
        
        if selected_session_idx < len(result.sessions):
            session = result.sessions[selected_session_idx]
            
            if session.chunks:
                # Create timeline visualization
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
                
                col1, col2 = st.columns(2)
                
                with col1:
                    fig = px.scatter(
                        df,
                        x='Time (s)',
                        y='Chunk Size (bytes)',
                        size='Token Count',
                        hover_data=['Chunk #'],
                        title="Chunk Size Timeline"
                    )
                    fig.update_layout(template="plotly_white", height=400)
                    st.plotly_chart(fig, use_container_width=True)
                
                with col2:
                    fig = px.line(
                        df,
                        x='Time (s)',
                        y='Token Count',
                        title="Token Count Timeline",
                        markers=True
                    )
                    fig.update_layout(template="plotly_white", height=400)
                    st.plotly_chart(fig, use_container_width=True)
                
                # Summary statistics
                st.markdown("#### 📈 Timeline Statistics")
                
                col3, col4, col5 = st.columns(3)
                
                with col3:
                    st.metric("Total Chunks", len(session.chunks))
                    st.metric("Avg Chunk Size", f"{df['Chunk Size (bytes)'].mean():.1f} bytes")
                
                with col4:
                    st.metric("Total Duration", f"{df['Time (s)'].max():.2f}s")
                    st.metric("Avg Tokens/Chunk", f"{df['Token Count'].mean():.1f}")
                
                with col5:
                    chunk_intervals = df['Time (s)'].diff().dropna()
                    if len(chunk_intervals) > 0:
                        st.metric("Avg Interval", f"{chunk_intervals.mean():.3f}s")
                        st.metric("Interval Std", f"{chunk_intervals.std():.3f}s")
                
                # Data table
                with st.expander("📋 Detailed Timeline Data"):
                    st.dataframe(df, use_container_width=True)
    
    def _create_statistical_tab(self, result: AnalysisResult) -> None:
        """Create statistical analysis tab."""
        
        st.markdown("#### 📊 Statistical Analysis")
        
        # Correlation analysis
        metrics_data = self._prepare_metrics_dataframe(result)
        
        if not metrics_data.empty:
            col1, col2 = st.columns(2)
            
            with col1:
                st.markdown("##### 🔗 Correlation Matrix")
                correlation_matrix = metrics_data.corr()
                
                fig = px.imshow(
                    correlation_matrix,
                    text_auto=True,
                    aspect="auto",
                    title="Performance Metrics Correlation",
                    color_continuous_scale='RdBu_r'
                )
                fig.update_layout(height=500)
                st.plotly_chart(fig, use_container_width=True)
            
            with col2:
                st.markdown("##### 📈 Distribution Analysis")
                
                metric_to_analyze = st.selectbox(
                    "Select Metric:",
                    metrics_data.columns.tolist()
                )
                
                if metric_to_analyze:
                    values = metrics_data[metric_to_analyze].dropna()
                    
                    if len(values) > 0:
                        fig = px.histogram(
                            x=values,
                            nbins=20,
                            title=f"{metric_to_analyze} Distribution",
                            marginal="box"
                        )
                        fig.update_layout(
                            template="plotly_white",
                            height=400
                        )
                        st.plotly_chart(fig, use_container_width=True)
                        
                        # Statistics
                        st.markdown(f"**{metric_to_analyze} Statistics:**")
                        col_a, col_b, col_c = st.columns(3)
                        
                        with col_a:
                            st.metric("Mean", f"{values.mean():.2f}")
                            st.metric("Median", f"{values.median():.2f}")
                        
                        with col_b:
                            st.metric("Std Dev", f"{values.std():.2f}")
                            st.metric("Min", f"{values.min():.2f}")
                        
                        with col_c:
                            st.metric("Max", f"{values.max():.2f}")
                            st.metric("Range", f"{values.max() - values.min():.2f}")
    
    def _create_advanced_tab(self, result: AnalysisResult) -> None:
        """Create advanced analytics tab."""
        
        st.markdown("#### 🔍 Advanced Analytics")
        
        # Anomaly detection
        col1, col2 = st.columns(2)
        
        with col1:
            st.markdown("##### 🚨 Anomaly Detection")
            
            if result.anomalies.large_gaps:
                st.warning(f"Found {len(result.anomalies.large_gaps)} large gaps")
                
                gap_data = []
                for gap in result.anomalies.large_gaps:
                    gap_data.append({
                        'Session': gap.get('session_id', 'Unknown')[:10],
                        'Start Time': gap.get('start_time', 'Unknown'),
                        'Duration (ms)': gap.get('duration_ms', 0)
                    })
                
                if gap_data:
                    df_gaps = pd.DataFrame(gap_data)
                    st.dataframe(df_gaps, use_container_width=True)
            
            if result.anomalies.outlier_chunks:
                st.warning(f"Found {len(result.anomalies.outlier_chunks)} outlier chunks")
                
                outlier_info = pd.DataFrame({
                    'Chunk Index': result.anomalies.outlier_chunks,
                    'Type': ['Outlier'] * len(result.anomalies.outlier_chunks)
                })
                st.dataframe(outlier_info, use_container_width=True)
        
        with col2:
            st.markdown("##### 🎯 Performance Clustering")
            
            metrics_data = self._prepare_metrics_dataframe(result)
            
            if len(metrics_data) >= 3:
                # Prepare clustering data
                features = ['ttft_ms', 'mean_itl_ms', 'tokens_per_second']
                available_features = [f for f in features if f in metrics_data.columns]
                
                if len(available_features) >= 2:
                    clustering_data = metrics_data[available_features].dropna()
                    
                    if len(clustering_data) >= 3:
                        # Apply clustering
                        scaler = StandardScaler()
                        scaled_data = scaler.fit_transform(clustering_data)
                        
                        n_clusters = min(3, len(clustering_data))
                        kmeans = KMeans(n_clusters=n_clusters, random_state=42)
                        cluster_labels = kmeans.fit_predict(scaled_data)
                        
                        # Visualize clusters
                        if len(available_features) >= 2:
                            fig = px.scatter(
                                x=clustering_data.iloc[:, 0],
                                y=clustering_data.iloc[:, 1],
                                color=cluster_labels,
                                title="Performance Clusters",
                                labels={
                                    'x': available_features[0],
                                    'y': available_features[1]
                                }
                            )
                            fig.update_layout(
                                template="plotly_white",
                                height=400
                            )
                            st.plotly_chart(fig, use_container_width=True)
                        
                        # Cluster summary
                        cluster_summary = pd.DataFrame({
                            'Cluster': cluster_labels,
                            'Session': clustering_data.index[:len(cluster_labels)]
                        })
                        
                        st.markdown("**Cluster Assignments:**")
                        st.dataframe(cluster_summary, use_container_width=True)
        
        # Performance insights
        st.markdown("##### 💡 Key Insights")
        
        insights_col1, insights_col2 = st.columns(2)
        
        with insights_col1:
            st.markdown("**Automated Insights:**")
            for insight in result.key_insights:
                st.info(f"💡 {insight}")
        
        with insights_col2:
            st.markdown("**Recommendations:**")
            for recommendation in result.recommendations:
                st.success(f"🎯 {recommendation}")
    
    def _prepare_metrics_dataframe(self, result: AnalysisResult) -> pd.DataFrame:
        """Prepare metrics dataframe for analysis."""
        
        metrics_data = []
        
        for session_id, timing in result.per_session_timing.items():
            session = next((s for s in result.sessions if s.session_id == session_id), None)
            if not session:
                continue
            
            row = {
                'session_id': session_id,
                'ttft_ms': timing.ttft_ms,
                'mean_itl_ms': timing.mean_itl_ms,
                'median_itl_ms': timing.median_itl_ms,
                'std_itl_ms': timing.std_itl_ms,
                'tokens_per_second': timing.tokens_per_second,
                'bytes_per_second': timing.bytes_per_second,
                'total_tokens': session.total_tokens,
                'total_bytes': session.total_bytes,
                'chunk_count': len(session.chunks),
                'duration_seconds': session.duration_seconds
            }
            metrics_data.append(row)
        
        return pd.DataFrame(metrics_data).set_index('session_id')
    
    def _generate_report(self, result: AnalysisResult) -> None:
        """Generate comprehensive report."""
        
        report_data = {
            'summary': {
                'sessions': result.session_count,
                'total_bytes': result.total_bytes_analyzed,
                'total_tokens': result.total_tokens_analyzed,
                'analysis_duration': result.analysis_duration_seconds
            },
            'performance': {
                'avg_ttft_ms': result.overall_timing_stats.ttft_ms,
                'avg_itl_ms': result.overall_timing_stats.mean_itl_ms,
                'throughput_tps': result.overall_timing_stats.tokens_per_second
            },
            'anomalies': {
                'large_gaps': len(result.anomalies.large_gaps),
                'outlier_chunks': len(result.anomalies.outlier_chunks),
                'unusual_patterns': len(result.anomalies.unusual_patterns)
            }
        }
        
        st.download_button(
            label="📊 Download Report",
            data=json.dumps(report_data, indent=2),
            file_name=f"llmshark_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json",
            mime="application/json"
        )
        
        st.success("Report generated successfully!")
    
    def _export_data(self, result: AnalysisResult) -> None:
        """Export data to CSV."""
        
        metrics_df = self._prepare_metrics_dataframe(result)
        
        csv_data = metrics_df.to_csv(index=True)
        
        st.download_button(
            label="📁 Download CSV",
            data=csv_data,
            file_name=f"llmshark_data_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv",
            mime="text/csv"
        )
        
        st.success("Data exported successfully!")


def launch_dashboard(result: AnalysisResult, port: int = 8501) -> None:
    """Launch the Streamlit dashboard."""
    
    import subprocess
    import sys
    
    dashboard = StreamlitDashboard()
    
    # Save result for dashboard access
    result_path = Path("temp_analysis_result.json")
    with open(result_path, 'w') as f:
        # This would need proper serialization
        pass
    
    # Launch Streamlit
    subprocess.run([
        sys.executable, "-m", "streamlit", "run", 
        __file__, "--server.port", str(port)
    ])


if __name__ == "__main__":
    # This would be called when running the dashboard directly
    st.error("Dashboard needs to be launched through the main LLMShark CLI") 