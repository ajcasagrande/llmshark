#!/usr/bin/env python3
"""
Advanced Visualization Demo for LLMShark

This example demonstrates the state-of-the-art visualization capabilities
including interactive dashboards, statistical analysis, and performance analytics.
"""

from pathlib import Path
from typing import List

from llmshark.analyzer import StreamAnalyzer
from llmshark.advanced_visualization import AdvancedVisualizer
from llmshark.dashboard_app import launch_dashboard
from llmshark.models import AnalysisResult
from llmshark.parser import PCAPParser
from llmshark.streamlit_dashboard import StreamlitDashboard


def run_visualization_demo(pcap_files: List[Path], output_dir: Path) -> None:
    """Run comprehensive visualization demo."""
    
    print("🦈 LLMShark Advanced Visualization Demo")
    print("=" * 50)
    
    # 1. Parse PCAP files
    print("\n📁 Step 1: Parsing PCAP files...")
    parser = PCAPParser()
    all_sessions = []
    
    for pcap_file in pcap_files:
        print(f"  • Processing {pcap_file.name}")
        sessions = parser.parse_file(pcap_file)
        all_sessions.extend(sessions)
        print(f"    Found {len(sessions)} streaming sessions")
    
    if not all_sessions:
        print("❌ No streaming sessions found!")
        return
    
    print(f"✅ Total sessions found: {len(all_sessions)}")
    
    # 2. Analyze sessions
    print("\n🔬 Step 2: Analyzing streaming performance...")
    analyzer = StreamAnalyzer()
    result = analyzer.analyze_sessions(all_sessions, detect_anomalies=True)
    
    print(f"  • Session count: {result.session_count}")
    print(f"  • Total tokens: {result.total_tokens_analyzed:,}")
    print(f"  • Total bytes: {result.total_bytes_analyzed:,}")
    print(f"  • Analysis duration: {result.analysis_duration_seconds:.2f}s")
    
    if result.overall_timing_stats.ttft_ms:
        print(f"  • Average TTFT: {result.overall_timing_stats.ttft_ms:.1f}ms")
    if result.overall_timing_stats.mean_itl_ms:
        print(f"  • Average ITL: {result.overall_timing_stats.mean_itl_ms:.1f}ms")
    if result.overall_timing_stats.tokens_per_second:
        print(f"  • Throughput: {result.overall_timing_stats.tokens_per_second:.1f} tokens/sec")
    
    # 3. Generate advanced visualizations
    print("\n🎨 Step 3: Creating state-of-the-art visualizations...")
    
    output_dir.mkdir(parents=True, exist_ok=True)
    visualizer = AdvancedVisualizer()
    
    # Interactive Dashboard
    print("  • Creating interactive dashboard...")
    dashboard_path = visualizer.create_interactive_dashboard(result, output_dir)
    print(f"    ✅ Dashboard saved: {dashboard_path}")
    
    # Performance Overview
    print("  • Generating performance overview...")
    performance_fig = visualizer._create_performance_overview(result)
    performance_path = output_dir / "performance_overview.html"
    performance_fig.write_html(str(performance_path))
    print(f"    ✅ Performance overview: {performance_path}")
    
    # Timeline Analysis
    print("  • Creating timeline analysis...")
    timeline_fig = visualizer._create_advanced_timeline(result)
    timeline_path = output_dir / "timeline_analysis.html"
    timeline_fig.write_html(str(timeline_path))
    print(f"    ✅ Timeline analysis: {timeline_path}")
    
    # Statistical Analysis
    print("  • Generating statistical distributions...")
    stats_fig = visualizer._create_statistical_distributions(result)
    stats_path = output_dir / "statistical_analysis.html"
    stats_fig.write_html(str(stats_path))
    print(f"    ✅ Statistical analysis: {stats_path}")
    
    # Anomaly Detection
    print("  • Creating anomaly detection visualizations...")
    anomaly_fig = visualizer._create_anomaly_detection_viz(result)
    anomaly_path = output_dir / "anomaly_detection.html"
    anomaly_fig.write_html(str(anomaly_path))
    print(f"    ✅ Anomaly detection: {anomaly_path}")
    
    # Correlation Analysis
    print("  • Building correlation matrix...")
    correlation_fig = visualizer._create_correlation_matrix(result)
    correlation_path = output_dir / "correlation_matrix.html"
    correlation_fig.write_html(str(correlation_path))
    print(f"    ✅ Correlation matrix: {correlation_path}")
    
    # Performance Clustering
    print("  • Performing performance clustering...")
    clustering_fig = visualizer._create_performance_clustering(result)
    clustering_path = output_dir / "performance_clustering.html"
    clustering_fig.write_html(str(clustering_path))
    print(f"    ✅ Performance clustering: {clustering_path}")
    
    # 4. Display summary
    print("\n📊 Step 4: Visualization Summary")
    print("-" * 30)
    
    quality_score = visualizer._calculate_quality_score(result)
    print(f"🌟 Overall Quality Score: {quality_score:.0f}/100")
    
    if result.anomalies.large_gaps:
        print(f"⚠️  Large gaps detected: {len(result.anomalies.large_gaps)}")
    
    if result.anomalies.outlier_chunks:
        print(f"🔍 Outlier chunks found: {len(result.anomalies.outlier_chunks)}")
    
    # Key insights
    if result.key_insights:
        print("\n💡 Key Insights:")
        for insight in result.key_insights[:3]:  # Show top 3
            print(f"  • {insight}")
    
    # Recommendations
    if result.recommendations:
        print("\n🎯 Top Recommendations:")
        for rec in result.recommendations[:3]:  # Show top 3
            print(f"  • {rec}")
    
    print(f"\n✅ All visualizations saved to: {output_dir}")
    print("\n🚀 Next Steps:")
    print("  1. Open the interactive dashboard in your browser")
    print("  2. Explore individual visualization files")
    print("  3. Use the CLI dashboard command for real-time analysis:")
    print(f"     llmshark dashboard {' '.join(str(f) for f in pcap_files)}")
    
    return result


def demonstrate_dashboard_features(result: AnalysisResult) -> None:
    """Demonstrate dashboard features."""
    
    print("\n🖥️  Dashboard Features Demo")
    print("=" * 30)
    
    print("Available dashboard types:")
    print("  • Dash (default) - Advanced interactive components")
    print("  • Streamlit - User-friendly interface")
    
    print("\nKey features:")
    print("  📊 Real-time performance metrics")
    print("  🕒 Interactive timeline analysis")
    print("  📈 Statistical distributions")
    print("  🔍 Anomaly detection with clustering")
    print("  🎯 Performance correlation analysis")
    print("  📋 Exportable reports and data")
    
    print("\nInteractive capabilities:")
    print("  • Filter by session, time range, metrics")
    print("  • Zoom, pan, hover for detailed data")
    print("  • Real-time updates and refresh")
    print("  • Export charts as PNG, PDF, HTML")
    print("  • CSV data export for further analysis")


def create_sample_report(result: AnalysisResult, output_dir: Path) -> None:
    """Create sample analysis report."""
    
    report = {
        "llmshark_analysis_report": {
            "metadata": {
                "version": "1.0",
                "generated_at": "2024-01-20T10:30:00Z",
                "analysis_type": "streaming_performance"
            },
            "summary": {
                "sessions_analyzed": result.session_count,
                "total_tokens": result.total_tokens_analyzed,
                "total_bytes": result.total_bytes_analyzed,
                "analysis_duration_seconds": result.analysis_duration_seconds
            },
            "performance_metrics": {
                "ttft_ms": result.overall_timing_stats.ttft_ms,
                "mean_itl_ms": result.overall_timing_stats.mean_itl_ms,
                "median_itl_ms": result.overall_timing_stats.median_itl_ms,
                "tokens_per_second": result.overall_timing_stats.tokens_per_second,
                "bytes_per_second": result.overall_timing_stats.bytes_per_second
            },
            "anomalies": {
                "large_gaps_count": len(result.anomalies.large_gaps),
                "outlier_chunks_count": len(result.anomalies.outlier_chunks),
                "unusual_patterns": result.anomalies.unusual_patterns
            },
            "insights": result.key_insights,
            "recommendations": result.recommendations
        }
    }
    
    import json
    report_path = output_dir / "analysis_report.json"
    with open(report_path, 'w') as f:
        json.dump(report, f, indent=2, default=str)
    
    print(f"📋 Analysis report saved: {report_path}")


if __name__ == "__main__":
    import argparse
    import sys
    
    parser = argparse.ArgumentParser(
        description="LLMShark Advanced Visualization Demo"
    )
    parser.add_argument(
        "pcap_files",
        nargs="+",
        type=Path,
        help="PCAP files to analyze"
    )
    parser.add_argument(
        "--output-dir",
        "-o",
        type=Path,
        default=Path("demo_output"),
        help="Output directory for visualizations"
    )
    parser.add_argument(
        "--launch-dashboard",
        action="store_true",
        help="Launch interactive dashboard after analysis"
    )
    parser.add_argument(
        "--port",
        type=int,
        default=8050,
        help="Port for dashboard (default: 8050)"
    )
    
    args = parser.parse_args()
    
    # Validate input files
    valid_files = []
    for pcap_file in args.pcap_files:
        if pcap_file.exists() and pcap_file.is_file():
            valid_files.append(pcap_file)
        else:
            print(f"❌ File not found: {pcap_file}")
    
    if not valid_files:
        print("❌ No valid PCAP files provided!")
        sys.exit(1)
    
    # Run demo
    try:
        result = run_visualization_demo(valid_files, args.output_dir)
        
        demonstrate_dashboard_features(result)
        create_sample_report(result, args.output_dir)
        
        if args.launch_dashboard:
            print(f"\n🚀 Launching dashboard on port {args.port}...")
            launch_dashboard(result, args.port)
        
    except KeyboardInterrupt:
        print("\n⏹️  Demo interrupted by user")
    except Exception as e:
        print(f"❌ Demo error: {e}")
        sys.exit(1) 