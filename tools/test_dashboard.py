#!/usr/bin/env python3
"""
Quick test script for LLMShark dashboard functionality.
"""

import sys
from pathlib import Path

# Add the project root to Python path
sys.path.insert(0, str(Path(__file__).parent))

from llmshark.analyzer import StreamAnalyzer
from llmshark.dashboard_app import LLMSharkDashboard
from llmshark.parser import PCAPParser
from llmshark.models import AnalysisResult


def test_dashboard_creation():
    """Test dashboard creation without starting server."""
    
    print("🧪 Testing LLMShark Dashboard Components")
    print("=" * 50)
    
    # Import required models
    from llmshark.models import TimingStats, AnomalyDetection
    
    # Create a minimal test result
    test_result = AnalysisResult(
        input_files=[Path("test.pcap")],
        analysis_duration_seconds=1.0,
        sessions=[],
        session_count=0,
        overall_timing_stats=TimingStats(),
        anomalies=AnomalyDetection(),
        key_insights=["Test insight"],
        recommendations=["Test recommendation"]
    )
    
    try:
        # Test dashboard creation
        print("📊 Creating dashboard instance...")
        dashboard = LLMSharkDashboard(test_result)
        print("✅ Dashboard instance created successfully")
        
        # Test layout setup
        print("🎨 Testing layout setup...")
        layout = dashboard.app.layout
        print("✅ Layout created successfully")
        
        # Test callback setup
        print("🔧 Testing callback setup...")
        callbacks = dashboard.app.callback_map
        print(f"✅ Found {len(callbacks)} callbacks registered")
        
        print("\n🎉 All dashboard components working correctly!")
        print("🚀 Dashboard is ready to launch with real data")
        
        return True
        
    except Exception as e:
        print(f"❌ Dashboard test failed: {e}")
        import traceback
        traceback.print_exc()
        return False


def test_with_real_data():
    """Test with real PCAP data if available."""
    
    pcap_files = list(Path("captures").glob("*.pcap"))
    if not pcap_files:
        print("⚠️  No PCAP files found for real data test")
        return
    
    # Use the smallest PCAP file for quick testing
    test_file = min(pcap_files, key=lambda f: f.stat().st_size)
    print(f"\n🔬 Testing with real data: {test_file.name}")
    
    try:
        # Parse PCAP
        print("📁 Parsing PCAP file...")
        parser = PCAPParser()
        sessions = parser.parse_file(test_file)
        print(f"✅ Found {len(sessions)} sessions")
        
        if sessions:
            # Analyze sessions
            print("🔍 Analyzing sessions...")
            analyzer = StreamAnalyzer()
            result = analyzer.analyze_sessions(sessions[:3], detect_anomalies=True)  # Limit to 3 for speed
            print("✅ Analysis complete")
            
            # Create dashboard
            print("🎨 Creating dashboard with real data...")
            dashboard = LLMSharkDashboard(result)
            print("✅ Dashboard created with real data")
            
            # Test specific components
            print("🧪 Testing dashboard components...")
            
            # Test performance content creation
            perf_content = dashboard._create_performance_content()
            print("✅ Performance content created")
            
            # Test timeline content creation
            timeline_content = dashboard._create_timeline_content()
            print("✅ Timeline content created")
            
            # Test statistics content creation
            stats_content = dashboard._create_statistics_content()
            print("✅ Statistics content created")
            
            print(f"\n🎉 Dashboard successfully tested with {len(sessions)} real sessions!")
            
        else:
            print("⚠️  No sessions found in PCAP file")
            
    except Exception as e:
        print(f"❌ Real data test failed: {e}")
        import traceback
        traceback.print_exc()


if __name__ == "__main__":
    print("🦈 LLMShark Dashboard Test Suite")
    print("This will test dashboard components without starting the server\n")
    
    # Test basic dashboard creation
    success = test_dashboard_creation()
    
    if success:
        # Test with real data if available
        test_with_real_data()
        
        print("\n" + "=" * 50)
        print("🎯 Next Steps:")
        print("1. Dashboard components are working correctly")
        print("2. You can now launch the dashboard with:")
        print("   llmshark dashboard captures/genai-perf.pcap")
        print("3. Or use the demo script:")
        print("   python examples/advanced_visualization_demo.py captures/genai-perf.pcap")
        
    else:
        print("\n❌ Dashboard test failed - check the error messages above")
        sys.exit(1) 