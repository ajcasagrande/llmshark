# LLMShark Advanced Visualization Guide

## Overview

LLMShark now includes state-of-the-art visualization capabilities for comprehensive analysis of LLM streaming performance data. These modern, interactive visualizations provide deep insights into streaming behavior, performance patterns, and anomalies.

## Features

### 🎨 Interactive Dashboards
- **Real-time analysis** with live updating metrics
- **Modern UI** with responsive design and intuitive controls  
- **Multi-platform support** (Dash, Streamlit)
- **Exportable reports** in multiple formats

### 📊 Advanced Analytics
- **Performance clustering** using machine learning algorithms
- **Statistical distributions** with curve fitting
- **Correlation analysis** across multiple metrics
- **Anomaly detection** with visual highlighting

### 🖥️ Visualization Types
- **Performance Overview**: KPI dashboards with gauge charts
- **Timeline Analysis**: Interactive chunk-by-chunk analysis
- **Statistical Analysis**: Distribution fitting and correlation matrices
- **Anomaly Detection**: Outlier identification and pattern analysis

## Quick Start

### Installation

Install LLMShark with visualization dependencies:

```bash
pip install llmshark[viz]
```

Or install individual packages:

```bash
pip install plotly dash streamlit bokeh altair scikit-learn
```

### Command Line Usage

#### Launch Interactive Dashboard

```bash
# Launch Dash dashboard (recommended)
llmshark dashboard capture.pcap --port 8050

# Launch Streamlit dashboard  
llmshark dashboard capture.pcap --type streamlit --port 8501

# Multiple files with auto-open browser
llmshark dashboard *.pcap --auto-open
```

#### Generate Static Visualizations

```bash
# Generate all visualization types
llmshark visualize capture.pcap -o visualizations/

# Generate specific visualization types
llmshark visualize capture.pcap -o viz/ --type performance
llmshark visualize capture.pcap -o viz/ --type timeline
llmshark visualize capture.pcap -o viz/ --type statistics
```

#### Batch Analysis with Visualizations

```bash
# Analyze entire directory with visualizations
llmshark batch captures/ -o results/ --visualize
```

### Python API Usage

```python
from pathlib import Path
from llmshark.analyzer import StreamAnalyzer
from llmshark.advanced_visualization import AdvancedVisualizer
from llmshark.dashboard_app import launch_dashboard
from llmshark.parser import PCAPParser

# Parse and analyze
parser = PCAPParser()
sessions = parser.parse_file(Path("capture.pcap"))

analyzer = StreamAnalyzer()
result = analyzer.analyze_sessions(sessions, detect_anomalies=True)

# Create advanced visualizations
visualizer = AdvancedVisualizer()
dashboard_path = visualizer.create_interactive_dashboard(result, Path("output/"))

# Launch interactive dashboard
launch_dashboard(result, port=8050)
```

## Visualization Components

### 1. Performance Overview Dashboard

**Key Features:**
- Real-time KPI metrics (TTFT, ITL, Throughput)
- Quality score calculation
- Session comparison charts
- Performance trend analysis

**Visualizations:**
- TTFT distribution histogram with statistical overlays
- Throughput comparison across sessions
- ITL box plots for variability analysis
- Quality gauge with performance thresholds

### 2. Timeline Analysis

**Key Features:**
- Interactive chunk-by-chunk timeline
- Anomaly highlighting
- Zoom and pan capabilities
- Token count visualization

**Visualizations:**
- Scatter plot with chunk size vs. time
- Token count line chart
- Anomaly markers for outlier detection
- Interactive hover tooltips

### 3. Statistical Analysis

**Key Features:**
- Distribution fitting (normal, gamma, etc.)
- Correlation matrix analysis
- Performance clustering
- Statistical significance testing

**Visualizations:**
- Histogram with fitted distributions
- Heatmap correlation matrices
- Scatter plots with trend lines
- Box plots for comparative analysis

### 4. Anomaly Detection

**Key Features:**
- Automated outlier detection
- Pattern recognition
- Clustering analysis
- Alert visualization

**Visualizations:**
- Anomaly timeline with markers
- Clustering scatter plots
- Pattern analysis charts
- Alert summary cards

## Dashboard Features

### Interactive Controls

- **Session Filtering**: Select specific sessions for analysis
- **Time Range Selection**: Focus on specific time periods
- **Metric Filtering**: View specific performance metrics
- **Real-time Updates**: Live refresh capabilities

### Export Options

- **Chart Export**: PNG, PDF, SVG formats
- **Data Export**: CSV, JSON formats
- **Report Generation**: Comprehensive HTML reports
- **Dashboard Sharing**: Shareable URLs

### Responsive Design

- **Mobile-friendly**: Optimized for tablets and phones
- **Cross-browser**: Compatible with all modern browsers
- **Accessibility**: WCAG compliant design
- **Dark/Light Mode**: Theme switching

## Customization

### Theme Configuration

```python
from llmshark.advanced_visualization import AdvancedVisualizer

visualizer = AdvancedVisualizer()
visualizer.color_palette = {
    'primary': '#667eea',
    'secondary': '#764ba2',
    'accent': '#f093fb',
    # ... more colors
}
```

### Custom Visualizations

```python
import plotly.graph_objects as go

def create_custom_chart(result):
    fig = go.Figure()
    # Custom visualization logic
    return fig

# Add to dashboard
dashboard.add_custom_chart(create_custom_chart)
```

## Performance Metrics

### Key Performance Indicators (KPIs)

1. **Time to First Token (TTFT)**
   - Measures initial response latency
   - Target: < 500ms for good UX
   - Visualization: Histogram, trend line

2. **Inter-Token Latency (ITL)**
   - Measures consistency of token delivery
   - Target: Low variance, < 100ms mean
   - Visualization: Box plots, distribution

3. **Throughput**
   - Tokens/second delivery rate
   - Target: > 25 tokens/sec for smooth streaming
   - Visualization: Bar charts, time series

4. **Quality Score**
   - Composite performance metric (0-100)
   - Combines TTFT, ITL, throughput
   - Visualization: Gauge chart, trend

### Advanced Metrics

- **Anomaly Count**: Number of detected outliers
- **Consistency Score**: Coefficient of variation
- **Pattern Recognition**: Periodic behavior detection
- **Session Comparison**: Relative performance ranking

## Best Practices

### Dashboard Usage

1. **Start with Overview**: Review KPI dashboard first
2. **Drill Down**: Use timeline for detailed analysis
3. **Compare Sessions**: Use filtering for comparisons
4. **Export Insights**: Save key findings as reports

### Performance Analysis

1. **Baseline Establishment**: Analyze normal operation patterns
2. **Anomaly Investigation**: Focus on outliers and gaps
3. **Trend Analysis**: Look for performance degradation
4. **Optimization**: Use recommendations for improvements

### Visualization Tips

1. **Interactive Elements**: Use zoom, pan, hover for details
2. **Filter Combinations**: Combine filters for focused analysis
3. **Export Strategy**: Save visualizations for presentations
4. **Regular Monitoring**: Set up automated dashboard updates

## Troubleshooting

### Common Issues

**Dashboard Not Loading**
```bash
# Check dependencies
pip install -r requirements.txt

# Verify port availability
netstat -an | grep 8050
```

**Visualization Errors**
```bash
# Update visualization packages
pip install --upgrade plotly dash streamlit

# Check memory usage for large datasets
htop
```

**Performance Issues**
```bash
# Reduce data size for large captures
llmshark analyze large.pcap --sample-rate 0.1

# Use batch processing for multiple files
llmshark batch captures/ --parallel
```

### Debug Mode

```bash
# Enable verbose logging
llmshark dashboard capture.pcap --verbose

# Debug mode for development
llmshark dashboard capture.pcap --debug
```

## Examples

### Complete Analysis Workflow

```bash
# 1. Quick analysis with dashboard
llmshark dashboard capture.pcap

# 2. Generate comprehensive visualizations  
llmshark visualize capture.pcap -o analysis/

# 3. Batch process multiple captures
llmshark batch captures/ -o results/ --compare

# 4. Export for presentation
llmshark visualize capture.pcap -o export/ --format png
```

### Python Automation

```python
import asyncio
from pathlib import Path
from llmshark import analyze_directory, create_dashboard

async def automated_analysis():
    # Analyze all captures in directory
    results = await analyze_directory(Path("captures/"))
    
    # Create comprehensive dashboard
    dashboard = create_dashboard(results)
    
    # Export visualizations
    dashboard.export_all(Path("reports/"))
    
    # Launch for review
    dashboard.launch(port=8050)

asyncio.run(automated_analysis())
```

## Advanced Features

### Machine Learning Integration

- **Performance Clustering**: K-means, DBSCAN algorithms
- **Anomaly Detection**: Isolation Forest, Local Outlier Factor
- **Pattern Recognition**: Time series analysis
- **Predictive Analytics**: Performance forecasting

### Real-time Monitoring

- **Live Updates**: WebSocket-based real-time data
- **Alert System**: Threshold-based notifications
- **Streaming Analysis**: Continuous PCAP processing
- **Dashboard Embedding**: iframe integration

### API Integration

- **REST API**: HTTP endpoints for data access
- **GraphQL**: Flexible query interface
- **WebSocket**: Real-time data streaming
- **Plugin System**: Custom visualization extensions

## Contributing

### Adding New Visualizations

1. Create visualization function in `advanced_visualization.py`
2. Add to dashboard layout in `dashboard_app.py`
3. Update CLI commands in `cli.py`
4. Add tests and documentation

### Extending Dashboards

1. Inherit from base dashboard classes
2. Override layout and callback methods
3. Add custom styling and themes
4. Register with plugin system

## Roadmap

### Planned Features

- **3D Visualizations**: Three-dimensional performance landscapes
- **VR/AR Support**: Immersive data exploration
- **AI-Powered Insights**: Automated analysis recommendations
- **Real-time Collaboration**: Multi-user dashboard sharing

### Integration Plans

- **Jupyter Notebooks**: Interactive analysis notebooks
- **BI Tools**: Tableau, Power BI connectors
- **Monitoring Systems**: Grafana, Prometheus integration
- **Cloud Platforms**: AWS, GCP, Azure deployment

---

For more information, visit the [LLMShark Documentation](https://llmshark.readthedocs.io) or check out the [examples directory](../examples/) for hands-on tutorials. 