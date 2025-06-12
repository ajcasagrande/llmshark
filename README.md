# 🦈 LLMShark

**Comprehensive analysis tool for LLM streaming traffic from PCAP files**

[![Python 3.10+](https://img.shields.io/badge/python-3.10+-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Code style: black](https://img.shields.io/badge/code%20style-black-000000.svg)](https://github.com/psf/black)
[![Ruff](https://img.shields.io/endpoint?url=https://raw.githubusercontent.com/charliermarsh/ruff/main/assets/badge/v2.json)](https://github.com/astral-sh/ruff)

LLMShark is a powerful tool for analyzing Large Language Model (LLM) streaming traffic captured in PCAP files. It provides in-depth analysis of HTTP/SSE (Server-Sent Events) streaming sessions, extracting detailed timing statistics, detecting anomalies, and generating comprehensive reports.

## ✨ Features

### 🔍 **Deep Analysis**
- **Time to First Token (TTFT)** analysis
- **Inter-Token Latency (ITL)** measurement and statistics
- HTTP session reconstruction from PCAP files
- SSE chunk parsing and timing analysis
- Throughput and performance metrics

### 🚨 **Anomaly Detection**
- Large timing gaps detection
- Silence period identification
- Statistical outlier detection
- Pattern anomaly recognition
- Configurable thresholds

### 📊 **Comparison & Reporting**
- Multi-capture comparison analysis
- Performance ranking and scoring
- Statistical significance testing
- HTML and JSON report generation
- Interactive visualizations (optional)

### 🎨 **Beautiful CLI**
- Rich terminal interface with colors and progress bars
- Multiple output formats (console, JSON, HTML)
- Batch processing capabilities
- Verbose and quiet modes

## 🚀 Installation

### From PyPI (Recommended)
```bash
pip install llmshark
```

### From Source
```bash
git clone https://github.com/llmshark/llmshark.git
cd llmshark
pip install -e .
```

### Development Installation
```bash
git clone https://github.com/llmshark/llmshark.git
cd llmshark
pip install -e ".[dev]"
```

### With Visualization Support
```bash
pip install "llmshark[viz]"
```

## 📋 Requirements

- Python 3.10 or higher
- Wireshark PCAP files containing HTTP/SSE traffic
- Root privileges may be required for live packet capture

### Dependencies
- **Core**: `scapy`, `pydantic`, `rich`, `typer`, `numpy`, `pandas`, `scipy`
- **Visualization**: `matplotlib`, `seaborn`, `plotly` (optional)
- **Development**: `pytest`, `black`, `ruff`, `mypy` (optional)

## 🎯 Quick Start

### Basic Analysis
```bash
# Analyze a single PCAP file
llmshark analyze capture.pcap

# Analyze multiple files with detailed output
llmshark analyze *.pcap --verbose

# Save results to files
llmshark analyze capture.pcap --output-dir ./results --format all
```

### Comparison Analysis
```bash
# Compare multiple captures
llmshark analyze session1.pcap session2.pcap --compare

# Batch process directory
llmshark batch ./pcap_files/ --output-dir ./analysis_results
```

### Quick File Information
```bash
# Get PCAP file information without full analysis
llmshark info capture.pcap
```

## 📖 Usage Examples

### Single File Analysis
```bash
llmshark analyze llm_session.pcap --output-dir ./results --format html
```

### Multi-File Comparison
```bash
llmshark analyze before_optimization.pcap after_optimization.pcap \
  --compare --output-dir ./comparison --verbose
```

### Batch Processing
```bash
llmshark batch ./captures/ --output-dir ./analysis \
  --recursive --pattern "*.pcap"
```

### Custom Configuration
```bash
llmshark analyze capture.pcap \
  --detect-anomalies \
  --format json \
  --output-dir ./results \
  --verbose
```

## 🏗️ Architecture

LLMShark is built with modern Python practices and consists of several key components:

```
llmshark/
├── models.py          # Pydantic data models
├── parser.py          # PCAP parsing and session extraction
├── analyzer.py        # Statistical analysis and anomaly detection
├── comparator.py      # Multi-capture comparison logic
├── visualization.py   # Charts and HTML report generation
└── cli.py            # Command-line interface
```

### Key Models
- **StreamSession**: Complete HTTP streaming session
- **StreamChunk**: Individual SSE data chunk
- **TimingStats**: Comprehensive timing statistics
- **AnalysisResult**: Complete analysis results
- **ComparisonReport**: Multi-capture comparison results

## 📊 Analysis Metrics

### Timing Metrics
- **TTFT (Time to First Token)**: Time from request to first response chunk
- **ITL (Inter-Token Latency)**: Time between consecutive tokens
- **Mean, Median, P95, P99**: Statistical distributions
- **Throughput**: Tokens per second, bytes per second

### Quality Metrics
- **Consistency**: Variance and coefficient of variation
- **Reliability**: Gap detection and silence periods
- **Performance**: Comparative scoring across sessions

### Anomaly Detection
- **Large Gaps**: Configurable threshold for timing gaps
- **Silence Periods**: Detection of inactive periods
- **Statistical Outliers**: Z-score based outlier detection
- **Pattern Analysis**: Unusual behavior identification

## 🔧 Configuration

### Environment Variables
```bash
export LLMSHARK_LOG_LEVEL=INFO
export LLMSHARK_OUTPUT_DIR=./results
export LLMSHARK_ANOMALY_THRESHOLD=3.0
```

### Command Line Options
```bash
llmshark analyze --help
```

## 📈 Output Formats

### Console Output
Rich terminal interface with:
- Summary statistics tables
- Performance insights
- Anomaly warnings
- Recommendations

### JSON Output
```json
{
  "session_count": 5,
  "total_tokens_analyzed": 1250,
  "overall_timing_stats": {
    "ttft_ms": 245.6,
    "mean_itl_ms": 67.8,
    "p95_itl_ms": 124.5
  },
  "key_insights": [...],
  "recommendations": [...]
}
```

### HTML Reports
- Interactive charts and graphs
- Detailed session breakdowns
- Comparison tables
- Exportable results

## 🧪 Testing

Run the test suite:
```bash
# Run all tests
pytest

# Run with coverage
pytest --cov=llmshark

# Run only unit tests
pytest -m unit

# Run only integration tests
pytest -m integration
```

## 🤝 Contributing

We welcome contributions! Please see our [Contributing Guide](CONTRIBUTING.md) for details.

### Development Setup
```bash
git clone https://github.com/llmshark/llmshark.git
cd llmshark
pip install -e ".[dev]"
pre-commit install
```

### Code Quality
- **Code Formatting**: `black` and `ruff`
- **Type Checking**: `mypy`
- **Testing**: `pytest` with coverage
- **Pre-commit Hooks**: Automated quality checks

## 📝 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🙏 Acknowledgments

- **Scapy**: For powerful packet analysis capabilities
- **Pydantic**: For robust data validation and modeling
- **Rich**: For beautiful terminal interfaces
- **Typer**: For excellent CLI framework

## 📚 Documentation

- [User Guide](docs/user-guide.md)
- [API Reference](docs/api-reference.md)
- [Examples](docs/examples.md)
- [Troubleshooting](docs/troubleshooting.md)

## 🐛 Bug Reports & Feature Requests

Please use the [GitHub Issues](https://github.com/llmshark/llmshark/issues) page to report bugs or request features.

## 📊 Performance

LLMShark is designed for efficiency:
- Streams processing for large PCAP files
- Memory-efficient chunk processing
- Parallel analysis capabilities
- Optimized for Python 3.10+ features

## 🔮 Roadmap

- [ ] Real-time capture analysis
- [ ] WebUI dashboard
- [ ] Plugin system for custom analyzers
- [ ] Machine learning anomaly detection
- [ ] Distributed analysis capabilities
- [ ] Integration with monitoring systems

---

**Made with ❤️ for the LLM and networking communities**
