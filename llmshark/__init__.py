"""
LLMShark - Comprehensive analysis tool for LLM streaming traffic from PCAP files.

This package provides tools for analyzing HTTP/SSE streaming data from Large Language
Model servers, extracting detailed timing statistics, and comparing multiple captures.
"""

__version__ = "0.1.0"
__author__ = "LLMShark Team"
__email__ = "team@llmshark.dev"

from .analyzer import StreamAnalyzer
from .models import AnalysisResult, StreamSession, StreamChunk, TimingStats
from .parser import PCAPParser
from .comparator import CaptureComparator

__all__ = [
    "StreamAnalyzer",
    "AnalysisResult",
    "StreamSession",
    "StreamChunk",
    "TimingStats",
    "PCAPParser",
    "CaptureComparator",
]
