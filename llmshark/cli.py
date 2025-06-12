"""
Command-line interface for LLMShark.

This module provides a rich terminal interface for analyzing LLM streaming
traffic from PCAP files with comprehensive reporting and visualization.
"""

import json
from pathlib import Path
from typing import List, Optional

import typer
from rich.console import Console
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn
from rich.table import Table
from rich.text import Text
from rich.tree import Tree

from . import __version__
from .analyzer import StreamAnalyzer
from .comparator import CaptureComparator
from .models import AnalysisResult, ComparisonReport
from .parser import PCAPParser, find_pcap_files

try:
    from .visualization import (
        create_timing_charts,
        create_comparison_charts,
        save_html_report,
    )
except ImportError:
    # Visualization dependencies not available
    def create_timing_charts(*args, **kwargs):
        return []

    def create_comparison_charts(*args, **kwargs):
        return []

    def save_html_report(*args, **kwargs):
        pass


app = typer.Typer(
    name="llmshark",
    help="🦈 Comprehensive analysis tool for LLM streaming traffic from PCAP files",
    rich_markup_mode="rich",
    add_completion=False,
)

console = Console()


def version_callback(value: bool) -> None:
    """Show version and exit."""
    if value:
        console.print(
            f"[bold blue]LLMShark[/bold blue] version [green]{__version__}[/green]"
        )
        raise typer.Exit()


@app.command()
def analyze(
    pcap_files: List[Path] = typer.Argument(
        ...,
        help="One or more PCAP files to analyze",
        exists=True,
        file_okay=True,
        dir_okay=False,
        readable=True,
    ),
    output_dir: Optional[Path] = typer.Option(
        None,
        "--output-dir",
        "-o",
        help="Directory to save analysis results",
        file_okay=False,
        dir_okay=True,
        writable=True,
    ),
    output_format: str = typer.Option(
        "console",
        "--format",
        "-f",
        help="Output format: console, json, html, all",
        case_sensitive=False,
    ),
    detect_anomalies: bool = typer.Option(
        True,
        "--detect-anomalies/--no-detect-anomalies",
        help="Enable or disable anomaly detection",
    ),
    compare_sessions: bool = typer.Option(
        True,
        "--compare/--no-compare",
        help="Compare sessions when multiple are found",
    ),
    verbose: bool = typer.Option(
        False,
        "--verbose",
        "-v",
        help="Enable verbose output",
    ),
    version: Optional[bool] = typer.Option(
        None,
        "--version",
        callback=version_callback,
        is_eager=True,
        help="Show version and exit",
    ),
) -> None:
    """
    🔍 Analyze LLM streaming traffic from PCAP files.

    This command performs comprehensive analysis of HTTP/SSE streaming sessions,
    extracting timing statistics, detecting anomalies, and generating insights.

    Examples:
        llmshark analyze capture.pcap
        llmshark analyze *.pcap --output-dir ./results --format html
        llmshark analyze session1.pcap session2.pcap --compare
    """
    try:
        # Validate input files
        validated_files = _validate_pcap_files(pcap_files)
        if not validated_files:
            console.print("[red]❌ No valid PCAP files found![/red]")
            raise typer.Exit(1)

        # Setup output directory
        if output_dir:
            output_dir.mkdir(parents=True, exist_ok=True)

        # Parse PCAP files
        console.print("[bold blue]🦈 LLMShark Analysis Starting[/bold blue]")
        console.print(f"📁 Analyzing {len(validated_files)} PCAP file(s)")

        sessions = _parse_pcap_files(validated_files, verbose)

        if not sessions:
            console.print(
                "[yellow]⚠️  No streaming sessions found in PCAP files[/yellow]"
            )
            console.print(
                "\n[dim]Make sure your PCAP files contain HTTP/SSE streaming traffic.[/dim]"
            )
            raise typer.Exit(0)

        # Analyze sessions
        analyzer = StreamAnalyzer()
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            console=console,
        ) as progress:
            task = progress.add_task("🔬 Analyzing streaming sessions...", total=None)
            result = analyzer.analyze_sessions(
                sessions, detect_anomalies=detect_anomalies
            )
            progress.update(task, description="✅ Analysis complete!")

        # Display results
        if output_format.lower() in ["console", "all"]:
            _display_analysis_console(result, verbose)

        # Compare captures if multiple files provided
        comparison_report = None
        if len(validated_files) > 1 and compare_sessions:
            comparator = CaptureComparator()
            # For simplicity, treat each file as a separate capture
            file_results = []
            for pcap_file in validated_files:
                file_sessions = [s for s in sessions if s.capture_file == pcap_file]
                if file_sessions:
                    file_analyzer = StreamAnalyzer()
                    file_result = file_analyzer.analyze_sessions(
                        file_sessions, detect_anomalies=False
                    )
                    file_results.append(file_result)

            if len(file_results) > 1:
                comparison_report = comparator.compare_captures(file_results)
                if output_format.lower() in ["console", "all"]:
                    _display_comparison_console(comparison_report, verbose)

        # Save results to files
        if output_dir and output_format.lower() in ["json", "all"]:
            _save_json_results(result, comparison_report, output_dir)

        if output_dir and output_format.lower() in ["html", "all"]:
            _save_html_results(result, comparison_report, output_dir)

        console.print(
            f"\n[green]✅ Analysis complete! Processed {result.session_count} sessions.[/green]"
        )

    except KeyboardInterrupt:
        console.print("\n[yellow]⚠️  Analysis interrupted by user[/yellow]")
        raise typer.Exit(1)
    except Exception as e:
        console.print(f"\n[red]❌ Error during analysis: {e}[/red]")
        if verbose:
            console.print_exception()
        raise typer.Exit(1)


@app.command()
def info(
    pcap_files: List[Path] = typer.Argument(
        ...,
        help="PCAP files to inspect",
        exists=True,
        file_okay=True,
        dir_okay=False,
        readable=True,
    ),
) -> None:
    """
    ℹ️  Show information about PCAP files without full analysis.

    This command provides quick information about PCAP files including
    packet counts, duration, and basic statistics.
    """
    parser = PCAPParser()

    for pcap_file in pcap_files:
        info = parser.get_pcap_info(pcap_file)

        if not info:
            console.print(f"[red]❌ Could not read PCAP file: {pcap_file}[/red]")
            continue

        table = Table(title=f"📊 PCAP Info: {pcap_file.name}")
        table.add_column("Property", style="cyan")
        table.add_column("Value", style="green")

        table.add_row("File Size", f"{info['file_size_bytes']:,} bytes")
        table.add_row("Total Packets", f"{info['packet_count']:,}")
        table.add_row("HTTP Packets", f"{info['http_packet_count']:,}")
        table.add_row("TCP Packets", f"{info['tcp_packet_count']:,}")
        table.add_row(
            "Capture Duration", f"{info['capture_duration_seconds']:.2f} seconds"
        )

        if info["start_time"]:
            table.add_row(
                "Start Time", info["start_time"].strftime("%Y-%m-%d %H:%M:%S")
            )
        if info["end_time"]:
            table.add_row("End Time", info["end_time"].strftime("%Y-%m-%d %H:%M:%S"))

        console.print(table)
        console.print()


@app.command()
def batch(
    input_dir: Path = typer.Argument(
        ...,
        help="Directory containing PCAP files",
        exists=True,
        file_okay=False,
        dir_okay=True,
        readable=True,
    ),
    output_dir: Path = typer.Option(
        ...,
        "--output-dir",
        "-o",
        help="Directory to save batch analysis results",
        file_okay=False,
        dir_okay=True,
        writable=True,
    ),
    recursive: bool = typer.Option(
        True,
        "--recursive/--no-recursive",
        help="Search for PCAP files recursively",
    ),
    pattern: str = typer.Option(
        "*.pcap",
        "--pattern",
        "-p",
        help="File pattern to match (e.g., '*.pcap', '*.pcapng')",
    ),
) -> None:
    """
    📦 Batch analyze multiple PCAP files from a directory.

    This command finds all PCAP files in a directory and analyzes them
    in batch, generating individual and comparative reports.
    """
    # Find PCAP files
    pcap_files = find_pcap_files(input_dir, recursive=recursive)

    if not pcap_files:
        console.print(f"[red]❌ No PCAP files found in {input_dir}[/red]")
        raise typer.Exit(1)

    console.print(f"[blue]📁 Found {len(pcap_files)} PCAP files[/blue]")

    # Create output directory
    output_dir.mkdir(parents=True, exist_ok=True)

    # Process each file
    all_results = []

    with Progress(console=console) as progress:
        task = progress.add_task("Processing PCAP files...", total=len(pcap_files))

        for pcap_file in pcap_files:
            try:
                # Parse and analyze
                parser = PCAPParser()
                sessions = parser.parse_file(pcap_file)

                if sessions:
                    analyzer = StreamAnalyzer()
                    result = analyzer.analyze_sessions(sessions, detect_anomalies=True)
                    all_results.append(result)

                    # Save individual result
                    individual_output_dir = output_dir / pcap_file.stem
                    individual_output_dir.mkdir(exist_ok=True)
                    _save_json_results(result, None, individual_output_dir)

                progress.update(
                    task, advance=1, description=f"Processed {pcap_file.name}"
                )

            except Exception as e:
                console.print(f"[yellow]⚠️  Skipped {pcap_file.name}: {e}[/yellow]")
                progress.update(task, advance=1)

    # Generate comparison report
    if len(all_results) > 1:
        console.print("[blue]🔄 Generating comparison report...[/blue]")
        comparator = CaptureComparator()
        comparison_report = comparator.compare_captures(all_results)

        # Save comparison results
        _save_json_results(None, comparison_report, output_dir)
        _display_comparison_console(comparison_report, verbose=False)

    console.print(
        f"\n[green]✅ Batch analysis complete! Results saved to {output_dir}[/green]"
    )


def _validate_pcap_files(pcap_files: List[Path]) -> List[Path]:
    """Validate that files are readable PCAP files."""
    validated = []
    parser = PCAPParser()

    for pcap_file in pcap_files:
        if parser.validate_pcap_file(pcap_file):
            validated.append(pcap_file)
        else:
            console.print(
                f"[yellow]⚠️  Skipping invalid PCAP file: {pcap_file}[/yellow]"
            )

    return validated


def _parse_pcap_files(pcap_files: List[Path], verbose: bool) -> List:
    """Parse PCAP files and extract sessions."""
    parser = PCAPParser()
    all_sessions = []

    with Progress(console=console) as progress:
        task = progress.add_task("📡 Parsing PCAP files...", total=len(pcap_files))

        for pcap_file in pcap_files:
            try:
                sessions = parser.parse_file(pcap_file)
                all_sessions.extend(sessions)

                if verbose:
                    console.print(
                        f"  📁 {pcap_file.name}: {len(sessions)} sessions found"
                    )

                progress.update(task, advance=1)

            except Exception as e:
                console.print(
                    f"[yellow]⚠️  Error parsing {pcap_file.name}: {e}[/yellow]"
                )
                progress.update(task, advance=1)

    return all_sessions


def _display_analysis_console(result: AnalysisResult, verbose: bool) -> None:
    """Display analysis results in the console."""
    console.print("\n" + "=" * 60)
    console.print("[bold blue]📊 ANALYSIS RESULTS[/bold blue]")
    console.print("=" * 60)

    # Summary panel
    summary_table = Table(show_header=False, box=None)
    summary_table.add_column("Metric", style="cyan")
    summary_table.add_column("Value", style="green")

    summary_table.add_row("Sessions Analyzed", f"{result.session_count:,}")
    summary_table.add_row("Total Tokens", f"{result.total_tokens_analyzed:,}")
    summary_table.add_row("Total Bytes", f"{result.total_bytes_analyzed:,}")
    summary_table.add_row(
        "Analysis Duration", f"{result.analysis_duration_seconds:.2f}s"
    )

    if result.average_tokens_per_second:
        summary_table.add_row(
            "Avg Tokens/sec", f"{result.average_tokens_per_second:.1f}"
        )

    console.print(Panel(summary_table, title="📈 Summary", border_style="blue"))

    # Timing statistics
    timing = result.overall_timing_stats

    timing_table = Table(title="⏱️  Timing Statistics")
    timing_table.add_column("Metric", style="cyan")
    timing_table.add_column("Value", style="green")
    timing_table.add_column("Unit", style="dim")

    if timing.ttft_ms is not None:
        timing_table.add_row("Time to First Token", f"{timing.ttft_ms:.1f}", "ms")

    if timing.mean_itl_ms is not None:
        timing_table.add_row(
            "Mean Inter-Token Latency", f"{timing.mean_itl_ms:.1f}", "ms"
        )
        timing_table.add_row("Median ITL", f"{timing.median_itl_ms:.1f}", "ms")
        timing_table.add_row("95th Percentile ITL", f"{timing.p95_itl_ms:.1f}", "ms")
        timing_table.add_row("99th Percentile ITL", f"{timing.p99_itl_ms:.1f}", "ms")
        timing_table.add_row("ITL Std Dev", f"{timing.std_itl_ms:.1f}", "ms")

    if timing.tokens_per_second is not None:
        timing_table.add_row(
            "Throughput", f"{timing.tokens_per_second:.1f}", "tokens/sec"
        )

    console.print(timing_table)

    # Anomalies
    anomalies = result.anomalies
    if anomalies.large_gaps or anomalies.silence_periods or anomalies.unusual_patterns:
        console.print("\n[bold red]🚨 ANOMALIES DETECTED[/bold red]")

        if anomalies.large_gaps:
            console.print(f"  • {len(anomalies.large_gaps)} large timing gaps")
        if anomalies.silence_periods:
            console.print(f"  • {len(anomalies.silence_periods)} silence periods")
        if anomalies.unusual_patterns:
            console.print(f"  • {len(anomalies.unusual_patterns)} unusual patterns")
            if verbose:
                for pattern in anomalies.unusual_patterns:
                    console.print(f"    - {pattern}")

    # Key insights
    if result.key_insights:
        insights_text = Text()
        for insight in result.key_insights:
            insights_text.append(f"• {insight}\n")

        console.print(
            Panel(insights_text, title="💡 Key Insights", border_style="yellow")
        )

    # Recommendations
    if result.recommendations:
        rec_text = Text()
        for rec in result.recommendations:
            rec_text.append(f"• {rec}\n")

        console.print(Panel(rec_text, title="🎯 Recommendations", border_style="green"))

    # Session details (if verbose)
    if verbose and result.sessions:
        console.print("\n[bold]📋 Session Details[/bold]")

        sessions_table = Table()
        sessions_table.add_column("Session ID", style="cyan")
        sessions_table.add_column("Chunks", justify="right")
        sessions_table.add_column("Tokens", justify="right")
        sessions_table.add_column("Duration", justify="right")
        sessions_table.add_column("TTFT", justify="right")
        sessions_table.add_column("Mean ITL", justify="right")

        for session in result.sessions[:10]:  # Show first 10 sessions
            timing = result.per_session_timing.get(session.session_id)

            ttft_str = f"{timing.ttft_ms:.1f}ms" if timing and timing.ttft_ms else "-"
            itl_str = (
                f"{timing.mean_itl_ms:.1f}ms" if timing and timing.mean_itl_ms else "-"
            )
            duration_str = (
                f"{session.duration_seconds:.2f}s" if session.duration_seconds else "-"
            )

            sessions_table.add_row(
                (
                    session.session_id[:20] + "..."
                    if len(session.session_id) > 20
                    else session.session_id
                ),
                str(session.chunk_count),
                f"{session.total_tokens:,}",
                duration_str,
                ttft_str,
                itl_str,
            )

        console.print(sessions_table)

        if len(result.sessions) > 10:
            console.print(
                f"[dim]... and {len(result.sessions) - 10} more sessions[/dim]"
            )


def _display_comparison_console(report: ComparisonReport, verbose: bool) -> None:
    """Display comparison results in the console."""
    console.print("\n" + "=" * 60)
    console.print("[bold magenta]🔄 COMPARISON RESULTS[/bold magenta]")
    console.print("=" * 60)

    if len(report.captures) < 2:
        console.print("[yellow]⚠️  Need at least 2 captures for comparison[/yellow]")
        return

    # Performance rankings
    rankings_table = Table(title="🏆 Performance Rankings")
    rankings_table.add_column("Rank", justify="center")
    rankings_table.add_column("Capture", style="cyan")
    rankings_table.add_column("Sessions", justify="right")
    rankings_table.add_column("Avg TTFT", justify="right")
    rankings_table.add_column("Avg ITL", justify="right")
    rankings_table.add_column("Performance Score", justify="right")

    for i, capture_idx in enumerate(report.performance_rankings):
        capture = report.captures[capture_idx]
        timing = capture.overall_timing_stats

        rank_style = "green" if i == 0 else "yellow" if i == 1 else "red"
        rank_icon = "🥇" if i == 0 else "🥈" if i == 1 else "🥉" if i == 2 else "📊"

        ttft_str = f"{timing.ttft_ms:.1f}ms" if timing.ttft_ms else "-"
        itl_str = f"{timing.mean_itl_ms:.1f}ms" if timing.mean_itl_ms else "-"

        # Calculate simple performance score for display
        score = 0
        if timing.ttft_ms:
            score += timing.ttft_ms / 1000
        if timing.mean_itl_ms:
            score += timing.mean_itl_ms / 1000

        rankings_table.add_row(
            f"[{rank_style}]{rank_icon} {i+1}[/{rank_style}]",
            f"Capture {capture_idx + 1}",
            str(capture.session_count),
            ttft_str,
            itl_str,
            f"{score:.3f}" if score > 0 else "-",
        )

    console.print(rankings_table)

    # Common patterns
    if report.common_patterns:
        patterns_text = Text()
        for pattern in report.common_patterns:
            patterns_text.append(f"• {pattern}\n")

        console.print(
            Panel(patterns_text, title="🔗 Common Patterns", border_style="blue")
        )

    # Unique patterns
    if report.unique_patterns:
        for capture_idx, patterns in report.unique_patterns.items():
            if patterns:
                unique_text = Text()
                for pattern in patterns:
                    unique_text.append(f"• {pattern}\n")

                console.print(
                    Panel(
                        unique_text,
                        title=f"🎯 Unique to Capture {capture_idx + 1}",
                        border_style="cyan",
                    )
                )

    # Improvement opportunities
    if report.improvement_opportunities:
        improvements_text = Text()
        for improvement in report.improvement_opportunities:
            improvements_text.append(f"• {improvement}\n")

        console.print(
            Panel(
                improvements_text,
                title="📈 Improvement Opportunities",
                border_style="green",
            )
        )

    # Consistency metrics
    if report.consistency_score is not None:
        consistency_text = Text()
        consistency_text.append(f"Consistency Score: {report.consistency_score:.3f}\n")

        if report.consistency_score > 0.8:
            consistency_text.append(
                "Very consistent performance across captures", style="green"
            )
        elif report.consistency_score > 0.6:
            consistency_text.append("Moderately consistent performance", style="yellow")
        else:
            consistency_text.append("Inconsistent performance detected", style="red")

        console.print(
            Panel(
                consistency_text,
                title="📊 Consistency Analysis",
                border_style="magenta",
            )
        )


def _save_json_results(
    result: Optional[AnalysisResult],
    comparison: Optional[ComparisonReport],
    output_dir: Path,
) -> None:
    """Save results to JSON files."""
    if result:
        json_file = output_dir / "analysis_results.json"
        with open(json_file, "w") as f:
            json.dump(result.model_dump(mode="json"), f, indent=2, default=str)
        console.print(f"💾 Saved analysis results to {json_file}")

    if comparison:
        comparison_file = output_dir / "comparison_report.json"
        with open(comparison_file, "w") as f:
            json.dump(comparison.model_dump(mode="json"), f, indent=2, default=str)
        console.print(f"💾 Saved comparison report to {comparison_file}")


def _save_html_results(
    result: Optional[AnalysisResult],
    comparison: Optional[ComparisonReport],
    output_dir: Path,
) -> None:
    """Save results to HTML files."""
    try:
        if result:
            html_file = output_dir / "analysis_report.html"
            save_html_report(result, comparison, html_file)
            console.print(f"💾 Saved HTML report to {html_file}")
    except ImportError:
        console.print(
            "[yellow]⚠️  HTML output requires additional dependencies[/yellow]"
        )
    except Exception as e:
        console.print(f"[yellow]⚠️  Could not save HTML report: {e}[/yellow]")


def main():
    """Main entry point for the CLI."""
    app()


if __name__ == "__main__":
    main()
