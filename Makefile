.PHONY: help install install-dev test test-cov lint format type-check clean build upload docs serve-docs
.DEFAULT_GOAL := help

# Colors for terminal output
BLUE := \033[0;34m
GREEN := \033[0;32m
YELLOW := \033[1;33m
RED := \033[0;31m
NC := \033[0m # No Color

help: ## Show this help message
	@echo -e "$(BLUE)LLMShark Development Commands$(NC)"
	@echo -e ""
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "$(GREEN)%-20s$(NC) %s\n", $$1, $$2}'

install: ## Install package in current environment
	@echo -e "$(BLUE)Installing LLMShark...$(NC)"
	pip install -e .

install-dev: ## Install package with development dependencies
	@echo -e "$(BLUE)Installing LLMShark with development dependencies...$(NC)"
	pip install -e ".[dev]"
	@echo -e "$(GREEN)✓ Installation complete$(NC)"

install-viz: ## Install package with visualization dependencies
	@echo -e "$(BLUE)Installing LLMShark with visualization dependencies...$(NC)"
	pip install -e ".[viz]"
	@echo -e "$(GREEN)✓ Installation complete$(NC)"

install-all: ## Install package with all dependencies
	@echo -e "$(BLUE)Installing LLMShark with all dependencies...$(NC)"
	pip install -e ".[dev,viz]"
	@echo -e "$(GREEN)✓ Installation complete$(NC)"

test: ## Run tests
	@echo -e "$(BLUE)Running tests...$(NC)"
	pytest -v

test-cov: ## Run tests with coverage
	@echo -e "$(BLUE)Running tests with coverage...$(NC)"
	pytest -v --cov=llmshark --cov-report=term-missing --cov-report=html

test-unit: ## Run only unit tests
	@echo -e "$(BLUE)Running unit tests...$(NC)"
	pytest -v -m unit

test-integration: ## Run only integration tests
	@echo -e "$(BLUE)Running integration tests...$(NC)"
	pytest -v -m integration

lint: ## Run linting with ruff
	@echo -e "$(BLUE)Running linting...$(NC)"
	ruff check llmshark tests
	@echo -e "$(GREEN)✓ Linting complete$(NC)"

lint-fix: ## Run linting with automatic fixes
	@echo -e "$(BLUE)Running linting with fixes...$(NC)"
	ruff check llmshark tests --fix
	@echo -e "$(GREEN)✓ Linting with fixes complete$(NC)"

format: ## Format code with black and ruff
	@echo -e "$(BLUE)Formatting code...$(NC)"
	black llmshark tests
	ruff format llmshark tests
	@echo -e "$(GREEN)✓ Formatting complete$(NC)"

type-check: ## Run type checking with mypy
	@echo -e "$(BLUE)Running type checking...$(NC)"
	mypy llmshark
	@echo -e "$(GREEN)✓ Type checking complete$(NC)"

quality: ## Run all quality checks (lint, format, type-check)
	@echo -e "$(BLUE)Running all quality checks...$(NC)"
	$(MAKE) lint
	$(MAKE) format
	$(MAKE) type-check
	@echo -e "$(GREEN)✓ All quality checks complete$(NC)"

clean: ## Clean build artifacts and cache
	@echo -e "$(BLUE)Cleaning build artifacts...$(NC)"
	rm -rf build/
	rm -rf dist/
	rm -rf *.egg-info/
	rm -rf .pytest_cache/
	rm -rf .mypy_cache/
	rm -rf .ruff_cache/
	rm -rf htmlcov/
	find . -type d -name __pycache__ -exec rm -rf {} +
	find . -type f -name "*.pyc" -delete
	find . -type f -name "*.pyo" -delete
	@echo -e "$(GREEN)✓ Cleanup complete$(NC)"

build: ## Build package
	@echo -e "$(BLUE)Building package...$(NC)"
	python -m build
	@echo -e "$(GREEN)✓ Build complete$(NC)"

check-build: ## Check package build
	@echo -e "$(BLUE)Checking package build...$(NC)"
	python -m twine check dist/*
	@echo -e "$(GREEN)✓ Package check complete$(NC)"

upload-test: ## Upload to test PyPI
	@echo -e "$(BLUE)Uploading to test PyPI...$(NC)"
	python -m twine upload --repository testpypi dist/*

upload: ## Upload to PyPI
	@echo -e "$(YELLOW)Uploading to PyPI...$(NC)"
	@read -p "Are you sure you want to upload to PyPI? [y/N] " confirm && [ "$$confirm" = "y" ]
	python -m twine upload dist/*
	@echo -e "$(GREEN)✓ Upload complete$(NC)"

dev-setup: ## Set up development environment
	@echo -e "$(BLUE)Setting up development environment...$(NC)"
	python -m venv .venv
	@echo -e "$(YELLOW)Activate virtual environment with: source .venv/bin/activate$(NC)"
	@echo -e "Then run: make install-dev"

pre-commit-install: ## Install pre-commit hooks
	@echo -e "$(BLUE)Installing pre-commit hooks...$(NC)"
	pre-commit install
	@echo -e "$(GREEN)✓ Pre-commit hooks installed$(NC)"

pre-commit-run: ## Run pre-commit on all files
	@echo -e "$(BLUE)Running pre-commit on all files...$(NC)"
	pre-commit run --all-files

# Example commands for testing the CLI
demo-info: ## Show demo of info command
	@echo -e "$(BLUE)Demo: Getting PCAP file info$(NC)"
	@echo -e "Command: llmshark info sample.pcap"
	@echo -e "$(YELLOW)Note: Requires a sample PCAP file$(NC)"

demo-analyze: ## Show demo of analyze command
	@echo -e "$(BLUE)Demo: Analyzing PCAP file$(NC)"
	@echo -e "Command: llmshark analyze sample.pcap --verbose"
	@echo -e "$(YELLOW)Note: Requires a sample PCAP file$(NC)"

demo-batch: ## Show demo of batch command
	@echo -e "$(BLUE)Demo: Batch processing$(NC)"
	@echo -e "Command: llmshark batch ./samples/ --output-dir ./results"
	@echo -e "$(YELLOW)Note: Requires sample PCAP files in ./samples/$(NC)"

# Documentation commands
docs-serve: ## Serve documentation locally
	@echo -e "$(BLUE)Starting documentation server...$(NC)"
	@echo -e "$(YELLOW)Note: Requires mkdocs or similar documentation tool$(NC)"

# Virtual environment helpers
venv-create: ## Create virtual environment
	@echo -e "$(BLUE)Creating virtual environment...$(NC)"
	python -m venv .venv
	@echo -e "$(GREEN)✓ Virtual environment created$(NC)"
	@echo -e "$(YELLOW)Activate with: source .venv/bin/activate$(NC)"

venv-activate: ## Show command to activate virtual environment
	@echo -e "$(BLUE)To activate virtual environment:$(NC)"
	@echo -e "source .venv/bin/activate"

# Release workflow
release-check: ## Check if ready for release
	@echo -e "$(BLUE)Checking release readiness...$(NC)"
	$(MAKE) clean
	$(MAKE) quality
	$(MAKE) test-cov
	$(MAKE) build
	$(MAKE) check-build
	@echo -e "$(GREEN)✓ Release checks complete$(NC)"

release: ## Full release workflow
	@echo -e "$(BLUE)Starting release workflow...$(NC)"
	$(MAKE) release-check
	@echo -e "$(YELLOW)Ready for release! Run 'make upload' to publish to PyPI$(NC)"

# Development workflow
dev: ## Complete development workflow
	@echo -e "$(BLUE)Running development workflow...$(NC)"
	$(MAKE) quality
	$(MAKE) test
	@echo -e "$(GREEN)✓ Development workflow complete$(NC)"

# Show project structure
structure: ## Show project structure
	@echo -e "$(BLUE)LLMShark Project Structure:$(NC)"
	@tree -I '__pycache__|*.pyc|.pytest_cache|.mypy_cache|.ruff_cache|htmlcov|.venv|*.egg-info' || find . -type f -name "*.py" | head -20

# Show package info
info: ## Show package information
	@echo -e "$(BLUE)LLMShark Package Information:$(NC)"
	@echo -e "Name: LLMShark"
	@echo -e "Description: Comprehensive analysis tool for LLM streaming traffic"
	@echo -e "Python: 3.10+"
	@echo -e "License: MIT"
	@echo -e ""
	@echo -e "$(GREEN)Key Features:$(NC)"
	@echo -e "- PCAP file analysis"
	@echo -e "- HTTP/SSE stream parsing"
	@echo -e "- Timing statistics (TTFT, ITL)"
	@echo -e "- Anomaly detection"
	@echo -e "- Multi-capture comparison"
	@echo -e "- Rich terminal interface" 