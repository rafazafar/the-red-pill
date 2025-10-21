.PHONY: help install install-dev test lint format check clean run docs

# Default target
help:
	@echo "Available commands:"
	@echo "  install     - Install production dependencies"
	@echo "  install-dev - Install development dependencies"
	@echo "  test        - Run tests"
	@echo "  lint        - Run linting"
	@echo "  format      - Format code"
	@echo "  check       - Run all checks (lint + test)"
	@echo "  clean       - Clean up build artifacts"
	@echo "  run         - Run the discovery tool locally"
	@echo "  docs        - Build documentation"
	@echo ""
	@echo "Example usage:"
	@echo "  make install-dev  # Set up development environment"
	@echo "  make run          # Run local discovery"
	@echo "  make test         # Run tests"

# Installation
install:
	uv sync --no-dev

install-dev:
	uv sync --extra dev --extra test --extra docs

# Development
test:
	uv run pytest

test-cov:
	uv run pytest --cov=modules --cov=server_discovery --cov-report=html --cov-report=term

lint:
	uv run ruff check .
	uv run mypy .

format:
	uv run black .
	uv run isort .
	uv run ruff check --fix .

check: lint test

# Cleanup
clean:
	rm -rf build/
	rm -rf dist/
	rm -rf *.egg-info/
	rm -rf .pytest_cache/
	rm -rf .coverage
	rm -rf htmlcov/
	rm -rf .mypy_cache/
	rm -rf .ruff_cache/
	find . -type d -name __pycache__ -exec rm -rf {} +
	find . -type f -name "*.pyc" -delete

# Running
run:
	uv run python server_discovery.py --local

run-remote:
	@echo "Usage: make run-remote TARGET=user@host [PASSWORD=true]"
	@if [ -z "$(TARGET)" ]; then \
		echo "Error: TARGET is required. Example: make run-remote TARGET=user@192.168.1.100"; \
		exit 1; \
	fi
	@if [ "$(PASSWORD)" = "true" ]; then \
		uv run python server_discovery.py $(TARGET) --password; \
	else \
		uv run python server_discovery.py $(TARGET); \
	fi

run-remote-password:
	@echo "Usage: make run-remote-password TARGET=user@host"
	@if [ -z "$(TARGET)" ]; then \
		echo "Error: TARGET is required. Example: make run-remote-password TARGET=user@192.168.1.100"; \
		exit 1; \
	fi
	uv run python server_discovery.py $(TARGET) --password

# Example discovery runs
example-local:
	uv run python server_discovery.py --local --output html

example-remote:
	@echo "Example remote discovery (replace with your target):"
	@echo "Key-based: uv run python server_discovery.py user@192.168.1.100 --output all"
	@echo "Password:  uv run python server_discovery.py user@192.168.1.100 --password --output all"

# Documentation
docs:
	uv run mkdocs build

docs-serve:
	uv run mkdocs serve

# Development setup
setup-dev: install-dev
	uv run pre-commit install

# Build
build:
	uv build

# Release (for maintainers)
release-test:
	uv build
	uv publish --repository testpypi

release:
	uv build
	uv publish