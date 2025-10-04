# Makefile for TerraSafe - Terraform Security Scanner
.PHONY: help install test run-demo clean docker lint coverage

# Variables
PYTHON := python3
VENV := venv
PIP := $(VENV)/bin/pip
PYTEST := $(VENV)/bin/pytest
SCANNER := $(VENV)/bin/python security_scanner.py

# Default target
help:
	@echo "TerraSafe - Available commands:"
	@echo "  make install    - Set up virtual environment and install dependencies"
	@echo "  make test       - Run all tests (unit + integration)"
	@echo "  make test-unit  - Run unit tests only"
	@echo "  make test-int   - Run integration tests only"
	@echo "  make coverage   - Generate test coverage report"
	@echo "  make lint       - Run code quality checks"
	@echo "  make demo       - Run demo on all test files"
	@echo "  make scan FILE=<path> - Scan specific Terraform file"
	@echo "  make docker     - Build and run in Docker container"
	@echo "  make clean      - Remove generated files and cache"

# Install dependencies
install: requirements-dev.txt
	@echo "🔧 Setting up environment..."
	$(PYTHON) -m venv $(VENV)
	$(PIP) install --upgrade pip
	$(PIP) install -r requirements.txt
	$(PIP) install -r requirements-dev.txt
	@echo "✅ Installation complete"

# Create requirements-dev.txt if it doesn't exist
requirements-dev.txt:
	@echo "pytest==7.4.3" > requirements-dev.txt
	@echo "coverage==7.3.2" >> requirements-dev.txt
	@echo "pylint==3.0.3" >> requirements-dev.txt
	@echo "black==23.12.0" >> requirements-dev.txt
	@echo "flake8==6.1.0" >> requirements-dev.txt

# Run all tests
test: install
	@echo "🧪 Running all tests..."
	$(VENV)/bin/python test_runner.py

# Run unit tests only
test-unit: install
	@echo "🧪 Running unit tests..."
	$(VENV)/bin/python test_runner.py --unit

# Run integration tests only  
test-int: install
	@echo "🧪 Running integration tests..."
	$(VENV)/bin/python test_runner.py --integration

# Generate coverage report
coverage: install
	@echo "📊 Generating coverage report..."
	$(VENV)/bin/coverage run -m pytest test_security_scanner.py
	$(VENV)/bin/coverage report
	$(VENV)/bin/coverage html
	@echo "✅ Coverage report saved to htmlcov/index.html"

# Run linting
lint: install
	@echo "🔍 Running code quality checks..."
	$(VENV)/bin/flake8 security_scanner.py --max-line-length=120
	$(VENV)/bin/pylint security_scanner.py --max-line-length=120 || true
	@echo "✅ Linting complete"

# Format code
format: install
	@echo "🎨 Formatting code..."
	$(VENV)/bin/black security_scanner.py test_security_scanner.py
	@echo "✅ Code formatted"

# Run demo
demo: install
	@echo "🚀 Running TerraSafe demo..."
	@chmod +x run_demo.sh
	./run_demo.sh

# Scan specific file
scan: install
	@if [ -z "$(FILE)" ]; then \
		echo "❌ Error: Please specify FILE=<path>"; \
		echo "   Example: make scan FILE=test_files/vulnerable.tf"; \
		exit 1; \
	fi
	@echo "🔍 Scanning $(FILE)..."
	$(SCANNER) $(FILE)

# Docker build and run
docker:
	@echo "🐳 Building Docker image..."
	docker build -t terrasafe:latest .
	@echo "🚀 Running in Docker..."
	docker run --rm -v $(PWD)/test_files:/app/test_files terrasafe:latest test_files/vulnerable.tf

# Create Dockerfile if it doesn't exist
Dockerfile:
	@echo "FROM python:3.9-slim" > Dockerfile
	@echo "WORKDIR /app" >> Dockerfile
	@echo "COPY requirements.txt ." >> Dockerfile
	@echo "RUN pip install --no-cache-dir -r requirements.txt" >> Dockerfile
	@echo "COPY security_scanner.py ." >> Dockerfile
	@echo "COPY models/ ./models/" >> Dockerfile
	@echo "ENTRYPOINT [\"python\", \"security_scanner.py\"]" >> Dockerfile

# Clean up
clean:
	@echo "🧹 Cleaning up..."
	rm -rf $(VENV)
	rm -rf __pycache__
	rm -rf *.pyc
	rm -rf htmlcov
	rm -rf .coverage
	rm -rf .pytest_cache
	rm -rf models/*.pkl
	rm -f scan_results_*.json scan_history.json
	@echo "✅ Cleanup complete"

# Train model
train-model: install
	@echo "🤖 Training ML model..."
	$(VENV)/bin/python -c "from security_scanner import IntelligentSecurityScanner; scanner = IntelligentSecurityScanner()"
	@echo "✅ Model trained and saved"

# GitHub Actions local test
test-ci:
	@echo "🔄 Testing GitHub Actions workflow locally..."
	@which act > /dev/null || (echo "Install 'act' first: https://github.com/nektos/act" && exit 1)
	act -j security-scan