# Wag Python Implementation Makefile

ID=$(shell id -u)
GID=$(shell id -g)

.PHONY: install dev-install test lint format type-check build clean dev dev-adminui docker .build_ui

# Install Python package
install:
	pip install -e .

# Install with development dependencies
dev-install:
	pip install -e '.[dev]'

# Run tests
test:
	pytest tests/

# Run linter
lint:
	ruff check wag/

# Format code
format:
	black wag/

# Run type checker
type-check:
	mypy wag/

# Build distribution packages
build: .build_ui
	python -m build

# Clean build artifacts
clean:
	rm -rf build/ dist/ *.egg-info
	find . -type d -name __pycache__ -exec rm -rf {} + 2>/dev/null || true
	find . -type f -name "*.pyc" -delete

# Development with Docker Compose
dev: .build_ui
	sudo docker compose -f docker-compose.dev.yml up 

# Run admin UI in development mode
dev-adminui:
	cd adminui/frontend; DEV_API_URL=http://127.0.0.1:4433 npm run dev

# Build Docker image
docker:
	sudo docker run -u "$(ID):$(GID)" --rm -t -v `pwd`:/wag wag_builder

# Build UI components
.build_ui:
	cd adminui/frontend; npm install; npm run build
	cd internal/mfaportal/resources/frontend; npm install; npm run build
