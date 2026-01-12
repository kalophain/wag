# Wag - Python Implementation

This is a Python reimplementation of the Wag WireGuard VPN server with MFA, route restriction, and device enrollment capabilities.

## About This Implementation

This Python version maintains compatibility with the original Go implementation while leveraging Python's ecosystem. It uses:
- **Pixi** as the package manager for reproducible environments
- **Click** for CLI command parsing
- **FastAPI** for web servers
- **SQLAlchemy** for database management
- **Pydantic** for configuration validation

## Requirements

- Python 3.11 or higher
- Pixi package manager (for dependency management)
- iptables
- WireGuard kernel module

## Installation

### Using Pixi (Recommended)

1. Install Pixi:
```sh
curl -fsSL https://pixi.sh/install.sh | bash
```

2. Clone the repository:
```sh
git clone https://github.com/NHAS/wag.git
cd wag
```

3. Install dependencies:
```sh
pixi install
```

4. Run Wag:
```sh
pixi run start -c config.json
```

### Using pip

1. Install from source:
```sh
git clone https://github.com/NHAS/wag.git
cd wag
pip install -e .
```

2. Run Wag:
```sh
wag start -c config.json
```

## Usage

The Python implementation provides the same CLI commands as the Go version:

```sh
wag --help                    # Show help
wag version                   # Show version
wag start -c config.json      # Start server
wag registration --add --username john  # Add registration token
wag devices --list            # List devices
wag users --list              # List users
wag firewall --list           # List firewall rules
wag webadmin --add --username admin --password pass  # Add admin
wag config --validate -f config.json  # Validate config
```

## Development

### Setup Development Environment

```sh
pixi install --environment dev
```

### Running Tests

```sh
pixi run test
```

### Linting and Formatting

```sh
pixi run lint      # Run linter
pixi run format    # Format code
pixi run type-check  # Run type checker
```

### Building Distribution

```sh
pixi run build
```

## Configuration

The Python implementation uses the same JSON configuration format as the Go version. See the main [README.md](README.md) for detailed configuration options.

## Architecture

The Python implementation follows the same architectural patterns as the Go version:

- **wag/commands/**: CLI command implementations
- **wag/internal/**: Core business logic
  - **config/**: Configuration management
  - **data/**: Database layer
  - **router/**: WireGuard management
  - **acls/**: Access control lists
  - **mfaportal/**: MFA authentication portal
  - **publicwebserver/**: Public registration server
  - **autotls/**: TLS/ACME certificate management
- **wag/adminui/**: Administrative web interface backend
- **wag/pkg/control/**: Control socket server/client

## Current Status

This is an initial Python implementation with:
- ✅ Complete CLI structure with all commands
- ✅ Configuration management framework
- ✅ Project packaging (pyproject.toml, pixi.toml)
- ⚠️ Core functionality requires full implementation
- ⚠️ Web servers need FastAPI implementation  
- ⚠️ Database layer needs SQLAlchemy implementation
- ⚠️ WireGuard integration needs implementation
- ⚠️ MFA mechanisms need implementation

## Contributing

Contributions are welcome! The Python implementation aims to maintain feature parity with the Go version while leveraging Python's strengths.

## License

Same as the original Wag project - AGPL-3.0
