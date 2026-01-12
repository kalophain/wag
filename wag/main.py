#!/usr/bin/env python3
"""Main entry point for Wag VPN server."""

import sys
import os
import click
from typing import Optional

from wag.commands.start import start
from wag.commands.registration import registration
from wag.commands.devices import devices
from wag.commands.users import users
from wag.commands.firewall import firewall
from wag.commands.webadmin import webadmin
from wag.commands.version import version
from wag.commands.config import config


@click.group()
@click.version_option(version="7.0.0", prog_name="wag")
def cli():
    """
    Wag - WireGuard VPN with MFA, route restriction and device enrollment.
    
    Adds 2FA and device enrolment to WireGuard deployments.
    """
    # Set umask equivalent to Go's 017 (octal)
    os.umask(0o017)


# Register all subcommands
cli.add_command(start)
cli.add_command(registration)
cli.add_command(devices)
cli.add_command(users)
cli.add_command(firewall)
cli.add_command(webadmin)
cli.add_command(version)
cli.add_command(config)


def main():
    """Main entry point."""
    try:
        cli()
    except Exception as e:
        click.echo(f"Error: {e}", err=True)
        sys.exit(1)


if __name__ == "__main__":
    main()
