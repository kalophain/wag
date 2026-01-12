"""Config command - manages configuration."""

import click
import asyncio
from typing import Optional

from wag.pkg.control.client import ControlClient


@click.command()
@click.option('--socket', '-s', default='/tmp/wag.sock', help='Wag socket location')
@click.option('--show', is_flag=True, help='Show current configuration')
@click.option('--validate', is_flag=True, help='Validate configuration file')
@click.option('--file', '-f', type=click.Path(exists=True), help='Configuration file to validate')
def config(
    socket: str,
    show: bool,
    validate: bool,
    file: Optional[str]
):
    """
    Manages configuration.
    
    Examples:
        wag config --show
        wag config --validate --file config.json
    """
    try:
        if validate and file:
            from wag.internal.config import load_config
            cfg = load_config(file)
            click.echo(f"Configuration file {file} is valid")
        elif show:
            asyncio.run(handle_config_show(socket))
        else:
            raise click.UsageError("Must specify --show or --validate with --file")
    except Exception as e:
        click.echo(f"Error: {e}", err=True)
        raise click.Abort()


async def handle_config_show(socket: str):
    """Show current configuration."""
    client = ControlClient(socket)
    
    try:
        await client.connect()
        config_data = await client.get_config()
        click.echo("Current Configuration:")
        import json
        click.echo(json.dumps(config_data, indent=2))
    finally:
        await client.disconnect()
