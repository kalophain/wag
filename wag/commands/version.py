"""Version command - displays version information."""

import click
from wag import __version__


@click.command()
def version():
    """
    Display version information.
    """
    click.echo(f"Wag version {__version__}")
    click.echo("Python implementation with Pixi package manager")
