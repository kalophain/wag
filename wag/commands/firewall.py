"""Firewall command - manages firewall rules."""

import click
import asyncio
from typing import Optional

from wag.pkg.control.client import ControlClient


@click.command()
@click.option('--socket', '-s', default='/tmp/wag.sock', help='Wag socket location')
@click.option('--list', 'list_rules', is_flag=True, help='List current firewall rules')
@click.option('--reload', is_flag=True, help='Reload firewall rules from configuration')
@click.option('--flush', is_flag=True, help='Flush all firewall rules')
def firewall(
    socket: str,
    list_rules: bool,
    reload: bool,
    flush: bool
):
    """
    Manages firewall rules.
    
    Examples:
        wag firewall --list
        wag firewall --reload
    """
    try:
        asyncio.run(handle_firewall(socket, list_rules, reload, flush))
    except Exception as e:
        click.echo(f"Error: {e}", err=True)
        raise click.Abort()


async def handle_firewall(
    socket: str,
    list_rules: bool,
    reload: bool,
    flush: bool
):
    """Handle firewall operations."""
    client = ControlClient(socket)
    
    try:
        await client.connect()
        
        if list_rules:
            rules = await client.list_firewall_rules()
            click.echo("Firewall Rules:")
            for rule in rules:
                click.echo(f"  {rule}")
                
        elif reload:
            await client.reload_firewall()
            click.echo("Firewall rules reloaded")
            
        elif flush:
            await client.flush_firewall()
            click.echo("Firewall rules flushed")
        else:
            raise click.UsageError("Must specify an action: --list, --reload, or --flush")
            
    finally:
        await client.disconnect()
