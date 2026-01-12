"""Webadmin command - manages administrative users for the web UI."""

import click
import asyncio
from typing import Optional

from wag.pkg.control.client import ControlClient


@click.command()
@click.option('--socket', '-s', default='/tmp/wag.sock', help='Wag instance control socket')
@click.option('--list', 'list_admins', is_flag=True, help='List web administration users')
@click.option('--add', is_flag=True, help='Add web administrator user (requires --password)')
@click.option('--del', 'delete', is_flag=True, help='Delete admin user')
@click.option('--lockaccount', is_flag=True, help='Lock admin account disable login for this web administrator user')
@click.option('--unlockaccount', is_flag=True, help='Unlock a web administrator account')
@click.option('--username', '-u', help='Admin Username to act upon')
@click.option('--password', '-p', help='Password for admin user')
def webadmin(
    socket: str,
    list_admins: bool,
    add: bool,
    delete: bool,
    lockaccount: bool,
    unlockaccount: bool,
    username: Optional[str],
    password: Optional[str]
):
    """
    Manages the administrative users for the web UI.
    
    Examples:
        wag webadmin --add --username admin --password secretpass
        wag webadmin --list
        wag webadmin --del --username admin
    """
    try:
        asyncio.run(handle_webadmin(
            socket, list_admins, add, delete,
            lockaccount, unlockaccount, username, password
        ))
    except Exception as e:
        click.echo(f"Error: {e}", err=True)
        raise click.Abort()


async def handle_webadmin(
    socket: str,
    list_admins: bool,
    add: bool,
    delete: bool,
    lockaccount: bool,
    unlockaccount: bool,
    username: Optional[str],
    password: Optional[str]
):
    """Handle webadmin operations."""
    client = ControlClient(socket)
    
    try:
        await client.connect()
        
        if list_admins:
            admins = await client.list_webadmins(username=username)
            click.echo("username,locked,created_at")
            for admin in admins:
                click.echo(f"{admin['username']},{admin.get('locked', False)},{admin.get('created_at', '')}")
                
        elif add:
            if not username or not password:
                raise click.UsageError("--username and --password are required when adding")
            
            await client.add_webadmin(username, password)
            click.echo(f"Added admin user: {username}")
            
        elif delete:
            if not username:
                raise click.UsageError("--username is required when deleting")
            
            await client.delete_webadmin(username)
            click.echo(f"Deleted admin user: {username}")
            
        elif lockaccount:
            if not username:
                raise click.UsageError("--username is required when locking account")
            
            await client.lock_webadmin(username)
            click.echo(f"Locked admin account: {username}")
            
        elif unlockaccount:
            if not username:
                raise click.UsageError("--username is required when unlocking account")
            
            await client.unlock_webadmin(username)
            click.echo(f"Unlocked admin account: {username}")
        else:
            raise click.UsageError("Must specify an action: --list, --add, --del, --lockaccount, or --unlockaccount")
            
    finally:
        await client.disconnect()
