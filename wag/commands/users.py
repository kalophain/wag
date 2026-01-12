"""Users command - manages users and their MFA settings."""

import click
import asyncio
from typing import Optional

from wag.pkg.control.client import ControlClient


@click.command()
@click.option('--socket', '-s', default='/tmp/wag.sock', help='Wag socket location')
@click.option('--list', 'list_users', is_flag=True, help='List users, if --username supplied will filter by user')
@click.option('--del', 'delete', is_flag=True, help='Delete user and all associated devices')
@click.option('--reset-mfa', 'reset_mfa', is_flag=True, help='Reset MFA details, invalidates all sessions and sets MFA to be shown')
@click.option('--lockaccount', is_flag=True, help='Lock account disable authentication from any device, deauthenticates user active sessions')
@click.option('--unlockaccount', is_flag=True, help='Unlock a locked account, does not unlock specific device locks')
@click.option('--username', '-u', help='Username to act upon')
def users(
    socket: str,
    list_users: bool,
    delete: bool,
    reset_mfa: bool,
    lockaccount: bool,
    unlockaccount: bool,
    username: Optional[str]
):
    """
    Manages users MFA and can delete all users devices.
    
    Examples:
        wag users --list
        wag users --reset-mfa --username john
        wag users --lockaccount --username john
    """
    try:
        asyncio.run(handle_users(
            socket, list_users, delete, reset_mfa,
            lockaccount, unlockaccount, username
        ))
    except Exception as e:
        click.echo(f"Error: {e}", err=True)
        raise click.Abort()


async def handle_users(
    socket: str,
    list_users: bool,
    delete: bool,
    reset_mfa: bool,
    lockaccount: bool,
    unlockaccount: bool,
    username: Optional[str]
):
    """Handle user operations."""
    client = ControlClient(socket)
    
    try:
        await client.connect()
        
        if list_users:
            users_list = await client.list_users(username=username)
            click.echo("username,locked,mfa_type,device_count")
            for user in users_list:
                click.echo(
                    f"{user['username']},{user.get('locked', False)},"
                    f"{user.get('mfa_type', '')},"
                    f"{user.get('device_count', 0)}"
                )
                
        elif delete:
            if not username:
                raise click.UsageError("--username is required when deleting")
            
            await client.delete_user(username)
            click.echo(f"Deleted user: {username}")
            
        elif reset_mfa:
            if not username:
                raise click.UsageError("--username is required when resetting MFA")
            
            await client.reset_user_mfa(username)
            click.echo(f"Reset MFA for user: {username}")
            
        elif lockaccount:
            if not username:
                raise click.UsageError("--username is required when locking account")
            
            await client.lock_user_account(username)
            click.echo(f"Locked account: {username}")
            
        elif unlockaccount:
            if not username:
                raise click.UsageError("--username is required when unlocking account")
            
            await client.unlock_user_account(username)
            click.echo(f"Unlocked account: {username}")
        else:
            raise click.UsageError("Must specify an action: --list, --del, --reset-mfa, --lockaccount, or --unlockaccount")
            
    finally:
        await client.disconnect()
