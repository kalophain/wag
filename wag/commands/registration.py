"""Registration command - manages device registration tokens."""

import click
import asyncio
from typing import Optional, List

from wag.pkg.control.client import ControlClient


@click.command()
@click.option('--socket', '-s', default='/tmp/wag.sock', help='Wag socket to act on')
@click.option('--add', is_flag=True, help='Create a new enrolment token')
@click.option('--del', 'delete', is_flag=True, help='Delete existing enrolment token')
@click.option('--list', 'list_tokens', is_flag=True, help='List tokens')
@click.option('--username', '-u', help='User to add device to')
@click.option('--token', '-t', help='Manually set registration token (Optional)')
@click.option('--overwrite', '-o', help='Add registration token for an existing user device')
@click.option('--group', '-g', multiple=True, help='Manually set user group (can supply multiple)')
@click.option('--groups', help='Set user groups manually, comma delimited list')
def registration(
    socket: str,
    add: bool,
    delete: bool,
    list_tokens: bool,
    username: Optional[str],
    token: Optional[str],
    overwrite: Optional[str],
    group: tuple,
    groups: Optional[str]
):
    """
    Deals with creating, deleting and listing the registration tokens.
    
    Examples:
        wag registration --add --username john
        wag registration --list
        wag registration --del --token abc123
    """
    try:
        asyncio.run(handle_registration(
            socket, add, delete, list_tokens, username, 
            token, overwrite, group, groups
        ))
    except Exception as e:
        click.echo(f"Error: {e}", err=True)
        raise click.Abort()


async def handle_registration(
    socket: str,
    add: bool,
    delete: bool,
    list_tokens: bool,
    username: Optional[str],
    token: Optional[str],
    overwrite: Optional[str],
    group: tuple,
    groups: Optional[str]
):
    """Handle registration token operations."""
    client = ControlClient(socket)
    
    try:
        await client.connect()
        
        if add:
            if not username:
                raise click.UsageError("--username is required when adding a token")
            
            # Parse groups
            user_groups: List[str] = []
            if groups:
                user_groups = [g.strip() for g in groups.split(',')]
            elif group:
                user_groups = list(group)
            
            result = await client.add_registration_token(
                username=username,
                token=token,
                overwrite=overwrite,
                groups=user_groups
            )
            click.echo(f"token,username")
            click.echo(f"{result['token']},{username}")
            
        elif delete:
            if not token:
                raise click.UsageError("--token is required when deleting")
            
            await client.delete_registration_token(token)
            click.echo(f"Deleted token: {token}")
            
        elif list_tokens:
            tokens = await client.list_registration_tokens()
            click.echo("token,username,groups,overwrite")
            for t in tokens:
                groups_str = ','.join(t.get('groups', []))
                overwrite_str = t.get('overwrite', '')
                click.echo(f"{t['token']},{t['username']},{groups_str},{overwrite_str}")
        else:
            raise click.UsageError("Must specify --add, --del, or --list")
            
    finally:
        await client.disconnect()
