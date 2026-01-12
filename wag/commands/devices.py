"""Devices command - manages WireGuard devices."""

import click
import asyncio
from typing import Optional

from wag.pkg.control.client import ControlClient


@click.command()
@click.option('--socket', '-s', default='/tmp/wag.sock', help='Wag control socket to act on')
@click.option('--list', 'list_devices', is_flag=True, help='List wireguard devices')
@click.option('--del', 'delete', is_flag=True, help='Remove device and block wireguard access')
@click.option('--lock', is_flag=True, help='Lock device access to mfa routes')
@click.option('--unlock', is_flag=True, help='Unlock device')
@click.option('--mfa-sessions', 'mfa_sessions', is_flag=True, help='Get list of devices with active authorised sessions')
@click.option('--username', '-u', help='Owner of device (indicates that command acts on all devices owned by user)')
@click.option('--address', '-a', help='Address of device')
def devices(
    socket: str,
    list_devices: bool,
    delete: bool,
    lock: bool,
    unlock: bool,
    mfa_sessions: bool,
    username: Optional[str],
    address: Optional[str]
):
    """
    Manages devices.
    
    Examples:
        wag devices --list
        wag devices --del --address 192.168.1.2
        wag devices --lock --username john
    """
    try:
        asyncio.run(handle_devices(
            socket, list_devices, delete, lock, unlock,
            mfa_sessions, username, address
        ))
    except Exception as e:
        click.echo(f"Error: {e}", err=True)
        raise click.Abort()


async def handle_devices(
    socket: str,
    list_devices: bool,
    delete: bool,
    lock: bool,
    unlock: bool,
    mfa_sessions: bool,
    username: Optional[str],
    address: Optional[str]
):
    """Handle device operations."""
    client = ControlClient(socket)
    
    try:
        await client.connect()
        
        if list_devices:
            devices_list = await client.list_devices(username=username)
            click.echo("address,username,publickey,endpoint,last_handshake")
            for device in devices_list:
                click.echo(
                    f"{device['address']},{device['username']},"
                    f"{device['public_key']},{device.get('endpoint', '')},"
                    f"{device.get('last_handshake', '')}"
                )
                
        elif delete:
            if not address and not username:
                raise click.UsageError("--address or --username is required when deleting")
            
            await client.delete_device(address=address, username=username)
            click.echo(f"Deleted device(s)")
            
        elif lock:
            if not address and not username:
                raise click.UsageError("--address or --username is required when locking")
            
            await client.lock_device(address=address, username=username)
            click.echo(f"Locked device(s)")
            
        elif unlock:
            if not address and not username:
                raise click.UsageError("--address or --username is required when unlocking")
            
            await client.unlock_device(address=address, username=username)
            click.echo(f"Unlocked device(s)")
            
        elif mfa_sessions:
            sessions = await client.get_mfa_sessions()
            click.echo("address,username,expires_at")
            for session in sessions:
                click.echo(f"{session['address']},{session['username']},{session['expires_at']}")
        else:
            raise click.UsageError("Must specify an action: --list, --del, --lock, --unlock, or --mfa-sessions")
            
    finally:
        await client.disconnect()
