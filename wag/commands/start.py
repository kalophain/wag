"""Start command - starts the Wag server."""

import click
import asyncio
import signal
import sys
from pathlib import Path
from typing import Optional

from wag.internal.config import load_config
from wag.internal.data import Database
from wag.internal.router import Router
from wag.adminui.server import AdminUIServer
from wag.internal.mfaportal.server import MFAPortalServer
from wag.internal.publicwebserver.server import PublicWebServer
from wag.pkg.control.server import ControlServer


@click.command()
@click.option(
    '--config',
    '-c',
    default='./config.json',
    type=click.Path(exists=True),
    help='Configuration file location'
)
@click.option(
    '--join',
    '-j',
    default=None,
    help='Cluster join token'
)
@click.option(
    '--noiptables',
    is_flag=True,
    help='Do not add iptables rules'
)
def start(config: str, join: Optional[str], noiptables: bool):
    """
    Start wag server (does not daemonise).
    
    Starts the main Wag VPN server with all components including:
    - WireGuard interface management
    - Web servers (public, tunnel, management)
    - MFA portal
    - Admin UI
    - Control socket server
    """
    try:
        # Load configuration
        cfg = load_config(config)
        
        # Setup signal handlers
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        
        shutdown_event = asyncio.Event()
        
        def signal_handler(sig, frame):
            click.echo("\nShutting down gracefully...")
            shutdown_event.set()
        
        signal.signal(signal.SIGINT, signal_handler)
        signal.signal(signal.SIGTERM, signal_handler)
        
        # Run the server
        loop.run_until_complete(run_server(cfg, join, noiptables, shutdown_event))
        
    except Exception as e:
        click.echo(f"Error starting server: {e}", err=True)
        sys.exit(1)


async def run_server(cfg, join: Optional[str], noiptables: bool, shutdown_event):
    """Run the main server with all components."""
    click.echo("Starting Wag server...")
    
    # Initialize database
    db = Database(cfg)
    await db.initialize()
    
    # Initialize router (WireGuard management)
    router = Router(cfg, db, noiptables)
    await router.start()
    
    # Start control socket server
    control_server = ControlServer(cfg, db)
    control_task = asyncio.create_task(control_server.start())
    
    # Start web servers
    tasks = []
    
    # Public web server (registration)
    if cfg.webserver.public.enabled:
        public_server = PublicWebServer(cfg, db)
        tasks.append(asyncio.create_task(public_server.start()))
    
    # MFA portal (tunnel)
    if cfg.webserver.tunnel.enabled:
        mfa_server = MFAPortalServer(cfg, db, router)
        tasks.append(asyncio.create_task(mfa_server.start()))
    
    # Admin UI
    if cfg.webserver.management.enabled:
        admin_server = AdminUIServer(cfg, db, router)
        tasks.append(asyncio.create_task(admin_server.start()))
    
    click.echo("Wag server started successfully")
    
    # Wait for shutdown signal
    await shutdown_event.wait()
    
    # Cleanup
    click.echo("Stopping services...")
    for task in tasks:
        task.cancel()
    
    await router.stop()
    await db.close()
    
    click.echo("Wag server stopped")
