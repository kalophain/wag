"""Router and firewall management for Wag."""
import asyncio
import logging
from datetime import timedelta
from ipaddress import IPv4Address, IPv6Address, ip_address
from typing import Any, Dict, List, Optional, Union

logger = logging.getLogger(__name__)


class FirewallDevice:
    """Represents a device in the firewall."""

    def __init__(
        self,
        public_key: str,
        address: Union[IPv4Address, IPv6Address],
        username: str,
        device_id: str,
    ):
        """Initialize a firewall device.
        
        Args:
            public_key: WireGuard public key
            address: IP address assigned to device
            username: Username who owns the device
            device_id: Unique device identifier
        """
        self.public_key = public_key
        self.address = address
        self.username = username
        self.device_id = device_id
        self.last_activity: Optional[float] = None
        self.authorized: bool = False


class Policies:
    """User policies and routes."""

    def __init__(self):
        """Initialize policies."""
        self.policies: Dict[str, Any] = {}
        self.routes: List[str] = []


class Firewall:
    """WireGuard firewall and routing manager."""

    def __init__(
        self,
        db: Any,
        has_iptables: bool = True,
        testing: bool = False,
    ):
        """Initialize the firewall.
        
        Args:
            db: Database instance
            has_iptables: Whether to use iptables
            testing: Whether in testing mode
        """
        self.db = db
        self.has_iptables = has_iptables
        self.testing = testing
        self.closed = False

        # User and device mappings
        self.user_policies: Dict[str, Policies] = {}
        self.user_is_locked: Dict[str, bool] = {}
        self.address_to_device: Dict[Union[IPv4Address, IPv6Address], FirewallDevice] = {}
        self.address_to_policies: Dict[Union[IPv4Address, IPv6Address], Policies] = {}
        self.address_to_user: Dict[Union[IPv4Address, IPv6Address], str] = {}
        self.pubkey_to_device: Dict[str, FirewallDevice] = {}
        self.user_to_devices: Dict[str, Dict[str, FirewallDevice]] = {}
        self.currently_connected_peers: Dict[str, str] = {}

        # Configuration
        self.inactivity_timeout: Optional[timedelta] = None
        self.device_name: str = ""
        self.node_id: str = ""

        # WireGuard device
        self.device: Optional[Any] = None
        self.ctrl: Optional[Any] = None

        # Event watchers
        self.watchers: List[Any] = []

        # Lock
        self._lock = asyncio.Lock()

    async def initialize(self, device_name: str, address: str, mtu: int) -> None:
        """Initialize the firewall.
        
        Args:
            device_name: WireGuard device name
            address: WireGuard network address
            mtu: MTU size
        """
        logger.info("[ROUTER] Starting up")

        # Get configuration from database
        inactivity_timeout_int = await self.db.get_session_inactivity_timeout_minutes()
        if inactivity_timeout_int > 0:
            self.inactivity_timeout = timedelta(minutes=inactivity_timeout_int)
        else:
            self.inactivity_timeout = None

        self.node_id = self.db.get_current_node_id()
        self.device_name = device_name

        # Get initial data
        initial_users, known_devices = await self.db.get_initial_data()

        # Setup WireGuard
        if self.testing:
            await self._setup_wireguard_debug(None)
        else:
            await self._setup_wireguard(device_name, address, mtu)

        logger.info("[ROUTER] Adding users")
        await self._setup_users(initial_users)

        logger.info("[ROUTER] Adding wireguard devices")
        await self._setup_devices(known_devices)

        if self.has_iptables:
            route_mode = "MASQUERADE (NAT)"
            logger.info(f"[ROUTER] Setting up iptables in {route_mode} mode")
            await self._setup_iptables()

        logger.info("[ROUTER] Registering event handlers")
        await self._handle_events()

        logger.info("[ROUTER] Setup finished")

    async def _setup_wireguard(self, device_name: str, address: str, mtu: int) -> None:
        """Setup WireGuard device.
        
        Args:
            device_name: Device name
            address: Network address
            mtu: MTU size
        """
        # TODO: Interface with the WireGuard kernel module or userspace implementation
        logger.info(f"[ROUTER] Setting up WireGuard device {device_name}")
        raise NotImplementedError("WireGuard setup not yet implemented")

    async def _setup_wireguard_debug(self, test_dev: Any) -> None:
        """Setup WireGuard in debug mode.
        
        Args:
            test_dev: Test device
        """
        logger.info("[ROUTER] Setting up WireGuard in debug mode")
        # Debug mode doesn't require actual WireGuard setup
        pass

    async def _setup_users(self, users: Any) -> None:
        """Setup users from initial data.
        
        Args:
            users: User data
        """
        # TODO: Process and setup users from database
        raise NotImplementedError("User setup not yet implemented")

    async def _setup_devices(self, devices: Any) -> None:
        """Setup devices from initial data.
        
        Args:
            devices: Device data
        """
        # TODO: Process and setup devices from database
        raise NotImplementedError("Device setup not yet implemented")

    async def _setup_iptables(self) -> None:
        """Setup iptables rules."""
        # TODO: Configure iptables/nftables rules
        raise NotImplementedError("iptables setup not yet implemented")

    async def _teardown_iptables(self) -> None:
        """Teardown iptables rules."""
        # TODO: Remove iptables/nftables rules
        raise NotImplementedError("iptables teardown not yet implemented")

    async def _handle_events(self) -> None:
        """Setup event handlers for database changes."""
        # TODO: Setup watchers for database events
        raise NotImplementedError("Event handling not yet implemented")

    async def close(self) -> None:
        """Close the firewall and cleanup resources."""
        async with self._lock:
            if self.closed:
                return

            logger.info("Removing handlers")
            for watcher in self.watchers:
                if hasattr(watcher, "close"):
                    await watcher.close()

            logger.info("Removing wireguard device")
            if self.device:
                if hasattr(self.device, "close"):
                    await self.device.close()

            if self.ctrl:
                if hasattr(self.ctrl, "close"):
                    await self.ctrl.close()

            logger.info("Wireguard device removed")

            if self.has_iptables:
                await self._teardown_iptables()

            self.closed = True

    async def get_routes(self, username: str) -> List[str]:
        """Get routes for a user.
        
        Args:
            username: Username to get routes for
            
        Returns:
            List of route strings
            
        Raises:
            ValueError: If user not found or policies invalid
        """
        async with self._lock:
            if username not in self.user_policies:
                raise ValueError(f"user not found: {username}")

            user = self.user_policies[username]
            if user.policies is None:
                raise ValueError("user policies map was None")

            return user.routes.copy()

    async def set_inactivity_timeout(self, inactivity_timeout_minutes: int) -> None:
        """Set inactivity timeout.
        
        Args:
            inactivity_timeout_minutes: Timeout in minutes, -1 to disable
            
        Raises:
            RuntimeError: If firewall is closed
        """
        async with self._lock:
            if self.closed:
                raise RuntimeError("firewall instance has been closed")

            if inactivity_timeout_minutes < 0:
                self.inactivity_timeout = None
            else:
                self.inactivity_timeout = timedelta(minutes=inactivity_timeout_minutes)

    async def refresh_user_acls(self, username: str) -> None:
        """Refresh ACLs for a user.
        
        Args:
            username: Username to refresh ACLs for
        """
        async with self._lock:
            if self.closed:
                raise RuntimeError("firewall instance has been closed")
            # Refresh user ACLs from database
            pass


class Router:
    """Router manager wrapping the firewall."""

    def __init__(self, config: Any, db: Any, no_iptables: bool = False):
        """Initialize router.
        
        Args:
            config: Configuration object
            db: Database instance
            no_iptables: Whether to disable iptables
        """
        self.config = config
        self.db = db
        self.no_iptables = no_iptables
        self.firewall: Optional[Firewall] = None

    async def start(self) -> None:
        """Start the router."""
        self.firewall = Firewall(self.db, has_iptables=not self.no_iptables)
        await self.firewall.initialize(
            self.config.wireguard.dev_name,
            self.config.wireguard.address,
            self.config.wireguard.mtu,
        )

    async def stop(self) -> None:
        """Stop the router."""
        if self.firewall:
            await self.firewall.close()


async def new_firewall(db: Any, iptables: bool = True) -> Firewall:
    """Create a new firewall instance.
    
    Args:
        db: Database instance
        iptables: Whether to use iptables
        
    Returns:
        Initialized Firewall instance
    """
    fw = Firewall(db, has_iptables=iptables, testing=False)
    return fw


async def new_debug_firewall(db: Any, test_dev: Any = None) -> Firewall:
    """Create a new debug firewall instance.
    
    Args:
        db: Database instance
        test_dev: Test device
        
    Returns:
        Initialized Firewall instance for testing
    """
    fw = Firewall(db, has_iptables=False, testing=True)
    return fw
