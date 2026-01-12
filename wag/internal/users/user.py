"""User management operations."""

from collections.abc import Callable
from dataclasses import dataclass
from typing import Any


@dataclass
class Device:
    """Represents a user device."""

    username: str
    address: str
    public_key: str
    preshared_key: str | None = None
    endpoint: str | None = None
    last_handshake: str | None = None


@dataclass
class UserData:
    """User data structure."""

    username: str
    locked: bool
    enforcing: bool


class User:
    """
    Represents a user in the system with device and MFA management.

    This is a Python implementation of the Go user struct from internal/users/user.go
    """

    def __init__(self, db, username: str, locked: bool = False, enforcing: bool = False):
        """
        Initialize a User instance.

        Args:
            db: Database interface instance
            username: User's username
            locked: Whether the user account is locked
            enforcing: Whether MFA is being enforced
        """
        self.db = db
        self.username = username
        self.locked = locked
        self.enforcing = enforcing

    async def reset_device_auth_attempts(self, address: str) -> None:
        """Reset authentication attempts for a device."""
        await self.db.set_device_authentication_attempts(self.username, address, 0)

    async def reset_mfa(self) -> None:
        """Reset user's MFA configuration."""
        await self.db.set_user_mfa(self.username, self.username, "unset")
        await self.unenforce_mfa()

    async def set_device_auth_attempts(self, address: str, number: int) -> None:
        """Set authentication attempts for a device."""
        await self.db.set_device_authentication_attempts(self.username, address, number)

    async def set_device_public_key(self, publickey: str, address: str) -> None:
        """
        Set device public key.

        Args:
            publickey: WireGuard public key
            address: Device IP address

        Raises:
            ValueError: If public key format is invalid
        """
        # In Python, we'd validate the key format here
        # For now, just pass it to the database
        await self.db.update_device_public_key(self.username, address, publickey)

    async def get_device_preshared_key(self, address: str) -> str:
        """
        Get device pre-shared key.

        Args:
            address: Device IP address

        Returns:
            Pre-shared key or empty string if unset
        """
        device = await self.db.get_device_by_address(address)
        psk = device.get("preshared_key", "unset")
        return "" if psk == "unset" else psk

    async def add_device(self, publickey: str, static_ip: str | None = None, tag: str | None = None) -> Device:
        """
        Add a new device for this user.

        Args:
            publickey: WireGuard public key
            static_ip: Optional static IP address
            tag: Optional device tag

        Returns:
            Created Device object
        """
        device_data = await self.db.add_device(self.username, publickey, static_ip or "", tag or "")
        return Device(**device_data)

    async def delete_device(self, address: str) -> None:
        """Delete a device."""
        await self.db.delete_device(address)

    async def get_device(self, device_id: str) -> Device:
        """Get a specific device."""
        device_data = await self.db.get_device(self.username, device_id)
        return Device(**device_data)

    async def get_devices(self) -> list[Device]:
        """Get all devices for this user."""
        devices_data = await self.db.get_devices_by_user(self.username)
        return [Device(**d) for d in devices_data]

    async def lock(self) -> None:
        """Lock the user account."""
        self.locked = True
        await self.db.set_user_lock(self.username)

    async def unlock(self) -> None:
        """Unlock the user account."""
        self.locked = False
        await self.db.set_user_unlock(self.username)

    async def enforce_mfa(self) -> None:
        """Enable MFA enforcement for the user."""
        await self.db.set_enforce_mfa_on(self.username)

    async def unenforce_mfa(self) -> None:
        """Disable MFA enforcement for the user."""
        await self.db.set_enforce_mfa_off(self.username)

    def is_enforcing_mfa(self) -> bool:
        """Check if MFA is being enforced."""
        return self.db.is_enforcing_mfa(self.username)

    async def delete(self) -> None:
        """Delete the user."""
        await self.db.delete_user(self.username)

    async def authenticate(self, device: str, mfa_type: str, authenticator: Callable[[str, str], Any]) -> None:
        """
        Authenticate a device with MFA.

        Args:
            device: Device address
            mfa_type: Type of MFA (totp, webauthn, etc.)
            authenticator: Function to validate MFA

        Raises:
            Exception: If authentication fails
        """
        # Pre-emptively increment authentication attempts
        await self.db.increment_authentication_attempt(self.username, device)

        # Get authentication details
        auth_details = await self.db.get_authentication_details(self.username, device)
        mfa = auth_details["mfa"]
        user_mfa_type = auth_details["mfa_type"]
        attempts = auth_details["attempts"]
        locked = auth_details["locked"]

        lockout = await self.db.get_lockout()

        if attempts >= lockout:
            raise Exception("device is locked")

        if locked:
            raise Exception("account is locked")

        if user_mfa_type != mfa_type:
            raise Exception(f"authenticator {mfa_type} used for user with {user_mfa_type}")

        # Validate MFA
        authenticator(mfa, self.username)

        # Device successfully authenticated
        if not self.is_enforcing_mfa():
            await self.enforce_mfa()

        await self.db.authorise_device(self.username, device)

    async def deauthenticate(self, device: str) -> None:
        """Deauthenticate a device."""
        await self.db.deauthenticate_device(device)

    async def mfa(self) -> str:
        """Get MFA secret/URL for the user."""
        url = await self.db.get_mfa_secret(self.username)
        return url

    async def get_mfa_type(self) -> str:
        """Get the type of MFA configured for the user."""
        try:
            mfa_type = await self.db.get_mfa_type(self.username)
            return mfa_type
        except Exception:
            return "unset"


async def create_user(db, username: str) -> User:
    """
    Create a new user in the database.

    Args:
        db: Database interface
        username: Username for the new user

    Returns:
        User object
    """
    user_data = await db.create_user_data_account(username)
    return User(db=db, username=user_data["username"], locked=user_data["locked"], enforcing=user_data["enforcing"])


async def get_user(db, username: str) -> User:
    """
    Get an existing user from the database.

    Args:
        db: Database interface
        username: Username to retrieve

    Returns:
        User object
    """
    user_data = await db.get_user_data(username)
    return User(db=db, username=user_data["username"], locked=user_data["locked"], enforcing=user_data["enforcing"])


async def get_user_from_address(db, address: str) -> User:
    """
    Get a user from a device address.

    Args:
        db: Database interface
        address: Device IP address

    Returns:
        User object

    Raises:
        ValueError: If address is invalid
    """
    if not address:
        raise ValueError("address was empty")

    user_data = await db.get_user_data_from_address(address)
    return User(db=db, username=user_data["username"], locked=user_data["locked"], enforcing=user_data["enforcing"])


# Context key for storing user in request context
USER_CONTEXT_KEY = "user"


def get_user_from_context(context: dict) -> User:
    """
    Get user from request context.

    Args:
        context: Request context dictionary

    Returns:
        User object from context

    Raises:
        KeyError: If user not in context
    """
    return context[USER_CONTEXT_KEY]
