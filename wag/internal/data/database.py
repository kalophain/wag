"""Database interface for Wag."""
import json
from abc import ABC, abstractmethod
from typing import Any, Optional

from .models import (
    GeneralSettings,
    LoginSettings,
    OIDC,
    PAM,
    Webauthn,
    Webserver,
    WebserverConfiguration,
)


# Database keys
CONFIG_KEY = "wag-config-"
FULL_JSON_CONFIG_KEY = CONFIG_KEY + "full"
HELP_MAIL_KEY = CONFIG_KEY + "general-help-mail"
DEFAULT_WG_FILENAME_KEY = CONFIG_KEY + "general-wg-filename"
CHECK_UPDATES_KEY = CONFIG_KEY + "general-check-updates"
INACTIVITY_TIMEOUT_KEY = CONFIG_KEY + "authentication-inactivity-timeout"
SESSION_LIFETIME_KEY = CONFIG_KEY + "authentication-max-session-lifetime"
LOCKOUT_KEY = CONFIG_KEY + "authentication-lockout"
ISSUER_KEY = CONFIG_KEY + "authentication-issuer"
MFA_METHODS_ENABLED_KEY = CONFIG_KEY + "authentication-methods"
DEFAULT_MFA_METHOD_KEY = CONFIG_KEY + "authentication-default-method"
OIDC_DETAILS_KEY = CONFIG_KEY + "authentication-oidc"
PAM_DETAILS_KEY = CONFIG_KEY + "authentication-pam"
EXTERNAL_ADDRESS_KEY = CONFIG_KEY + "network-external-address"
DNS_KEY = CONFIG_KEY + "network-dns"
MEMBERSHIP_KEY = "wag-membership"
DEVICE_REF = "deviceref-"
TOKENS_KEY = "tokens-"
WEBSERVER_CONFIG_KEY = CONFIG_KEY + "webserver-"
TUNNEL_WEBSERVER_CONFIG_KEY = WEBSERVER_CONFIG_KEY + Webserver.TUNNEL.value
PUBLIC_WEBSERVER_CONFIG_KEY = WEBSERVER_CONFIG_KEY + Webserver.PUBLIC.value
MANAGEMENT_WEBSERVER_CONFIG_KEY = WEBSERVER_CONFIG_KEY + Webserver.MANAGEMENT.value

# Other prefixes
USERS_PREFIX = "users-"
GROUP_MEMBERSHIP_PREFIX = MEMBERSHIP_KEY + "-"
ACLS_PREFIX = "wag-acls-"
GROUPS_PREFIX = "wag-groups-"
GROUPS_INDEX_PREFIX = "wag-index-groups-"
CONFIG_PREFIX = "wag-config-"
AUTHENTICATION_PREFIX = "wag-config-authentication-"
NODE_INFO = "wag/node/"
NODE_ERRORS = "wag/node/errors"


class Database(ABC):
    """Abstract database interface for Wag."""

    @abstractmethod
    async def initialize(self) -> None:
        """Initialize the database connection."""
        pass

    @abstractmethod
    async def close(self) -> None:
        """Close the database connection."""
        pass

    @abstractmethod
    def get_current_node_id(self) -> str:
        """Get the current node ID."""
        pass

    # Configuration getters/setters
    @abstractmethod
    async def get_webserver_config(
        self, for_what: Webserver
    ) -> WebserverConfiguration:
        """Get webserver configuration."""
        pass

    @abstractmethod
    async def set_webserver_config(
        self, for_what: Webserver, details: WebserverConfiguration
    ) -> None:
        """Set webserver configuration."""
        pass

    @abstractmethod
    async def get_all_webserver_configs(self) -> dict[str, WebserverConfiguration]:
        """Get all webserver configurations."""
        pass

    @abstractmethod
    async def get_pam(self) -> PAM:
        """Get PAM configuration."""
        pass

    @abstractmethod
    async def get_oidc(self) -> OIDC:
        """Get OIDC configuration."""
        pass

    @abstractmethod
    async def get_webauthn(self) -> Webauthn:
        """Get WebAuthn configuration."""
        pass

    @abstractmethod
    async def get_wireguard_config_name(self) -> str:
        """Get WireGuard configuration filename."""
        pass

    @abstractmethod
    async def set_default_mfa_method(self, method: str) -> None:
        """Set default MFA method."""
        pass

    @abstractmethod
    async def get_default_mfa_method(self) -> str:
        """Get default MFA method."""
        pass

    @abstractmethod
    async def set_enabled_mfa_methods(self, methods: list[str]) -> None:
        """Set enabled MFA methods."""
        pass

    @abstractmethod
    async def get_enabled_mfa_methods(self) -> list[str]:
        """Get enabled MFA methods."""
        pass

    @abstractmethod
    async def should_check_updates(self) -> bool:
        """Check if updates should be checked."""
        pass

    @abstractmethod
    async def get_tunnel_domain_url(self) -> str:
        """Get tunnel domain URL."""
        pass

    @abstractmethod
    async def set_issuer(self, issuer: str) -> None:
        """Set issuer."""
        pass

    @abstractmethod
    async def get_issuer(self) -> str:
        """Get issuer."""
        pass

    @abstractmethod
    async def set_help_mail(self, help_mail: str) -> None:
        """Set help mail."""
        pass

    @abstractmethod
    async def get_help_mail(self) -> str:
        """Get help mail."""
        pass

    @abstractmethod
    async def get_external_address(self) -> str:
        """Get external address."""
        pass

    @abstractmethod
    async def set_dns(self, dns: list[str]) -> None:
        """Set DNS servers."""
        pass

    @abstractmethod
    async def get_dns(self) -> list[str]:
        """Get DNS servers."""
        pass

    @abstractmethod
    async def get_login_settings(self) -> LoginSettings:
        """Get login settings."""
        pass

    @abstractmethod
    async def get_general_settings(self) -> GeneralSettings:
        """Get general settings."""
        pass

    @abstractmethod
    async def set_login_settings(self, settings: LoginSettings) -> None:
        """Set login settings."""
        pass

    @abstractmethod
    async def set_general_settings(self, settings: GeneralSettings) -> None:
        """Set general settings."""
        pass

    @abstractmethod
    async def set_session_lifetime_minutes(self, lifetime_minutes: int) -> None:
        """Set session lifetime in minutes."""
        pass

    @abstractmethod
    async def get_session_lifetime_minutes(self) -> int:
        """Get session lifetime in minutes. Returns -1 if disabled."""
        pass

    @abstractmethod
    async def set_session_inactivity_timeout_minutes(
        self, inactivity_timeout: int
    ) -> None:
        """Set session inactivity timeout in minutes."""
        pass

    @abstractmethod
    async def get_session_inactivity_timeout_minutes(self) -> int:
        """Get session inactivity timeout in minutes. Returns -1 if disabled."""
        pass

    @abstractmethod
    async def get_lockout(self) -> int:
        """Get account lockout threshold."""
        pass

    @abstractmethod
    async def get_initial_data(self) -> tuple[Any, Any]:
        """Get initial users and devices data."""
        pass


def domain_to_url(domain: str, listen_address: str, is_tls: bool) -> str:
    """Convert domain and listen address to full URL.
    
    Args:
        domain: Domain name
        listen_address: Listen address with port
        is_tls: Whether TLS is enabled
        
    Returns:
        Full URL string
        
    Raises:
        ValueError: If domain is empty
    """
    if not domain:
        raise ValueError("domain was empty")

    scheme = "https://" if is_tls else "http://"
    url = scheme + domain

    # Check if domain has a port
    domain_port = None
    try:
        _, domain_port = domain.rsplit(":", 1)
    except ValueError:
        # No port in domain, try to get from listen address
        try:
            _, domain_port = listen_address.rsplit(":", 1)
            url = url + ":" + domain_port
        except ValueError:
            # No port in listen address either
            return url

    # Remove default ports
    if is_tls and domain_port == "443":
        url = url.replace(":443", "")
    elif not is_tls and domain_port == "80":
        url = url.replace(":80", "")

    return url
