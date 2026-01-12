"""Configuration management for Wag."""
import json
import socket
from ipaddress import IPv4Network, IPv6Network, ip_address, ip_network
from pathlib import Path
from typing import Any, Optional

from pydantic import BaseModel, Field, field_validator, model_validator


class AcmeConfig(BaseModel):
    """ACME configuration for automatic TLS certificates."""
    email: str = ""
    ca_provider: str = Field(default="", alias="CAProvider")
    cloudflare_dns_token: str = Field(default="", alias="CloudflareDNSToken")


class WebserverDetails(BaseModel):
    """Base webserver configuration details."""
    listen_address: str = Field(alias="ListenAddress")
    domain: str = Field(default="", alias="Domain")
    tls: bool = Field(default=False, alias="TLS")
    certificate_path: str = Field(default="", alias="CertificatePath")
    private_key_path: str = Field(default="", alias="PrivateKeyPath")


class PublicWebserverConfig(WebserverDetails):
    """Public webserver configuration."""
    download_config_file_name: str = Field(
        default="wg0.conf", alias="DownloadConfigFileName"
    )
    external_address: str = Field(alias="ExternalAddress")


class OIDCConfig(BaseModel):
    """OIDC authentication configuration."""
    issuer_url: str = Field(default="", alias="IssuerURL")
    client_secret: str = Field(default="", alias="ClientSecret")
    client_id: str = Field(default="", alias="ClientID")
    groups_claim_name: str = Field(default="groups", alias="GroupsClaimName")
    device_username_claim: str = Field(default="", alias="DeviceUsernameClaim")
    scopes: list[str] = Field(default_factory=list, alias="Scopes")


class PAMConfig(BaseModel):
    """PAM authentication configuration."""
    service_name: str = Field(default="", alias="ServiceName")


class TunnelWebserverConfig(BaseModel):
    """Tunnel webserver configuration."""
    port: str = Field(alias="Port")
    domain: str = Field(default="", alias="Domain")
    tls: bool = Field(default=False, alias="TLS")
    certificate_path: str = Field(default="", alias="CertificatePath")
    private_key_path: str = Field(default="", alias="PrivateKeyPath")
    help_mail: str = Field(alias="HelpMail")
    max_session_lifetime_minutes: int = Field(alias="MaxSessionLifetimeMinutes")
    session_inactivity_timeout_minutes: int = Field(
        alias="SessionInactivityTimeoutMinutes"
    )
    default_method: str = Field(default="", alias="DefaultMethod")
    issuer: str = Field(alias="Issuer")
    methods: list[str] = Field(default_factory=list, alias="Methods")
    oidc: OIDCConfig = Field(default_factory=OIDCConfig, alias="OIDC")
    pam: PAMConfig = Field(default_factory=PAMConfig, alias="PAM")


class ManagementPasswordConfig(BaseModel):
    """Management password configuration."""
    enabled: Optional[bool] = Field(default=True, alias="Enabled")


class ManagementOIDCConfig(BaseModel):
    """Management OIDC configuration."""
    issuer_url: str = Field(default="", alias="IssuerURL")
    client_secret: str = Field(default="", alias="ClientSecret")
    client_id: str = Field(default="", alias="ClientID")
    enabled: bool = Field(default=False, alias="Enabled")


class ManagementWebserverConfig(WebserverDetails):
    """Management webserver configuration."""
    enabled: bool = Field(default=False, alias="Enabled")
    password: ManagementPasswordConfig = Field(
        default_factory=ManagementPasswordConfig, alias="Password"
    )
    oidc: ManagementOIDCConfig = Field(
        default_factory=ManagementOIDCConfig, alias="OIDC"
    )


class WebserverConfig(BaseModel):
    """Complete webserver configuration."""
    acme: AcmeConfig = Field(default_factory=AcmeConfig, alias="Acme")
    public: PublicWebserverConfig = Field(alias="Public")
    lockout: int = Field(alias="Lockout")
    tunnel: TunnelWebserverConfig = Field(alias="Tunnel")
    management: ManagementWebserverConfig = Field(
        default_factory=ManagementWebserverConfig, alias="Management"
    )


class WireguardConfig(BaseModel):
    """WireGuard configuration."""
    dev_name: str = Field(alias="DevName")
    listen_port: int = Field(alias="ListenPort")
    private_key: str = Field(alias="PrivateKey")
    address: str = Field(alias="Address")
    mtu: int = Field(default=1420, alias="MTU")
    log_level: int = Field(default=0, alias="LogLevel")
    server_persistent_keepalive: int = Field(
        default=0, alias="ServerPersistentKeepAlive"
    )
    dns: list[str] = Field(default_factory=list, alias="DNS")

    # These are computed from address
    server_address: Optional[str] = None
    network_range: Optional[Any] = None

    @field_validator("listen_port")
    @classmethod
    def validate_listen_port(cls, v: int) -> int:
        """Validate WireGuard listen port."""
        if v == 0:
            raise ValueError("wireguard ListenPort not set")
        if v < 1 or v > 65535:
            raise ValueError("wireguard ListenPort must be between 1 and 65535")
        return v


class AclPolicy(BaseModel):
    """Access control list policy."""
    mfa: list[str] = Field(default_factory=list, alias="Mfa")
    allow: list[str] = Field(default_factory=list, alias="Allow")
    deny: list[str] = Field(default_factory=list, alias="Deny")


class AclsConfig(BaseModel):
    """Access control lists configuration."""
    groups: dict[str, list[str]] = Field(default_factory=dict, alias="Groups")
    policies: dict[str, AclPolicy] = Field(default_factory=dict, alias="Policies")

    # Internal reverse lookup map
    reverse_group_lookup: dict[str, dict[str, bool]] = {}


class ClusteringConfig(BaseModel):
    """Clustering configuration."""
    name: str = Field(default="default", alias="Name")
    listen_addresses: list[str] = Field(
        default_factory=lambda: ["https://localhost:2380"], alias="ListenAddresses"
    )
    peers: dict[str, list[str]] = Field(default_factory=dict, alias="Peers")
    database_location: str = Field(default="", alias="DatabaseLocation")
    etcd_log_level: str = Field(default="error", alias="ETCDLogLevel")
    witness: bool = Field(default=False, alias="Witness")
    cluster_state: str = Field(default="new", alias="ClusterState")
    tls_manager_storage: str = Field(default="certificates", alias="TLSManagerStorage")
    tls_manager_listen_url: str = Field(
        default="https://127.0.0.1:4455", alias="TLSManagerListenURL"
    )


class Config(BaseModel):
    """Main Wag configuration."""
    socket: str = Field(default="/tmp/wag.sock", alias="Socket")
    gid: Optional[int] = Field(default=None, alias="GID")
    check_updates: bool = Field(default=False, alias="CheckUpdates")
    number_proxies: int = Field(default=0, alias="NumberProxies")
    dev_mode: bool = Field(default=False, alias="DevMode")
    expose_ports: list[str] = Field(default_factory=list, alias="ExposePorts")
    nat: bool = Field(default=True, alias="NAT")
    webserver: WebserverConfig = Field(alias="Webserver")
    wireguard: WireguardConfig = Field(alias="Wireguard")
    clustering: ClusteringConfig = Field(
        default_factory=ClusteringConfig, alias="Clustering"
    )
    acls: AclsConfig = Field(default_factory=AclsConfig, alias="Acls")

    class Config:
        """Pydantic config."""
        populate_by_name = True
        extra = "forbid"

    @model_validator(mode="after")
    def validate_config(self) -> "Config":
        """Validate the complete configuration."""
        # Set defaults
        if not self.socket:
            self.socket = "/tmp/wag.sock"

        if not self.webserver.public.download_config_file_name:
            self.webserver.public.download_config_file_name = "wg0.conf"

        if self.wireguard.mtu == 0:
            self.wireguard.mtu = 1420

        # Clustering defaults
        if not self.clustering.tls_manager_storage:
            self.clustering.tls_manager_storage = "certificates"

        if not self.clustering.tls_manager_listen_url:
            self.clustering.tls_manager_listen_url = "https://127.0.0.1:4455"

        if not self.clustering.tls_manager_listen_url.startswith("https://"):
            raise ValueError("tls manager listen url must be https://")

        if not self.clustering.peers:
            self.clustering.peers = {}

        if not self.clustering.name:
            self.clustering.name = "default"

        if not self.clustering.listen_addresses:
            self.clustering.listen_addresses = ["https://localhost:2380"]

        if not self.clustering.cluster_state:
            self.clustering.cluster_state = "new"

        # Parse WireGuard address
        try:
            network = ip_network(self.wireguard.address, strict=False)
            self.wireguard.network_range = network
            # Server address is the network address
            self.wireguard.server_address = str(
                list(network.hosts())[0] if network.num_addresses > 2 else network.network_address
            )
        except Exception as e:
            raise ValueError(f"wireguard address invalid: {e}")

        # Validate WireGuard private key format (basic check)
        if not self.wireguard.private_key or len(self.wireguard.private_key) < 32:
            raise ValueError("cannot parse wireguard key: invalid format")

        # Validate external address
        self._validate_external_address(self.webserver.public.external_address)

        # Validate lockout
        if self.webserver.lockout <= 0:
            raise ValueError("lockout policy unconfigured")

        # Validate session policies
        if self.webserver.tunnel.max_session_lifetime_minutes == 0:
            raise ValueError(
                "session max lifetime policy is not set (may be disabled by setting it to -1)"
            )

        if self.webserver.tunnel.session_inactivity_timeout_minutes == 0:
            raise ValueError(
                "session inactivity timeout policy is not set (may be disabled by setting it to -1)"
            )

        # Validate tunnel port
        if not self.webserver.tunnel.port:
            raise ValueError("tunnel listener port is not set (Tunnel.Port)")

        # Validate public listen address
        if not self.webserver.public.listen_address:
            raise ValueError("public listen address is not set (Public.ListenAddress)")

        # Validate DNS entries
        self.wireguard.dns = self._validate_dns(self.wireguard.dns)

        # Validate exposed ports
        if self.number_proxies > 0 and len(self.expose_ports) == 0:
            raise ValueError(
                "you have set 'NumberProxies' mode which disables adding the tunnel port "
                "to iptables but not defined any ExposedPorts (iptables rules added on the "
                "wag vpn host) thus clients would not be able to access the MFA portal"
            )

        for port_spec in self.expose_ports:
            self._validate_port_spec(port_spec)

        # Build reverse group lookup
        self.acls.reverse_group_lookup = {}
        for group, members in self.acls.groups.items():
            if not group.startswith("group:"):
                raise ValueError(f"group does not have 'group:' prefix: {group}")

            for user in members:
                if user not in self.acls.reverse_group_lookup:
                    self.acls.reverse_group_lookup[user] = {}
                self.acls.reverse_group_lookup[user][group] = True

        # Set default method if only one method
        if len(self.webserver.tunnel.methods) == 1:
            self.webserver.tunnel.default_method = self.webserver.tunnel.methods[0]

        # Set management password enabled default
        if self.webserver.management.password.enabled is None:
            self.webserver.management.password.enabled = True

        return self

    def _validate_external_address(self, external_address: str) -> None:
        """Validate external address."""
        if not external_address:
            raise ValueError("invalid ExternalAddress is empty")

        # Try to split host and port
        try:
            host, _ = external_address.rsplit(":", 1)
            external_address = host
        except ValueError:
            pass  # No port specified

        # Try to parse as IP
        try:
            ip_address(external_address)
            return
        except ValueError:
            pass

        # Try to resolve as domain
        try:
            addresses = socket.getaddrinfo(external_address, None)
            if not addresses:
                raise ValueError(
                    f"invalid ExternalAddress: {external_address} - no addresses found"
                )
        except socket.gaierror:
            raise ValueError(
                f"invalid ExternalAddress: {external_address} - unable to lookup as domain"
            )

    def _validate_dns(self, dns_entries: list[str]) -> list[str]:
        """Validate and process DNS entries."""
        new_dns_entries = []
        for entry in dns_entries:
            parsed_addresses = self._parse_address(entry.strip())
            new_dns_entries.extend(parsed_addresses)
        return new_dns_entries

    def _parse_address(self, address: str) -> list[str]:
        """Parse an address which can be IP, CIDR, or domain."""
        address = address.strip()

        # Try to parse as IP address
        try:
            addr = ip_address(address)
            mask = "/32" if addr.version == 4 else "/128"
            return [f"{address}{mask}"]
        except ValueError:
            pass

        # Try to parse as CIDR
        try:
            network = ip_network(address, strict=False)
            return [str(network)]
        except ValueError:
            pass

        # Try to resolve as domain
        try:
            addresses = socket.getaddrinfo(address, None)
            if not addresses:
                raise ValueError(f"no addresses for {address}")

            output = []
            for addr_info in addresses:
                ip_str = addr_info[4][0]
                try:
                    addr = ip_address(ip_str)
                    mask = "/32" if addr.version == 4 else "/128"
                    output.append(f"{ip_str}{mask}")
                except ValueError:
                    continue

            if not output:
                raise ValueError(
                    f"no addresses for domain {address} were added, potentially because "
                    "they were all ipv6 which is unsupported"
                )

            return output
        except socket.gaierror:
            raise ValueError(f"unable to resolve address from: {address}")

    def _validate_port_spec(self, port_spec: str) -> None:
        """Validate port specification (e.g., '80/tcp', '100-200/udp')."""
        parts = port_spec.split("/")
        if len(parts) < 2:
            raise ValueError(
                f"{port_spec} is not in a valid port format. E.g 80/tcp, 100-200/udp"
            )

        port_part = parts[0]
        protocol = parts[1].lower()

        if self.number_proxies > 0:
            try:
                _, public_port = self.webserver.public.listen_address.rsplit(":", 1)
                if port_part == public_port:
                    raise ValueError(
                        "you have tried to expose the vpn service (with ExposedPorts) "
                        "while also having 'Proxied' set to true, this will cause wag "
                        "to respect X-Forwarded-For from an external source which will "
                        "result in a security vulnerability, as such this is an error"
                    )
            except ValueError:
                pass  # No port in listen address

        if protocol not in ["tcp", "udp"]:
            raise ValueError(f"{port_spec} invalid protocol (supports tcp/udp)")

        # Check if it's a range
        if "-" in port_part:
            scope = port_part.split("-")
            if len(scope) != 2:
                raise ValueError(
                    f"{port_part} invalid port range format. E.g 100-200/udp"
                )
            try:
                start = int(scope[0])
                end = int(scope[1])
                if end < start:
                    raise ValueError(
                        f"{port_part} end port must be greater than start port. E.g 100-200/udp"
                    )
            except ValueError as e:
                raise ValueError(
                    f"{port_part} Could not convert port range to numbers. E.g 100-200/udp"
                ) from e
        else:
            # Single port
            try:
                port = int(port_part)
                if port < 1 or port > 65535:
                    raise ValueError(f"{port_part} port must be between 1 and 65535")
            except ValueError as e:
                raise ValueError(
                    f"{port_part} is not a valid port number. E.g 80/tcp, 100-200/udp"
                ) from e


def load_config(path: str) -> Config:
    """Load configuration from a JSON file.
    
    Args:
        path: Path to the configuration file
        
    Returns:
        Loaded and validated Config object
        
    Raises:
        ValueError: If configuration is invalid
        FileNotFoundError: If config file doesn't exist
    """
    config_path = Path(path)
    if not config_path.exists():
        raise FileNotFoundError(f"Configuration file not found: {path}")

    with open(config_path, "r") as f:
        try:
            data = json.load(f)
        except json.JSONDecodeError as e:
            raise ValueError(f"Invalid JSON in configuration file: {e}")

    try:
        config = Config.model_validate(data)
        return config
    except Exception as e:
        raise ValueError(f"Configuration validation failed: {e}")


# Global configuration instance
_config_instance: Optional[Config] = None


def get_config() -> Optional[Config]:
    """Get the global configuration instance."""
    return _config_instance


def set_config(config: Config) -> None:
    """Set the global configuration instance."""
    global _config_instance
    _config_instance = config


def load_and_set_config(path: str) -> Config:
    """Load configuration from file and set as global instance."""
    config = load_config(path)
    set_config(config)
    return config
