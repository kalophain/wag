"""Data models for Admin UI API."""
from datetime import datetime
from typing import Any, List, Optional

from pydantic import BaseModel, Field


class LoginRequestDTO(BaseModel):
    """Login request."""
    username: str
    password: str


class AdminUserDTO(BaseModel):
    """Admin user data transfer object."""
    username: str
    locked: bool = False
    change: bool = False
    type: str = "local"  # "local" or "oidc"
    last_login: Optional[datetime] = None
    last_login_addr: Optional[str] = None


class LoginResponseDTO(BaseModel):
    """Login response."""
    success: bool
    user: Optional[AdminUserDTO] = None
    csrf_token: str = ""
    csrf_header: str = ""


class ConfigResponseDTO(BaseModel):
    """UI configuration response."""
    sso: bool
    password: bool


class GenericResponseDTO(BaseModel):
    """Generic success/error response."""
    success: bool
    message: str = "OK"


class ChangePasswordRequestDTO(BaseModel):
    """Change password request."""
    current_password: str
    new_password: str


class ServerInfoDTO(BaseModel):
    """Server information response."""
    subnet: str
    port: int
    public_key: str
    external_address: str
    version: str
    cluster_management_enabled: bool


class LogLinesDTO(BaseModel):
    """Console log lines response."""
    log_lines: List[str] = Field(default_factory=list)


class UsersData(BaseModel):
    """User list item."""
    username: str
    devices: int
    locked: bool
    date_added: str = ""
    mfa_type: str = ""
    groups: List[str] = Field(default_factory=list)


class EditUsersDTO(BaseModel):
    """User edit action."""
    action: str  # "lock", "unlock", "resetMFA"
    usernames: List[str]


class DevicesData(BaseModel):
    """Device list item."""
    owner: str
    is_locked: bool
    active: bool = False
    internal_ip: str
    public_key: str
    last_endpoint: str = ""
    tag: str = ""


class EditDevicesDTO(BaseModel):
    """Device edit action."""
    action: str  # "lock", "unlock"
    addresses: List[str]


class TokensData(BaseModel):
    """Registration token list item."""
    token: str
    username: str
    groups: List[str] = Field(default_factory=list)
    overwrites: str = ""
    static_ip: str = ""
    uses: int
    tag: str = ""


class RegistrationTokenRequestDTO(BaseModel):
    """Registration token create request."""
    username: str
    token: str = ""
    overwrites: str = ""
    static_ip: str = ""
    groups: List[str] = Field(default_factory=list)
    uses: int
    tag: str = ""


class WgDevicesData(BaseModel):
    """WireGuard device diagnostic data."""
    rx: int
    tx: int
    public_key: str
    address: str
    last_endpoint: str
    last_handshake_time: str


class FirewallTestRequestDTO(BaseModel):
    """Firewall test request."""
    address: str
    port: int = 0
    protocol: str
    target: str


class FirewallResponseDTO(BaseModel):
    """Firewall test response."""
    username: str = ""
    message: str
    success: bool
    acls: Optional[dict] = None


class AclsTestRequestDTO(BaseModel):
    """ACLs test request."""
    username: str


class AclsTestResponseDTO(BaseModel):
    """ACLs test response."""
    username: str = ""
    message: str = ""
    success: bool
    acls: Optional[dict] = None


class MFAMethodDTO(BaseModel):
    """MFA method information."""
    friendly_name: str
    method: str


class NotificationDTO(BaseModel):
    """Notification message."""
    id: str
    heading: str
    message: List[str]
    url: str
    time: datetime
    color: str
    open_new_tab: bool


class TestNotificationsRequestDTO(BaseModel):
    """Test notification request."""
    message: str


class EventsResponseDTO(BaseModel):
    """Events and errors response."""
    events: List[dict] = Field(default_factory=list)
    errors: List[dict] = Field(default_factory=list)


class AcknowledgeErrorResponseDTO(BaseModel):
    """Acknowledge error request."""
    error_id: str


class MembershipDTO(BaseModel):
    """Cluster membership information."""
    id: str
    name: str
    drained: bool
    witness: bool
    leader: bool
    learner: bool
    current_node: bool
    version: str
    last_ping: str
    status: str
    peer_urls: List[str] = Field(default_factory=list)


class NewNodeRequestDTO(BaseModel):
    """New cluster node request."""
    node_name: str
    connection_url: str
    manager_url: str


class NewNodeResponseDTO(BaseModel):
    """New cluster node response."""
    join_token: str = ""
    error_message: str = ""


class NodeControlRequestDTO(BaseModel):
    """Node control action request."""
    node: str
    action: str  # "promote", "drain", "restore", "stepdown", "remove"


class WebServerConfigDTO(BaseModel):
    """Web server configuration."""
    server_name: str
    listen_address: str
    domain: str
    tls: bool
    static_certificates: bool
    certificate: str = ""
    private_key: str = ""


class AcmeDetailsResponseDTO(BaseModel):
    """ACME details response."""
    provider_url: str
    email: str
    api_token_set: bool


class StringDTO(BaseModel):
    """Simple string data."""
    data: str


class WebhookInputAttributesDTO(BaseModel):
    """Webhook input attributes."""
    type: str
    attributes: List[dict] = Field(default_factory=list)
    error: str = ""


class WebhookInputUrlDTO(BaseModel):
    """Webhook input URL."""
    type: str
    url: str
    id: str
    auth_header: str
