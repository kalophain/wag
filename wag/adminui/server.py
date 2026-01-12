"""Admin UI FastAPI server implementation."""
import asyncio
import logging
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional

from fastapi import FastAPI, WebSocket, Depends, HTTPException, Header, Request, Response
from fastapi.responses import JSONResponse
from fastapi.middleware.cors import CORSMiddleware
from itsdangerous import URLSafeTimedSerializer, BadSignature, SignatureExpired
import uvicorn

from wag.adminui.models import (
    LoginRequestDTO, LoginResponseDTO, ConfigResponseDTO, GenericResponseDTO,
    ChangePasswordRequestDTO, ServerInfoDTO, LogLinesDTO, UsersData, EditUsersDTO,
    DevicesData, EditDevicesDTO, TokensData, RegistrationTokenRequestDTO,
    WgDevicesData, FirewallTestRequestDTO, AclsTestRequestDTO, AclsTestResponseDTO,
    MFAMethodDTO, NotificationDTO, TestNotificationsRequestDTO, EventsResponseDTO,
    AcknowledgeErrorResponseDTO, MembershipDTO, NewNodeRequestDTO, NewNodeResponseDTO,
    NodeControlRequestDTO, WebServerConfigDTO, AcmeDetailsResponseDTO, StringDTO,
    WebhookInputAttributesDTO, WebhookInputUrlDTO, AdminUserDTO
)

logger = logging.getLogger(__name__)


class AdminUIServer:
    """Admin UI web server using FastAPI."""
    
    def __init__(self, config: Any, db: Any, router: Any, ctrl_client: Any = None):
        """Initialize Admin UI server.
        
        Args:
            config: Configuration object
            db: Database interface
            router: Router/Firewall interface
            ctrl_client: Control client for backend operations
        """
        self.config = config
        self.db = db
        self.router = router
        self.ctrl = ctrl_client
        self.app = FastAPI(title="Wag Admin UI", version="7.0.0")
        self.csrf_header_name = "WAG-CSRF"
        self.secret_key = "change-me-in-production"  # TODO: Generate from config
        self.serializer = URLSafeTimedSerializer(self.secret_key)
        self.sessions: Dict[str, Dict[str, Any]] = {}
        self.log_queue: List[str] = []
        self.max_log_lines = 40
        
        # Setup CORS
        self.app.add_middleware(
            CORSMiddleware,
            allow_origins=["*"],  # Configure based on config
            allow_credentials=True,
            allow_methods=["*"],
            allow_headers=["*"],
        )
        
        self._setup_routes()
    
    def _setup_routes(self):
        """Setup all API routes."""
        app = self.app
        
        # Public routes (no auth required)
        app.post("/api/login")(self.do_login)
        app.get("/api/config")(self.ui_config)
        app.post("/api/refresh")(self.do_auth_refresh)
        
        # Protected routes - Info
        app.get("/api/info")(self.require_auth(self.server_info))
        app.get("/api/console_log")(self.require_auth(self.console_log))
        
        # Protected routes - Management Users
        app.get("/api/management/users")(self.require_auth(self.get_users))
        app.put("/api/management/users")(self.require_auth(self.edit_user))
        app.delete("/api/management/users")(self.require_auth(self.remove_users))
        app.get("/api/management/admin_users")(self.require_auth(self.admin_users_data))
        
        # Protected routes - Management Devices
        app.get("/api/management/devices")(self.require_auth(self.get_all_devices))
        app.put("/api/management/devices")(self.require_auth(self.edit_device))
        app.delete("/api/management/devices")(self.require_auth(self.delete_device))
        
        # Protected routes - Management Sessions
        app.get("/api/management/sessions")(self.require_auth(self.get_sessions))
        
        # Protected routes - Management Registration Tokens
        app.get("/api/management/registration_tokens")(self.require_auth(self.get_all_registration_tokens))
        app.post("/api/management/registration_tokens")(self.require_auth(self.create_registration_token))
        app.delete("/api/management/registration_tokens")(self.require_auth(self.delete_registration_tokens))
        
        # Protected routes - Management Webhooks
        app.get("/api/management/webhooks")(self.require_auth(self.get_webhooks))
        app.post("/api/management/webhooks")(self.require_auth(self.create_webhook))
        app.delete("/api/management/webhooks")(self.require_auth(self.delete_webhooks))
        app.post("/api/management/webhook/request")(self.require_auth(self.get_webhook_last_request))
        
        # Protected routes - Policy
        app.get("/api/policy/rules")(self.require_auth(self.get_all_policies))
        app.put("/api/policy/rules")(self.require_auth(self.edit_policy))
        app.post("/api/policy/rules")(self.require_auth(self.create_policy))
        app.delete("/api/policy/rules")(self.require_auth(self.delete_policies))
        
        # Protected routes - Groups
        app.get("/api/policy/groups")(self.require_auth(self.get_all_groups))
        app.put("/api/policy/groups")(self.require_auth(self.edit_group))
        app.post("/api/policy/groups")(self.require_auth(self.create_group))
        app.delete("/api/policy/groups")(self.require_auth(self.delete_groups))
        
        # Protected routes - Settings
        app.get("/api/settings/general")(self.require_auth(self.get_general_settings))
        app.put("/api/settings/general")(self.require_auth(self.update_general_settings))
        app.get("/api/settings/login")(self.require_auth(self.get_login_settings))
        app.put("/api/settings/login")(self.require_auth(self.update_login_settings))
        app.get("/api/settings/all_mfa_methods")(self.require_auth(self.get_all_mfa_methods))
        app.get("/api/settings/webservers")(self.require_auth(self.get_all_webserver_configs))
        app.put("/api/settings/webserver")(self.require_auth(self.edit_webserver_config))
        app.get("/api/settings/acme")(self.require_auth(self.get_acme_details))
        app.put("/api/settings/acme/email")(self.require_auth(self.edit_acme_email))
        app.put("/api/settings/acme/provider_url")(self.require_auth(self.edit_acme_provider))
        app.put("/api/settings/acme/cloudflare_api_key")(self.require_auth(self.edit_cloudflare_api_token))
        
        # Protected routes - Diagnostics
        app.get("/api/diag/wg")(self.require_auth(self.wg_diagnostics_data))
        app.get("/api/diag/firewall")(self.require_auth(self.get_firewall_state))
        app.post("/api/diag/check")(self.require_auth(self.firewall_check_test))
        app.post("/api/diag/acls")(self.require_auth(self.acls_test))
        app.post("/api/diag/notifications")(self.require_auth(self.test_notifications))
        
        # Protected routes - Cluster (if enabled)
        app.get("/api/cluster/members")(self.require_auth(self.members))
        app.post("/api/cluster/members")(self.require_auth(self.new_node))
        app.put("/api/cluster/members")(self.require_auth(self.node_control))
        app.get("/api/cluster/events")(self.require_auth(self.get_cluster_events))
        app.put("/api/cluster/events")(self.require_auth(self.cluster_events_acknowledge))
        
        # Protected routes - Other
        app.put("/api/change_password")(self.require_auth(self.change_password))
        app.get("/api/logout")(self.require_auth(self.logout))
    
    def require_auth(self, func):
        """Decorator to require authentication."""
        async def wrapper(request: Request, *args, **kwargs):
            session_id = request.cookies.get("admin_session")
            if not session_id or session_id not in self.sessions:
                raise HTTPException(status_code=401, detail="Unauthorized")
            
            session = self.sessions[session_id]
            if session.get("expires", datetime.now()) < datetime.now():
                del self.sessions[session_id]
                raise HTTPException(status_code=401, detail="Session expired")
            
            # Extend session
            session["expires"] = datetime.now() + timedelta(hours=1)
            
            return await func(request, *args, **kwargs)
        return wrapper
    
    async def ui_config(self) -> ConfigResponseDTO:
        """Get UI configuration."""
        # TODO: Read from actual config
        return ConfigResponseDTO(
            sso=False,  # self.config.webserver.management.oidc.enabled
            password=True  # self.config.webserver.management.password.enabled
        )
    
    async def do_login(self, login: LoginRequestDTO, response: Response) -> LoginResponseDTO:
        """Handle login request."""
        try:
            # TODO: Implement actual authentication
            # For now, stub implementation
            if not self.ctrl:
                raise HTTPException(status_code=500, detail="Control client not available")
            
            # Verify credentials with control client
            # admin = await self.ctrl.get_admin_user(login.username)
            # await self.ctrl.compare_admin_keys(login.username, login.password)
            
            # Create session
            session_id = self._generate_session_id()
            user = AdminUserDTO(
                username=login.username,
                locked=False,
                change=False,
                type="local"
            )
            
            self.sessions[session_id] = {
                "user": user,
                "expires": datetime.now() + timedelta(hours=1)
            }
            
            # Set cookie
            response.set_cookie(
                key="admin_session",
                value=session_id,
                httponly=True,
                max_age=3600,
                samesite="lax"
            )
            
            csrf_token = self._generate_csrf_token(session_id)
            
            return LoginResponseDTO(
                success=True,
                user=user,
                csrf_token=csrf_token,
                csrf_header=self.csrf_header_name
            )
        except Exception as e:
            logger.error(f"Login failed: {e}")
            return LoginResponseDTO(success=False)
    
    async def do_auth_refresh(self, request: Request) -> LoginResponseDTO:
        """Refresh authentication."""
        session_id = request.cookies.get("admin_session")
        if not session_id or session_id not in self.sessions:
            raise HTTPException(status_code=401, detail="Unauthorized")
        
        session = self.sessions[session_id]
        user = session.get("user")
        csrf_token = self._generate_csrf_token(session_id)
        
        return LoginResponseDTO(
            success=True,
            user=user,
            csrf_token=csrf_token,
            csrf_header=self.csrf_header_name
        )
    
    async def logout(self, request: Request, response: Response):
        """Handle logout."""
        session_id = request.cookies.get("admin_session")
        if session_id and session_id in self.sessions:
            del self.sessions[session_id]
        response.delete_cookie("admin_session")
        return Response(status_code=204)
    
    async def server_info(self, request: Request) -> ServerInfoDTO:
        """Get server information."""
        # TODO: Get real data from router/firewall and control client
        return ServerInfoDTO(
            subnet="10.0.0.0/24",
            port=51820,
            public_key="stub_public_key",
            external_address="example.com",
            version="7.0.0",
            cluster_management_enabled=False
        )
    
    async def console_log(self, request: Request) -> LogLinesDTO:
        """Get console log lines."""
        return LogLinesDTO(log_lines=self.log_queue.copy())
    
    # Stub implementations for all other endpoints
    async def get_users(self, request: Request) -> List[UsersData]:
        """Get all users."""
        # TODO: Implement with control client
        return []
    
    async def edit_user(self, request: Request, action: EditUsersDTO) -> GenericResponseDTO:
        """Edit user."""
        # TODO: Implement
        return GenericResponseDTO(success=True, message="OK")
    
    async def remove_users(self, request: Request, usernames: List[str]) -> GenericResponseDTO:
        """Remove users."""
        # TODO: Implement
        return GenericResponseDTO(success=True, message="OK")
    
    async def admin_users_data(self, request: Request) -> List[AdminUserDTO]:
        """Get admin users."""
        # TODO: Implement
        return []
    
    async def get_all_devices(self, request: Request) -> List[DevicesData]:
        """Get all devices."""
        # TODO: Implement
        return []
    
    async def edit_device(self, request: Request, action: EditDevicesDTO) -> GenericResponseDTO:
        """Edit device."""
        # TODO: Implement
        return GenericResponseDTO(success=True, message="OK")
    
    async def delete_device(self, request: Request, addresses: List[str]) -> GenericResponseDTO:
        """Delete device."""
        # TODO: Implement
        return GenericResponseDTO(success=True, message="OK")
    
    async def get_sessions(self, request: Request) -> List[dict]:
        """Get sessions."""
        # TODO: Implement
        return []
    
    async def get_all_registration_tokens(self, request: Request) -> List[TokensData]:
        """Get all registration tokens."""
        # TODO: Implement
        return []
    
    async def create_registration_token(self, request: Request, req: RegistrationTokenRequestDTO) -> GenericResponseDTO:
        """Create registration token."""
        # TODO: Implement
        return GenericResponseDTO(success=True, message="token_created")
    
    async def delete_registration_tokens(self, request: Request, tokens: List[str]) -> GenericResponseDTO:
        """Delete registration tokens."""
        # TODO: Implement
        return GenericResponseDTO(success=True, message="OK")
    
    async def get_webhooks(self, request: Request) -> List[dict]:
        """Get webhooks."""
        # TODO: Implement
        return []
    
    async def create_webhook(self, request: Request, webhook: dict) -> GenericResponseDTO:
        """Create webhook."""
        # TODO: Implement
        return GenericResponseDTO(success=True, message="OK")
    
    async def delete_webhooks(self, request: Request, webhooks: List[str]) -> GenericResponseDTO:
        """Delete webhooks."""
        # TODO: Implement
        return GenericResponseDTO(success=True, message="OK")
    
    async def get_webhook_last_request(self, request: Request, webhook_id: dict) -> GenericResponseDTO:
        """Get webhook last request."""
        # TODO: Implement
        return GenericResponseDTO(success=True, message="")
    
    async def get_all_policies(self, request: Request) -> List[dict]:
        """Get all policies."""
        # TODO: Implement
        return []
    
    async def edit_policy(self, request: Request, policy: dict) -> GenericResponseDTO:
        """Edit policy."""
        # TODO: Implement
        return GenericResponseDTO(success=True, message="OK")
    
    async def create_policy(self, request: Request, policy: dict) -> GenericResponseDTO:
        """Create policy."""
        # TODO: Implement
        return GenericResponseDTO(success=True, message="OK")
    
    async def delete_policies(self, request: Request, policies: List[str]) -> GenericResponseDTO:
        """Delete policies."""
        # TODO: Implement
        return GenericResponseDTO(success=True, message="OK")
    
    async def get_all_groups(self, request: Request) -> List[dict]:
        """Get all groups."""
        # TODO: Implement
        return []
    
    async def edit_group(self, request: Request, group: dict) -> GenericResponseDTO:
        """Edit group."""
        # TODO: Implement
        return GenericResponseDTO(success=True, message="OK")
    
    async def create_group(self, request: Request, group: dict) -> GenericResponseDTO:
        """Create group."""
        # TODO: Implement
        return GenericResponseDTO(success=True, message="OK")
    
    async def delete_groups(self, request: Request, groups: List[str]) -> GenericResponseDTO:
        """Delete groups."""
        # TODO: Implement
        return GenericResponseDTO(success=True, message="OK")
    
    async def get_general_settings(self, request: Request) -> dict:
        """Get general settings."""
        # TODO: Implement
        return {}
    
    async def update_general_settings(self, request: Request, settings: dict) -> GenericResponseDTO:
        """Update general settings."""
        # TODO: Implement
        return GenericResponseDTO(success=True, message="OK")
    
    async def get_login_settings(self, request: Request) -> dict:
        """Get login settings."""
        # TODO: Implement
        return {}
    
    async def update_login_settings(self, request: Request, settings: dict) -> GenericResponseDTO:
        """Update login settings."""
        # TODO: Implement
        return GenericResponseDTO(success=True, message="OK")
    
    async def get_all_mfa_methods(self, request: Request) -> List[MFAMethodDTO]:
        """Get all MFA methods."""
        # TODO: Implement
        return []
    
    async def get_all_webserver_configs(self, request: Request) -> List[WebServerConfigDTO]:
        """Get all webserver configs."""
        # TODO: Implement
        return []
    
    async def edit_webserver_config(self, request: Request, config: WebServerConfigDTO) -> GenericResponseDTO:
        """Edit webserver config."""
        # TODO: Implement
        return GenericResponseDTO(success=True, message="OK")
    
    async def get_acme_details(self, request: Request) -> AcmeDetailsResponseDTO:
        """Get ACME details."""
        # TODO: Implement
        return AcmeDetailsResponseDTO(provider_url="", email="", api_token_set=False)
    
    async def edit_acme_email(self, request: Request, email: StringDTO) -> GenericResponseDTO:
        """Edit ACME email."""
        # TODO: Implement
        return GenericResponseDTO(success=True, message="OK")
    
    async def edit_acme_provider(self, request: Request, provider: StringDTO) -> GenericResponseDTO:
        """Edit ACME provider."""
        # TODO: Implement
        return GenericResponseDTO(success=True, message="OK")
    
    async def edit_cloudflare_api_token(self, request: Request, token: StringDTO) -> GenericResponseDTO:
        """Edit Cloudflare API token."""
        # TODO: Implement
        return GenericResponseDTO(success=True, message="OK")
    
    async def wg_diagnostics_data(self, request: Request) -> List[WgDevicesData]:
        """Get WireGuard diagnostics data."""
        # TODO: Implement
        return []
    
    async def get_firewall_state(self, request: Request) -> List[dict]:
        """Get firewall state."""
        # TODO: Implement
        return []
    
    async def firewall_check_test(self, request: Request, test: FirewallTestRequestDTO) -> GenericResponseDTO:
        """Test firewall check."""
        # TODO: Implement
        return GenericResponseDTO(success=True, message="Test result")
    
    async def acls_test(self, request: Request, test: AclsTestRequestDTO) -> AclsTestResponseDTO:
        """Test ACLs."""
        # TODO: Implement
        return AclsTestResponseDTO(success=True, message="")
    
    async def test_notifications(self, request: Request, test: TestNotificationsRequestDTO) -> GenericResponseDTO:
        """Test notifications."""
        # TODO: Implement
        return GenericResponseDTO(success=True, message="OK")
    
    async def members(self, request: Request) -> List[MembershipDTO]:
        """Get cluster members."""
        # TODO: Implement
        return []
    
    async def new_node(self, request: Request, node: NewNodeRequestDTO) -> NewNodeResponseDTO:
        """Add new cluster node."""
        # TODO: Implement
        return NewNodeResponseDTO(join_token="", error_message="")
    
    async def node_control(self, request: Request, control: NodeControlRequestDTO) -> GenericResponseDTO:
        """Control cluster node."""
        # TODO: Implement
        return GenericResponseDTO(success=True, message="OK")
    
    async def get_cluster_events(self, request: Request) -> EventsResponseDTO:
        """Get cluster events."""
        # TODO: Implement
        return EventsResponseDTO(events=[], errors=[])
    
    async def cluster_events_acknowledge(self, request: Request, ack: AcknowledgeErrorResponseDTO) -> GenericResponseDTO:
        """Acknowledge cluster event."""
        # TODO: Implement
        return GenericResponseDTO(success=True, message="OK")
    
    async def change_password(self, request: Request, change: ChangePasswordRequestDTO) -> GenericResponseDTO:
        """Change password."""
        # TODO: Implement
        return GenericResponseDTO(success=True, message="OK")
    
    def _generate_session_id(self) -> str:
        """Generate a session ID."""
        import secrets
        return secrets.token_urlsafe(32)
    
    def _generate_csrf_token(self, session_id: str) -> str:
        """Generate CSRF token for session."""
        return self.serializer.dumps(session_id)
    
    async def start(self, host: str = "0.0.0.0", port: int = 8080):
        """Start the admin UI server."""
        logger.info(f"Starting Admin UI server on {host}:{port}")
        config = uvicorn.Config(
            self.app,
            host=host,
            port=port,
            log_level="info"
        )
        server = uvicorn.Server(config)
        await server.serve()
