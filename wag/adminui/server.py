"""Admin UI FastAPI server implementation."""
import logging
from datetime import datetime, timedelta
from typing import Any, Dict, List

from fastapi import FastAPI, HTTPException, Request, Response
from fastapi.middleware.cors import CORSMiddleware
from itsdangerous import URLSafeTimedSerializer
import uvicorn

from wag.adminui.models import (
    LoginRequestDTO, LoginResponseDTO, ConfigResponseDTO, GenericResponseDTO,
    ChangePasswordRequestDTO, AdminUserDTO
)
from wag.adminui import (
    users, devices, registration, policies, settings,
    diagnostics, clustering, webhooks, info
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
        self.version = "7.0.0"
        
        # Setup CORS
        self.app.add_middleware(
            CORSMiddleware,
            allow_origins=["*"],  # TODO: Configure based on config
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
    
    # Authentication endpoints
    async def ui_config(self) -> ConfigResponseDTO:
        """Get UI configuration."""
        # TODO: Read from actual config
        return ConfigResponseDTO(sso=False, password=True)
    
    async def do_login(self, login: LoginRequestDTO, response: Response) -> LoginResponseDTO:
        """Handle login request."""
        try:
            # TODO: Implement actual authentication with control client
            if not self.ctrl:
                raise HTTPException(status_code=500, detail="Control client not available")
            
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
    
    async def change_password(self, request: Request, change: ChangePasswordRequestDTO) -> GenericResponseDTO:
        """Change password."""
        # TODO: Implement password change
        return GenericResponseDTO(success=True, message="OK")
    
    # Delegate to modular implementations
    async def server_info(self, request: Request):
        return await info.server_info(self.ctrl, self.router, self.db, self.config, self.version, request)
    
    async def console_log(self, request: Request):
        return await info.console_log(self.log_queue, request)
    
    async def get_users(self, request: Request):
        return await users.get_users(self.ctrl, request)
    
    async def edit_user(self, request: Request, action):
        return await users.edit_user(self.ctrl, request, action)
    
    async def remove_users(self, request: Request, usernames: List[str]):
        return await users.remove_users(self.ctrl, request, usernames)
    
    async def admin_users_data(self, request: Request):
        return await users.admin_users_data(self.ctrl, request)
    
    async def get_all_devices(self, request: Request):
        return await devices.get_all_devices(self.ctrl, request)
    
    async def edit_device(self, request: Request, action):
        return await devices.edit_device(self.ctrl, request, action)
    
    async def delete_device(self, request: Request, addresses: List[str]):
        return await devices.delete_device(self.ctrl, request, addresses)
    
    async def get_sessions(self, request: Request):
        return await diagnostics.get_sessions(self.ctrl, request)
    
    async def get_all_registration_tokens(self, request: Request):
        return await registration.get_all_registration_tokens(self.ctrl, request)
    
    async def create_registration_token(self, request: Request, req):
        return await registration.create_registration_token(self.ctrl, request, req)
    
    async def delete_registration_tokens(self, request: Request, tokens: List[str]):
        return await registration.delete_registration_tokens(self.ctrl, request, tokens)
    
    async def get_webhooks(self, request: Request):
        return await webhooks.get_webhooks(self.ctrl, request)
    
    async def create_webhook(self, request: Request, webhook: dict):
        return await webhooks.create_webhook(self.ctrl, request, webhook)
    
    async def delete_webhooks(self, request: Request, webhooks_list: List[str]):
        return await webhooks.delete_webhooks(self.ctrl, request, webhooks_list)
    
    async def get_webhook_last_request(self, request: Request, webhook_id: dict):
        return await webhooks.get_webhook_last_request(self.ctrl, request, webhook_id)
    
    async def get_all_policies(self, request: Request):
        return await policies.get_all_policies(self.ctrl, request)
    
    async def edit_policy(self, request: Request, policy: dict):
        return await policies.edit_policy(self.ctrl, request, policy)
    
    async def create_policy(self, request: Request, policy: dict):
        return await policies.create_policy(self.ctrl, request, policy)
    
    async def delete_policies(self, request: Request, policies_list: List[str]):
        return await policies.delete_policies(self.ctrl, request, policies_list)
    
    async def get_all_groups(self, request: Request):
        return await policies.get_all_groups(self.ctrl, request)
    
    async def edit_group(self, request: Request, group: dict):
        return await policies.edit_group(self.ctrl, request, group)
    
    async def create_group(self, request: Request, group: dict):
        return await policies.create_group(self.ctrl, request, group)
    
    async def delete_groups(self, request: Request, groups: List[str]):
        return await policies.delete_groups(self.ctrl, request, groups)
    
    async def get_general_settings(self, request: Request):
        return await settings.get_general_settings(self.ctrl, request)
    
    async def update_general_settings(self, request: Request, settings_data: dict):
        return await settings.update_general_settings(self.ctrl, request, settings_data)
    
    async def get_login_settings(self, request: Request):
        return await settings.get_login_settings(self.ctrl, request)
    
    async def update_login_settings(self, request: Request, settings_data: dict):
        return await settings.update_login_settings(self.ctrl, request, settings_data)
    
    async def get_all_mfa_methods(self, request: Request):
        return await settings.get_all_mfa_methods(self.ctrl, request)
    
    async def get_all_webserver_configs(self, request: Request):
        return await settings.get_all_webserver_configs(self.ctrl, request)
    
    async def edit_webserver_config(self, request: Request, config):
        return await settings.edit_webserver_config(self.ctrl, request, config)
    
    async def get_acme_details(self, request: Request):
        return await settings.get_acme_details(self.ctrl, request)
    
    async def edit_acme_email(self, request: Request, email):
        return await settings.edit_acme_email(self.ctrl, request, email)
    
    async def edit_acme_provider(self, request: Request, provider):
        return await settings.edit_acme_provider(self.ctrl, request, provider)
    
    async def edit_cloudflare_api_token(self, request: Request, token):
        return await settings.edit_cloudflare_api_token(self.ctrl, request, token)
    
    async def wg_diagnostics_data(self, request: Request):
        return await diagnostics.wg_diagnostics_data(self.ctrl, self.router, request)
    
    async def get_firewall_state(self, request: Request):
        return await diagnostics.get_firewall_state(self.ctrl, request)
    
    async def firewall_check_test(self, request: Request, test):
        return await diagnostics.firewall_check_test(self.ctrl, self.router, request, test)
    
    async def acls_test(self, request: Request, test):
        return await diagnostics.acls_test(self.ctrl, request, test)
    
    async def test_notifications(self, request: Request, test):
        return await diagnostics.test_notifications(self.db, request, test)
    
    async def members(self, request: Request):
        return await clustering.members(self.db, request)
    
    async def new_node(self, request: Request, node):
        return await clustering.new_node(self.db, request, node)
    
    async def node_control(self, request: Request, control):
        return await clustering.node_control(self.db, request, control)
    
    async def get_cluster_events(self, request: Request):
        return await clustering.get_cluster_events(self.db, request)
    
    async def cluster_events_acknowledge(self, request: Request, ack):
        return await clustering.cluster_events_acknowledge(self.db, request, ack)
    
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
