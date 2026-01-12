"""Unit tests for Admin UI server."""
import pytest
from unittest.mock import Mock, AsyncMock
from fastapi.testclient import TestClient

from wag.adminui.server import AdminUIServer
from wag.adminui.models import ConfigResponseDTO, LoginRequestDTO


class TestAdminUIServer:
    """Test cases for Admin UI server."""
    
    def setup_method(self):
        """Setup test fixtures."""
        self.config = Mock()
        self.db = Mock()
        self.router = Mock()
        self.ctrl_client = Mock()
        
        self.server = AdminUIServer(
            config=self.config,
            db=self.db,
            router=self.router,
            ctrl_client=self.ctrl_client
        )
        self.client = TestClient(self.server.app)
    
    def test_server_initialization(self):
        """Test server initializes correctly."""
        assert self.server.app is not None
        assert self.server.config == self.config
        assert self.server.db == self.db
        assert self.server.router == self.router
        assert self.server.ctrl == self.ctrl_client
    
    def test_ui_config_endpoint(self):
        """Test UI config endpoint returns expected structure."""
        response = self.client.get("/api/config")
        assert response.status_code == 200
        data = response.json()
        assert "sso" in data
        assert "password" in data
        assert isinstance(data["sso"], bool)
        assert isinstance(data["password"], bool)
    
    def test_login_endpoint_exists(self):
        """Test login endpoint is accessible."""
        # This will fail authentication but endpoint should exist
        response = self.client.post("/api/login", json={
            "username": "test",
            "password": "test"
        })
        # Should get response (even if auth fails)
        assert response.status_code in [200, 400, 401, 500]
    
    def test_protected_endpoint_requires_auth(self):
        """Test protected endpoints require authentication."""
        response = self.client.get("/api/info")
        # Should get 401 (unauthorized) or 422 (unprocessable - FastAPI validation)
        assert response.status_code in [401, 422]
    
    def test_all_user_management_endpoints_exist(self):
        """Test user management endpoints are registered."""
        endpoints = [
            ("/api/management/users", "GET"),
            ("/api/management/users", "PUT"),
            ("/api/management/users", "DELETE"),
            ("/api/management/admin_users", "GET"),
        ]
        
        for path, method in endpoints:
            # All should return 401 (unauthorized) since we're not logged in
            if method == "GET":
                response = self.client.get(path)
            elif method == "PUT":
                response = self.client.put(path, json={})
            elif method == "DELETE":
                response = self.client.request("DELETE", path, json=[])
            
            assert response.status_code in [401, 422], f"{method} {path} should require auth or fail validation"
    
    def test_all_device_management_endpoints_exist(self):
        """Test device management endpoints are registered."""
        endpoints = [
            ("/api/management/devices", "GET"),
            ("/api/management/devices", "PUT"),
            ("/api/management/devices", "DELETE"),
        ]
        
        for path, method in endpoints:
            if method == "GET":
                response = self.client.get(path)
            elif method == "PUT":
                response = self.client.put(path, json={})
            elif method == "DELETE":
                response = self.client.request("DELETE", path, json=[])
            
            assert response.status_code in [401, 422], f"{method} {path} should require auth or fail validation"
    
    def test_all_policy_endpoints_exist(self):
        """Test policy management endpoints are registered."""
        endpoints = [
            ("/api/policy/rules", "GET"),
            ("/api/policy/rules", "PUT"),
            ("/api/policy/rules", "POST"),
            ("/api/policy/rules", "DELETE"),
            ("/api/policy/groups", "GET"),
            ("/api/policy/groups", "PUT"),
            ("/api/policy/groups", "POST"),
            ("/api/policy/groups", "DELETE"),
        ]
        
        for path, method in endpoints:
            if method == "GET":
                response = self.client.get(path)
            elif method == "PUT":
                response = self.client.put(path, json={})
            elif method == "POST":
                response = self.client.post(path, json={})
            elif method == "DELETE":
                response = self.client.request("DELETE", path, json=[])
            
            assert response.status_code in [401, 422], f"{method} {path} should require auth or fail validation"
    
    def test_all_settings_endpoints_exist(self):
        """Test settings endpoints are registered."""
        endpoints = [
            ("/api/settings/general", "GET"),
            ("/api/settings/general", "PUT"),
            ("/api/settings/login", "GET"),
            ("/api/settings/login", "PUT"),
            ("/api/settings/all_mfa_methods", "GET"),
            ("/api/settings/webservers", "GET"),
            ("/api/settings/webserver", "PUT"),
            ("/api/settings/acme", "GET"),
            ("/api/settings/acme/email", "PUT"),
            ("/api/settings/acme/provider_url", "PUT"),
            ("/api/settings/acme/cloudflare_api_key", "PUT"),
        ]
        
        for path, method in endpoints:
            if method == "GET":
                response = self.client.get(path)
            elif method == "PUT":
                response = self.client.put(path, json={})
            
            assert response.status_code in [401, 422], f"{method} {path} should require auth or fail validation"
    
    def test_all_diagnostics_endpoints_exist(self):
        """Test diagnostics endpoints are registered."""
        endpoints = [
            ("/api/diag/wg", "GET"),
            ("/api/diag/firewall", "GET"),
            ("/api/diag/check", "POST"),
            ("/api/diag/acls", "POST"),
            ("/api/diag/notifications", "POST"),
        ]
        
        for path, method in endpoints:
            if method == "GET":
                response = self.client.get(path)
            elif method == "POST":
                response = self.client.post(path, json={})
            
            assert response.status_code in [401, 422], f"{method} {path} should require auth or fail validation"
    
    def test_session_management(self):
        """Test session ID generation."""
        session_id1 = self.server._generate_session_id()
        session_id2 = self.server._generate_session_id()
        
        assert session_id1 != session_id2
        assert len(session_id1) > 0
        assert len(session_id2) > 0
    
    def test_csrf_token_generation(self):
        """Test CSRF token generation."""
        session_id = "test_session_123"
        csrf_token = self.server._generate_csrf_token(session_id)
        
        assert csrf_token is not None
        assert len(csrf_token) > 0
