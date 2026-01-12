"""Control socket client stub."""
class ControlClient:
    def __init__(self, socket_path):
        self.socket_path = socket_path
    async def connect(self):
        pass
    async def disconnect(self):
        pass
    async def add_registration_token(self, **kwargs):
        return {"token": "stub_token"}
    async def delete_registration_token(self, token):
        pass
    async def list_registration_tokens(self):
        return []
    async def list_devices(self, username=None):
        return []
    async def delete_device(self, **kwargs):
        pass
    async def lock_device(self, **kwargs):
        pass
    async def unlock_device(self, **kwargs):
        pass
    async def get_mfa_sessions(self):
        return []
    async def list_users(self, username=None):
        return []
    async def delete_user(self, username):
        pass
    async def reset_user_mfa(self, username):
        pass
    async def lock_user_account(self, username):
        pass
    async def unlock_user_account(self, username):
        pass
    async def list_firewall_rules(self):
        return []
    async def reload_firewall(self):
        pass
    async def flush_firewall(self):
        pass
    async def list_webadmins(self, username=None):
        return []
    async def add_webadmin(self, username, password):
        pass
    async def delete_webadmin(self, username):
        pass
    async def lock_webadmin(self, username):
        pass
    async def unlock_webadmin(self, username):
        pass
    async def get_config(self):
        return {}
