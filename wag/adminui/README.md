# Admin UI - Python Implementation

This directory contains the Python implementation of the Wag admin web interface, reimplemented from the original Go version.

## Overview

The admin UI is a FastAPI-based web application that provides a RESTful API for managing the Wag VPN server. It handles:

- User authentication and session management
- User and device management
- Registration token management
- Policy and group configuration
- Server settings and diagnostics
- Cluster management (if enabled)
- Webhook management

## Architecture

### Modular Design

The implementation uses a modular architecture for maintainability:

```
wag/adminui/
├── __init__.py          # Package exports
├── models.py            # Data models (DTOs) - 30+ Pydantic models
├── server.py            # FastAPI application and routing
├── users.py             # User management endpoints
├── devices.py           # Device management endpoints
├── registration.py      # Registration token endpoints
├── policies.py          # Policy and group endpoints
├── settings.py          # Settings management endpoints
├── diagnostics.py       # Diagnostics and testing endpoints
├── clustering.py        # Cluster management endpoints
├── webhooks.py          # Webhook endpoints
└── info.py              # Server info and logging endpoints
```

### Key Components

#### 1. Models (`models.py`)

Pydantic models that define the structure of API requests and responses:
- Request/Response DTOs for all endpoints
- Matching the Go implementation's data structures
- Automatic validation and serialization

#### 2. Server (`server.py`)

The main FastAPI application:
- Route registration
- Authentication middleware
- Session management
- CSRF protection
- Delegates to modular endpoint implementations

#### 3. Endpoint Modules

Each module implements related endpoints:
- **users.py**: List, edit, lock/unlock, reset MFA for users
- **devices.py**: List, edit, lock/unlock, delete devices
- **registration.py**: Create, list, delete registration tokens
- **policies.py**: CRUD operations for policies and groups
- **settings.py**: General, login, webserver, and ACME settings
- **diagnostics.py**: WireGuard stats, firewall tests, ACL tests
- **clustering.py**: Cluster member management and events
- **webhooks.py**: Webhook management
- **info.py**: Server information and console logs

## API Endpoints

### Public Endpoints (No Auth Required)

- `POST /api/login` - Authenticate and create session
- `GET /api/config` - Get UI configuration (SSO/password enabled)
- `POST /api/refresh` - Refresh authentication session

### Protected Endpoints (Auth Required)

#### Info & Logging
- `GET /api/info` - Get server information
- `GET /api/console_log` - Get recent console log lines

#### User Management
- `GET /api/management/users` - List all users
- `PUT /api/management/users` - Edit users (lock/unlock/resetMFA)
- `DELETE /api/management/users` - Delete users
- `GET /api/management/admin_users` - List admin users

#### Device Management
- `GET /api/management/devices` - List all devices
- `PUT /api/management/devices` - Edit devices (lock/unlock)
- `DELETE /api/management/devices` - Delete devices
- `GET /api/management/sessions` - List active sessions

#### Registration Tokens
- `GET /api/management/registration_tokens` - List tokens
- `POST /api/management/registration_tokens` - Create token
- `DELETE /api/management/registration_tokens` - Delete tokens

#### Policy Management
- `GET /api/policy/rules` - List all policies
- `POST /api/policy/rules` - Create policy
- `PUT /api/policy/rules` - Edit policy
- `DELETE /api/policy/rules` - Delete policies

#### Group Management
- `GET /api/policy/groups` - List all groups
- `POST /api/policy/groups` - Create group
- `PUT /api/policy/groups` - Edit group
- `DELETE /api/policy/groups` - Delete groups

#### Settings
- `GET /api/settings/general` - Get general settings
- `PUT /api/settings/general` - Update general settings
- `GET /api/settings/login` - Get login settings
- `PUT /api/settings/login` - Update login settings
- `GET /api/settings/all_mfa_methods` - List available MFA methods
- `GET /api/settings/webservers` - List webserver configs
- `PUT /api/settings/webserver` - Update webserver config
- `GET /api/settings/acme` - Get ACME details
- `PUT /api/settings/acme/email` - Update ACME email
- `PUT /api/settings/acme/provider_url` - Update ACME provider
- `PUT /api/settings/acme/cloudflare_api_key` - Update Cloudflare API key

#### Diagnostics
- `GET /api/diag/wg` - Get WireGuard diagnostics
- `GET /api/diag/firewall` - Get firewall state
- `POST /api/diag/check` - Test firewall rules
- `POST /api/diag/acls` - Test user ACLs
- `POST /api/diag/notifications` - Test notifications

#### Cluster Management (if enabled)
- `GET /api/cluster/members` - List cluster members
- `POST /api/cluster/members` - Add new node
- `PUT /api/cluster/members` - Control node (promote/drain/remove)
- `GET /api/cluster/events` - Get cluster events and errors
- `PUT /api/cluster/events` - Acknowledge error

#### Webhooks
- `GET /api/management/webhooks` - List webhooks
- `POST /api/management/webhooks` - Create webhook
- `DELETE /api/management/webhooks` - Delete webhooks
- `POST /api/management/webhook/request` - Get webhook last request

#### Other
- `PUT /api/change_password` - Change admin password
- `GET /api/logout` - Logout and destroy session

## Authentication & Security

### Session Management
- Cookie-based sessions (`admin_session`)
- 1-hour session timeout with automatic extension
- Sessions stored in-memory (can be extended to use Redis)

### CSRF Protection
- CSRF tokens generated for each session
- Custom header `WAG-CSRF` required for state-changing operations
- Tokens validated using `itsdangerous` library

### Password Authentication
- Admin username/password login
- Passwords verified through control client
- Failed login tracking

### OIDC Authentication (Planned)
- SSO support via OIDC providers
- Configuration-based enabling

## Dependencies

The admin UI requires:

- **FastAPI** - Web framework
- **Uvicorn** - ASGI server
- **Pydantic** - Data validation and settings
- **itsdangerous** - Secure session management
- **python-multipart** - Form data parsing (for file uploads)

See `pyproject.toml` for complete dependency list.

## Usage

### Starting the Server

```python
from wag.adminui import AdminUIServer

# Initialize with dependencies
server = AdminUIServer(
    config=config_obj,
    db=database,
    router=firewall,
    ctrl_client=control_client
)

# Start server
await server.start(host="0.0.0.0", port=8080)
```

### Configuration

The server can be configured through the config object:

```python
config.webserver.management.password.enabled = True
config.webserver.management.oidc.enabled = False
config.webserver.management.listen_address = "0.0.0.0:8080"
```

## Testing

Unit tests are located in `tests/unit/test_adminui.py`.

Run tests with pytest:

```bash
pytest tests/unit/test_adminui.py -v
```

The tests verify:
- Server initialization
- Route registration
- Authentication requirements
- Endpoint existence
- Session and CSRF token generation

## Development

### Adding New Endpoints

1. Define DTOs in `models.py`
2. Implement endpoint logic in appropriate module
3. Wire up in `server.py`'s `_setup_routes()`
4. Add delegate method in `server.py`

Example:

```python
# In models.py
class NewFeatureDTO(BaseModel):
    name: str
    value: int

# In feature.py
async def get_feature(ctrl_client, request: Request) -> NewFeatureDTO:
    data = await ctrl_client.get_feature()
    return NewFeatureDTO(**data)

# In server.py
def _setup_routes(self):
    # ...
    app.get("/api/feature")(self.require_auth(self.get_feature))

async def get_feature(self, request: Request):
    return await feature.get_feature(self.ctrl, request)
```

## API Compatibility

The Python implementation maintains API compatibility with the Go version:
- Same URL paths
- Same request/response formats
- Same authentication flow
- Same error responses

This ensures the existing frontend can work with either backend.

## Future Enhancements

- [ ] WebSocket support for real-time notifications
- [ ] WebSocket for webhook testing
- [ ] Redis-based session storage for clustering
- [ ] Rate limiting
- [ ] Audit logging
- [ ] OpenAPI documentation generation
- [ ] Integration tests with frontend

## License

Same as Wag - AGPL-3.0
