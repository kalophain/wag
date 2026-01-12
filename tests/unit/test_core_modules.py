"""Test the translated core modules."""
import asyncio
from ipaddress import IPv4Address

from wag.internal.config import load_config, Config
from wag.internal.data import LoginSettings, GeneralSettings, OIDC, PAM, Webserver
from wag.internal.router import Firewall, FirewallDevice


def test_config_loading():
    """Test that config module can load a configuration file."""
    config = load_config("example_config.json")
    
    assert isinstance(config, Config)
    assert config.wireguard.dev_name == "wg1"
    assert config.wireguard.listen_port == 53230
    assert config.webserver.tunnel.domain == "vpn.test"
    assert config.webserver.lockout == 5
    print("✓ Config loading test passed")


def test_config_validation():
    """Test that config validation works."""
    config = load_config("example_config.json")
    
    # Check defaults are applied
    assert config.webserver.public.download_config_file_name == "wg0.conf"
    assert config.wireguard.mtu == 1420
    assert config.clustering.name == "default"
    
    # Check computed values
    assert config.wireguard.server_address is not None
    assert config.wireguard.network_range is not None
    
    # Check ACL reverse lookup
    assert "toaster" in config.acls.reverse_group_lookup
    assert "group:administrators" in config.acls.reverse_group_lookup["toaster"]
    
    print("✓ Config validation test passed")


def test_data_models():
    """Test that data models work correctly."""
    # Test LoginSettings
    login_settings = LoginSettings(
        session_inactivity_timeout_minutes=30,
        max_session_lifetime_minutes=480,
        lockout=5,
        default_mfa_method="totp",
        enabled_mfa_methods=["totp", "webauthn"],
        issuer="test.example.com",
        oidc=OIDC(),
        pam=PAM(service_name="")
    )
    assert login_settings.lockout == 5
    assert login_settings.issuer == "test.example.com"
    
    # Test GeneralSettings
    general_settings = GeneralSettings(
        help_mail="help@example.com",
        external_address="192.168.1.1",
        dns=["8.8.8.8", "1.1.1.1"],
        wireguard_config_filename="wg0.conf",
        check_updates=True
    )
    assert general_settings.help_mail == "help@example.com"
    assert len(general_settings.dns) == 2
    
    # Test Webserver enum
    assert Webserver.TUNNEL.value == "tunnel"
    
    print("✓ Data models test passed")


def test_router_classes():
    """Test that router classes can be instantiated."""
    # Test FirewallDevice
    device = FirewallDevice(
        public_key="test_key",
        address=IPv4Address("192.168.1.100"),
        username="testuser",
        device_id="device123"
    )
    assert device.username == "testuser"
    assert device.public_key == "test_key"
    
    # Test Firewall
    class MockDB:
        def get_current_node_id(self):
            return "node1"
        async def get_session_inactivity_timeout_minutes(self):
            return 30
        async def get_initial_data(self):
            return {}, {}
    
    # Firewall can be instantiated (initialization is separate)
    firewall = Firewall(MockDB(), has_iptables=False, testing=True)
    assert firewall.testing is True
    assert firewall.closed is False
    
    print("✓ Router classes test passed")


async def test_router_async():
    """Test async router operations."""
    class MockDB:
        def get_current_node_id(self):
            return "node1"
        async def get_session_inactivity_timeout_minutes(self):
            return 30
        async def get_initial_data(self):
            return {}, {}
    
    # Firewall can be instantiated without full initialization
    firewall = Firewall(MockDB(), has_iptables=False, testing=True)
    
    # Test set_inactivity_timeout (this method is implemented)
    await firewall.set_inactivity_timeout(60)
    assert firewall.inactivity_timeout.total_seconds() == 3600
    
    # Test disabling timeout
    await firewall.set_inactivity_timeout(-1)
    assert firewall.inactivity_timeout is None
    
    print("✓ Router async operations test passed")


if __name__ == "__main__":
    test_config_loading()
    test_config_validation()
    test_data_models()
    test_router_classes()
    asyncio.run(test_router_async())
    print("\n✓✓✓ All core module tests passed! ✓✓✓")
