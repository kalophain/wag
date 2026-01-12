"""Tests for routetypes module."""

from wag.internal.routetypes import (
    Key, Policy, parse_rules, validate_rules,
    TCP, UDP, ICMP, ANY, PUBLIC, SINGLE, RANGE, DENY
)


def test_key_basic():
    """Test Key creation and string representation."""
    # IPv4 key
    key = Key(prefixlen=24, ip=b'\x0a\x00\x00\x00')  # 10.0.0.0
    assert str(key) == "10.0.0.0/24"
    
    # IPv6 key
    key_v6 = Key(prefixlen=64, ip=b'\x20\x01\x0d\xb8' + b'\x00' * 12)
    assert "/64" in str(key_v6)


def test_policy_types():
    """Test Policy type checking."""
    policy = Policy(policy_type=PUBLIC | SINGLE, proto=TCP, lower_port=80)
    
    assert policy.is_type(PUBLIC)
    assert policy.is_type(SINGLE)
    assert not policy.is_type(DENY)


def test_policy_bytes():
    """Test Policy serialization to bytes."""
    policy = Policy(policy_type=SINGLE, proto=TCP, lower_port=80, upper_port=0)
    
    data = policy.to_bytes()
    assert len(data) == 8
    
    # Unpack and verify
    new_policy = Policy()
    new_policy.from_bytes(data)
    
    assert new_policy.policy_type == policy.policy_type
    assert new_policy.proto == policy.proto
    assert new_policy.lower_port == policy.lower_port


def test_parse_rules_basic():
    """Test basic rule parsing."""
    mfa = ["10.0.0.0/8 80/tcp", "192.168.1.0/24 443/tcp"]
    public = []
    deny = []
    
    rules, errors = parse_rules(mfa, public, deny)
    
    assert len(errors) == 0
    assert len(rules) == 2
    
    # Check first rule
    assert len(rules[0].keys) > 0
    assert len(rules[0].values) > 0


def test_parse_single_port():
    """Test parsing single port rules."""
    mfa = ["10.0.0.1 22/tcp"]
    rules, errors = parse_rules(mfa, [], [])
    
    assert len(errors) == 0
    assert len(rules) == 1
    assert rules[0].values[0].lower_port == 22
    assert rules[0].values[0].proto == TCP


def test_parse_port_range():
    """Test parsing port range rules."""
    mfa = ["10.0.0.1 8000-9000/tcp"]
    rules, errors = parse_rules(mfa, [], [])
    
    assert len(errors) == 0
    assert len(rules) == 1
    assert rules[0].values[0].is_type(RANGE)
    assert rules[0].values[0].lower_port == 8000
    assert rules[0].values[0].upper_port == 9000


def test_parse_icmp():
    """Test parsing ICMP rules."""
    mfa = ["10.0.0.1 icmp"]
    rules, errors = parse_rules(mfa, [], [])
    
    assert len(errors) == 0
    assert len(rules) == 1
    assert rules[0].values[0].proto == ICMP


def test_parse_any_any():
    """Test parsing any/any rules (address only)."""
    mfa = ["10.0.0.0/24"]
    rules, errors = parse_rules(mfa, [], [])
    
    assert len(errors) == 0
    assert len(rules) == 1
    assert rules[0].values[0].proto == ANY


def test_validate_rules():
    """Test rule validation."""
    # Valid rules
    error = validate_rules(["10.0.0.0/8 80/tcp"], [], [])
    assert error is None
    
    # Invalid rules
    error = validate_rules(["invalid address 80/tcp"], [], [])
    assert error is not None


def test_policy_string_representation():
    """Test Policy string formatting."""
    # Public single port
    policy = Policy(policy_type=PUBLIC | SINGLE, proto=TCP, lower_port=80)
    assert "public" in str(policy)
    assert "80" in str(policy)
    assert "tcp" in str(policy)
    
    # Deny range
    policy = Policy(policy_type=DENY | RANGE, proto=UDP, lower_port=1000, upper_port=2000)
    assert "deny" in str(policy)
    assert "1000-2000" in str(policy)
    assert "udp" in str(policy)


if __name__ == "__main__":
    test_key_basic()
    test_policy_types()
    test_policy_bytes()
    test_parse_rules_basic()
    test_parse_single_port()
    test_parse_port_range()
    test_parse_icmp()
    test_parse_any_any()
    test_validate_rules()
    test_policy_string_representation()
    print("✓ All routetypes tests passed")
