"""Tests for acls module."""

from wag.internal.acls import Acl


def test_acl_creation():
    """Test ACL creation."""
    acl = Acl(
        mfa=["10.0.0.0/8 80/tcp"],
        allow=["192.168.0.0/16"],
        deny=["172.16.0.0/12"]
    )
    
    assert len(acl.mfa) == 1
    assert len(acl.allow) == 1
    assert len(acl.deny) == 1


def test_acl_defaults():
    """Test ACL with default empty lists."""
    acl = Acl()
    
    assert acl.mfa == []
    assert acl.allow == []
    assert acl.deny == []


def test_acl_equality():
    """Test ACL equality comparison."""
    acl1 = Acl(mfa=["10.0.0.0/8"], allow=[], deny=[])
    acl2 = Acl(mfa=["10.0.0.0/8"], allow=[], deny=[])
    acl3 = Acl(mfa=["192.168.0.0/16"], allow=[], deny=[])
    
    assert acl1.equals(acl2)
    assert not acl1.equals(acl3)
    assert acl1 == acl2
    assert acl1 != acl3


def test_acl_to_dict():
    """Test ACL to dictionary conversion."""
    acl = Acl(mfa=["10.0.0.0/8"], allow=[], deny=["172.16.0.0/12"])
    
    d = acl.to_dict()
    assert "Mfa" in d
    assert "Deny" in d
    assert "Allow" not in d  # Empty list omitted


if __name__ == "__main__":
    test_acl_creation()
    test_acl_defaults()
    test_acl_equality()
    test_acl_to_dict()
    print("✓ All acls tests passed")
