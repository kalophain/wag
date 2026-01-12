"""Access Control Lists (ACLs) for network access control."""

from dataclasses import dataclass


@dataclass
class Acl:
    """
    Represents an Access Control List with MFA, allow, and deny rules.
    """

    mfa: list[str] | None = None
    allow: list[str] | None = None
    deny: list[str] | None = None

    def __post_init__(self):
        """Ensure all fields are lists, not None."""
        if self.mfa is None:
            self.mfa = []
        if self.allow is None:
            self.allow = []
        if self.deny is None:
            self.deny = []

    def equals(self, other: "Acl") -> bool:
        """
        Check if this ACL equals another ACL.

        Args:
            other: Another Acl object to compare with

        Returns:
            True if ACLs are equal, False otherwise
        """
        if self is other:
            return True

        if not isinstance(other, Acl):
            return False

        return self.mfa == other.mfa and self.allow == other.allow and self.deny == other.deny

    def __eq__(self, other) -> bool:
        """Equality operator."""
        return self.equals(other)

    def to_dict(self) -> dict:
        """
        Convert ACL to dictionary (for JSON serialization).

        Returns:
            Dictionary representation, omitting empty lists
        """
        result = {}
        if self.mfa:
            result["Mfa"] = self.mfa
        if self.allow:
            result["Allow"] = self.allow
        if self.deny:
            result["Deny"] = self.deny
        return result
