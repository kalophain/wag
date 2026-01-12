"""Data models for Wag."""
from enum import Enum
from typing import Any, Optional

from pydantic import BaseModel, Field, field_validator


class Webserver(str, Enum):
    """Webserver type enum."""
    TUNNEL = "tunnel"
    MANAGEMENT = "management"
    PUBLIC = "public"


class OIDC(BaseModel):
    """OIDC authentication details."""
    issuer: str = Field(default="", alias="issuer")
    client_secret: str = Field(default="", alias="client_secret")
    client_id: str = Field(default="", alias="client_id")
    groups_claim_name: str = Field(default="groups", alias="group_claim_name")
    device_username_claim: str = Field(default="", alias="device_username_claim")
    scopes: list[str] = Field(default_factory=list, alias="scopes")

    class Config:
        """Pydantic config."""
        populate_by_name = True

    def equals(self, other: Optional["OIDC"]) -> bool:
        """Check if two OIDC configs are equal."""
        if other is None:
            return False
        return (
            self.issuer == other.issuer
            and self.client_secret == other.client_secret
            and self.client_id == other.client_id
            and self.device_username_claim == other.device_username_claim
            and self.scopes == other.scopes
        )


class PAM(BaseModel):
    """PAM authentication details."""
    service_name: str = Field(default="", alias="service_name")

    class Config:
        """Pydantic config."""
        populate_by_name = True


class Webauthn(BaseModel):
    """WebAuthn configuration."""
    display_name: str
    id: str
    origin: str


class WebserverConfiguration(BaseModel):
    """Webserver configuration stored in database."""
    listen_address: str = Field(alias="listen_address")
    domain: str = Field(default="", alias="domain")
    tls: bool = Field(default=False, alias="tls")
    static_certs: bool = Field(default=False, alias="static_certificates")
    certificate_pem: str = Field(default="", alias="certificate")
    private_key_pem: str = Field(default="", alias="private_key")

    class Config:
        """Pydantic config."""
        populate_by_name = True

    def equals(self, other: Optional["WebserverConfiguration"]) -> bool:
        """Check if two webserver configs are equal."""
        if other is None:
            return False
        return (
            self.domain == other.domain
            and self.tls == other.tls
            and self.listen_address == other.listen_address
            and self.certificate_pem == other.certificate_pem
            and self.private_key_pem == other.private_key_pem
        )


class LoginSettings(BaseModel):
    """Login and authentication settings."""
    session_inactivity_timeout_minutes: int = Field(
        alias="session_inactivity_timeout_minutes"
    )
    max_session_lifetime_minutes: int = Field(alias="max_session_lifetime_minutes")
    lockout: int = Field(alias="lockout")
    default_mfa_method: str = Field(alias="default_mfa_method")
    enabled_mfa_methods: list[str] = Field(alias="enabled_mfa_methods")
    issuer: str = Field(alias="issuer")
    oidc_details: OIDC = Field(default_factory=OIDC, alias="oidc")
    pam_details: PAM = Field(default_factory=PAM, alias="pam")

    class Config:
        """Pydantic config."""
        populate_by_name = True

    @field_validator("issuer")
    @classmethod
    def validate_issuer(cls, v: str) -> str:
        """Validate and clean issuer."""
        return v.strip()

    @field_validator("enabled_mfa_methods")
    @classmethod
    def validate_mfa_methods(cls, v: list[str]) -> list[str]:
        """Validate MFA methods."""
        if len(v) >= 10:
            raise ValueError("Too many MFA methods (max 10)")
        valid_methods = ["totp", "webauthn", "oidc", "pam"]
        for method in v:
            if method not in valid_methods:
                raise ValueError(
                    f"Invalid MFA method: {method}. Must be one of {valid_methods}"
                )
        return v


class GeneralSettings(BaseModel):
    """General settings."""
    help_mail: str = Field(alias="help_mail")
    external_address: str = Field(alias="external_address")
    dns: list[str] = Field(default_factory=list, alias="dns")
    wireguard_config_filename: str = Field(alias="wireguard_config_filename")
    check_updates: bool = Field(default=False, alias="check_updates")

    class Config:
        """Pydantic config."""
        populate_by_name = True

    @field_validator("help_mail", "external_address", "wireguard_config_filename")
    @classmethod
    def strip_whitespace(cls, v: str) -> str:
        """Strip whitespace from string fields."""
        return v.strip()

    @field_validator("dns")
    @classmethod
    def strip_dns_entries(cls, v: list[str]) -> list[str]:
        """Strip whitespace from DNS entries."""
        return [entry.strip() for entry in v]
