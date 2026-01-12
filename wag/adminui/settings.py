"""Settings management endpoints for Admin UI."""
import logging
from typing import List

from fastapi import HTTPException, Request

from wag.adminui.models import (
    GenericResponseDTO, MFAMethodDTO, WebServerConfigDTO,
    AcmeDetailsResponseDTO, StringDTO
)

logger = logging.getLogger(__name__)


async def get_general_settings(ctrl_client, request: Request) -> dict:
    """Get general settings."""
    try:
        if not ctrl_client:
            raise HTTPException(status_code=500, detail="Control client not available")
        
        settings = await ctrl_client.get_general_settings()
        return settings
    except Exception as e:
        logger.error(f"Error getting general settings: {e}")
        raise HTTPException(status_code=500, detail=str(e))


async def update_general_settings(ctrl_client, request: Request, settings: dict) -> GenericResponseDTO:
    """Update general settings."""
    try:
        if not ctrl_client:
            raise HTTPException(status_code=500, detail="Control client not available")
        
        await ctrl_client.set_general_settings(settings)
        return GenericResponseDTO(success=True, message="OK")
    except Exception as e:
        logger.error(f"Error updating general settings: {e}")
        raise HTTPException(status_code=500, detail=str(e))


async def get_login_settings(ctrl_client, request: Request) -> dict:
    """Get login settings."""
    try:
        if not ctrl_client:
            raise HTTPException(status_code=500, detail="Control client not available")
        
        settings = await ctrl_client.get_login_settings()
        return settings
    except Exception as e:
        logger.error(f"Error getting login settings: {e}")
        raise HTTPException(status_code=500, detail=str(e))


async def update_login_settings(ctrl_client, request: Request, settings: dict) -> GenericResponseDTO:
    """Update login settings."""
    try:
        if not ctrl_client:
            raise HTTPException(status_code=500, detail="Control client not available")
        
        await ctrl_client.set_login_settings(settings)
        return GenericResponseDTO(success=True, message="OK")
    except Exception as e:
        logger.error(f"Error updating login settings: {e}")
        raise HTTPException(status_code=500, detail=str(e))


async def get_all_mfa_methods(ctrl_client, request: Request) -> List[MFAMethodDTO]:
    """Get all available MFA methods."""
    try:
        # TODO: Get from authenticators module
        # For now, return common MFA methods
        return [
            MFAMethodDTO(friendly_name="TOTP (Time-based One-Time Password)", method="totp"),
            MFAMethodDTO(friendly_name="WebAuthn", method="webauthn"),
            MFAMethodDTO(friendly_name="OIDC", method="oidc"),
            MFAMethodDTO(friendly_name="PAM", method="pam"),
        ]
    except Exception as e:
        logger.error(f"Error getting MFA methods: {e}")
        raise HTTPException(status_code=500, detail=str(e))


async def get_all_webserver_configs(ctrl_client, request: Request) -> List[WebServerConfigDTO]:
    """Get all webserver configurations."""
    try:
        if not ctrl_client:
            raise HTTPException(status_code=500, detail="Control client not available")
        
        confs = await ctrl_client.get_all_webservers_settings()
        results = []
        
        for name, conf in confs.items():
            results.append(WebServerConfigDTO(
                server_name=name,
                listen_address=conf.get("listen_address", ""),
                domain=conf.get("domain", ""),
                tls=conf.get("tls", False),
                static_certificates=conf.get("static_certs", False),
                certificate=conf.get("certificate_pem", ""),
                private_key="Valid" if conf.get("private_key_pem") else ""
            ))
        
        results.sort(key=lambda x: x.server_name)
        return results
    except Exception as e:
        logger.error(f"Error getting webserver configs: {e}")
        raise HTTPException(status_code=500, detail=str(e))


async def edit_webserver_config(ctrl_client, request: Request, config: WebServerConfigDTO) -> GenericResponseDTO:
    """Edit webserver configuration."""
    try:
        if not ctrl_client:
            raise HTTPException(status_code=500, detail="Control client not available")
        
        # Validate listen address format
        host, port = config.listen_address.rsplit(":", 1)
        
        # Get existing config to preserve private key if "Valid" marker is used
        details = await ctrl_client.get_single_webserver_settings(config.server_name)
        
        if config.private_key == "Valid":
            config.private_key = details.get("private_key_pem", "")
        
        # Validate TLS cert if provided
        if config.certificate or config.private_key or config.static_certificates:
            # TODO: Validate certificate and key pair
            pass
        
        server_update = {
            "listen_address": config.listen_address,
            "domain": config.domain,
            "tls": config.tls,
            "static_certs": config.static_certificates,
            "certificate_pem": config.certificate,
            "private_key_pem": config.private_key
        }
        
        await ctrl_client.set_single_webserver_setting(config.server_name, server_update)
        return GenericResponseDTO(success=True, message="OK")
    except Exception as e:
        logger.error(f"Error editing webserver config: {e}")
        raise HTTPException(status_code=500, detail=str(e))


async def get_acme_details(ctrl_client, request: Request) -> AcmeDetailsResponseDTO:
    """Get ACME details."""
    try:
        if not ctrl_client:
            raise HTTPException(status_code=500, detail="Control client not available")
        
        provider_url = await ctrl_client.get_acme_provider()
        email = await ctrl_client.get_acme_email()
        
        try:
            cf_token = await ctrl_client.get_acme_dns01_cloudflare_token()
            has_token = bool(cf_token and cf_token.get("api_token"))
        except:
            has_token = False
        
        return AcmeDetailsResponseDTO(
            provider_url=provider_url or "",
            email=email or "",
            api_token_set=has_token
        )
    except Exception as e:
        logger.error(f"Error getting ACME details: {e}")
        raise HTTPException(status_code=500, detail=str(e))


async def edit_acme_email(ctrl_client, request: Request, email: StringDTO) -> GenericResponseDTO:
    """Edit ACME email."""
    try:
        if not ctrl_client:
            raise HTTPException(status_code=500, detail="Control client not available")
        
        await ctrl_client.set_acme_email(email.data)
        return GenericResponseDTO(success=True, message="OK")
    except Exception as e:
        logger.error(f"Error editing ACME email: {e}")
        raise HTTPException(status_code=500, detail=str(e))


async def edit_acme_provider(ctrl_client, request: Request, provider: StringDTO) -> GenericResponseDTO:
    """Edit ACME provider."""
    try:
        if not ctrl_client:
            raise HTTPException(status_code=500, detail="Control client not available")
        
        await ctrl_client.set_acme_provider(provider.data)
        return GenericResponseDTO(success=True, message="OK")
    except Exception as e:
        logger.error(f"Error editing ACME provider: {e}")
        raise HTTPException(status_code=500, detail=str(e))


async def edit_cloudflare_api_token(ctrl_client, request: Request, token: StringDTO) -> GenericResponseDTO:
    """Edit Cloudflare API token."""
    try:
        if not ctrl_client:
            raise HTTPException(status_code=500, detail="Control client not available")
        
        await ctrl_client.set_acme_dns01_cloudflare_token(token.data)
        return GenericResponseDTO(success=True, message="OK")
    except Exception as e:
        logger.error(f"Error editing Cloudflare API token: {e}")
        raise HTTPException(status_code=500, detail=str(e))
