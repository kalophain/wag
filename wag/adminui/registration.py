"""Registration token management endpoints for Admin UI."""
import logging
from typing import List

from fastapi import HTTPException, Request

from wag.adminui.models import TokensData, RegistrationTokenRequestDTO, GenericResponseDTO

logger = logging.getLogger(__name__)


async def get_all_registration_tokens(ctrl_client, request: Request) -> List[TokensData]:
    """Get all registration tokens."""
    try:
        if not ctrl_client:
            raise HTTPException(status_code=500, detail="Control client not available")
        
        registrations = await ctrl_client.registrations()
        tokens = []
        
        for reg in registrations:
            tokens.append(TokensData(
                username=reg.username,
                token=reg.token,
                groups=reg.groups,
                static_ip=reg.static_ip if hasattr(reg, 'static_ip') else "",
                overwrites=reg.overwrites if hasattr(reg, 'overwrites') else "",
                uses=reg.num_uses if hasattr(reg, 'num_uses') else 1,
                tag=reg.tag if hasattr(reg, 'tag') else ""
            ))
        
        return tokens
    except Exception as e:
        logger.error(f"Error getting registration tokens: {e}")
        raise HTTPException(status_code=500, detail=str(e))


async def create_registration_token(ctrl_client, request: Request, req: RegistrationTokenRequestDTO) -> GenericResponseDTO:
    """Create registration token."""
    try:
        if not ctrl_client:
            raise HTTPException(status_code=500, detail="Control client not available")
        
        # Validate input
        req.username = req.username.strip()
        req.overwrites = req.overwrites.strip()
        
        if req.uses <= 0:
            raise HTTPException(status_code=400, detail="Cannot create token with <= 0 uses")
        
        result = await ctrl_client.new_registration(
            req.token,
            req.username,
            req.overwrites,
            req.static_ip,
            req.uses,
            req.tag,
            *req.groups
        )
        
        return GenericResponseDTO(success=True, message=result.token)
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error creating registration token: {e}")
        raise HTTPException(status_code=500, detail=str(e))


async def delete_registration_tokens(ctrl_client, request: Request, tokens: List[str]) -> GenericResponseDTO:
    """Delete registration token(s)."""
    try:
        if not ctrl_client:
            raise HTTPException(status_code=500, detail="Control client not available")
        
        errors = []
        for token in tokens:
            try:
                await ctrl_client.delete_registration(token)
            except Exception as e:
                errors.append(str(e))
        
        if errors:
            error_msg = "\n".join(errors)
            raise HTTPException(status_code=500, detail=error_msg)
        
        return GenericResponseDTO(success=True, message="OK")
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error deleting registration tokens: {e}")
        raise HTTPException(status_code=500, detail=str(e))
