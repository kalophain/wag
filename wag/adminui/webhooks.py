"""Webhook endpoints for Admin UI."""
import logging
from typing import List

from fastapi import HTTPException, Request

from wag.adminui.models import GenericResponseDTO

logger = logging.getLogger(__name__)


async def get_webhooks(ctrl_client, request: Request) -> List[dict]:
    """Get all webhooks."""
    try:
        if not ctrl_client:
            raise HTTPException(status_code=500, detail="Control client not available")
        
        hooks = await ctrl_client.get_webhooks()
        return hooks
    except Exception as e:
        logger.error(f"Error getting webhooks: {e}")
        raise HTTPException(status_code=500, detail=str(e))


async def get_webhook_last_request(ctrl_client, request: Request, webhook_data: dict) -> GenericResponseDTO:
    """Get webhook last request."""
    try:
        if not ctrl_client:
            raise HTTPException(status_code=500, detail="Control client not available")
        
        webhook_id = webhook_data.get("id")
        if not webhook_id:
            raise HTTPException(status_code=400, detail="Missing webhook ID")
        
        req = await ctrl_client.get_webhook_last_request(webhook_id)
        return GenericResponseDTO(success=True, message=req)
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error getting webhook last request: {e}")
        raise HTTPException(status_code=400, detail=str(e))


async def create_webhook(ctrl_client, request: Request, webhook: dict) -> GenericResponseDTO:
    """Create webhook."""
    try:
        if not ctrl_client:
            raise HTTPException(status_code=500, detail="Control client not available")
        
        await ctrl_client.create_webhook(webhook)
        return GenericResponseDTO(success=True, message="OK")
    except Exception as e:
        logger.error(f"Error creating webhook: {e}")
        raise HTTPException(status_code=400, detail=str(e))


async def delete_webhooks(ctrl_client, request: Request, webhooks: List[str]) -> GenericResponseDTO:
    """Delete webhook(s)."""
    try:
        if not ctrl_client:
            raise HTTPException(status_code=500, detail="Control client not available")
        
        await ctrl_client.delete_webhooks(webhooks)
        return GenericResponseDTO(success=True, message="OK")
    except Exception as e:
        logger.error(f"Error deleting webhooks: {e}")
        raise HTTPException(status_code=400, detail=str(e))
