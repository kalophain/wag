"""Clustering endpoints for Admin UI."""
import logging
from datetime import datetime, timedelta
from typing import List

from fastapi import HTTPException, Request

from wag.adminui.models import (
    MembershipDTO, NewNodeRequestDTO, NewNodeResponseDTO,
    NodeControlRequestDTO, GenericResponseDTO, EventsResponseDTO,
    AcknowledgeErrorResponseDTO
)

logger = logging.getLogger(__name__)


async def members(db, request: Request) -> List[MembershipDTO]:
    """Get cluster members."""
    try:
        if not db:
            raise HTTPException(status_code=500, detail="Database not available")
        
        if not db.cluster_management_enabled():
            return []
        
        members = []
        for member in db.get_cluster_members():
            drained = await db.is_cluster_node_drained(str(member.id))
            witness = await db.is_cluster_node_witness(str(member.id))
            
            try:
                version = await db.get_cluster_node_version(str(member.id))
            except:
                version = "unknown"
            
            status = "healthy"
            if drained:
                status = "drained"
            elif not member.is_started():
                status = "wait for first connection..."
            elif member.is_learner:
                status = "learner"
            
            ping = ""
            if status != "learner":
                try:
                    last_ping = await db.get_cluster_node_last_ping(str(member.id))
                    
                    if last_ping < datetime.now() - timedelta(seconds=30):
                        status += "(lagging ping)"
                    
                    if last_ping < datetime.now() - timedelta(seconds=60):
                        status = "dead"
                    
                    ping = last_ping.strftime("%d %b %y %H:%M")
                except:
                    status = "no last ping"
            
            members.append(MembershipDTO(
                id=str(member.id),
                peer_urls=member.peer_urls,
                name=member.name,
                learner=member.is_learner,
                drained=drained,
                witness=witness,
                current_node=db.get_current_node_id() == member.id,
                leader=db.get_cluster_leader() == member.id,
                status=status,
                last_ping=ping,
                version=version
            ))
        
        return members
    except Exception as e:
        logger.error(f"Error getting cluster members: {e}")
        raise HTTPException(status_code=500, detail=str(e))


async def new_node(db, request: Request, new_node_req: NewNodeRequestDTO) -> NewNodeResponseDTO:
    """Add new cluster node."""
    try:
        if not db:
            raise HTTPException(status_code=500, detail="Database not available")
        
        join_token = await db.add_cluster_member(
            new_node_req.node_name,
            new_node_req.connection_url,
            new_node_req.manager_url
        )
        
        logger.info(f"Added new node: {new_node_req.node_name} {new_node_req.connection_url}")
        
        return NewNodeResponseDTO(join_token=join_token, error_message="")
    except Exception as e:
        logger.error(f"Error adding new node: {e}")
        return NewNodeResponseDTO(join_token="", error_message=str(e))


async def node_control(db, request: Request, control: NodeControlRequestDTO) -> GenericResponseDTO:
    """Control cluster node."""
    try:
        if not db:
            raise HTTPException(status_code=500, detail="Database not available")
        
        if control.action == "promote":
            logger.info(f"Promoting node {control.node}")
            await db.promote_cluster_member(control.node)
            
        elif control.action in ["drain", "restore"]:
            logger.info(f"{control.action} node {control.node}")
            await db.set_drained(control.node, control.action == "drain")
            
        elif control.action == "stepdown":
            logger.info("Node instructed to step down from leadership")
            await db.cluster_node_step_down()
            
        elif control.action == "remove":
            logger.info(f"Attempting to remove node {control.node}")
            
            if db.get_current_node_id() == control.node:
                raise HTTPException(status_code=400, detail="Cannot remove current node")
            
            await db.remove_cluster_member(control.node)
            
        else:
            raise HTTPException(status_code=400, detail="Unknown action")
        
        return GenericResponseDTO(success=True, message="OK")
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error controlling node: {e}")
        raise HTTPException(status_code=500, detail=str(e))


async def get_cluster_events(db, request: Request) -> EventsResponseDTO:
    """Get cluster events."""
    try:
        if not db:
            raise HTTPException(status_code=500, detail="Database not available")
        
        events = db.get_event_queue()
        errors = await db.get_all_errors()
        
        return EventsResponseDTO(events=events, errors=errors)
    except Exception as e:
        logger.error(f"Error getting cluster events: {e}")
        raise HTTPException(status_code=500, detail=str(e))


async def cluster_events_acknowledge(db, request: Request, ack: AcknowledgeErrorResponseDTO) -> GenericResponseDTO:
    """Acknowledge cluster event/error."""
    try:
        if not db:
            raise HTTPException(status_code=500, detail="Database not available")
        
        await db.resolve_error(ack.error_id)
        return GenericResponseDTO(success=True, message="OK")
    except Exception as e:
        logger.error(f"Error acknowledging cluster event: {e}")
        raise HTTPException(status_code=500, detail=str(e))
