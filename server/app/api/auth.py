from __future__ import annotations

from datetime import timedelta

from fastapi import APIRouter, Depends, HTTPException, Request, status
from sqlalchemy.orm import Session

from app.config import get_settings
from app.db import get_db
from app.schemas import LoginRequest, TokenResponse, UserCreate, UserResponse, AuditLogResponse
from app.services.auth import (
    authenticate_user,
    create_user,
    decode_token,
    create_access_token,
    get_user_by_id,
    log_audit,
)
from app.models import AuditLog

router = APIRouter(prefix="/auth", tags=["auth"])
settings = get_settings()


def get_current_user(request: Request, db: Session = Depends(get_db)):
    """Dependency to extract current user from Authorization header or return None."""
    token = request.scope.get("token")
    
    if not token:
        return None
    
    decoded = decode_token(token)
    if not decoded:
        return None
    
    user = get_user_by_id(db, decoded["user_id"])
    if not user or not user.is_active:
        return None
    
    return user


@router.post("/login", response_model=TokenResponse)
async def login(request: LoginRequest, db: Session = Depends(get_db)):
    """Authenticate user and return JWT access token."""
    user = authenticate_user(db, request.username, request.password)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
        )
    
    access_token_expires = timedelta(hours=settings.access_token_expire_hours)
    access_token = create_access_token(
        data={"sub": user.id, "username": user.username},
        expires_delta=access_token_expires,
    )
    
    return TokenResponse(
        access_token=access_token,
        token_type="bearer",
        user={
            "id": user.id,
            "username": user.username,
            "email": user.email,
            "role": user.role,
        },
    )


@router.post("/register", response_model=UserResponse, status_code=201)
async def register(user_data: UserCreate, db: Session = Depends(get_db)):
    """Register a new user."""
    from app.services.auth import get_user_by_username
    
    if get_user_by_username(db, user_data.username):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Username already registered",
        )
    
    user = create_user(
        db,
        username=user_data.username,
        email=user_data.email,
        password=user_data.password,
        full_name=user_data.full_name,
        role=user_data.role,
    )
    
    return UserResponse(
        id=user.id,
        username=user.username,
        email=user.email,
        full_name=user.full_name,
        role=user.role,
        is_active=user.is_active,
        last_login=user.last_login,
        created_at=user.created_at,
    )


@router.get("/me", response_model=UserResponse)
async def get_current_user_info(
    request: Request,
    db: Session = Depends(get_db),
):
    """Get current authenticated user info."""
    user = get_current_user(request, db)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Not authenticated",
        )
    
    return UserResponse(
        id=user.id,
        username=user.username,
        email=user.email,
        full_name=user.full_name,
        role=user.role,
        is_active=user.is_active,
        last_login=user.last_login,
        created_at=user.created_at,
    )


@router.get("/audit-log", response_model=list[AuditLogResponse])
async def get_audit_log(
    limit: int = 100,
    offset: int = 0,
    request: Request = None,
    user: object = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """Get audit log entries (admin only)."""
    if not user or getattr(user, 'role', None) not in ["admin"]:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Only admins can view audit logs",
        )
    
    from sqlalchemy import select
    
    query = select(AuditLog).order_by(AuditLog.occurred_at.desc()).limit(limit).offset(offset)
    entries = db.execute(query).scalars().all()
    
    return [
        AuditLogResponse(
            id=entry.id,
            entity_type=entry.entity_type,
            entity_id=entry.entity_id,
            action=entry.action,
            actor=entry.actor,
            occurred_at=entry.occurred_at,
            details=entry.details,
        )
        for entry in entries
    ]
