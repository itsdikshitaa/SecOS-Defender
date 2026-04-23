from contextlib import asynccontextmanager

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware

from app.api.routes import router
from app.api.auth import router as auth_router
from app.config import get_settings
from app.db import SessionLocal
from app.services.bootstrap import bootstrap
from app.services.rules import RuleEngine
from app.services.vulnerability import VulnerabilityService


settings = get_settings()


@asynccontextmanager
async def lifespan(app: FastAPI):
    rule_engine = RuleEngine(settings.rules_path)
    vulnerability_service = VulnerabilityService(settings.vulnerability_feed_path)
    with SessionLocal() as db:
        bootstrap(rule_engine, vulnerability_service, db)
    app.state.rule_engine = rule_engine
    app.state.vulnerability_service = vulnerability_service
    yield


app = FastAPI(title=settings.app_name, lifespan=lifespan)
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.allowed_origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.middleware("http")
async def extract_token(request: Request, call_next):
    """Extract JWT token from Authorization header and add to request scope."""
    auth_header = request.headers.get("Authorization", "")
    token = None
    if auth_header.startswith("Bearer "):
        token = auth_header[7:]
    request.scope["token"] = token
    response = await call_next(request)
    return response


app.include_router(auth_router, prefix=settings.api_v1_prefix)
app.include_router(router, prefix=settings.api_v1_prefix)
