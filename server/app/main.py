from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.errors import RateLimitExceeded
from slowapi.middleware import SlowAPIMiddleware
from slowapi.util import get_remote_address

from app.api.routes import router
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
app.add_middleware(SlowAPIMiddleware)
app.state.limiter = Limiter(key_func=get_remote_address, default_limits=[settings.rate_limit])
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)  # type: ignore[arg-type]
app.include_router(router, prefix=settings.api_v1_prefix)
