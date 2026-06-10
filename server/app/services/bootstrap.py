import logging

from sqlalchemy.orm import Session

from app.db import Base, engine
from app.services.rules import RuleEngine
from app.services.vulnerability import VulnerabilityService


logger = logging.getLogger(__name__)


def bootstrap(rule_engine: RuleEngine, vulnerability_service: VulnerabilityService, db: Session) -> None:
    Base.metadata.create_all(bind=engine)
    try:
        vulnerability_service.load()
        logger.info("Loaded %d vulnerability advisories", len(vulnerability_service._advisories))
    except (FileNotFoundError, ValueError, OSError) as e:
        logger.error("Failed to load vulnerability feed: %s. Continuing without vulnerability data.", e)
    try:
        rule_engine.sync_rulepacks(db)
        logger.info("Synchronized %d rule packs", len(rule_engine.rules))
    except Exception as e:
        logger.error("Failed to sync rule packs: %s. Continuing without rules.", e)
