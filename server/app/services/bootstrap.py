from sqlalchemy.orm import Session

from app.db import Base, engine
from app.services.rules import RuleEngine
from app.services.vulnerability import VulnerabilityService


def bootstrap(rule_engine: RuleEngine, vulnerability_service: VulnerabilityService, db: Session) -> None:
    Base.metadata.create_all(bind=engine)
    vulnerability_service.load()
    rule_engine.sync_rulepacks(db)
