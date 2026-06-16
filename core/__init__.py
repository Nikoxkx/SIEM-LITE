"""
Core SIEM engine modules.

This package contains the central processing components:
- Normalizer: Field normalization and standardization
- Enrichment: GeoIP, ASN, asset inventory lookups
- ThreatIntel: IOC matching and reputation
- Storage: Event and alert persistence
- CorrelationEngine: Multi-event correlation
- RulesEngine: Rule evaluation and detection
- AggregationEngine: Time-window aggregation
- AnomalyEngine: Statistical anomaly detection
- RiskScoring: Risk score computation
- AlertingEngine: Alert generation and routing
- QueryEngine: Search and filtering
- Pipeline: Event processing orchestration
"""

from .normalizer import Normalizer
from .enrichment import EnrichmentEngine
from .threat_intel import ThreatIntelEngine
from .storage import StorageBackend, SQLiteBackend, InMemoryBackend
from .rules_engine import RulesEngine
from .correlation import CorrelationEngine
from .aggregation import AggregationEngine
from .anomaly import AnomalyEngine
from .risk_scoring import RiskScoringEngine
from .alerting import AlertingEngine
from .query import QueryEngine, Query
from .pipeline import ProcessingPipeline
from .engine import SIEMEngine

__all__ = [
    "Normalizer",
    "EnrichmentEngine",
    "ThreatIntelEngine",
    "StorageBackend", "SQLiteBackend", "InMemoryBackend",
    "RulesEngine",
    "CorrelationEngine",
    "AggregationEngine",
    "AnomalyEngine",
    "RiskScoringEngine",
    "AlertingEngine",
    "QueryEngine", "Query",
    "ProcessingPipeline",
    "SIEMEngine",
]
