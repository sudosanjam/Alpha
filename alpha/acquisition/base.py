"""
Acquisition Base Classes and Interfaces for Alpha.
"""

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import List, Optional
from alpha.models import Observation, ScanMetadata, FreshnessState


@dataclass
class BackendStatus:
    available: bool
    name: str
    status_text: str  # AVAILABLE, UNAVAILABLE, REQUIRES ACTION, NOT EXPOSED, UNKNOWN
    error_details: Optional[str] = None
    requires_action: bool = False
    action_hint: Optional[str] = None


@dataclass
class ScanBatch:
    observations: List[Observation] = field(default_factory=list)
    metadata: ScanMetadata = field(default_factory=ScanMetadata)


class AcquisitionBackend(ABC):
    """Abstract interface for all wireless observation acquisition backends."""

    @abstractmethod
    def get_name(self) -> str:
        """Return the friendly identifier of the backend."""
        pass

    @abstractmethod
    def check_availability(self) -> BackendStatus:
        """Verify if backend tools, APIs, and permissions are currently accessible."""
        pass

    @abstractmethod
    def scan(self, session_id: str = "default") -> ScanBatch:
        """Perform a single acquisition cycle and return normalized observations."""
        pass
