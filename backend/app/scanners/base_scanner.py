"""
Base Scanner
============
Abstract base class that all scanner modules must implement.
"""

from abc import ABC, abstractmethod
from typing import List

import httpx

from app.models.schemas import SecurityIssue


class BaseScanner(ABC):
    """All scanner modules extend this class."""

    @abstractmethod
    async def scan(self, url: str, response: httpx.Response) -> List[SecurityIssue]:
        """
        Analyse the URL and HTTP response.
        Returns a (possibly empty) list of SecurityIssue findings.
        """
        ...
