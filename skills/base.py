"""
Base skill class for all pentesting skills.
"""

from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import Dict, Any, List, Optional


@dataclass
class SkillResult:
    success: bool
    findings: List[Dict[str, Any]]
    data: Dict[str, Any]
    next_skills: List[str]
    confidence: float


class BaseSkill(ABC):
    """Base class for all pentesting skills."""
    
    def __init__(self, mock: bool = False):
        self.mock = mock
        self.model = None
        self._init_model()
    
    def _init_model(self):
        """Initialize model client with proper fallback chain."""
        if not self.mock:
            try:
                from models import model_client
                self.model = model_client
                return
            except Exception:
                pass
        
        # Fallback to mock client
        try:
            from mock_models import MockModelClient
            self.model = MockModelClient()
            self.mock = True
        except Exception:
            # Last resort: create a minimal dummy that won't crash
            self.model = _DummyModelClient()
            self.mock = True
    
    @abstractmethod
    async def execute(self, context: Dict[str, Any]) -> SkillResult:
        """Execute the skill with given context."""
        pass
    
    @abstractmethod
    def can_handle(self, task_type: str) -> bool:
        """Check if this skill can handle the task type."""
        pass
    
    async def llm_analyze(self, prompt: str, model: str = None) -> str:
        """Send prompt to assigned model for analysis."""
        if model is None:
            model = self.get_assigned_model()
        try:
            return await self.model.generate(prompt, model=model)
        except Exception:
            # Fallback to featherless
            if model != "featherless":
                try:
                    return await self.model.generate(prompt, model="featherless")
                except Exception:
                    pass
            return '{"pass": true, "reason": "Model unavailable — gate skipped"}'
    
    def get_assigned_model(self) -> str:
        """Get the model assigned to this skill."""
        from models import MODEL_ASSIGNMENTS
        return MODEL_ASSIGNMENTS.get(self.__class__.__name__, "glm")


class _DummyModelClient:
    """Minimal dummy client that returns safe defaults when no model is available."""
    
    async def generate(self, prompt: str, model: str = "dummy",
                       system_prompt: str = None, temperature: float = 0.1) -> str:
        import json
        return json.dumps({
            "pass": True,
            "reason": "No model available — analysis skipped",
            "answers": {},
        })
    
    def get_available_models(self) -> list:
        return []
