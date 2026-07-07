"""
Base skill class for all pentesting skills.
"""

from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import Dict, Any, List


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
        """Initialize model client."""
        if not self.mock:
            try:
                from models import model_client
                self.model = model_client
            except:
                self.mock = True
        
        if self.mock:
            from mock_models import mock_client
            self.model = mock_client
    
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
        except Exception as e:
            # Fallback to featherless
            if model != "featherless":
                return await self.model.generate(prompt, model="featherless")
            raise
    
    def get_assigned_model(self) -> str:
        """Get the model assigned to this skill."""
        from models import MODEL_ASSIGNMENTS
        return MODEL_ASSIGNMENTS.get(self.__class__.__name__, "glm")
