"""
Tests for AI Pentesting Daemon.
"""

import asyncio
import pytest
from models import model_client
from pipeline import PentestPipeline
from skills.recon import ReconSkill
from skills.hunt import HuntSkill
from skills.validate import ValidateSkill
from skills.report import ReportSkill
from tools import tool_executor


class TestModels:
    """Test model client."""
    
    def test_available_models(self):
        """Test that models are available."""
        models = model_client.get_available_models()
        assert len(models) > 0
    
    def test_task_model_assignment(self):
        """Test task model assignment."""
        model = model_client.get_task_model("subdomain_enum")
        assert model is not None


class TestSkills:
    """Test skill modules."""
    
    def test_recon_can_handle(self):
        """Test recon skill."""
        skill = ReconSkill(mock=True)
        assert skill.can_handle("recon")
        assert skill.can_handle("subdomain_enum")
    
    def test_hunt_can_handle(self):
        """Test hunt skill."""
        skill = HuntSkill(mock=True)
        assert skill.can_handle("hunt")
        assert skill.can_handle("idor")
    
    def test_validate_can_handle(self):
        """Test validate skill."""
        skill = ValidateSkill(mock=True)
        assert skill.can_handle("validate")
        assert skill.can_handle("triage")
    
    def test_report_can_handle(self):
        """Test report skill."""
        skill = ReportSkill(mock=True)
        assert skill.can_handle("report")
        assert skill.can_handle("hackerone")


class TestPipeline:
    """Test pipeline."""
    
    def test_pipeline_creation(self):
        """Test pipeline creation."""
        pipeline = PentestPipeline(config={"mock_mode": True})
        assert pipeline.mock_mode is True
        assert "recon" in pipeline.skills
    
    @pytest.mark.asyncio
    async def test_pipeline_run(self):
        """Test pipeline execution."""
        pipeline = PentestPipeline(config={"mock_mode": True})
        results = await pipeline.run("example.com", mode="quick")
        assert "findings" in results
        assert "report" in results


class TestTools:
    """Test tool executor."""
    
    def test_unknown_tool(self):
        """Test unknown tool handling."""
        result = asyncio.get_event_loop().run_until_complete(
            tool_executor.execute("unknown_tool", {})
        )
        assert result.success is False


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
