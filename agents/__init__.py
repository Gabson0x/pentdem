"""
AI Agents for specific pentesting tasks.
"""

from typing import Dict, Any, List
from dataclasses import dataclass


@dataclass
class AgentConfig:
    name: str
    model: str
    system_prompt: str
    skills: List[str]


# Pre-configured agents
AGENTS = {
    "recon": AgentConfig(
        name="Recon Agent",
        model="deepseek",
        system_prompt="""You are a reconnaissance specialist. Your job is to:
1. Enumerate subdomains
2. Detect live hosts
3. Crawl for URLs
4. Identify technology stack
Always return results in JSON format.""",
        skills=["recon"]
    ),
    
    "hunter": AgentConfig(
        name="Vulnerability Hunter",
        model="glm",
        system_prompt="""You are a vulnerability hunter. Your job is to:
1. Analyze URLs for vulnerability patterns
2. Test for IDOR, SSRF, XSS, SQLi
3. Identify potential attack vectors
Always return findings in JSON format with type, url, param, severity, description.""",
        skills=["hunt"]
    ),
    
    "validator": AgentConfig(
        name="Finding Validator",
        model="glm",
        system_prompt="""You are a finding validator. Your job is to:
1. Run the 7-Question Gate on each finding
2. Assess CVSS severity
3. Deduplicate findings
Always return validation results in JSON format.""",
        skills=["validate"]
    ),
    
    "reporter": AgentConfig(
        name="Report Writer",
        model="qwen",
        system_prompt="""You are a security report writer. Your job is to:
1. Write professional bug bounty reports
2. Format for the target platform (HackerOne, Bugcrowd, etc.)
3. Include clear steps to reproduce
Always return reports in markdown format.""",
        skills=["report"]
    ),
    
    "analyst": AgentConfig(
        name="Security Analyst",
        model="kimi",
        system_prompt="""You are a security analyst with 128K context. Your job is to:
1. Analyze large codebases and JS files
2. Read disclosed reports for patterns
3. Identify complex attack chains
Always provide detailed analysis.""",
        skills=["recon", "hunt"]
    ),
}


class AgentRunner:
    """Run specialized agents."""
    
    def __init__(self):
        self.agents = AGENTS
    
    async def run_agent(self, agent_name: str, task: str, context: Dict[str, Any] = None) -> str:
        """Run an agent with a task."""
        from models import model_client
        
        agent = self.agents.get(agent_name)
        if not agent:
            return f"Unknown agent: {agent_name}"
        
        prompt = task
        if context:
            prompt += f"\n\nContext: {context}"
        
        return await model_client.generate(
            prompt=prompt,
            model=agent.model,
            system_prompt=agent.system_prompt
        )
    
    def list_agents(self) -> List[Dict]:
        """List available agents."""
        return [
            {"name": name, "model": agent.model, "skills": agent.skills}
            for name, agent in self.agents.items()
        ]


# Global agent runner
agent_runner = AgentRunner()
