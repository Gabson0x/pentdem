"""
MCP (Model Context Protocol) server for AI Pentesting Daemon.
Provides tool access to Claude and other AI models.
"""

import json
from typing import Dict, Any, List
from fastapi import FastAPI
from pydantic import BaseModel


app = FastAPI(title="Pentest MCP Server")


class ToolDefinition(BaseModel):
    name: str
    description: str
    inputSchema: Dict[str, Any]


class ToolCall(BaseModel):
    name: str
    arguments: Dict[str, Any]


# Tool definitions for MCP
TOOLS: List[ToolDefinition] = [
    ToolDefinition(
        name="enumerate_subdomains",
        description="Enumerate subdomains for a target domain",
        inputSchema={
            "type": "object",
            "properties": {
                "target": {"type": "string", "description": "Target domain"}
            },
            "required": ["target"]
        }
    ),
    ToolDefinition(
        name="check_live_hosts",
        description="Check which hosts are live from a list",
        inputSchema={
            "type": "object",
            "properties": {
                "hosts": {"type": "array", "items": {"type": "string"}, "description": "List of hosts"}
            },
            "required": ["hosts"]
        }
    ),
    ToolDefinition(
        name="crawl_urls",
        description="Crawl a target for URLs",
        inputSchema={
            "type": "object",
            "properties": {
                "target": {"type": "string", "description": "Target URL/domain"}
            },
            "required": ["target"]
        }
    ),
    ToolDefinition(
        name="test_idor",
        description="Test for IDOR vulnerabilities",
        inputSchema={
            "type": "object",
            "properties": {
                "url": {"type": "string", "description": "URL to test"},
                "params": {"type": "array", "items": {"type": "string"}, "description": "Parameters to test"}
            },
            "required": ["url"]
        }
    ),
    ToolDefinition(
        name="test_ssrf",
        description="Test for SSRF vulnerabilities",
        inputSchema={
            "type": "object",
            "properties": {
                "url": {"type": "string", "description": "URL to test"},
                "param": {"type": "string", "description": "Parameter to inject URL"}
            },
            "required": ["url"]
        }
    ),
    ToolDefinition(
        name="test_xss",
        description="Test for XSS vulnerabilities",
        inputSchema={
            "type": "object",
            "properties": {
                "url": {"type": "string", "description": "URL to test"},
                "param": {"type": "string", "description": "Parameter to inject script"}
            },
            "required": ["url"]
        }
    ),
    ToolDefinition(
        name="generate_report",
        description="Generate a security report",
        inputSchema={
            "type": "object",
            "properties": {
                "findings": {"type": "array", "description": "List of findings"},
                "platform": {"type": "string", "enum": ["hackerone", "bugcrowd", "intigriti", "immunefi"]}
            },
            "required": ["findings", "platform"]
        }
    ),
]


@app.get("/tools")
async def list_tools():
    """List available tools."""
    return {"tools": [t.dict() for t in TOOLS]}


@app.post("/call")
async def call_tool(call: ToolCall):
    """Call a tool."""
    from tools import tool_executor
    
    result = await tool_executor.execute(call.name, call.arguments)
    
    return {
        "success": result.success,
        "output": result.output,
        "error": result.error
    }


@app.get("/health")
async def health():
    return {"status": "healthy"}
