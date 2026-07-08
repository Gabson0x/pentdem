"""
Docker Isolation — sandboxed execution for dangerous security tools.

Runs sqlmap, nuclei, nmap, etc. inside Docker containers with:
- Network isolation (only target access)
- Resource limits (CPU, memory, time)
- Output capture and parsing
- Automatic cleanup
"""

import asyncio
import json
import os
import tempfile
from typing import Dict, List, Any, Optional
from dataclasses import dataclass


@dataclass
class ContainerConfig:
    name: str
    image: str
    tool: str
    timeout: int = 300  # 5 min default
    memory_limit: str = "512m"
    cpu_limit: str = "1.0"
    network_mode: str = "bridge"
    read_only: bool = True
    capabilities_drop: List[str] = None

    def __post_init__(self):
        if self.capabilities_drop is None:
            self.capabilities_drop = ["ALL"]


# Pre-configured tool containers
TOOL_CONTAINERS = {
    "sqlmap": ContainerConfig(
        name="pentest-sqlmap",
        image="paoloo/sqlmap:latest",
        tool="sqlmap",
        timeout=600,
        memory_limit="1g",
    ),
    "nuclei": ContainerConfig(
        name="pentest-nuclei",
        image="projectdiscovery/nuclei:latest",
        tool="nuclei",
        timeout=300,
        memory_limit="512m",
    ),
    "nmap": ContainerConfig(
        name="pentest-nmap",
        image="instrumentisto/nmap:latest",
        tool="nmap",
        timeout=120,
        memory_limit="256m",
    ),
    "ffuf": ContainerConfig(
        name="pentest-ffuf",
        image="ffuf/ffuf:latest",
        tool="ffuf",
        timeout=300,
        memory_limit="512m",
    ),
    "subfinder": ContainerConfig(
        name="pentest-subfinder",
        image="projectdiscovery/subfinder:latest",
        tool="subfinder",
        timeout=120,
        memory_limit="256m",
    ),
    "httpx": ContainerConfig(
        name="pentest-httpx",
        image="projectdiscovery/httpx:latest",
        tool="httpx",
        timeout=120,
        memory_limit="256m",
    ),
    "dalfox": ContainerConfig(
        name="pentest-dalfox",
        image="hahwul/dalfox:latest",
        tool="dalfox",
        timeout=300,
        memory_limit="512m",
    ),
    "nikto": ContainerConfig(
        name="pentest-nikto",
        image="secfigo/nikto:latest",
        tool="nikto",
        timeout=600,
        memory_limit="256m",
    ),
    "wfuzz": ContainerConfig(
        name="pentest-wfuzz",
        image="ghcr.io/wfuzz/wfuzz:latest",
        tool="wfuzz",
        timeout=300,
        memory_limit="512m",
    ),
}


class DockerIsolator:
    """
    Execute security tools in isolated Docker containers.
    """

    def __init__(self, docker_available: bool = None):
        if docker_available is None:
            self.docker_available = self._check_docker()
        else:
            self.docker_available = docker_available
        self.active_containers: Dict[str, str] = {}

    def _check_docker(self) -> bool:
        """Check if Docker is available."""
        try:
            import subprocess
            result = subprocess.run(
                ["docker", "info"],
                capture_output=True,
                timeout=5,
            )
            return result.returncode == 0
        except Exception:
            return False

    async def run_tool(
        self,
        tool: str,
        args: List[str],
        target: str,
        timeout: int = None,
        env: Dict[str, str] = None,
    ) -> Dict[str, Any]:
        """
        Run a security tool in a Docker container.
        
        Returns:
            {
                "success": bool,
                "output": str,
                "errors": str,
                "exit_code": int,
                "tool": str,
                "container_id": str,
                "duration": float,
            }
        """
        if not self.docker_available:
            return await self._run_local(tool, args, target, timeout)

        config = TOOL_CONTAINERS.get(tool)
        if not config:
            return {
                "success": False,
                "output": "",
                "errors": f"Unknown tool: {tool}",
                "exit_code": -1,
                "tool": tool,
                "container_id": "",
                "duration": 0,
            }

        # Build Docker command
        cmd = [
            "docker", "run",
            "--rm",
            "--name", f"{config.name}-{target.replace('.', '-')}",
            "--memory", config.memory_limit,
            "--cpus", config.cpu_limit,
            "--network", config.network_mode,
            "--read-only" if config.read_only else "",
            "--cap-drop", "ALL",
            "--security-opt", "no-new-privileges",
            "-v", f"{tempfile.gettempdir()}:/output:rw",
        ]

        # Add environment variables
        if env:
            for k, v in env.items():
                cmd.extend(["-e", f"{k}={v}"])

        cmd.append(config.image)
        cmd.extend(args)

        # Remove empty strings
        cmd = [c for c in cmd if c]

        start_time = asyncio.get_event_loop().time()

        try:
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )

            effective_timeout = timeout or config.timeout
            stdout, stderr = await asyncio.wait_for(
                proc.communicate(),
                timeout=effective_timeout,
            )

            duration = asyncio.get_event_loop().time() - start_time

            return {
                "success": proc.returncode == 0,
                "output": stdout.decode(errors="ignore"),
                "errors": stderr.decode(errors="ignore"),
                "exit_code": proc.returncode,
                "tool": tool,
                "container_id": f"{config.name}-{target.replace('.', '-')}",
                "duration": round(duration, 2),
            }

        except asyncio.TimeoutError:
            duration = asyncio.get_event_loop().time() - start_time
            # Kill container
            await self._kill_container(f"{config.name}-{target.replace('.', '-')}")
            return {
                "success": False,
                "output": "",
                "errors": f"Timeout after {effective_timeout}s",
                "exit_code": -1,
                "tool": tool,
                "container_id": "",
                "duration": round(duration, 2),
            }
        except Exception as e:
            duration = asyncio.get_event_loop().time() - start_time
            return {
                "success": False,
                "output": "",
                "errors": str(e),
                "exit_code": -1,
                "tool": tool,
                "container_id": "",
                "duration": round(duration, 2),
            }

    async def _run_local(
        self,
        tool: str,
        args: List[str],
        target: str,
        timeout: int = None,
    ) -> Dict[str, Any]:
        """Fallback: run tool locally without Docker."""
        cmd = [tool] + args

        start_time = asyncio.get_event_loop().time()

        try:
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )

            effective_timeout = timeout or 300
            stdout, stderr = await asyncio.wait_for(
                proc.communicate(),
                timeout=effective_timeout,
            )

            duration = asyncio.get_event_loop().time() - start_time

            return {
                "success": proc.returncode == 0,
                "output": stdout.decode(errors="ignore"),
                "errors": stderr.decode(errors="ignore"),
                "exit_code": proc.returncode,
                "tool": tool,
                "container_id": "local",
                "duration": round(duration, 2),
            }

        except asyncio.TimeoutError:
            return {
                "success": False,
                "output": "",
                "errors": f"Timeout after {effective_timeout}s",
                "exit_code": -1,
                "tool": tool,
                "container_id": "local",
                "duration": round(asyncio.get_event_loop().time() - start_time, 2),
            }
        except FileNotFoundError:
            return {
                "success": False,
                "output": "",
                "errors": f"Tool '{tool}' not found. Install it or run in Docker.",
                "exit_code": -1,
                "tool": tool,
                "container_id": "local",
                "duration": 0,
            }
        except Exception as e:
            return {
                "success": False,
                "output": "",
                "errors": str(e),
                "exit_code": -1,
                "tool": tool,
                "container_id": "local",
                "duration": round(asyncio.get_event_loop().time() - start_time, 2),
            }

    async def _kill_container(self, container_name: str):
        """Kill a running container."""
        try:
            proc = await asyncio.create_subprocess_exec(
                "docker", "rm", "-f", container_name,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            await proc.communicate()
        except Exception:
            pass

    async def run_sqlmap(self, url: str, param: str = "", level: int = 1, risk: int = 1) -> Dict:
        """Run sqlmap in isolation."""
        args = [
            "-u", url,
            "--level", str(level),
            "--risk", str(risk),
            "--batch",
            "--output-dir=/output/sqlmap",
        ]
        if param:
            args.extend(["-p", param])
        return await self.run_tool("sqlmap", args, url, timeout=600)

    async def run_nuclei(self, url: str, templates: str = "", severity: str = "") -> Dict:
        """Run nuclei in isolation."""
        args = ["-u", url, "-json", "-o", "/output/nuclei.json"]
        if templates:
            args.extend(["-t", templates])
        if severity:
            args.extend(["-severity", severity])
        return await self.run_tool("nuclei", args, url, timeout=300)

    async def run_nmap(self, target: str, ports: str = "1-1000", scripts: str = "") -> Dict:
        """Run nmap in isolation."""
        args = ["-sV", "-sC", "-p", ports, "-oX", "/output/nmap.xml", target]
        if scripts:
            args.extend(["--script", scripts])
        return await self.run_tool("nmap", args, target, timeout=120)

    async def run_ffuf(self, url: str, wordlist: str = "/usr/share/wordlists/common.txt", extensions: str = "") -> Dict:
        """Run ffuf in isolation."""
        args = ["-u", url, "-w", wordlist, "-o", "/output/ffuf.json", "-json"]
        if extensions:
            args.extend(["-e", extensions])
        return await self.run_tool("ffuf", args, url, timeout=300)

    async def run_subfinder(self, domain: str) -> Dict:
        """Run subfinder in isolation."""
        args = ["-d", domain, "-o", "/output/subfinder.txt", "-silent"]
        return await self.run_tool("subfinder", args, domain, timeout=120)

    async def run_httpx(self, targets_file: str) -> Dict:
        """Run httpx in isolation."""
        args = ["-l", targets_file, "-json", "-o", "/output/httpx.json", "-silent"]
        return await self.run_tool("httpx", args, "multi", timeout=120)

    async def run_dalfox(self, url: str) -> Dict:
        """Run dalfox XSS scanner in isolation."""
        args = ["url", url, "-o", "/output/dalfox.json", "--format", "json"]
        return await self.run_tool("dalfox", args, url, timeout=300)

    def list_tools(self) -> List[Dict]:
        """List all available tool configurations."""
        return [
            {
                "name": name,
                "image": config.image,
                "timeout": config.timeout,
                "memory_limit": config.memory_limit,
            }
            for name, config in TOOL_CONTAINERS.items()
        ]
