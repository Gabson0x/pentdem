import asyncio
import subprocess
import shutil
from typing import List, Dict, Optional
from .payloads import PayloadDB


class ToolExecutor:
    """Execute real security tools via subprocess with proper error handling."""

    TIMEOUT = 120
    MAX_CONCURRENT = 5

    def __init__(self, mock: bool = False):
        self.mock = mock
        self._semaphore = asyncio.Semaphore(self.MAX_CONCURRENT)
        self.payloads = PayloadDB()

    async def run(self, tool: str, args: List[str], timeout: int = None) -> Dict:
        if self.mock:
            return self._mock_result(tool)

        if not self._tool_available(tool):
            return {"success": False, "error": f"{tool} not installed", "stdout": ""}

        cmd = [tool] + args
        timeout = timeout or self.TIMEOUT

        async with self._semaphore:
            try:
                proc = await asyncio.wait_for(
                    asyncio.create_subprocess_exec(
                        *cmd,
                        stdout=subprocess.PIPE,
                        stderr=subprocess.PIPE,
                    ),
                    timeout=timeout,
                )
                stdout, stderr = await proc.communicate()
                return {
                    "success": proc.returncode == 0,
                    "stdout": stdout.decode("utf-8", errors="replace"),
                    "stderr": stderr.decode("utf-8", errors="replace"),
                    "returncode": proc.returncode,
                }
            except asyncio.TimeoutError:
                return {"success": False, "error": f"{tool} timed out ({timeout}s)", "stdout": ""}
            except Exception as e:
                return {"success": False, "error": str(e), "stdout": ""}

    async def run_multiple(self, tool: str, args_list: List[List[str]]) -> List[Dict]:
        tasks = [self.run(tool, args) for args in args_list]
        return await asyncio.gather(*tasks, return_exceptions=True)

    def _tool_available(self, name: str) -> bool:
        return shutil.which(name) is not None

    def _mock_result(self, tool: str) -> Dict:
        mocks = {
            "subfinder": "api.example.com\ndev.example.com\nadmin.example.com\ncdn.example.com\nmail.example.com",
            "httpx": "https://api.example.com [200] [nginx]\nhttps://dev.example.com [200] [Apache]\nhttps://admin.example.com [403] [nginx]",
            "katana": "https://api.example.com/v1/users\nhttps://api.example.com/v1/admin\nhttps://dev.example.com/.env\nhttps://admin.example.com/login",
            "ffuf": "admin                  [Status: 200, Size: 1234]\napi                    [Status: 200, Size: 5678]\n.backup                [Status: 200, Size: 345]\n.git/config            [Status: 200, Size: 123]",
            "nuclei": "[critical] https://admin.example.com - spring-actuator\n[high] https://api.example.com - cors-misconfig\n[medium] https://dev.example.com - debug-mode",
            "curl": 'HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n{"status":"ok","data":{"users":[{"id":1,"name":"admin"}]}}',
            "python3": '{"scan":"completed"}',
        }
        return {
            "success": True,
            "stdout": mocks.get(tool, f"Mock output for {tool}"),
            "stderr": "",
            "returncode": 0,
        }


tool_executor = ToolExecutor()
