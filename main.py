#!/usr/bin/env python3
"""
AI Pentesting Daemon
Autonomous bug bounty hunting with multi-model orchestration.
"""

import asyncio
import os
from dotenv import load_dotenv

load_dotenv()

from server import app
import uvicorn

async def main():
    host = os.getenv("HOST", "0.0.0.0")
    port = int(os.getenv("PORT", "8888"))
    config_uvicorn = uvicorn.Config(app, host=host, port=port, log_level="info")
    server = uvicorn.Server(config_uvicorn)
    print(f"AI Pentest Daemon v2.0 running on {host}:{port}")
    await server.serve()

if __name__ == "__main__":
    asyncio.run(main())
