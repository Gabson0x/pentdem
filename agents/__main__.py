"""Allow running: python3 -m agents.autonomous <target> [--mock]"""
import asyncio
from agents.autonomous import main

if __name__ == "__main__":
    asyncio.run(main())
