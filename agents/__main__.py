"""Allow running: python3 -m agents <target> [--mock]"""
import asyncio
import sys

from agents.autonomous import AutonomousAgent


async def main():
    if len(sys.argv) < 2:
        print("Usage: python3 -m agents <target> [--mock]")
        sys.exit(1)

    target = sys.argv[1]
    mock = "--mock" in sys.argv

    agent = AutonomousAgent(mock=mock)

    async def progress(phase, message, progress):
        bar_len = 40
        filled = int(bar_len * progress)
        bar = "=" * filled + "-" * (bar_len - filled)
        print(f"\r[{bar}] {progress*100:.0f}% - {phase}: {message}", end="", flush=True)

    agent.set_progress_callback(progress)
    results = await agent.run(target)

    print("\n\n[+] Summary:")
    print(f"  Findings: {len(results.get('findings', []))}")
    print(f"  Chains: {len(results.get('chains', []))}")

    import json
    if results.get("findings"):
        print(f"\n[+] Top findings:")
        for f in results["findings"][:10]:
            print(f"  [{f.get('severity','?').upper()}] {f.get('type','?')} @ {f.get('url','?')}")


if __name__ == "__main__":
    asyncio.run(main())
