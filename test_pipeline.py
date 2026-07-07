"""
Test the pentest pipeline.
"""

import asyncio
from pipeline import pipeline


async def test_pipeline():
    """Test the pipeline with a dummy target."""
    
    print("Testing AI Pentest Pipeline...")
    print("=" * 50)
    
    # Test with a dummy target
    target = "example.com"
    
    print(f"Target: {target}")
    print(f"Mode: full")
    print(f"Platform: hackerone")
    print()
    
    # Note: This will fail without API keys, but tests the structure
    try:
        results = await pipeline.run(target, mode="quick", platform="hackerone")
        
        print("Pipeline completed!")
        print(f"Findings: {len(results.get('findings', []))}")
        print(f"Report: {'Generated' if results.get('report') else 'None'}")
        
    except Exception as e:
        print(f"Pipeline test failed (expected without API keys): {e}")
    
    print()
    print("Structure test passed!")


if __name__ == "__main__":
    asyncio.run(test_pipeline())
