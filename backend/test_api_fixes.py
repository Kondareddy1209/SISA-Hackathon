#!/usr/bin/env python
import json
import httpx
import asyncio

async def run_tests():
    base_url = "http://localhost:8000/api/analyze"
    
    print("=" * 70)
    print("TEST 1: Text with password + api_key")
    print("=" * 70)
    
    payload1 = {
        "input_type": "text",
        "content": "My email is admin@company.com and my password is TEST_PASSWORD. The API key is sk-EXAMPLE000000000",
        "options": {
            "mask": True,
            "block_high_risk": True
        }
    }
    
    async with httpx.AsyncClient(timeout=30) as client:
        response = await client.post(base_url, json=payload1)
        result = response.json()
        print(json.dumps(result, indent=2))
        print("\nTest 1 Findings:")
        for f in result.get("findings", []):
            match = f.get('match') or f.get('value') or 'N/A'
            print(f"  - {f['type']}: {match}")
        print(f"\nTest 1 Risk: {result.get('risk_level')} (score: {result.get('risk_score')})")
        print(f"Test 1 Insights: {result.get('insights')}")
    
    print("\n" + "=" * 70)
    print("TEST 2: Chat with secret=")
    print("=" * 70)
    
    payload2 = {
        "input_type": "chat",
        "content": "Hi, my token is Bearer TESTTOKENVALUE and secret=TEST_SECRET_VALUE",
        "options": {
            "mask": True,
            "block_high_risk": True
        }
    }
    
    async with httpx.AsyncClient(timeout=30) as client:
        response = await client.post(base_url, json=payload2)
        result = response.json()
        print(json.dumps(result, indent=2))
        print("\nTest 2 Findings:")
        for f in result.get("findings", []):
            match = f.get('match') or f.get('value') or 'N/A'
            print(f"  - {f['type']}: {match}")
        print(f"\nTest 2 Risk: {result.get('risk_level')} (score: {result.get('risk_score')})")
        print(f"Test 2 Insights: {result.get('insights')}")
    
    print("\n" + "=" * 70)
    print("TEST 3: Log with FAILED login brute force")
    print("=" * 70)
    
    payload3 = {
        "input_type": "log",
        "content": "FAILED login attempt for user admin\nFAILED login attempt for user admin\nFAILED login attempt for user admin\nFAILED login attempt for user admin\nFAILED login attempt for user admin\nFAILED login attempt for user admin",
        "options": {
            "mask": True,
            "block_high_risk": True,
            "log_analysis": False
        }
    }
    
    async with httpx.AsyncClient(timeout=30) as client:
        response = await client.post(base_url, json=payload3)
        result = response.json()
        print(json.dumps(result, indent=2))
        print("\nTest 3 Findings:")
        for f in result.get("findings", []):
            print(f"  - {f['type']}: {f['match']}")
        print(f"\nTest 3 Risk: {result.get('risk_level')} (score: {result.get('risk_score')})")

asyncio.run(run_tests())
