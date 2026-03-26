# test.py
import asyncio, traceback, sys
sys.path.insert(0, '.')

class MockRequest:
    def __init__(self):
        # In FastAPI, request.state is often a special object
        class State:
            pass
        self.state = State()

async def test():
    try:
        from app.models.request_models import AnalyzeRequest
        from app.api.routes.analyze import analyze_route

        sample_log = """2026-03-10 10:00:01 INFO User login
email=admin@company.com
password=TEST_ONLY
api_key=sk-EXAMPLE000000000
ERROR stack trace: NullPointerException
at service.java:45"""

        req = AnalyzeRequest(
            input_type="log",
            content=sample_log,
            options={"mask_output": True, "use_ai": False, "block_on_critical": True}
        )
        # Mock request object
        mock_req = MockRequest()
        
        result = await analyze_route(req, mock_req)
        print("SUCCESS:", result)
    except Exception as e:
        print("ERROR FOUND:")
        traceback.print_exc()

if __name__ == "__main__":
    asyncio.run(test())
