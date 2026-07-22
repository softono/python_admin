"""Dev entrypoint: uvicorn app.main:app --host 0.0.0.0 --port <PORT>."""
import uvicorn

from app.core.config import settings

if __name__ == "__main__":
    uvicorn.run("app.main:app", host="127.0.0.1", port=settings.port, reload=False)
