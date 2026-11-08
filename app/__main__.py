"""
app/__main__.py — allows running with: python -m app.mcp_server
"""
import logging
import uvicorn
from app.config import settings
from app.mcp_server import build_app

logging.basicConfig(
    level=settings.log_level,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)

app = build_app()

if __name__ == "__main__":
    uvicorn.run(
        app,
        host=settings.mcp_host,
        port=settings.mcp_port,
        log_level=settings.log_level.lower(),
    )
