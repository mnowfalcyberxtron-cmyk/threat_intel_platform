"""main.py — CyberXTron TIP v2.4 — Full Advisory Monitor + Fixed AI"""
import asyncio, logging, sys, traceback, io
from contextlib import asynccontextmanager
from pathlib import Path

# Fix Windows console encoding for emojis
import sys
import io

class SafeStreamHandler(logging.StreamHandler):
    """Prevents UnicodeEncodeError when Windows console doesn't support emojis."""
    def emit(self, record):
        try:
            msg = self.format(record)
            stream = self.stream
            stream.write(msg + self.terminator)
            self.flush()
        except UnicodeEncodeError:
            try:
                # Replace unsupported characters and try writing again
                safe_msg = msg.encode('cp1252', errors='replace').decode('cp1252')
                stream.write(safe_msg + self.terminator)
                self.flush()
            except Exception:
                pass
        except Exception:
            self.handleError(record)

if sys.platform == "win32":
    # Let python handle standard outputs in replace mode using UTF8 stream where possible,
    # but actual print handler will use SafeStreamHandler.
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8', errors='replace')
    sys.stderr = io.TextIOWrapper(sys.stderr.buffer, encoding='utf-8', errors='replace')

import uvicorn
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse
from fastapi import Request
import json

from config import settings, request_api_keys

from database.db import Database
from engine.scheduler import MonitoringScheduler
from engine.ai_engine import AIEngine
from reports.generator import ReportGenerator
from engine.validator import IOCValidator

import api.routes as routes_module
import api.ai_routes as ai_module
import api.export as export_module
import api.hibr_routes as hibr_module
import api.rl_routes as rl_module
import api.darkweb_routes as dw_module
import api.feed_routes as feed_module
import api.advisory_routes as adv_module
import api.social_routes as social_module
import api.breach_routes as breach_module
import api.telegram_routes as telegram_module
import api.auth_routes as auth_module

from api.routes import router
from api.ai_routes import ai_router
from api.export import export_router
from api.hibr_routes import hibr_router
from api.rl_routes import rl_router
from api.darkweb_routes import dw_router
from api.feed_routes import feed_router
from api.advisory_routes import advisory_router
from api.social_routes import router as social_router
from api.onion_routes import router as onion_router
from api.breach_routes import breach_router
from api.telegram_routes import router as telegram_router
from api.auth_routes import router as auth_router
import api.onion_routes as onion_module

from connectors.hibr import HIBRConnector
from connectors.ransomware_live import RansomwareLiveConnector

Path(settings.LOG_DIR).mkdir(parents=True, exist_ok=True)
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    handlers=[
        SafeStreamHandler(sys.stdout) if sys.platform == "win32" else logging.StreamHandler(sys.stdout),
        logging.FileHandler(Path(settings.LOG_DIR)/"platform.log","a","utf-8"),
    ],
)
logger = logging.getLogger("main")

db        = Database()
scheduler = MonitoringScheduler(db)
ai_engine = AIEngine()
report_gen = ReportGenerator(db)
validator  = IOCValidator(db)
hibr_conn  = HIBRConnector()
rl_conn    = RansomwareLiveConnector()


@asynccontextmanager
async def lifespan(app: FastAPI):
    logger.info("="*60)
    logger.info("  CyberXTron TIP v2.4 — Starting")
    logger.info("  AI        : %s", settings.AI_PROVIDER.upper())
    logger.info("  HIBR      : %s", "[ENABLED]" if settings.ENABLE_HIBR else "disabled")
    logger.info("  RL Pro    : %s", "[ENABLED]" if settings.ENABLE_RANSOMWARE_API else "public+RansomWatch")
    logger.info("  Tor/DW    : %s", "[ENABLED]" if settings.ENABLE_DARKWEB else "disabled")
    logger.info("  WebFeed   : every 5 min")
    logger.info("  Advisories: Top 25 companies — every 30 min")
    logger.info("="*60)

    try:
        settings.ensure_dirs()
        await db.initialize()
        ai_engine.set_db(db)

        # Wire all modules
        routes_module._db = db; routes_module._scheduler = scheduler; routes_module._report_gen = report_gen; routes_module._validator = validator
        ai_module._db = db;     ai_module._ai = ai_engine
        export_module._db = db
        hibr_module._db = db;   hibr_module._ai = ai_engine; hibr_module._hibr = hibr_conn
        rl_module._db = db;     rl_module._ai = ai_engine;   rl_module._rl = rl_conn
        dw_module._db = db;     dw_module._scheduler = scheduler
        feed_module._db = db
        adv_module._db = db;    adv_module._ai = ai_engine;  adv_module._scheduler = scheduler
        social_module._db = db
        onion_module._db = db;  onion_module._scheduler = scheduler
        breach_module._db = db; breach_module._scheduler = scheduler
        telegram_module._db = db
        auth_module._db = db

        scheduler.start()
        if settings.AUTO_RUN_ALL_ON_STARTUP:
            logger.info("Running all feeds immediately...")
            asyncio.create_task(scheduler.run_all_now())
        else:
            logger.info("Startup feed auto-run disabled (AUTO_RUN_ALL_ON_STARTUP=false)")
        logger.info("Dashboard  -> http://localhost:%d", settings.PORT)
        logger.info("API Docs   -> http://localhost:%d/api/docs", settings.PORT)
        yield
    except Exception as e:
        logger.error("CRITICAL STARTUP ERROR: %s", e)
        traceback.print_exc()
        raise e
    finally:
        logger.info("Shutting down...")
        scheduler.stop()
        await ai_engine.close()
        await db.close()


app = FastAPI(title="CyberXTron TIP", version="2.4.0",
              lifespan=lifespan, docs_url="/api/docs", redoc_url=None)
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_methods=["*"], allow_headers=["*"])

for r in [router, ai_router, export_router, hibr_router, rl_router,
          dw_router, feed_router, advisory_router, social_router, onion_router, breach_router, telegram_router, auth_router]:
    app.include_router(r)

FRONTEND = Path(__file__).parent / "frontend"
STATIC   = FRONTEND / "static"
if STATIC.exists():
    app.mount("/static", StaticFiles(directory=str(STATIC)), name="static")

SCREENSHOTS = Path("data/screenshots")
SCREENSHOTS.mkdir(parents=True, exist_ok=True)
app.mount("/screenshots", StaticFiles(directory=str(SCREENSHOTS)), name="screenshots")

@app.middleware("http")
async def log_user_activity_middleware(request: Request, call_next):
    user_id = request.headers.get("X-User-ID")
    path = request.url.path
    method = request.method
    
    # Skip logging for static files, logs, and health checks
    if path.startswith(("/static", "/screenshots", "/favicon.ico", "/api/logs", "/api/health")) or method == "OPTIONS":
        return await call_next(request)

    response = await call_next(request)
    
    if user_id and response.status_code < 400:
        try:
            # We don't want to slow down the request, but we need to log it.
            # Since this is a simple app, we just await it here as it's a fast DB insert.
            action = f"{method} {path}"
            # Extract meaningful action names
            if "/api/iocs" in path and method == "GET": action = "VIEW_IOCS"
            elif "/api/rl/group" in path: action = "VIEW_THREAT_ACTOR"
            elif "/api/victims" in path: action = "VIEW_VICTIMS"
            elif "/api/alerts" in path: action = "VIEW_ALERTS"
            elif "/api/ai/analyze" in path: action = "AI_ANALYSIS"
            elif "/api/refresh" in path: action = "TRIGGER_SCAN"
            
            # Details: query params
            details = str(request.query_params) if request.query_params else ""
            
            # Use background task to avoid blocking response
            from fastapi import BackgroundTasks
            asyncio.create_task(db.log_user_activity(int(user_id), action, details, request.client.host))
        except Exception:
            pass
            
    return response

@app.middleware("http")
async def extract_api_keys(request: Request, call_next):
    keys_str = request.headers.get("X-API-Keys")
    token = None
    if keys_str:
        try:
            keys = json.loads(keys_str)
            token = request_api_keys.set(keys)
        except Exception:
            pass
    try:
        response = await call_next(request)
        return response
    finally:
        if token:
            request_api_keys.reset(token)

@app.get("/")
async def login_page():
    p = FRONTEND / "login.html"
    return FileResponse(str(p)) if p.exists() else {"msg":"Run from project root"}

@app.get("/dashboard")
async def dashboard():
    p = FRONTEND / "index.html"
    return FileResponse(str(p)) if p.exists() else {"msg":"Run from project root"}

if __name__ == "__main__":
    try:
        uvicorn.run("main:app", host=settings.HOST, port=settings.PORT, reload=False, log_level="info")
    except BaseException as e:
        print(f"FATAL UVICORN ERROR: {e}")
        traceback.print_exc()
        sys.exit(1)
