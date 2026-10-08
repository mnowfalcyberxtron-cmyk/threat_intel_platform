"""main.py — ThreatIntel TIP v2.4 — Full Advisory Monitor + Fixed AI"""
import asyncio, logging, sys, traceback, io, os, socket
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
from fastapi.responses import FileResponse, JSONResponse, RedirectResponse, Response
from fastapi import Request, HTTPException
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
from connectors.ics_ai_enrichment import run_ics_ai_enrichment_loop

# Detect Vercel environment
IS_VERCEL = "VERCEL" in os.environ
if IS_VERCEL:
    settings.LOG_DIR = "/tmp/logs"
    settings.DB_PATH = "/tmp/threat_intel.db" # Database will be ephemeral on Vercel

try:
    Path(settings.LOG_DIR).mkdir(parents=True, exist_ok=True)
except Exception:
    pass # Read-only filesystem

handlers = [SafeStreamHandler(sys.stdout) if sys.platform == "win32" else logging.StreamHandler(sys.stdout)]
try:
    log_file = Path(settings.LOG_DIR)/"platform.log"
    handlers.append(logging.FileHandler(log_file,"a","utf-8"))
except Exception:
    pass # Cannot write to disk on Vercel

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    handlers=handlers,
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
    logger.info("  ThreatIntel TIP v2.4 — Starting")
    logger.info("  AI        : %s", settings.AI_PROVIDER.upper())
    logger.info("  HIBR      : %s", "[ENABLED]" if settings.ENABLE_HIBR else "disabled")
    logger.info("  RL Pro    : %s", "[ENABLED]" if settings.ENABLE_RANSOMWARE_API else "public+RansomWatch")
    logger.info("  Tor/DW    : %s", "[ENABLED]" if settings.ENABLE_DARKWEB else "disabled")
    logger.info("  WebFeed   : every 5 min")
    logger.info("  Advisories: Top 25 companies — every 30 min")
    logger.info("="*60)

    try:
        if not IS_VERCEL:
            settings.ensure_dirs()
            if settings.ENABLE_DARKWEB:
                try:
                    from utils.tor_manager import ensure_tor_proxy
                    tor = await ensure_tor_proxy(settings.TOR_SOCKS_HOST, settings.TOR_SOCKS_PORT)
                    if tor.get("ok"):
                        logger.info("Tor verified at %s", tor.get("proxy_url"))
                    else:
                        logger.warning("Tor not verified at startup: %s", tor.get("error"))
                except Exception as tor_err:
                    logger.warning("Tor startup check failed: %s", tor_err)
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
        
        # Initialize ICS advisory caching system (sync to SQLite on startup)
        try:
            await adv_module.init_ics_advisory_system()
        except Exception as e:
            logger.error("Failed to initialize ICS advisory system: %s", e)

        if not IS_VERCEL:
            scheduler.start()

            # ICS AI Enrichment background loop
            # Rewrites Impact/Title/Affected/Fixed, sets Patch/PoC booleans and XTRON score
            # Runs on advisories with CVE published date >= 2026-07-01
            asyncio.create_task(run_ics_ai_enrichment_loop(db, startup_delay=90.0))
            logger.info("ICS AI Enrichment loop scheduled (starts in 90s, CVE pub >= 2026-07-01).")

            if settings.AUTO_RUN_ALL_ON_STARTUP:
                logger.info("Tor/Network settling (15s delay)...")
                await asyncio.sleep(15)
                logger.info("Running all feeds immediately...")
                asyncio.create_task(scheduler.run_all_now())

            # CVEList bulk enrichment — download ZIP from GitHub in-memory (no local file needed)
            async def _cvelist_startup():
                try:
                    from connectors.cvelist_enrichment import (
                        download_and_build_cvelist_index,
                        run_cvelist_enrichment_loop,
                        run_cvelist_live_sync_loop,
                    )
                    await asyncio.sleep(20)  # Let scheduler settle first
                    gh_token = getattr(settings, "GITHUB_TOKEN", None)
                    index = await download_and_build_cvelist_index(github_token=gh_token)
                    if index:
                        await run_cvelist_enrichment_loop(db, index, startup_delay=0)
                    # Always start the live sync loop (polls every 5 min for new CVEs)
                    await run_cvelist_live_sync_loop(db, github_token=gh_token)
                except Exception as exc:
                    logger.error("CVEList startup failed: %s", exc)

            asyncio.create_task(_cvelist_startup())
            logger.info("CVEList in-memory enrichment scheduled (downloads ZIP from GitHub).")


        else:
            logger.info("Vercel mode: Scheduler and auto-run disabled (using Vercel Crons instead)")
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


app = FastAPI(title="ThreatIntel TIP", version="2.4.0",
              lifespan=lifespan, docs_url="/api/docs", redoc_url=None)
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_methods=["*"], allow_headers=["*"])

for r in [router, ai_router, export_router, hibr_router, rl_router,
          dw_router, feed_router, advisory_router, social_router, onion_router, breach_router, telegram_router, auth_router]:
    app.include_router(r)

FRONTEND = Path(__file__).parent / "frontend"
STATIC   = FRONTEND / "static"
if STATIC.exists():
    app.mount("/static", StaticFiles(directory=str(STATIC)), name="static")

SCREENSHOTS = Path("/tmp/screenshots" if IS_VERCEL else "data/screenshots")
try:
    SCREENSHOTS.mkdir(parents=True, exist_ok=True)
except Exception:
    pass
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
async def check_authentication(request: Request, call_next):
    path = request.url.path
    public_exact = {
        "/",
        "/login.html",
        "/api/auth/login",
        "/api/auth/signup",
        "/api/health",
        "/api/docs",
        "/openapi.json",
        "/favicon.ico",
    }
    public_prefixes = ("/static/", "/screenshots/")

    if path in public_exact or any(path.startswith(prefix) for prefix in public_prefixes):
        return await call_next(request)
    
    # Check for session cookie
    session = request.cookies.get("session_token")
    authenticated = False
    if session and ":" in session:
        user_id, email = session.split(":", 1)
        email = email.strip().lower()
        if user_id == "0":
            authenticated = email == settings.ADMIN_EMAIL.lower()
        else:
            if user_id.isdigit() and email:
                try:
                    user = await db.get_user_by_email(email)
                    authenticated = bool(user and str(user.get("id")) == user_id)
                except Exception:
                    authenticated = False

    if not authenticated:
        # If it's a browser request for a page, redirect to login
        if "text/html" in request.headers.get("accept", ""):
            return RedirectResponse(url="/")
        # If it's an API request, return 401
        return JSONResponse({"detail": "Authentication required"}, status_code=401)
        
    try:
        return await call_next(request)
    except RuntimeError as e:
        if "No response returned" in str(e):
            return JSONResponse({"detail": "Client disconnected / timeout"}, status_code=499)
        raise e

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
    except RuntimeError as e:
        if "No response returned" in str(e):
            return JSONResponse({"detail": "Client disconnected / timeout"}, status_code=499)
        raise e
    finally:
        if token:
            request_api_keys.reset(token)

@app.get("/")
async def login_page():
    p = FRONTEND / "login.html"
    return FileResponse(str(p)) if p.exists() else {"msg":"Run from project root"}

@app.get("/favicon.ico")
async def favicon_icon():
    svg = """
    <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 64 64">
      <rect width="64" height="64" rx="14" fill="#0f172a"/>
      <path d="M18 42V22h8.5c5.8 0 9.5 2.8 9.5 7.2 0 4.5-3.7 7.2-9.5 7.2H18zm7.4-5.6h1.1c2.7 0 4.4-1.2 4.4-3.6s-1.7-3.6-4.4-3.6h-1.1v7.2zm18.6 5.6V22h6.6v20h-6.6zm-14.9 0l10.7-20h7.2l-10.7 20h-7.2z" fill="#22c55e"/>
    </svg>
    """.strip()
    return Response(content=svg.encode("utf-8"), media_type="image/svg+xml")

@app.get("/login.html")
async def login_html():
    p = FRONTEND / "login.html"
    return FileResponse(str(p)) if p.exists() else {"msg":"Run from project root"}

@app.get("/dashboard")
async def dashboard():
    p = FRONTEND / "index.html"
    return FileResponse(str(p)) if p.exists() else {"msg":"Run from project root"}

def _pick_available_port(preferred_port: int, max_attempts: int = 20) -> int:
    """Return the preferred port if free, otherwise try the next free port."""
    for port in [preferred_port] + list(range(preferred_port + 1, preferred_port + max_attempts + 1)):
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                sock.bind((settings.HOST, port))
            return port
        except OSError:
            continue
    raise RuntimeError(f"No free port found between {preferred_port} and {preferred_port + max_attempts}")

if __name__ == "__main__":
    try:
        selected_port = settings.PORT
        try:
            selected_port = _pick_available_port(settings.PORT)
        except RuntimeError:
            pass
        if selected_port != settings.PORT:
            logger.warning("Port %s is busy; switching to free port %s", settings.PORT, selected_port)
            settings.PORT = selected_port
        uvicorn.run("main:app", host=settings.HOST, port=settings.PORT, reload=False, log_level="info")
    except (KeyboardInterrupt, asyncio.CancelledError):
        pass
    except Exception as e:
        print(f"FATAL UVICORN ERROR: {e}")
        traceback.print_exc()
        sys.exit(1)
