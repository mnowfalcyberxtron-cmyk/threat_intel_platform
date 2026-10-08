"""ThreatIntel Tor SOCKS proxy discovery and optional autostart helpers."""

import asyncio
import getpass
import logging
import os
import shutil
import socket
import subprocess
import time
from pathlib import Path
from typing import Any, Iterable

logger = logging.getLogger("utils.tor_manager")

TOR_CHECK_URL = "https://check.torproject.org/api/ip"
DEFAULT_TOR_PORTS = (9050,)
TOR_BROWSER_RESERVED_PORTS = {9150, 9151}
DEFAULT_AUTO_START_PORTS = (9050, 9052, 19050)

_last_tor_check_ts = 0.0
_last_tor_status: dict[str, Any] = {}
_active_tor_port = 0
_last_start_attempt_ts = 0.0
_managed_tor_pid = 0
_tor_start_lock = asyncio.Lock()


def _coerce_port(value) -> int | None:
    try:
        port = int(value)
        return port if 0 < port < 65536 else None
    except Exception:
        return None


def _unique_ports(ports: Iterable[int | None]) -> list[int]:
    seen: set[int] = set()
    out: list[int] = []
    for port in ports:
        port = _coerce_port(port)
        if port and port not in seen:
            seen.add(port)
            out.append(port)
    return out


def _candidate_ports(preferred_port: int | None = None) -> list[int]:
    configured: list[int | None] = [preferred_port]
    try:
        from config import settings

        configured.extend(
            [
                getattr(settings, "TOR_SOCKS_PORT", None),
                getattr(settings, "TOR_SOCKS_PORT_FALLBACK", None),
            ]
        )
    except Exception:
        pass
    configured.extend(DEFAULT_TOR_PORTS)
    return _unique_ports(configured)


def _autostart_candidate_ports(preferred_port: int | None = None) -> list[int]:
    configured: list[int | None] = []
    try:
        from config import settings

        configured.append(getattr(settings, "TOR_AUTO_START_PORT", None))
    except Exception:
        pass
    configured.append(os.getenv("TOR_AUTO_START_PORT"))
    if _coerce_port(preferred_port) not in TOR_BROWSER_RESERVED_PORTS:
        configured.append(preferred_port)
    configured.extend(DEFAULT_AUTO_START_PORTS)
    return [port for port in _unique_ports(configured) if port not in TOR_BROWSER_RESERVED_PORTS]


def _bootstrap_timeout(default: int = 60) -> int:
    try:
        from config import settings

        timeout = int(getattr(settings, "TOR_BOOTSTRAP_TIMEOUT", default))
        return max(5, timeout)
    except Exception:
        return default


def _auto_start_enabled() -> bool:
    try:
        from config import settings

        return bool(getattr(settings, "TOR_AUTO_START", False))
    except Exception:
        return os.getenv("TOR_AUTO_START", "").strip().lower() in {"1", "true", "yes", "on"}


def _is_local_host(host: str) -> bool:
    return str(host).strip().lower() in {"127.0.0.1", "localhost", "::1"}


def _port_is_bindable(host: str, port: int) -> bool:
    if not _is_local_host(host):
        return True
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            sock.bind((host, int(port)))
            return True
    except Exception:
        return False


def _startup_port(host: str, preferred_port: int) -> int:
    candidates = _autostart_candidate_ports(preferred_port)
    for candidate in candidates:
        if _port_is_bindable(host, candidate):
            return candidate
    return candidates[0] if candidates else 0


def _tor_data_dir() -> str:
    env_dir = os.getenv("TOR_DATA_DIR", "").strip()
    path = Path(env_dir) if env_dir else Path("data") / "tor-runtime"
    path.mkdir(parents=True, exist_ok=True)
    return str(path.resolve())


def _tor_pid_file() -> Path:
    return Path(_tor_data_dir()) / "tor.pid"


def _tor_log_file() -> Path:
    return Path(_tor_data_dir()) / "tor.log"


def _read_tor_log_tail(max_chars: int = 1200) -> str:
    try:
        text = _tor_log_file().read_text(encoding="utf-8", errors="ignore")
        return text[-max_chars:].strip()
    except Exception:
        return ""


def _write_managed_pid(pid: int) -> None:
    try:
        _tor_pid_file().write_text(str(int(pid)), encoding="ascii")
    except Exception as exc:
        logger.debug("Could not write Tor PID file: %s", exc)


def _read_managed_pid() -> int:
    try:
        return int(_tor_pid_file().read_text(encoding="ascii").strip())
    except Exception:
        return 0


def _clear_managed_pid() -> None:
    try:
        _tor_pid_file().unlink(missing_ok=True)
    except Exception:
        pass


def _status(
    *,
    ok: bool,
    host: str,
    port: int,
    is_tor: bool = False,
    exit_ip: str = "",
    error: str = "",
    attempts: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    return {
        "ok": ok,
        "is_tor": is_tor,
        "host": host,
        "port": port,
        "proxy_url": f"socks5://{host}:{port}" if port else "",
        "exit_ip": exit_ip,
        "error": error,
        "attempts": attempts or [],
    }


def _set_active_proxy(host: str, port: int, status: dict[str, Any]) -> None:
    global _last_tor_check_ts, _last_tor_status, _active_tor_port

    _active_tor_port = port
    _last_tor_check_ts = time.time()
    _last_tor_status = dict(status)
    try:
        from config import settings

        settings.TOR_SOCKS_HOST = host
        settings.TOR_SOCKS_PORT = port
    except Exception:
        pass


def _set_failed_status(status: dict[str, Any]) -> None:
    global _last_tor_check_ts, _last_tor_status

    _last_tor_check_ts = time.time()
    _last_tor_status = dict(status)


def is_tor_running(host: str = "127.0.0.1", port: int = 9050) -> bool:
    """Return True when a local TCP listener accepts a connection.

    This is only a port-open diagnostic. Use ensure_tor_proxy() when code needs
    a verified Tor SOCKS proxy.
    """
    try:
        with socket.create_connection((host, int(port)), timeout=1.0):
            return True
    except Exception:
        return False


async def verify_tor_proxy(
    host: str = "127.0.0.1",
    port: int = 9050,
    *,
    timeout: float = 15.0,
) -> dict[str, Any]:
    """Verify that a SOCKS proxy is really Tor by checking IsTor=true."""
    port = _coerce_port(port) or 0
    if not host or not port:
        return _status(ok=False, host=host, port=port, error="Invalid Tor proxy host/port")

    try:
        import aiohttp
        from aiohttp_socks import ProxyConnector
    except Exception as exc:
        return _status(
            ok=False,
            host=host,
            port=port,
            error=f"aiohttp-socks/aiohttp unavailable: {exc}",
        )

    proxy_url = f"socks5://{host}:{port}"
    try:
        connector = ProxyConnector.from_url(proxy_url, rdns=True)
        client_timeout = aiohttp.ClientTimeout(total=timeout, connect=min(5.0, timeout))
        async with aiohttp.ClientSession(connector=connector, timeout=client_timeout) as session:
            async with session.get(TOR_CHECK_URL) as resp:
                if resp.status != 200:
                    return _status(
                        ok=False,
                        host=host,
                        port=port,
                        error=f"Tor check returned HTTP {resp.status}",
                    )
                data = await resp.json(content_type=None)
                is_tor = bool(data.get("IsTor"))
                return _status(
                    ok=is_tor,
                    is_tor=is_tor,
                    host=host,
                    port=port,
                    exit_ip=str(data.get("IP") or ""),
                    error="" if is_tor else "Proxy responded but IsTor=false",
                )
    except asyncio.TimeoutError:
        return _status(ok=False, host=host, port=port, error="Tor check timed out")
    except Exception as exc:
        return _status(ok=False, host=host, port=port, error=str(exc)[:240])


async def detect_verified_tor_proxy(
    host: str = "127.0.0.1",
    preferred_port: int | None = None,
    *,
    timeout: float = 12.0,
) -> dict[str, Any]:
    """Probe configured Tor ports and return the first proxy verified as Tor."""
    attempts: list[dict[str, Any]] = []
    ports = _candidate_ports(preferred_port)
    for port in ports:
        result = await verify_tor_proxy(host, port, timeout=timeout)
        attempts.append(result)
        if result.get("ok"):
            logger.debug("Verified Tor SOCKS proxy on %s:%d", host, port)
            _set_active_proxy(host, port, result)
            result["attempts"] = attempts
            return result

    error = "No verified Tor SOCKS proxy found"
    if attempts:
        error = attempts[-1].get("error") or error
    return _status(
        ok=False,
        host=host,
        port=ports[0] if ports else 0,
        error=error,
        attempts=attempts,
    )


def detect_active_tor_port(host: str = "127.0.0.1", preferred_port: int | None = None) -> int:
    """Return the first configured port with a TCP listener.

    Kept for compatibility and diagnostics. It does not prove the listener is
    Tor, so runtime callers should prefer detect_verified_tor_proxy().
    """
    for port in _candidate_ports(preferred_port):
        if is_tor_running(host, port):
            logger.debug("Detected TCP listener on %s:%d", host, port)
            return port
    return 0


def find_tor_binary() -> str:
    """Locate tor.exe/tor in common install paths or PATH."""
    env_path = os.getenv("TOR_BINARY", "").strip()
    if env_path and Path(env_path).exists():
        return env_path

    username = getpass.getuser()
    home = Path.home()
    candidate_paths = [
        home / "Desktop" / "Tor Browser" / "Browser" / "TorBrowser" / "Tor" / "tor.exe",
        Path(fr"C:\Users\{username}\Desktop\Tor Browser\Browser\TorBrowser\Tor\tor.exe"),
        Path(r"C:\Users\xtronuser\Desktop\Tor Browser\Browser\TorBrowser\Tor\tor.exe"),
        home / "AppData" / "Local" / "TorBrowser" / "Browser" / "TorBrowser" / "Tor" / "tor.exe",
        Path(r"C:\Program Files\Tor Browser\Browser\TorBrowser\Tor\tor.exe"),
        Path(r"C:\Program Files (x86)\Tor Browser\Browser\TorBrowser\Tor\tor.exe"),
        Path("/usr/bin/tor"),
        Path("/usr/local/bin/tor"),
    ]
    for path in candidate_paths:
        if path.exists():
            return str(path)

    path = shutil.which("tor")
    return path or ""


async def ensure_tor_proxy(
    host: str = "127.0.0.1",
    port: int | None = None,
    *,
    allow_start: bool | None = None,
    timeout: float | None = None,
) -> dict[str, Any]:
    """Return a verified Tor proxy, optionally starting tor when configured.

    By default the app prefers a manually running Tor Browser/system Tor. Raw
    tor autostart is opt-in with TOR_AUTO_START=true and uses the app-owned
    TOR_AUTO_START_PORT, keeping Tor Browser's 9150/9151 ports free.
    """
    global _last_start_attempt_ts

    requested_port = _coerce_port(port) or _candidate_ports(None)[0]
    timeout = timeout or 15.0
    now_ts = time.time()

    if (
        _last_tor_status.get("ok")
        and _active_tor_port
        and _last_tor_status.get("host") == host
        and now_ts - _last_tor_check_ts < 30
    ):
        return dict(_last_tor_status)

    verified = await detect_verified_tor_proxy(host, requested_port, timeout=timeout)
    if verified.get("ok"):
        return verified

    if allow_start is None:
        allow_start = _auto_start_enabled()

    if not allow_start:
        verified["error"] = (
            f"{verified.get('error') or 'Tor proxy is not verified'}; "
            "start Tor Browser manually or set TOR_AUTO_START=true to let the app launch tor.exe"
        )
        _set_failed_status(verified)
        return verified

    if not _is_local_host(host):
        verified["error"] = f"{verified.get('error')}; cannot auto-start Tor for remote host {host}"
        _set_failed_status(verified)
        return verified

    async with _tor_start_lock:
        verified = await detect_verified_tor_proxy(host, requested_port, timeout=timeout)
        if verified.get("ok"):
            return verified

        now_ts = time.time()
        if _last_start_attempt_ts and (now_ts - _last_start_attempt_ts < 10):
            verified["error"] = "Skipping repeated Tor start attempt; previous attempt is still settling"
            _set_failed_status(verified)
            return verified

        tor_path = find_tor_binary()
        if not tor_path:
            failed = _status(
                ok=False,
                host=host,
                port=requested_port,
                error="Tor binary not found. Set TOR_BINARY or start Tor Browser manually.",
                attempts=verified.get("attempts", []),
            )
            _set_failed_status(failed)
            return failed

        start_port = _startup_port(host, requested_port)
        if not start_port:
            failed = _status(
                ok=False,
                host=host,
                port=requested_port,
                error="No safe local port is available for app-managed Tor autostart.",
                attempts=verified.get("attempts", []),
            )
            _set_failed_status(failed)
            return failed

        if start_port != requested_port:
            logger.warning(
                "Configured Tor port %d is reserved or unavailable for app autostart; trying %d instead.",
                requested_port,
                start_port,
            )

        timeout_s = _bootstrap_timeout()
        _last_start_attempt_ts = now_ts
        logger.info(
            "No verified Tor proxy detected on %s. Launching %s on SOCKS port %d (timeout %ds).",
            host,
            tor_path,
            start_port,
            timeout_s,
        )

        try:
            creation_flags = subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0
            data_dir = _tor_data_dir()
            log_file = str(_tor_log_file())
            proc = subprocess.Popen(
                [
                    tor_path,
                    "--SocksPort",
                    str(start_port),
                    "--DataDirectory",
                    data_dir,
                    "--Log",
                    f"notice file {log_file}",
                ],
                cwd=str(Path(tor_path).parent),
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                creationflags=creation_flags,
            )
            global _managed_tor_pid
            _managed_tor_pid = int(proc.pid or 0)
            if _managed_tor_pid:
                _write_managed_pid(_managed_tor_pid)
        except Exception as exc:
            failed = _status(
                ok=False,
                host=host,
                port=start_port,
                error=f"Failed to launch Tor: {exc}",
                attempts=verified.get("attempts", []),
            )
            _set_failed_status(failed)
            return failed

        deadline = time.time() + timeout_s
        attempts = list(verified.get("attempts", []))
        while time.time() < deadline:
            await asyncio.sleep(1.0)
            exit_code = proc.poll()
            if exit_code is not None:
                _clear_managed_pid()
                _managed_tor_pid = 0
                failed = _status(
                    ok=False,
                    host=host,
                    port=start_port,
                    error=f"Tor process exited early with code {exit_code}. {_read_tor_log_tail()}",
                    attempts=attempts,
                )
                _set_failed_status(failed)
                return failed

            result = await verify_tor_proxy(host, start_port, timeout=min(10.0, timeout))
            attempts.append(result)
            if result.get("ok"):
                result["attempts"] = attempts
                _set_active_proxy(host, start_port, result)
                logger.info("Tor SOCKS proxy is verified on %s:%d", host, start_port)
                return result

        failed = _status(
            ok=False,
            host=host,
            port=start_port,
            error=(
                f"Tor process was spawned, but no verified SOCKS proxy appeared within {timeout_s} seconds. "
                f"{_read_tor_log_tail()}"
            ),
            attempts=attempts,
        )
        _set_failed_status(failed)
        return failed


async def auto_start_tor(host: str = "127.0.0.1", port: int | None = None) -> bool:
    """Compatibility wrapper that ensures a verified Tor proxy exists."""
    result = await ensure_tor_proxy(host, port)
    return bool(result.get("ok"))


def stop_tor() -> bool:
    """Terminate the Tor process started by this app and clear cached status."""
    global _last_tor_status, _active_tor_port, _last_start_attempt_ts, _managed_tor_pid
    try:
        if not _managed_tor_pid:
            _managed_tor_pid = _read_managed_pid()

        if not _managed_tor_pid:
            logger.warning("No app-managed Tor process is registered; leaving external Tor/Tor Browser processes alone.")
            _last_tor_status = {}
            _active_tor_port = 0
            _last_start_attempt_ts = 0.0
            _clear_managed_pid()
            return False

        if os.name == "nt":
            subprocess.run(
                ["taskkill", "/F", "/PID", str(_managed_tor_pid)],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                check=False,
            )
        else:
            subprocess.run(
                ["kill", str(_managed_tor_pid)],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                check=False,
            )
        _last_tor_status = {}
        _active_tor_port = 0
        _last_start_attempt_ts = 0.0
        _managed_tor_pid = 0
        _clear_managed_pid()
        return True
    except Exception as exc:
        logger.error("Failed to stop Tor: %s", exc)
        return False
