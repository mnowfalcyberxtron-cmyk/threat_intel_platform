"""NVD CVSS background enrichment for ICS advisories."""

import asyncio
import logging
import re
from typing import Any

import httpx

from config import settings

logger = logging.getLogger(__name__)

NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
BATCH_SIZE = 5
POLL_INTERVAL = 60.0
CVSS4_RATE_LIMIT_BACKOFF = 60.0
CVE_ID_RE = re.compile(r"^CVE-\d{4}-\d{4,}$", re.IGNORECASE)


def _nvd_api_key() -> str:
    return str(getattr(settings, "NVD_API_KEY", "") or "").strip()


def _extract_best_cvss(vulnerability: dict[str, Any]) -> tuple[str, str, str]:
    metrics = vulnerability.get("cve", {}).get("metrics", {}) or {}
    # Priority: CVSS 3.1 (industry standard, most widely used) → 3.0 → 4.0 → 2.0
    for source, key in (
        ("3.1", "cvssMetricV31"),
        ("3.0", "cvssMetricV30"),
        ("4.0", "cvssMetricV40"),
        ("2.0", "cvssMetricV2"),
    ):
        entries = metrics.get(key) or []
        if not entries:
            continue
        cvss_data = entries[0].get("cvssData", {}) or {}
        score = cvss_data.get("baseScore")
        severity = cvss_data.get("baseSeverity") or entries[0].get("baseSeverity")
        if score is not None:
            return str(score), str(severity or "").capitalize(), source
    return "", "", ""


def _extract_reference_signals(vulnerability: dict[str, Any], cve_id: str) -> tuple[str, str]:
    """Derive conservative patch/PoC hints from NVD references."""
    references = vulnerability.get("cve", {}).get("references") or {}
    refs = references.get("referenceData") if isinstance(references, dict) else references
    refs = refs or []
    cve = (cve_id or "").lower()
    patch = ""
    poc = ""
    patch_terms = ("patch", "fixed", "hotfix", "security update", "release notes", "upgrade")
    poc_terms = ("poc", "proof-of-concept", "proof of concept", "exploit-db", "metasploit", "packetstorm")

    for ref in refs:
        if not isinstance(ref, dict):
            continue
        tags = [str(tag).lower() for tag in (ref.get("tags") or [])]
        url = str(ref.get("url") or "").lower()
        name = str(ref.get("name") or "").lower()
        text = f"{url} {name} {' '.join(tags)}"

        if not patch and ("patch" in tags or any(term in text for term in patch_terms)):
            patch = "Yes"
        if not poc and ("exploit" in tags or any(term in text for term in poc_terms)):
            poc = "Yes (public PoC exists)"

        # GitHub is noisy, so require the exact CVE ID to appear with exploit/PoC wording.
        if not poc and cve and cve in text and "github.com" in text and any(term in text for term in ("poc", "exploit")):
            poc = "Yes (public PoC exists)"

        if patch and poc:
            break

    return patch, poc


async def _set_status(db, row_id: int, status: str) -> None:
    await db._conn.execute(
        "UPDATE ics_advisories SET nvd_enrichment_status=? WHERE id=?",
        (status, row_id),
    )
    await db._conn.commit()


async def _set_nvd_enrichment(
    db,
    row_id: int,
    cve_id: str,
    score: str,
    severity: str,
    cvss_source: str,
    patch_availability: str,
    poc_availability: str,
    status: str,
) -> None:
    nvd_url = f"https://nvd.nist.gov/vuln/detail/{cve_id}" if cve_id else ""
    await db._conn.execute(
        """UPDATE ics_advisories
           SET cvss_score=COALESCE(NULLIF(?, ''), cvss_score),
               nvd_cvss_v4_score=CASE WHEN ? = '4.0' THEN COALESCE(NULLIF(?, ''), nvd_cvss_v4_score) ELSE nvd_cvss_v4_score END,
               severity=COALESCE(NULLIF(?, ''), severity),
               patch_availability=CASE
                 WHEN LOWER(COALESCE(patch_availability, '')) IN ('', 'unknown', 'n/a', 'na', 'none', 'null')
                  AND ? != '' THEN ?
                 ELSE patch_availability
               END,
               poc_availability=CASE
                 WHEN LOWER(COALESCE(poc_availability, '')) IN ('', 'unknown', 'n/a', 'na', 'none', 'null')
                  AND ? != '' THEN ?
                 ELSE poc_availability
               END,
               nist_url=COALESCE(NULLIF(nist_url, ''), NULLIF(?, '')),
               nvd_enrichment_status=?
           WHERE id=?""",
        (
            score,
            cvss_source,
            score,
            severity,
            patch_availability,
            patch_availability,
            poc_availability,
            poc_availability,
            nvd_url,
            status,
            row_id,
        ),
    )
    await db._conn.commit()


async def _pending_rows(db, batch_size: int):
    async with db._conn.execute(
        """SELECT id, cve_id
           FROM ics_advisories
           WHERE nvd_enrichment_status = 'pending'
             AND cve_id IS NOT NULL
             AND TRIM(cve_id) != ''
             AND UPPER(TRIM(cve_id)) != 'N/A'
           ORDER BY COALESCE(NULLIF(cve_published_date, ''), release_date, '1970-01-01') DESC,
                    CAST(substr(UPPER(TRIM(cve_id)), 5, 4) AS INTEGER) DESC,
                    id DESC
           LIMIT ?""",
        (batch_size,),
    ) as cur:
        return await cur.fetchall()


async def run_nvd_cvss4_enrichment_loop(
    db,
    *,
    startup_delay: float = 10.0,
    run_once: bool = False,
    batch_size: int = BATCH_SIZE,
):
    """Fetch the best available CVSS score and reference signals from NVD."""
    logger.info("[NVDEnricher] Started CVSS enrichment loop.")

    if startup_delay:
        await asyncio.sleep(startup_delay)

    while True:
        processed = 0
        try:
            pending_rows = await _pending_rows(db, batch_size)
            if not pending_rows:
                if run_once:
                    logger.info("[NVDEnricher] No pending CVEs.")
                    return
                await asyncio.sleep(POLL_INTERVAL)
                continue

            api_key = _nvd_api_key()
            headers = {"apiKey": api_key} if api_key else {}
            request_gap = 1.0 if api_key else 6.0
            backoff = 30.0 if api_key else CVSS4_RATE_LIMIT_BACKOFF

            async with httpx.AsyncClient(
                timeout=30.0,
                headers=headers,
                follow_redirects=True,
            ) as client:
                for row in pending_rows:
                    row_id = row["id"]
                    cve_id = str(row["cve_id"] or "").strip().upper()

                    if not CVE_ID_RE.match(cve_id):
                        await _set_status(db, row_id, "invalid")
                        processed += 1
                        continue

                    try:
                        resp = await client.get(NVD_API_URL, params={"cveId": cve_id})
                    except (httpx.TimeoutException, httpx.NetworkError) as exc:
                        logger.warning("[NVDEnricher] Transient fetch error for %s: %s", cve_id, exc)
                        break
                    except Exception as exc:
                        logger.error("[NVDEnricher] Unexpected fetch error for %s: %s", cve_id, exc)
                        break

                    if resp.status_code == 200:
                        try:
                            data = resp.json()
                        except Exception as exc:
                            logger.warning("[NVDEnricher] Invalid JSON for %s: %s", cve_id, exc)
                            break

                        vulns = data.get("vulnerabilities") or []
                        if not vulns:
                            await _set_status(db, row_id, "not_found")
                        else:
                            best_score, best_severity, cvss_source = _extract_best_cvss(vulns[0])
                            patch_signal, poc_signal = _extract_reference_signals(vulns[0], cve_id)
                            await _set_nvd_enrichment(
                                db,
                                row_id,
                                cve_id,
                                best_score,
                                best_severity,
                                cvss_source,
                                patch_signal,
                                poc_signal,
                                "completed",
                            )
                        processed += 1

                    elif resp.status_code in (403, 429):
                        logger.warning(
                            "[NVDEnricher] NVD returned HTTP %d for %s. Backing off %.0fs.",
                            resp.status_code,
                            cve_id,
                            backoff,
                        )
                        await asyncio.sleep(backoff)
                        break

                    elif resp.status_code in (400, 404):
                        logger.warning("[NVDEnricher] NVD returned HTTP %d for %s.", resp.status_code, cve_id)
                        await _set_status(db, row_id, "not_found")
                        processed += 1

                    else:
                        logger.warning(
                            "[NVDEnricher] NVD returned HTTP %d for %s. Keeping row pending.",
                            resp.status_code,
                            cve_id,
                        )
                        break

                    await asyncio.sleep(request_gap)

            if processed:
                logger.info("[NVDEnricher] Processed %d CVE rows.", processed)
                try:
                    await db.update_source_status("nvd_enrichment", "ok", processed)
                except Exception:
                    pass

            if run_once:
                return

        except Exception as exc:
            logger.error("[NVDEnricher] Loop error: %s", exc)
            if run_once:
                raise
            await asyncio.sleep(POLL_INTERVAL)
