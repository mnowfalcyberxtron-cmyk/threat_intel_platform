"""
connectors/advisory_monitor.py — Top 25 Company Advisory Monitor
Fetches official security advisory RSS feeds and external sources for
the top 25 technology companies. Runs every 30 minutes.

Produces structured advisories in CyberXTron format with:
- Company/Product, Title, Summary, Threat Actor, Malware/Exploit
- Targeted Countries/Industries, IOCs, MITRE TTPs, Reference URLs
"""

import re
import json
import asyncio
import xml.etree.ElementTree as ET
from typing import Any, Dict, List, Optional
from datetime import datetime, timezone
from connectors.base import BaseConnector, now_iso

# ── Top 25 Companies Advisory Sources ────────────────────────────────────────
TOP25_ADVISORY_FEEDS = [
    # Microsoft
    {"company": "Microsoft", "type": "official",
     "name": "Microsoft Security Response Center",
     "url": "https://msrc.microsoft.com/blog/feed",
     "rss": "https://msrc.microsoft.com/blog/feed"},
    {"company": "Microsoft", "type": "official",
     "name": "Microsoft Security Blog",
     "url": "https://www.microsoft.com/en-us/security/blog/feed/"},
    # Google
    {"company": "Google", "type": "official",
     "name": "Google Project Zero",
     "url": "https://googleprojectzero.blogspot.com/feeds/posts/default"},
    {"company": "Google", "type": "official",
     "name": "Google Security Blog",
     "url": "https://security.googleblog.com/feeds/posts/default"},
    # Fortinet
    {"company": "Fortinet", "type": "official",
     "name": "Fortinet Threat Research",
     "url": "https://www.fortinet.com/blog/threat-research.rss"},
    # Cisco
    {"company": "Cisco", "type": "official",
     "name": "Cisco Talos Intelligence",
     "url": "https://blog.talosintelligence.com/feeds/posts/default"},
    {"company": "Cisco", "type": "official",
     "name": "Cisco Security Advisories",
     "url": "https://sec.cloudapps.cisco.com/security/center/pubRss.x"},
    # Apple
    {"company": "Apple", "type": "official",
     "name": "Apple Security Updates",
     "url": "https://support.apple.com/en-us/111900"},
    # Amazon/AWS
    {"company": "Amazon/AWS", "type": "official",
     "name": "AWS Security Bulletins",
     "url": "https://aws.amazon.com/security/security-bulletins/feed/"},
    # IBM
    {"company": "IBM", "type": "official",
     "name": "IBM Security Intelligence",
     "url": "https://securityintelligence.com/feed/"},
    # Oracle
    {"company": "Oracle", "type": "official",
     "name": "Oracle Security Alerts",
     "url": "https://www.oracle.com/ocom/groups/public/@otn/documents/webcontent/rss-security-alerts.xml"},
    # Palo Alto
    {"company": "Palo Alto Networks", "type": "official",
     "name": "Unit 42 Threat Research",
     "url": "https://unit42.paloaltonetworks.com/feed/"},
    # Check Point
    {"company": "Check Point", "type": "official",
     "name": "Check Point Research",
     "url": "https://research.checkpoint.com/feed/"},
    # Adobe
    {"company": "Adobe", "type": "official",
     "name": "Adobe Security Bulletins",
     "url": "https://helpx.adobe.com/security/rss/security-updates.rss"},
    # VMware/Broadcom
    {"company": "VMware", "type": "official",
     "name": "VMware Security Advisories",
     "url": "https://blogs.vmware.com/security/feed"},
    # Intel
    {"company": "Intel", "type": "official",
     "name": "Intel Security Advisories",
     "url": "https://www.intel.com/content/www/us/en/security-center/default.html"},
    # Trend Micro
    {"company": "Trend Micro", "type": "official",
     "name": "Trend Micro Research",
     "url": "https://feeds.trendmicro.com/Anti-MalwareBlog/"},
    # Kaspersky
    {"company": "Kaspersky", "type": "official",
     "name": "Kaspersky Securelist",
     "url": "https://securelist.com/feed/"},
    # CrowdStrike
    {"company": "CrowdStrike", "type": "official",
     "name": "CrowdStrike Blog",
     "url": "https://www.crowdstrike.com/blog/feed/"},
    # Mandiant/FireEye
    {"company": "Mandiant", "type": "official",
     "name": "Mandiant Blog",
     "url": "https://www.mandiant.com/resources/blog/rss.xml"},
    # Sophos
    {"company": "Sophos", "type": "official",
     "name": "Sophos Threat Research",
     "url": "https://news.sophos.com/en-us/category/threat-research/feed/"},
    # SentinelOne
    {"company": "SentinelOne", "type": "official",
     "name": "SentinelOne Blog",
     "url": "https://www.sentinelone.com/blog/feed/"},
    # F5
    {"company": "F5 Networks", "type": "official",
     "name": "F5 Security Advisories",
     "url": "https://support.f5.com/csp/rss-feeds/hotfixes"},
    # Akamai
    {"company": "Akamai", "type": "official",
     "name": "Akamai Security Research",
     "url": "https://www.akamai.com/blog/rss"},
    # ESET
    {"company": "ESET", "type": "official",
     "name": "ESET WeLiveSecurity",
     "url": "https://www.welivesecurity.com/en/feed/"},
    # External cross-company sources
    {"company": "ALL", "type": "external",
     "name": "CISA Known Exploited",
     "url": "https://www.cisa.gov/uscert/ncas/alerts.xml"},
    {"company": "ALL", "type": "external",
     "name": "NIST NVD Recent CVEs",
     "url": "https://nvd.nist.gov/feeds/xml/cve/misc/nvd-rss.xml"},
    {"company": "ALL", "type": "external",
     "name": "The Hacker News",
     "url": "https://feeds.feedburner.com/TheHackersNews"},
    {"company": "ALL", "type": "external",
     "name": "Bleeping Computer",
     "url": "https://www.bleepingcomputer.com/feed/"},
    {"company": "ALL", "type": "external",
     "name": "SANS Internet Storm Center",
     "url": "https://isc.sans.edu/rssfeed_full.xml"},
    {"company": "ALL", "type": "external",
     "name": "Rapid7 Vulnerability DB",
     "url": "https://www.rapid7.com/blog/rss.xml"},
    {"company": "ALL", "type": "external",
     "name": "Qualys Security Blog",
     "url": "https://blog.qualys.com/feed"},
]

# Company name → product/keyword map for matching
COMPANY_KEYWORDS = {
    "Microsoft": ["microsoft","windows","azure","office","exchange","outlook",
                  "sharepoint","teams","defender","m365","active directory","iis"],
    "Google": ["google","chrome","android","gmail","workspace","gcp","kubernetes"],
    "Fortinet": ["fortinet","fortios","fortigate","forticlient","fortiweb","fortisiem"],
    "Cisco": ["cisco","ios xe","webex","meraki","asa","firepower","nexus","anyconnect"],
    "Apple": ["apple","ios","macos","safari","iphone","ipad","webkit","xcode"],
    "Amazon/AWS": ["amazon","aws","s3","lambda","ec2","iam","cloudfront"],
    "IBM": ["ibm","qradar","spectrum","websphere","db2","lotus"],
    "Oracle": ["oracle","java","mysql","weblogic","database","fusion","jdk"],
    "Palo Alto Networks": ["palo alto","pan-os","panorama","cortex","prisma","xdr"],
    "Check Point": ["check point","checkpoint","gaia","smartconsole","harmony"],
    "Adobe": ["adobe","acrobat","reader","coldfusion","flash","magento","commerce"],
    "VMware": ["vmware","vsphere","vcenter","esxi","horizon","nsx","workstation"],
    "Intel": ["intel","microcode","spectre","meltdown","sgx","amt","me"],
    "Qualcomm": ["qualcomm","snapdragon","adreno","hexagon"],
    "Trend Micro": ["trend micro","trendmicro","deep security","apex one"],
    "Kaspersky": ["kaspersky","kav","kes","kaspersky endpoint"],
    "CrowdStrike": ["crowdstrike","falcon","cs-falcon"],
    "Mandiant": ["mandiant","fireeye","helix","nx","hx"],
    "Sophos": ["sophos","utm","xg firewall","intercept x"],
    "SentinelOne": ["sentinelone","sentinel one"],
    "F5 Networks": ["f5","big-ip","nginx","traffix"],
    "Akamai": ["akamai","kona","edge","prolexic"],
    "ESET": ["eset","nod32","eset endpoint"],
    "Samsung": ["samsung","galaxy","tizen","exynos"],
    "HP/HPE": ["hp ","hpe ","hewlett","ilo","aruba","storeonce"],
}

CVE_RE     = re.compile(r'CVE-\d{4}-\d{4,7}', re.I)
IP_RE      = re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b')
DOMAIN_RE  = re.compile(r'\b(?:[a-z0-9\-]+\.)+(?:com|net|org|io|ru|cn|gov|edu|mil)\b', re.I)
HASH_RE    = re.compile(r'\b[a-fA-F0-9]{32,64}\b')
MITRE_RE   = re.compile(r'T\d{4}(?:\.\d{3})?')

MITRE_MAP = {
    "T1566":"Phishing","T1190":"Exploit Public-Facing Application",
    "T1059":"Command and Scripting Interpreter","T1078":"Valid Accounts",
    "T1486":"Data Encrypted for Impact","T1041":"Exfiltration Over C2 Channel",
    "T1055":"Process Injection","T1003":"OS Credential Dumping",
    "T1021":"Remote Services","T1047":"Windows Management Instrumentation",
    "T1053":"Scheduled Task/Job","T1070":"Indicator Removal",
    "T1083":"File and Directory Discovery","T1105":"Ingress Tool Transfer",
    "T1110":"Brute Force","T1133":"External Remote Services",
    "T1136":"Create Account","T1140":"Deobfuscate/Decode Files",
    "T1203":"Exploitation for Client Execution",
    "T1210":"Exploitation of Remote Services",
    "T1486":"Data Encrypted for Impact","T1490":"Inhibit System Recovery",
    "T1562":"Impair Defenses","T1568":"Dynamic Resolution",
}


class AdvisoryMonitorConnector(BaseConnector):
    name = "advisory_monitor"
    display_name = "Top 25 Companies Advisory Monitor"
    tier = 1

    async def fetch(self) -> List[Dict[str, Any]]:
        records = []
        headers = {
            "User-Agent": "CyberXTron-TIP/2.3 Advisory Monitor",
            "Accept": "application/rss+xml,application/xml,text/xml,*/*",
        }

        tasks = [self._fetch_feed(feed, headers) for feed in TOP25_ADVISORY_FEEDS]
        results = await asyncio.gather(*tasks, return_exceptions=True)

        for result in results:
            if isinstance(result, list):
                records.extend(result)

        # Deduplicate by URL
        seen = set()
        deduped = []
        for r in records:
            url = r.get("url","")
            if url not in seen:
                seen.add(url)
                deduped.append(r)

        self.logger.info("Advisory Monitor: %d advisories fetched", len(deduped))
        return deduped

    async def _fetch_feed(self, feed_config: dict, headers: dict) -> List[Dict]:
        url  = feed_config["url"]
        name = feed_config["name"]
        company = feed_config["company"]
        feed_type = feed_config["type"]

        text = await self._get(url, headers=headers)
        if not isinstance(text, str) or not text.strip():
            return []

        try:
            root = ET.fromstring(text)
        except Exception:
            return []

        ns = {"atom": "http://www.w3.org/2005/Atom"}
        items = []

        for item in (root.findall(".//item") + root.findall(".//atom:entry", ns)):
            title   = self._xt(item, ["title"]) or ""
            link    = self._xt(item, ["link","atom:link"], ns) or \
                     (item.find("link") is not None and item.find("link").get("href","")) or ""
            summary = self._xt(item, ["description","summary","content","atom:summary"], ns) or ""
            pubdate = self._xt(item, ["pubDate","published","updated"], ns) or ""

            if not title or not link: continue

            # Clean HTML
            clean = re.sub(r'<[^>]+>',' ', summary)
            clean = re.sub(r'\s+', ' ', clean).strip()[:1000]

            content = f"{title} {clean}"
            affected_company = company if company != "ALL" else self._detect_company(content)

            # --- STRICT FILTERING FOR EXTERNAL SOURCES ---
            # If from BleepingComputer/HackerNews/etc (company=="ALL"),
            # and no Top 25 company was detected, skip it.
            if company == "ALL" and affected_company == "General":
                continue

            # Extract structured fields
            cves    = list(set(CVE_RE.findall(content)))
            ips     = [ip for ip in set(IP_RE.findall(content))
                       if not ip.startswith(("10.","192.168.","127.","0."))][:10]
            domains = [d for d in list(set(DOMAIN_RE.findall(content)))[:10]
                       if d not in ("example.com","google.com","microsoft.com")]
            hashes  = [h for h in list(set(HASH_RE.findall(content))) if len(h) in (32,40,64)][:5]
            ttps    = list(set(MITRE_RE.findall(content)))

            items.append({
                "type":             "advisory",
                "company":          affected_company or "General",
                "advisory_type":    feed_type,
                "source_name":      name,
                "title":            title[:200],
                "summary":          clean[:600],
                "url":              link.strip(),
                "published":        self._parse_date(pubdate),
                "fetched_at":       now_iso(),
                "cves":             cves[:10],
                "iocs": {
                    "domains": domains,
                    "ips":     ips,
                    "hashes":  hashes,
                },
                "mitre_ttps":       [f"{t}: {MITRE_MAP.get(t,t)}" for t in ttps],
                "severity":         self._assess_severity(content, cves),
                "category":         self._categorize(content),
            })

        return items[:15]  # Max 15 per feed

    def _detect_company(self, text: str) -> str:
        tl = text.lower()
        for company, keywords in COMPANY_KEYWORDS.items():
            if any(kw in tl for kw in keywords):
                return company
        return "General"

    def _assess_severity(self, text: str, cves: list) -> str:
        tl = text.lower()
        if any(k in tl for k in ["critical","remote code execution","rce","0-day","zero-day","actively exploited"]):
            return "critical"
        if any(k in tl for k in ["high","privilege escalation","authentication bypass","sql injection"]):
            return "high"
        if cves: return "medium"
        return "low"

    def _categorize(self, text: str) -> str:
        tl = text.lower()
        if any(k in tl for k in ["ransomware","ransom"]): return "ransomware"
        if any(k in tl for k in ["cve-","vulnerability","patch","advisory","exploit"]): return "vulnerability"
        if any(k in tl for k in ["apt","nation","espionage","campaign"]): return "apt"
        if any(k in tl for k in ["malware","trojan","backdoor","rat"]): return "malware"
        if any(k in tl for k in ["phishing","credential","breach"]): return "credential"
        return "advisory"

    def _parse_date(self, s: str) -> str:
        if not s: return now_iso()
        from datetime import datetime, timezone
        
        # Try ISO format
        try:
            iso_s = s
            if iso_s.endswith('Z'): iso_s = iso_s[:-1] + '+00:00'
            return datetime.fromisoformat(iso_s).astimezone(timezone.utc).isoformat()
        except Exception:
            pass
            
        # Try RSS RFC 822/2822
        try:
            from email.utils import parsedate_to_datetime
            return parsedate_to_datetime(s).astimezone(timezone.utc).isoformat()
        except Exception:
            pass
            
        # Fallback to dateutil if installed
        try:
            from dateutil import parser
            return parser.parse(s).astimezone(timezone.utc).isoformat()
        except Exception:
            return now_iso()

    @staticmethod
    def _xt(el, tags, ns=None):
        for tag in tags:
            try:
                child = el.find(tag, ns) if (ns and ":" in tag) else el.find(tag)
                if child is not None and child.text:
                    return child.text.strip()
            except Exception:
                pass
        return ""
