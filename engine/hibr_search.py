import asyncio
import re
import json
import logging
from typing import Any, Dict, List, Optional, Set, Tuple
from config import settings

logger = logging.getLogger("engine.hibr_search")

# Common regex patterns
EMAIL_REGEX = re.compile(r"[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+")
PHONE_REGEX = re.compile(r"\+?[0-9]{1,4}[-.\s]?\(?[0-9]{1,3}?\)?[-.\s]?[0-9]{3,4}[-.\s]?[0-9]{3,4}")
DOMAIN_REGEX = re.compile(r"\b(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,6}\b")
# Reject values that look like decimals / GPS coords / version numbers
DECIMAL_LIKE = re.compile(r"^\+?\d+\.\d+$")
WALLET_REGEX = re.compile(r"\b(?:0x[a-fA-F0-9]{40}|[13][a-km-zA-HJ-NP-Z1-9]{26,35}|bc1[a-zA-HJ-NP-Z0-9]{25,39})\b")

# Words to exclude from extracted domains and usernames
EXCLUDED_DOMAINS = {
    "google.com", "gmail.com", "yahoo.com", "outlook.com", "hotmail.com", 
    "facebook.com", "t.me", "github.com", "haveibeenransom.com", "indiamart.com",
    "wetafx.co.nz", "istockphoto.com", "turbosquid.com", "mediashuttle.com", 
    "zoho.in", "avast.com", "cloudflare.com"
}
EXCLUDED_USERNAMES = {
    "admin", "administrator", "root", "user", "sales", "info", "support", 
    "itsupport", "prod", "test", "null", "unknown", "n/a", "na"
}

class HIBRSecuritySearchEngine:
    def __init__(self, hibr_connector, max_depth: int = 3, request_budget: int = 50, concurrency: int = 5):
        self.hibr = hibr_connector
        self.max_depth = max_depth
        self.request_budget = request_budget
        self.concurrency = concurrency
        
        self.visited_entities: Set[Tuple[str, str]] = set() # (type, value)
        self.entities_queue: List[Tuple[str, str, int, str]] = [] # (type, value, current_depth, parent_id)

        # Results storage
        self.all_metadata: List[Dict[str, Any]] = []
        self.all_fulldata: List[Dict[str, Any]] = []
        self.all_fullstealer: List[Dict[str, Any]] = []

        # Graph nodes and edges
        self.nodes: Dict[str, Dict[str, Any]] = {} # id -> node details
        self.edges: List[Dict[str, str]] = [] # [{"source": id, "target": id}]

        # Request counter to stay within budget
        self.requests_made = 0
        self._budget_warned = False  # Only log budget exceeded once
        
    def classify_entity(self, value: str) -> str:
        """Classify entity type based on syntax."""
        val = value.strip()
        if "@" in val:
            return "email"
        if WALLET_REGEX.match(val):
            return "wallets"
        # Phone: must start with + or be pure digits (with dashes/spaces), reject decimals/GPS coords
        if not DECIMAL_LIKE.match(val):
            if val.startswith("+") or (len(val) >= 7 and val.replace(" ", "").replace("-", "").isdigit()):
                return "phone"
        if DOMAIN_REGEX.match(val):
            # Exclude file extensions that are not real domains
            _FILE_EXTS = (".zip", ".bson", ".7z", ".txt", ".json", ".db", ".sql",
                          ".rar", ".gz", ".tar", ".csv", ".log", ".exe", ".dll",
                          ".bak", ".tmp", ".dat", ".xml", ".yaml", ".yml", ".ini")
            if any(val.lower().endswith(ext) for ext in _FILE_EXTS):
                return "username"
            return "domain"
        return "username"

    def normalize_entity(self, etype: str, value: str) -> str:
        """Normalize values for consistency."""
        val = value.strip().lower()
        if etype == "domain":
            val = val.replace("https://", "").replace("http://", "").split("/")[0]
            if val.startswith("www."):
                val = val[4:]
        elif etype == "phone":
            # Remove spaces, dashes, parentheses
            val = val.replace(" ", "").replace("-", "").replace("(", "").replace(")", "")
        return val

    def extract_from_raw(self, record: Any) -> List[Tuple[str, str]]:
        """Recursively scan all dictionary values or strings to find potential entities."""
        discovered = []
        
        # Helper to inspect strings
        def check_string(s: str, field_key: str = ""):
            s_clean = s.strip()
            if not s_clean:
                return
            
            # Check if we have explicit field mappings from keys
            if field_key:
                k_low = field_key.lower()
                if "email" in k_low and EMAIL_REGEX.match(s_clean):
                    discovered.append(("email", s_clean))
                    return
                if "phone" in k_low or "mobile" in k_low or "telephone" in k_low:
                    if len(s_clean) >= 7 and not DECIMAL_LIKE.match(s_clean):
                        discovered.append(("phone", s_clean))
                        return
                if "domain" in k_low or "website" in k_low:
                    if DOMAIN_REGEX.match(s_clean):
                        discovered.append(("domain", s_clean))
                        return
                if "wallet" in k_low and WALLET_REGEX.match(s_clean):
                    discovered.append(("wallets", s_clean))
                    return
                if "hwid" in k_low:
                    discovered.append(("hwid", s_clean))
                    return
                if "teleuser" in k_low or "telegram" in k_low:
                    discovered.append(("teleuser", s_clean))
                    return

            # Fallback to regex scans
            # 1. Emails
            for email in EMAIL_REGEX.findall(s):
                discovered.append(("email", email))
            # 2. Wallets
            for wallet in WALLET_REGEX.findall(s):
                discovered.append(("wallets", wallet))
            # 3. Phones (only if they look structured)
            for phone in PHONE_REGEX.findall(s):
                if len(phone.strip()) >= 8:
                    discovered.append(("phone", phone))
            # 4. Domains
            for domain in DOMAIN_REGEX.findall(s):
                discovered.append(("domain", domain))

        # Helper to traverse dict/list
        def traverse(obj: Any, parent_key: str = ""):
            if isinstance(obj, dict):
                for k, v in obj.items():
                    # Parse email_context or raw strings
                    if k == "email_context" and isinstance(v, str):
                        # email_context can be json or comma-separated pairs
                        try:
                            ctx_data = json.loads(v)
                            traverse(ctx_data, k)
                        except Exception:
                            # Parse comma-separated "key : value" pairs
                            for pair in v.split(","):
                                if ":" in pair:
                                    pk, pv = pair.split(":", 1)
                                    check_string(pv, pk.strip())
                            # Fallback scan entire string
                            check_string(v, k)
                    else:
                        traverse(v, k)
            elif isinstance(obj, list):
                for item in obj:
                    traverse(item, parent_key)
            elif isinstance(obj, str):
                check_string(obj, parent_key)

        traverse(record)
        return discovered

    def add_node(self, etype: str, evalue: str, depth: int, reason: str, parent_id: str = None) -> str:
        """Add a node to the relationship graph and create an edge if it has a parent."""
        node_id = f"{etype}:{evalue}"
        if node_id not in self.nodes:
            # Score decreases with depth
            confidence = max(0.4, round(1.0 - (depth * 0.15), 2))
            if depth == 0:
                confidence = 1.0
                
            self.nodes[node_id] = {
                "id": node_id,
                "type": etype,
                "value": evalue,
                "depth": depth,
                "confidence": confidence,
                "reason": reason,
                "path": parent_id
            }
        
        if parent_id and parent_id != node_id:
            edge = {"source": parent_id, "target": node_id}
            if edge not in self.edges:
                self.edges.append(edge)
                
        return node_id

    async def execute_parallel_searches(self, entities: List[Tuple[str, str, int, str]]):
        """Execute searches for a batch of entities concurrently, respecting budget and concurrency."""
        sem = asyncio.Semaphore(self.concurrency)
        tasks = []

        async def worker(etype: str, evalue: str, depth: int, parent_id: str):
            async with sem:
                if self.requests_made >= self.request_budget:
                    if not self._budget_warned:
                        self._budget_warned = True
                        logger.warning("HIBR recursive search: reached request budget of %d", self.request_budget)
                    return
                await self.search_entity(etype, evalue, depth, parent_id)

        for etype, evalue, depth, parent_id in entities:
            # Skip if visited
            normalized = self.normalize_entity(etype, evalue)
            if not normalized or (etype, normalized) in self.visited_entities:
                continue
            self.visited_entities.add((etype, normalized))
            
            tasks.append(worker(etype, evalue, depth, parent_id))

        if tasks:
            await asyncio.gather(*tasks)

    async def search_entity(self, etype: str, evalue: str, depth: int, parent_id: str):
        """Perform API requests on all relevant datasets for a specific entity."""
        node_id = self.add_node(etype, evalue, depth, f"Discovered from {parent_id or 'start query'}", parent_id)
        
        # Check domain exclusion
        if etype == "domain" and evalue.lower() in EXCLUDED_DOMAINS:
            return
        if etype == "username" and evalue.lower() in EXCLUDED_USERNAMES:
            return

        # Prepare parallel searches on HIBR datasets
        api_calls = []
        
        # 1. Metadata searches (only for domain, email, username, phone, id)
        if etype in ("domain", "email", "username", "phone", "id"):
            api_calls.append(self._fetch_metadata(etype, evalue))
            
        # 2. Fulldata searches (same fields)
        if etype in ("domain", "email", "username", "phone", "id"):
            api_calls.append(self._fetch_fulldata(etype, evalue))

        # 3. Fullstealer searches (wider range of fields)
        stealer_fields = {
            "domain": "domain", "email": "email", "username": "username", "phone": "phone", "id": "id",
            "wallets": "wallets", "teleuser": "teleuser", "teleid": "teleid", "telephone": "telephone",
            "steamuser": "steamuser", "steamid": "steamid", "vpn": "vpn", "ftp": "ftp", "hwid": "hwid"
        }
        if etype in stealer_fields:
            api_calls.append(self._fetch_fullstealer(stealer_fields[etype], evalue))

        # Execute HIBR API calls for this entity in parallel
        results = await asyncio.gather(*api_calls, return_exceptions=True)
        
        # Process results and extract new entities
        discovered_entities: List[Tuple[str, str]] = []
        
        for res in results:
            if isinstance(res, Exception) or not res:
                continue
            
            # Analyze response type to parse records
            if isinstance(res, dict):
                # Is it Metadata?
                if "sources" in res:
                    sources = res.get("sources", [])
                    for s in sources:
                        self.all_metadata.append(s)
                        discovered_entities.extend(self.extract_from_raw(s))
                
                # Is it Fulldata?
                elif "data" in res:
                    data = res.get("data", [])
                    for d in data:
                        self.all_fulldata.append(d)
                        discovered_entities.extend(self.extract_from_raw(d))
                        
                # Is it Fullstealer?
                elif "matches" in res:
                    matches = res.get("matches", [])
                    for m in matches:
                        self.all_fullstealer.append(m)
                        discovered_entities.extend(self.extract_from_raw(m))

        # Filter, normalize and queue newly discovered entities
        if depth + 1 <= self.max_depth:
            for new_type, new_val in discovered_entities:
                new_type_classified = self.classify_entity(new_val) if new_type in ("username", "domain") else new_type
                norm_val = self.normalize_entity(new_type_classified, new_val)

                # Skip invalid/excluded entities
                if not norm_val or len(norm_val) < 4:
                    continue
                if new_type_classified == "domain" and norm_val in EXCLUDED_DOMAINS:
                    continue
                if new_type_classified == "username" and norm_val in EXCLUDED_USERNAMES:
                    continue
                # Phone numbers generate too many rate-limited calls in recursion—skip them beyond depth 0
                if new_type_classified == "phone" and depth >= 1:
                    continue
                # Wallets, hwid, teleuser also rarely yield useful cross-references—skip in deep recursion
                if new_type_classified in ("wallets", "hwid") and depth >= 1:
                    continue

                # Check visited
                if (new_type_classified, norm_val) not in self.visited_entities:
                    self.entities_queue.append((new_type_classified, new_val, depth + 1, node_id))

                # Also, if we extract an email, extract its domain as a separate entity
                if new_type_classified == "email" and "@" in norm_val:
                    domain_part = norm_val.split("@")[-1]
                    if domain_part and domain_part not in EXCLUDED_DOMAINS:
                        if ("domain", domain_part) not in self.visited_entities:
                            self.entities_queue.append(("domain", domain_part, depth + 1, node_id))

    async def _fetch_metadata(self, field: str, query: str) -> Optional[Dict]:
        self.requests_made += 1
        try:
            return await self.hibr.search_metadata(field, query)
        except Exception as e:
            logger.error("HIBR search metadata error (%s:%s): %s", field, query, e)
            return None

    async def _fetch_fulldata(self, fields: str, query: str) -> Optional[Dict]:
        self.requests_made += 1
        try:
            # We will use improved search_fulldata which loops pagination internally
            return await self.hibr.search_fulldata(fields, query)
        except Exception as e:
            logger.error("HIBR search fulldata error (%s:%s): %s", fields, query, e)
            return None

    async def _fetch_fullstealer(self, fields: str, term: str) -> Optional[Dict]:
        self.requests_made += 1
        try:
            # We will use improved search_fullstealer which loops pagination internally
            return await self.hibr.search_fullstealer(fields, term)
        except Exception as e:
            logger.error("HIBR search fullstealer error (%s:%s): %s", fields, term, e)
            return None

    async def run(self, start_value: str, start_type: str = None) -> Dict[str, Any]:
        """Entrypoint for running the recursive search."""
        if not start_type:
            start_type = self.classify_entity(start_value)
            
        start_val_norm = self.normalize_entity(start_type, start_value)
        self.entities_queue.append((start_type, start_val_norm, 0, None))
        
        # Breadth-first level recursion
        for current_depth in range(self.max_depth + 1):
            # Extract entities at current depth level
            level_entities = [e for e in self.entities_queue if e[2] == current_depth]
            if not level_entities:
                break
                
            logger.info("HIBR Recursion: Level %d processing %d entities", current_depth, len(level_entities))
            await self.execute_parallel_searches(level_entities)
            
            # Break early if we exceeded request budget
            if self.requests_made >= self.request_budget:
                break

        # Deduplicate final records
        deduplicated_metadata = self.deduplicate_metadata(self.all_metadata)
        deduplicated_fulldata = self.deduplicate_fulldata(self.all_fulldata)
        deduplicated_fullstealer = self.deduplicate_fullstealer(self.all_fullstealer)

        # Generate output representations
        json_tree = self.generate_json_tree(start_type, start_val_norm)
        ascii_tree = self.generate_ascii_tree(json_tree)

        return {
            "start_entity": {"value": start_value, "type": start_type},
            "stats": {
                "depth_reached": current_depth,
                "api_calls_made": self.requests_made,
                "entities_discovered": len(self.visited_entities),
                "metadata_count": len(deduplicated_metadata),
                "fulldata_count": len(deduplicated_fulldata),
                "fullstealer_count": len(deduplicated_fullstealer)
            },
            "metadata": deduplicated_metadata,
            "fulldata": deduplicated_fulldata,
            "fullstealer": deduplicated_fullstealer,
            "graph": {
                "nodes": list(self.nodes.values()),
                "edges": self.edges
            },
            "timeline": {
                "json": json_tree,
                "ascii": ascii_tree
            }
        }

    # --- Deduplication logic ---
    def deduplicate_metadata(self, records: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        seen = set()
        unique = []
        for r in records:
            rid = r.get("id") or r.get("id_source") or str(r)
            if rid not in seen:
                seen.add(rid)
                unique.append(r)
        return unique

    def deduplicate_fulldata(self, records: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        seen = set()
        unique = []
        for r in records:
            fd = r.get("full_data", {}).get("full_data", {})
            # Create a unique key from email and domain and source
            eid = fd.get("email") or ""
            dom = fd.get("domain") or ""
            src = fd.get("id_source") or ""
            key = f"{eid}:{dom}:{src}"
            if key not in seen:
                seen.add(key)
                unique.append(r)
        return unique

    def deduplicate_fullstealer(self, records: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        seen = set()
        unique = []
        for r in records:
            # Deduplicate by HWID, IP, username or custom hash of match data
            match_str = json.dumps(r, sort_keys=True)
            match_hash = hash(match_str)
            if match_hash not in seen:
                seen.add(match_hash)
                unique.append(r)
        return unique

    # --- Tree Generation logic ---
    def generate_json_tree(self, start_type: str, start_val: str) -> Dict[str, Any]:
        """Construct hierarchical JSON tree representing paths of discovery."""
        root_id = f"{start_type}:{start_val}"
        
        def build_branch(node_id: str) -> Dict[str, Any]:
            node = self.nodes.get(node_id)
            if not node:
                return {}
            
            # Find children nodes (where this node is their path/parent)
            children_ids = [nid for nid, details in self.nodes.items() if details.get("path") == node_id]
            children_branches = [build_branch(cid) for cid in children_ids]
            
            # Remove empty branches
            children_branches = [b for b in children_branches if b]
            
            return {
                "id": node["id"],
                "type": node["type"],
                "value": node["value"],
                "confidence": node["confidence"],
                "reason": node["reason"],
                "children": children_branches
            }
            
        return build_branch(root_id)

    def generate_ascii_tree(self, branch: Dict[str, Any], prefix: str = "", is_last: bool = True) -> str:
        """Render the JSON tree into a clean text-based ASCII tree format."""
        if not branch:
            return ""
            
        lines = []
        connector = "└── " if is_last else "├── "
        lines.append(f"{prefix}{connector}{branch['value']} [{branch['type']}] (Conf: {branch['confidence']})")
        
        new_prefix = prefix + ("    " if is_last else "│   ")
        children = branch.get("children", [])
        for i, child in enumerate(children):
            is_child_last = (i == len(children) - 1)
            lines.append(self.generate_ascii_tree(child, new_prefix, is_child_last))
            
        return "\n".join(lines)
