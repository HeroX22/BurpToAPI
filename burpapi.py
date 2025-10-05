#!/usr/bin/env python3
import xml.etree.ElementTree as ET
import base64
import json
import argparse
import re
import os
import hashlib
from urllib.parse import urlparse, parse_qs
import glob
from collections import defaultdict
import logging
from functools import lru_cache
from concurrent.futures import ThreadPoolExecutor, as_completed

SENSITIVE_KEYS = {"id", "user", "username", "userid", "email", "token", "session", "password", "auth", "key"}

# --- Replace sanitize_for_logging with stronger multi-layer sanitization ---
def sanitize_for_logging(data: str) -> str:
    """Enhanced sanitization with multiple layers to reduce risk of leaking secrets."""
    if not isinstance(data, str):
        data = str(data)

    # Layer 0: JWT tokens first (avoid them being partially redacted by base64 rule)
    data = re.sub(r'eyJ[A-Za-z0-9_-]*\.[A-Za-z0-9_-]*\.[A-Za-z0-9_-]*', '[JWT_REDACTED]', data)

    # Layer 1: Authorization: Bearer - keep scheme, redact token
    data = re.sub(r'(?i)(authorization:\s*bearer\s+)[A-Za-z0-9\-\._~\+\/]+=*', r'\1[REDACTED]', data)

    # Layer 2: Base64-like long strings (possible encoded secrets)
    data = re.sub(r'\b[A-Za-z0-9+/]{40,}={0,2}\b', '[BASE64_REDACTED]', data)

    # Layer 3: Known key/password patterns (case-insensitive)
    sensitive_patterns = [
        (r'((?:password|pass|pwd)["\s:=]+)[^\s\'"&]+', r'\1[REDACTED]', re.IGNORECASE),
        (r'((?:bearer|token|key|auth)\s+)[\w\-\.=]+', r'\1[REDACTED]', re.IGNORECASE),
    # General authorization fallback: redact remaining value but PRESERVE Bearer (negative lookahead)
    # Ensure we don't match when optional whitespace is followed by 'bearer' (case-insensitive).
    (r'(authorization:\s*)(?!\s*bearer\b)([^\n\r]+)', r'\1[REDACTED]', re.IGNORECASE),
    ]

    for pattern, replacement, flags in sensitive_patterns:
        data = re.sub(pattern, replacement, data, flags=flags)

    return data

class SensitiveDataFilter(logging.Filter):
    """Logging filter that sanitizes message text before output."""
    def filter(self, record):
        try:
            record.msg = sanitize_for_logging(record.getMessage())
            # avoid double-formatting issues by clearing args
            record.args = ()
        except Exception:
            pass
        return True

def setup_logging(verbose: bool = False):
    """Setup logging configuration."""
    level = logging.DEBUG if verbose else logging.INFO
    logging.basicConfig(
        format="%(levelname)s: %(message)s",
        level=level
    )
    # attach sanitizing filter globally
    logging.getLogger().addFilter(SensitiveDataFilter())

# --- Enhanced safe_join_path: check original filename and reject traversal ---
def safe_join_path(folder: str, filename: str) -> str:
    """Enhanced path traversal prevention. Rejects suspicious filenames and symlink escapes."""
    # Reject suspicious input early (inspect original filename, not only basename)
    if filename is None:
        raise ValueError("Empty filename")
    # Reject null bytes explicitly (treat as invalid)
    if '\x00' in filename:
        raise ValueError("Invalid filename")
    norm = os.path.normpath(filename)
    # Reject obvious traversal or absolute names or any path separators in provided filename
    if norm.startswith(("..", "/", "\\")) or ".." in filename or any(sep in filename for sep in (os.sep, "/", "\\")):
        raise ValueError("Suspicious filename detected")
    safe_filename = os.path.basename(filename)
    # Remove null bytes and trim whitespace (already checked for nulls)
    safe_filename = safe_filename.strip()
    if safe_filename == '':
        raise ValueError("Invalid filename")
    full_path = os.path.realpath(os.path.join(folder, safe_filename))
    folder_abs = os.path.realpath(folder)
    if not full_path.startswith(folder_abs + os.sep) and full_path != folder_abs:
        raise ValueError("Path traversal attempt detected")
    return full_path

# --- Improved base64 decoding with validation; return original on invalid input ---
def decode_base64(data, is_base64):
    """Decode base64 data using validation and safe fallbacks."""
    if is_base64 == "true" and data:
        try:
            # validate=True will raise if input contains non-base64 chars
            decoded = base64.b64decode(data, validate=True)
        except Exception as e:
            logging.warning(f"Base64 decode failed or invalid input: {e}")
            return data
        # attempt decoding bytes using a list of encodings, but if none work return original decoded with replacement
        for enc in ('utf-8', 'latin-1', 'cp1252'):
            try:
                return decoded.decode(enc)
            except UnicodeDecodeError:
                continue
        return decoded.decode('utf-8', errors='replace')
    return data

def parse_headers(raw_request):
    """Parse headers from a raw HTTP request"""
    headers = {}
    lines = raw_request.split('\n')
    
    # Skip the first line (HTTP method line)
    for line in lines[1:]:
        line = line.strip()
        if not line:
            break  # Headers end at empty line
            
        if ': ' in line:
            key, value = line.split(': ', 1)
            headers[key] = value
    
    return headers

def parse_request_line(first_line):
    """Parse the first line of an HTTP request"""
    parts = first_line.strip().split(' ')
    if len(parts) >= 2:
        method = parts[0]
        path = parts[1]
        return method, path
    return None, None

def extract_request_body(raw_request, preserve_whitespace: bool = False):
    """Extract request body from raw HTTP request.

    This handles both CRLF (\r\n) and LF (\n) line endings by splitting
    on the first blank line (headers/body separator). Using a regex makes
    the split tolerant to different newline styles encountered in Burp
    exports so the body isn't accidentally dropped.

    preserve_whitespace: when True, do not strip leading/trailing whitespace
    (helps preserve multipart boundaries and exact payloads).
    """
    # Split on the first blank line (handle CRLF or LF)
    parts = re.split(r"\r?\n\r?\n", raw_request, maxsplit=1)
    if len(parts) > 1:
        return parts[1] if preserve_whitespace else parts[1].strip()
    return ""

def generate_request_hash(method, url, headers, body=None):
    """Generate a hash to identify duplicate requests"""
    # Parse URL to remove potential variability in query param order
    parsed_url = urlparse(url)
    path = parsed_url.path
    
    # Normalize query parameters (sort them)
    if parsed_url.query:
        query_params = parse_qs(parsed_url.query)
        # Convert to a sorted representation
        sorted_query = "&".join(f"{k}={','.join(sorted(v))}" for k, v in sorted(query_params.items()))
        normalized_url = f"{parsed_url.scheme}://{parsed_url.netloc}{path}?{sorted_query}"
    else:
        normalized_url = f"{parsed_url.scheme}://{parsed_url.netloc}{path}"
    
    # Create a hash based on method, URL, and essential headers
    key_headers = {}
    for header_name, header_value in headers.items():
        # Only include important headers that define the request semantics
        # Exclude headers that might vary between identical requests
        if header_name.lower() not in ['cookie', 'date', 'user-agent', 'x-timestamp', 'x-device-id']:
            key_headers[header_name.lower()] = header_value
    
    # Create hash input
    hash_input = f"{method.upper()}:{normalized_url}"
    
    # Add sorted headers to hash input
    if key_headers:
        headers_str = ";".join(f"{k}={v}" for k, v in sorted(key_headers.items()))
        hash_input += f":{headers_str}"
    
    # Add body to hash if present and not for GET/HEAD
    if body and method.upper() not in ["GET", "HEAD"]:
        # For JSON bodies, normalize by parsing and re-stringifying to handle whitespace differences
        content_type = next((v for k, v in headers.items() if k.lower() == 'content-type'), '')
        if 'application/json' in content_type.lower():
            try:
                json_body = json.loads(body)
                body = json.dumps(json_body, sort_keys=True)
            except:
                pass  # If JSON parsing fails, use the original body
        hash_input += f":{body}"
    
    # Generate SHA-256 hash
    return hashlib.sha256(hash_input.encode()).hexdigest()

def detect_auth_headers(headers):
    """Detect authentication headers and extract tokens/keys as variables."""
    auth_vars = {}
    for k, v in headers.items():
        kl = k.lower()
        if kl == "authorization":
            if v.lower().startswith("bearer "):
                auth_vars["bearer_token"] = v[7:]
            else:
                auth_vars["authorization"] = v
        elif kl in ("x-api-key", "api-key", "x-access-token"):
            auth_vars[kl.replace("-", "_")] = v
    return auth_vars

def extract_variables_from_path(path):
    """Convert numeric or UUID segments in path to Postman/OpenAPI variables."""
    segments = path.strip("/").split("/")
    new_segments = []
    variables = []
    for seg in segments:
        if re.match(r"^\d+$", seg):
            var = "id"
            new_segments.append(f":{var}")
            variables.append(var)
        elif re.match(r"^[0-9a-fA-F-]{8,}$", seg):
            var = "uuid"
            new_segments.append(f":{var}")
            variables.append(var)
        else:
            new_segments.append(seg)
    joined = "/".join(new_segments)
    # Ensure leading slash in returned path (tests expect it)
    if joined:
        return f"/{joined}", variables
    return "/", variables

def group_by_path(items, mode="path_prefix"):
    """Group items by path prefix or domain."""
    grouped = defaultdict(list)
    for item in items:
        url = item.get("url")
        parsed = urlparse(url)
        if mode == "domain":
            key = parsed.netloc
        elif mode == "path_prefix":
            prefix = parsed.path.strip("/").split("/")[0] if parsed.path.strip("/") else "root"
            key = prefix
        else:
            key = "All"
        grouped[key].append(item)
    return grouped

def parse_har_file(har_file):
    """Parse HAR file and yield items similar to Burp XML."""
    with open(har_file, "r", encoding="utf-8") as f:
        har = json.load(f)
    for entry in har["log"]["entries"]:
        req = entry["request"]
        resp = entry.get("response", {})
        url = req["url"]
        method = req["method"]
        headers = {h["name"]: h["value"] for h in req.get("headers", [])}
        body = req.get("postData", {}).get("text", "")
        status = str(resp.get("status", ""))
        resp_body = resp.get("content", {}).get("text", "")
        resp_headers = {h["name"]: h["value"] for h in resp.get("headers", [])}
        # store _raw_request as None for HAR (no raw HTTP message available)
        yield {
            "url": url,
            "method": method,
            "headers": headers,
            "body": body,
            "status": status,
            "response": resp_body,
            "_raw_request": None,
            "response_headers": resp_headers
        }

def update_postman_collection(existing_file, new_items):
    """Update existing Postman collection with new items (avoid duplicates)."""
    with open(existing_file, "r", encoding="utf-8") as f:
        collection = json.load(f)
    # Recursively collect hashes from existing collection (handle folders)
    existing_hashes = set()

    def collect_requests(obj):
        # obj can be a folder (with 'item') or a request
        if isinstance(obj, dict) and "request" in obj:
            req = obj["request"]
            url = req["url"]["raw"] if isinstance(req["url"], dict) else req["url"]
            method = req.get("method", "")
            headers = {h["key"]: h["value"] for h in req.get("header", [])}
            # Normalize body for different Postman body modes
            body_obj = req.get("body", {}) or {}
            body_text = ""
            mode = body_obj.get("mode", "")
            if mode == "raw":
                body_text = body_obj.get("raw", "")
            elif mode == "urlencoded":
                parts = []
                for p in body_obj.get("urlencoded", []):
                    k = p.get("key", "")
                    v = p.get("value", "")
                    parts.append(f"{k}={v}")
                body_text = "&".join(parts)
            elif mode == "formdata":
                parts = []
                for p in body_obj.get("formdata", []):
                    k = p.get("key", "")
                    v = p.get("value", "")
                    parts.append(f"{k}={v}")
                body_text = "&".join(parts)
            else:
                # fallback: try raw
                body_text = body_obj.get("raw", "") if isinstance(body_obj, dict) else str(body_obj)
            existing_hashes.add(generate_request_hash(method, url, headers, body_text))
            # store reference so we can replace empty bodies later if needed
            existing_hash_to_req = globals().setdefault("_existing_hash_to_req", {})
            existing_hash_to_req[generate_request_hash(method, url, headers, body_text)] = req
        elif isinstance(obj, dict) and "item" in obj:
            for child in obj.get("item", []):
                collect_requests(child)

    for top in collection.get("item", []):
        collect_requests(top)

    # Build mapping of existing top-level folders by name for insertion
    folder_map = {}
    for top in collection.get("item", []):
        if isinstance(top, dict) and "item" in top and "name" in top:
            folder_map[top["name"]] = top

    # If there are request objects at the top level (flattened collection),
    # move them into folders based on their first path segment to keep
    # the collection organized.
    original_items = list(collection.get("item", []))
    non_request_tops = [it for it in original_items if not (isinstance(it, dict) and "request" in it)]
    # Process top-level request entries and move them into folder_map
    for it in original_items:
        if isinstance(it, dict) and "request" in it:
            # determine target folder and move
            try:
                fname = folder_for_request(it["request"])
            except Exception:
                fname = "root"
            if fname in folder_map:
                folder_map[fname].setdefault("item", []).append(it)
            else:
                # create new folder object and register it
                newf = {"name": fname, "item": [it]}
                folder_map[fname] = newf

    # Rebuild collection['item'] to contain non-request top entries plus any folders
    rebuilt = list(non_request_tops)
    # Ensure all folder_map folders are present in rebuilt (preserve existing order when possible)
    for name, f in folder_map.items():
        if f not in rebuilt:
            rebuilt.append(f)
    collection["item"] = rebuilt

    # Helper to determine folder name from request url (first path segment)
    def folder_for_request(req_obj):
        url = req_obj["url"]["raw"] if isinstance(req_obj["url"], dict) else req_obj["url"]
        try:
            parsed = urlparse(url)
            seg = parsed.path.strip("/")
            if not seg:
                return "root"
            first = seg.split("/")[0]
            return first
        except Exception:
            return "root"

    # Insert new items into matching folders when possible, otherwise append as top-level
    for item in new_items:
        req = item.get("request", {})
        url = req.get("url", {}).get("raw") if isinstance(req.get("url", {}), dict) else req.get("url", "")
        method = req.get("method", "")
        headers = {h["key"]: h["value"] for h in req.get("header", [])}
        # Derive body_text similarly to existing collection
        body_obj = req.get("body", {}) or {}
        mode = body_obj.get("mode", "")
        if mode == "raw":
            body_text = body_obj.get("raw", "")
        elif mode == "urlencoded":
            parts = []
            for p in body_obj.get("urlencoded", []):
                k = p.get("key", "")
                v = p.get("value", "")
                parts.append(f"{k}={v}")
            body_text = "&".join(parts)
        elif mode == "formdata":
            parts = []
            for p in body_obj.get("formdata", []):
                k = p.get("key", "")
                v = p.get("value", "")
                parts.append(f"{k}={v}")
            body_text = "&".join(parts)
        else:
            body_text = body_obj.get("raw", "") if isinstance(body_obj, dict) else str(body_obj)

        h = generate_request_hash(method, url, headers, body_text)

        # If a matching request exists without a body but the new one has a body,
        # prefer replacing the existing request content with the new richer request.
        existing_map = globals().get("_existing_hash_to_req", {})
        if h in existing_hashes:
            existing_req = existing_map.get(h)
            if existing_req is not None:
                # detect if existing has empty body and new has non-empty
                def get_body_text(r):
                    bo = r.get("body", {}) or {}
                    mm = bo.get("mode", "")
                    if mm == "raw":
                        return bo.get("raw", "")
                    elif mm == "urlencoded":
                        return "&".join(f"{p.get('key','')}={p.get('value','')}" for p in bo.get("urlencoded", []))
                    elif mm == "formdata":
                        return "&".join(f"{p.get('key','')}={p.get('value','')}" for p in bo.get("formdata", []))
                    return bo.get("raw", "") if isinstance(bo, dict) else str(bo)

                if get_body_text(existing_req) == "" and body_text != "":
                    # replace existing request contents
                    existing_req.clear()
                    existing_req.update(req)
            # skip adding duplicate
            continue
        # choose folder
        folder_name = folder_for_request(req)
        if folder_name in folder_map:
            folder_map[folder_name].setdefault("item", []).append(item)
        else:
            # create new folder to keep structure instead of appending as raw request
            new_folder = {"name": folder_name, "item": [item]}
            collection.setdefault("item", []).append(new_folder)

    return collection

def export_insomnia(items, output_file):
    """Export items to Insomnia format."""
    insomnia = {
        "_type": "export",
        "__export_format": 4,
        "__export_date": "",
        "resources": []
    }
    for idx, item in enumerate(items):
        req = item["request"]
        url = req["url"]["raw"] if isinstance(req["url"], dict) else req["url"]
        headers = [{"name": h["key"], "value": h["value"]} for h in req.get("header",[])]
        body = req.get("body", {}).get("raw", "")
        insomnia["resources"].append({
            "_id": f"req_{idx}",
            "parentId": "wrk_1",
            "_type": "request",
            "name": item["name"],
            "method": req["method"],
            "url": url,
            "body": {"mimeType": "application/json", "text": body} if body else {},
            "headers": headers
        })
    with open(output_file, "w", encoding="utf-8") as f:
        json.dump(insomnia, f, indent=2)
    print(f"Exported to Insomnia: {output_file}")

def safe_json_loads(data: str):
    """Safely parse JSON, return None if fail."""
    try:
        return json.loads(data)
    except Exception:
        return None

def is_sensitive_key(key: str) -> bool:
    """Check if a key is considered sensitive."""
    lkey = key.lower()
    return (
        lkey in SENSITIVE_KEYS
        or lkey.startswith("x-api")
        or lkey.startswith("api-")
        or lkey.startswith("api_")
        or 'api_key' in lkey
        or lkey.startswith("apikey")
    )

def detect_pentest_candidates(items, filter_post_put=None):
    """Detect potentially weak or interesting requests for pentest."""
    candidates = []
    for entry in items:
        url = entry.get("url", "")
        method = entry.get("method", "").upper()
        headers = entry.get("headers", {})
        body = entry.get("body", "")
        parsed_url = urlparse(url)
        reasons = []

        # Path analysis
        path_segments = parsed_url.path.strip("/").split("/")
        for seg in path_segments:
            lseg = seg.lower()
            if is_sensitive_key(lseg) or re.match(r"^\d+$", seg) or re.match(r"^[0-9a-fA-F-]{8,}$", seg):
                reasons.append(f"sensitive or id-like in path: '{seg}'")
        # Query analysis
        query_params = parse_qs(parsed_url.query)
        for k in query_params:
            if is_sensitive_key(k):
                reasons.append(f"sensitive param in query: '{k}'")
        # POST/PUT/PATCH with body
        has_body = method in ("POST", "PUT", "PATCH") and body and len(body) > 0
        if has_body:
            reasons.append("has body")
        # Sensitive fields in JSON body
        if has_body:
            json_body = safe_json_loads(body)
            if isinstance(json_body, dict):
                for k in json_body:
                    if is_sensitive_key(k):
                        reasons.append(f"sensitive field in body: '{k}'")
        # Sensitive headers
        for hk, hv in headers.items():
            lhk = hk.lower()
            if is_sensitive_key(lhk) or lhk == "authorization":
                if lhk == "authorization":
                    if isinstance(hv, str) and hv.lower().startswith("basic "):
                        reasons.append("authorization: Basic (weak)")
                    elif isinstance(hv, str) and hv.lower().startswith("bearer "):
                        reasons.append("authorization: Bearer")
                    else:
                        reasons.append("authorization header present")
                else:
                    reasons.append(f"sensitive header: '{hk}'")
        # Filter by method if specified
        if filter_post_put and method not in filter_post_put:
            continue
        # Mark as candidate if any reason found
        if reasons:
            candidates.append({
                "url": url,
                "method": method,
                "reason": "; ".join(sorted(set(reasons)))
            })
    return candidates

def print_pentest_candidates(candidates, total, as_table=False):
    """Print pentest candidates and summary. If as_table=True, print as table."""
    if not candidates:
        logging.info("No potentially weak endpoints detected.")
        return
    if as_table:
        try:
            from tabulate import tabulate
            table = [[c['method'], c['url'], c['reason']] for c in candidates]
            print(tabulate(table, headers=["Method", "URL", "Reason"], tablefmt="github"))
        except ImportError:
            logging.warning("tabulate not installed, falling back to plain output.")
            for c in candidates:
                print(f"- {c['method']} {c['url']}  [{c['reason']}]")
    else:
        for c in candidates:
            print(f"- {c['method']} {c['url']}  [{c['reason']}]")
    print(f"\nSummary: {len(candidates)} pentest candidates out of {total} endpoints.\n")

def save_pentest_candidates_csv(candidates, pentest_output):
    """Save pentest candidates to CSV file."""
    import csv
    with open(pentest_output, "w", newline='', encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=["method", "url", "reason"])
        writer.writeheader()
        for c in candidates:
            writer.writerow(c)

def save_pentest_candidates(candidates, pentest_output):
    """Save pentest candidates to file, auto-detect format by extension."""
    try:
        if pentest_output.lower().endswith(".json"):
            with open(pentest_output, "w", encoding="utf-8") as f:
                json.dump(candidates, f, indent=2)
        elif pentest_output.lower().endswith(".csv"):
            save_pentest_candidates_csv(candidates, pentest_output)
        else:
            with open(pentest_output, "w", encoding="utf-8") as f:
                for c in candidates:
                    f.write(f"{c['method']} {c['url']} [{c['reason']}]\n")
        logging.info(f"Pentest candidates saved to: {pentest_output}")
    except Exception as e:
        logging.error(f"Failed to save pentest candidates: {e}")

def save_pentest_candidates_full(entries, pentest_output):
    """Save full pentest candidate requests (not just summary) to file."""
    try:
        if pentest_output.lower().endswith(".json"):
            with open(pentest_output, "w", encoding="utf-8") as f:
                json.dump(entries, f, indent=2)
        elif pentest_output.lower().endswith(".csv"):
            import csv
            # Flatten headers/body for CSV
            fieldnames = ["method", "url", "headers", "body", "status", "response"]
            with open(pentest_output, "w", newline='', encoding="utf-8") as f:
                writer = csv.DictWriter(f, fieldnames=fieldnames)
                writer.writeheader()
                for e in entries:
                    writer.writerow({
                        "method": e.get("method"),
                        "url": e.get("url"),
                        "headers": json.dumps(e.get("headers", {})),
                        "body": e.get("body", ""),
                        "status": e.get("status", ""),
                        "response": e.get("response", "")
                    })
        else:
            with open(pentest_output, "w", encoding="utf-8") as f:
                for e in entries:
                    f.write(f"{e.get('method')} {e.get('url')}\nHeaders: {json.dumps(e.get('headers', {}))}\nBody: {e.get('body','')}\n\n")
        logging.info(f"Pentest full requests saved to: {pentest_output}")
    except Exception as e:
        logging.error(f"Failed to save pentest requests: {e}")

def filter_headers(headers, exclude_headers=None):
    """Remove headers listed in exclude_headers."""
    if not exclude_headers:
        return headers
    return {k: v for k, v in headers.items() if k.lower() not in exclude_headers}

def auto_detect_input_type(filename):
    """Auto-detect input type (xml/har) based on file extension or content."""
    ext = os.path.splitext(filename)[1].lower()
    if ext == ".har":
        return "har"
    elif ext == ".xml":
        return "xml"
    # Try to detect by content
    try:
        with open(filename, "r", encoding="utf-8") as f:
            head = f.read(2048)
            if head.lstrip().startswith("{"):
                return "har" if '"log"' in head and '"entries"' in head else "xml"
            elif "<items>" in head or "<item>" in head:
                return "xml"
    except Exception:
        pass
    return "xml"

def extract_cookies(headers):
    """Extract cookies from headers as dict."""
    cookies = {}
    cookie_header = headers.get("Cookie") or headers.get("cookie")
    if cookie_header:
        for pair in cookie_header.split(";"):
            if "=" in pair:
                k, v = pair.strip().split("=", 1)
                cookies[k.strip()] = v.strip()
    return cookies

def print_stats(items):
    """Print summary statistics of endpoints."""
    from collections import Counter
    method_counter = Counter()
    domain_counter = Counter()
    for entry in items:
        method_counter[entry.get("method", "GET").upper()] += 1
        url = entry.get("url", "")
        domain = urlparse(url).netloc
        domain_counter[domain] += 1
    print(f"Total endpoints: {len(items)}")
    print("By method:", dict(method_counter))
    print("By domain:", dict(domain_counter))

def parse_xml_safely(input_file: str):
    """Parse XML with comprehensive XXE protection (uses defusedxml if available)."""
    try:
        from defusedxml import ElementTree as DefusedET  # type: ignore
        return DefusedET.parse(input_file)
    except Exception:
        # Stronger stdlib fallback with attempts to disable dangerous features
        parser = ET.XMLParser()
        # Try to disable entity expansion / external DTDs where supported
        try:
            parser.entity = {}  # type: ignore
        except Exception:
            pass
        # Where possible, disable external entity resolution via underlying parser (best-effort)
        try:
            if hasattr(parser, 'parser') and hasattr(parser.parser, 'SetParamEntityParsing'):
                parser.parser.SetParamEntityParsing(0)
        except Exception:
            pass
        return ET.parse(input_file, parser=parser)

# --- Streaming parser for very large Burp XMLs to reduce memory usage ---
def parse_burp_xml_streaming(input_file: str):
    """Stream-parse large Burp XML, yield items one by one."""
    context = ET.iterparse(input_file, events=("end",))
    # We don't need the root object permanently; free memory as we go.
    for event, elem in context:
        # handle both namespaced and plain 'item'
        tag = elem.tag
        if tag.endswith('item'):
            try:
                url_element = elem.find("url")
                request_element = elem.find("request")
                method_element = elem.find("method")
                status_element = elem.find("status")
                response_element = elem.find("response")
                if url_element is None or request_element is None:
                    elem.clear()
                    continue
                url = url_element.text
                method = method_element.text if method_element is not None else "GET"
                is_request_base64 = request_element.get("base64", "false")
                raw_request = decode_base64(request_element.text or "", is_request_base64)
                request_lines = raw_request.split('\n')
                first_line = request_lines[0] if request_lines else ""
                req_method, _ = parse_request_line(first_line)
                if req_method:
                    method = req_method
                headers = parse_headers(raw_request)
                body = extract_request_body(raw_request)
                status = status_element.text if status_element is not None else ""
                resp = decode_base64(response_element.text or "", response_element.get("base64", "false")) if response_element is not None else ""
                yield {
                    "url": url,
                    "method": method,
                    "headers": headers,
                    "body": body,
                    "status": status,
                    "response": resp,
                    "_raw_request": raw_request
                }
            except Exception as e:
                logging.debug(f"Error processing streaming item: {e}")
            finally:
                # Clear to free memory
                elem.clear()

# --- Cached hash generator to speed up deduplication (optional) ---
@lru_cache(maxsize=10000)
def generate_request_hash_cached(method, url, headers_tuple, body):
    """Cached wrapper for generate_request_hash."""
    headers = dict(headers_tuple)
    return generate_request_hash(method, url, headers, body)

# --- Optional: process multiple files in parallel (small helper) ---
def parse_multiple_files_parallel(files, max_workers=None):
    """Parse multiple files in parallel, returning dict filename->items."""
    max_workers = max_workers or (os.cpu_count() or 2)
    results = {}
    with ThreadPoolExecutor(max_workers=max_workers) as ex:
        futures = {ex.submit(parse_burp_or_har, f): f for f in files}
        for fut in as_completed(futures):
            fname = futures[fut]
            try:
                results[fname] = fut.result()
            except Exception as e:
                logging.error(f"Error parsing {fname}: {e}")
                results[fname] = []
    return results

def parse_burp_or_har(
    input_file: str,
    input_type: str = None,
    exclude_headers: list = None,
    show_progress: bool = False
) -> list:
    """Parse Burp XML or HAR file and return list of request items."""
    items = []
    tqdm = None
    if show_progress:
        try:
            from tqdm import tqdm as tqdm_mod
            tqdm = tqdm_mod
        except ImportError:
            tqdm = None
    if input_type == "har":
        har_entries = list(parse_har_file(input_file))
        progress_iter = tqdm(har_entries, desc="Parsing HAR") if tqdm else har_entries
        for item in progress_iter:
            if exclude_headers:
                item["headers"] = filter_headers(item["headers"], exclude_headers)
            items.append(item)
    else:
        # For large files, prefer streaming to reduce memory usage
        try:
            size = os.path.getsize(input_file)
        except Exception:
            size = 0
        try:
            if size > 50 * 1024 * 1024:  # >50MB -> streaming
                xml_iter = parse_burp_xml_streaming(input_file)
                progress_iter = tqdm(xml_iter, desc="Streaming XML") if tqdm else xml_iter
                for it in progress_iter:
                    if exclude_headers:
                        it["headers"] = filter_headers(it["headers"], exclude_headers)
                    items.append(it)
            else:
                # Use safe parser (defusedxml preferred)
                tree = parse_xml_safely(input_file)
                root = tree.getroot()
                xml_items = root.findall(".//item")
                progress_iter = tqdm(xml_items, desc="Parsing XML") if tqdm else xml_items
                for item in progress_iter:
                    url_element = item.find("url")
                    method_element = item.find("method")
                    request_element = item.find("request")
                    status_element = item.find("status")
                    response_element = item.find("response")
                    if url_element is None or request_element is None:
                        return
                    url = url_element.text
                    method = method_element.text if method_element is not None else "GET"
                    is_request_base64 = request_element.get("base64", "false")
                    raw_request = decode_base64(request_element.text or "", is_request_base64)
                    request_lines = raw_request.split('\n')
                    first_line = request_lines[0] if request_lines else ""
                    req_method, _ = parse_request_line(first_line)
                    if req_method:
                        method = req_method
                    headers = parse_headers(raw_request)
                    if exclude_headers:
                        headers = filter_headers(headers, exclude_headers)
                    body = extract_request_body(raw_request)
                    status = status_element.text if status_element is not None else ""
                    resp = decode_base64(response_element.text or "", response_element.get("base64", "false")) if response_element is not None else ""
                    items.append({
                        "url": url,
                        "method": method,
                        "headers": headers,
                        "body": body,
                        "status": status,
                        "response": resp,
                        "_raw_request": raw_request
                    })
        except Exception as e:
            logging.error(f"Error parsing XML file: {e}")
            return []
    return items

# --- Restore a small global helper for folder ordering (used by xml_to_postman) ---
def get_sorted_folders(grouped: dict, group_mode: str) -> list:
    """Return sorted folder/group keys for consistent order."""
    if group_mode == "flat":
        return ["All"]
    keys = sorted(grouped.keys())
    # keep 'root' first if present
    if "root" in keys:
        keys.remove("root")
        return ["root"] + keys
    return keys

# --- Restore a global build_postman_item to avoid local/unbound issues and keep body handling consistent ---
def build_postman_item(
    entry: dict,
    global_vars: dict,
    keep_path_id: bool = False
) -> dict:
    """Build a Postman item from entry and update global_vars."""
    url = entry.get("url", "")
    method = entry.get("method", "GET")
    headers = entry.get("headers", {}) or {}
    # prefer explicit body field; fallback to raw_request if present (preserve multipart etc)
    body = entry.get("body", "") if entry.get("body", "") is not None else ""
    if (not body) and entry.get("_raw_request"):
        # extract without stripping to preserve payload exactness
        body = extract_request_body(entry.get("_raw_request"), preserve_whitespace=True) or body
    status = entry.get("status", "")
    resp = entry.get("response", "")
    auth_vars = detect_auth_headers(headers)
    cookies = extract_cookies(headers)
    if cookies:
        global_vars.update({f"cookie_{k}": v for k, v in cookies.items()})
    global_vars.update(auth_vars)
    parsed_url = urlparse(url)
    if keep_path_id:
        path = parsed_url.path
        path_list = path.strip('/').split('/') if path else []
    else:
        path, _ = extract_variables_from_path(parsed_url.path)
        path_list = path.strip('/').split('/') if path else []
    protocol = parsed_url.scheme
    host = parsed_url.netloc.split('.') if parsed_url.netloc else []
    query = parsed_url.query
    pm_item = {
        "name": f"{method} {parsed_url.path}",
        "request": {
            "method": method,
            "header": [{"key": k, "value": v} for k, v in headers.items()],
            "url": {
                "raw": url,
                "protocol": protocol,
                "host": host,
                "path": path_list,
            }
        },
        "description": f"Auto-generated endpoint for `{method} {parsed_url.path}`.\n\nStatus: {status}"
    }
    if query:
        query_params = parse_qs(query)
        pm_item["request"]["url"]["query"] = [
            {"key": k, "value": v[0]} for k, v in query_params.items()
        ]
    # Always set body object for non-GET/HEAD methods; use empty string when body missing
    if method.upper() not in ["GET", "HEAD"]:
        content_type = headers.get("Content-Type", "") or headers.get("content-type", "") or ""
        if "application/json" in content_type.lower():
            if body:
                try:
                    json_body = json.loads(body)
                    pm_item["request"]["body"] = {
                        "mode": "raw",
                        "raw": json.dumps(json_body, indent=2),
                        "options": {"raw": {"language": "json"}}
                    }
                except Exception:
                    pm_item["request"]["body"] = {"mode": "raw", "raw": body}
            else:
                pm_item["request"]["body"] = {"mode": "raw", "raw": ""}
        elif "application/x-www-form-urlencoded" in content_type.lower():
            form_data = []
            if body:
                for param in body.split('&'):
                    if '=' in param:
                        key, value = param.split('=', 1)
                        form_data.append({"key": key, "value": value})
            pm_item["request"]["body"] = {"mode": "urlencoded", "urlencoded": form_data}
        else:
            pm_item["request"]["body"] = {"mode": "raw", "raw": body if body is not None else ""}
    if resp:
        pm_item["response"] = [{
            "name": f"Response {status}",
            "originalRequest": pm_item["request"],
            "status": status,
            "code": int(status) if status.isdigit() else 0,
            "_postman_previewlanguage": "json",
            "header": [],
            "body": resp
        }]
    return pm_item

def xml_to_postman(
    xml_file: str,
    output_file: str = None,
    deduplicate: bool = True,
    group_mode: str = "path_prefix",
    update: bool = False,
    input_type: str = None,
    pentest: bool = False,
    pentest_output: str = None,
    pentest_table: bool = False,
    exclude_headers: list = None,
    output_folder: str = None,
    collection_title: str = None,
    show_stats: bool = False,
    show_progress: bool = False
) -> str:
    """Convert Burp Suite XML or HAR to Postman Collection with grouping and enhanced features."""
    items = parse_burp_or_har(xml_file, input_type, exclude_headers, show_progress)
    if show_stats:
        print_stats(items)
    # --- Pentest folder logic ---
    pentest_candidates = []
    pentest_candidate_keys = set()
    pentest_entries = []
    if pentest:
        pentest_candidates = detect_pentest_candidates(items)
        print("\n[Pentest Candidates]")
        print_pentest_candidates(pentest_candidates, len(items), as_table=pentest_table)
        # Buat set key (method, url) untuk lookup cepat
        pentest_candidate_keys = set((c["method"].upper(), c["url"]) for c in pentest_candidates)
        # Kumpulkan full entry untuk pentest_output
        if pentest_output:
            pentest_entries = [entry for entry in items if (entry["method"].upper(), entry["url"]) in pentest_candidate_keys]
            save_pentest_candidates_full(pentest_entries, pentest_output)
    # --- Grouping logic ---
    grouped = group_by_path(items, mode=group_mode)
    postman_collection = {
        "info": {
            "name": collection_title or f"Converted from {os.path.basename(xml_file)}",
            "description": "Converted from Burp Suite XML export",
            "schema": "https://schema.getpostman.com/json/collection/v2.1.0/collection.json"
        },
        "item": []
    }
    global_vars = {}
    duplicate_count = 0
    seen_hashes = set()

    if pentest:
        # Folder: Pentest (dedup only here)
        pentest_folder = {"name": "Pentest", "item": []}
        pentest_hashes = set()
        for entry in items:
            key = (entry["method"].upper(), entry["url"])
            if key in pentest_candidate_keys:
                pm_item = build_postman_item(entry, global_vars, keep_path_id=True)
                req_hash = generate_request_hash(
                    entry["method"], entry["url"], entry["headers"], entry.get("body", "")
                )
                if req_hash in pentest_hashes:
                    continue
                pentest_hashes.add(req_hash)
                pentest_folder["item"].append(pm_item)
        pentest_folder["item"].sort(key=lambda x: (x["request"]["method"], "/".join(x["request"]["url"].get("path", []))))
        postman_collection["item"].append(pentest_folder)

    # Folder: API/grouped (semua endpoint, tidak dedup)
    sorted_folders = get_sorted_folders(grouped, group_mode)
    if group_mode == "flat":
        api_folder = {"name": "API", "item": []}
        for entry in grouped.get("All", []) if "All" in grouped else [i for g in grouped.values() for i in g]:
            pm_item = build_postman_item(entry, global_vars, keep_path_id=True)
            api_folder["item"].append(pm_item)
        api_folder["item"].sort(key=lambda x: (x["request"]["method"], "/".join(x["request"]["url"].get("path", []))))
        postman_collection["item"].append(api_folder)
    else:
        for folder in sorted_folders:
            group_items = grouped[folder]
            folder_item = {"name": folder, "item": []}
            for entry in group_items:
                pm_item = build_postman_item(entry, global_vars, keep_path_id=True)
                folder_item["item"].append(pm_item)
            folder_item["item"].sort(key=lambda x: (x["request"]["method"], "/".join(x["request"]["url"].get("path", []))))
            postman_collection["item"].append(folder_item)
    if global_vars:
        postman_collection["variable"] = [{"key": k, "value": v} for k, v in global_vars.items()]
    if output_file is None:
        base_name = os.path.splitext(os.path.basename(xml_file))[0]
        output_file = f"{base_name}_postman_collection.json"
    # If output_folder provided, get safe path
    if output_folder:
        try:
            output_file = safe_join_path(output_folder, output_file)
        except Exception as e:
            logging.error(f"Invalid output folder: {e}")
            raise
    # If update requested and existing file exists, merge items then write
    if update and os.path.exists(output_file):
        postman_collection = update_postman_collection(
            output_file,
            [i for f in postman_collection["item"] for i in (f["item"] if "item" in f else [f])]
        )
    # Write atomically (use the atomic_write helper)
    try:
        json_text = json.dumps(postman_collection, indent=2)
        atomic_write(output_file, json_text)
    except Exception as e:
        logging.error(f"Failed to write output file: {e}")
        raise
    print(f"Successfully converted to Postman collection: {output_file}")
    return output_file

def xml_to_openapi(
    xml_file: str,
    output_file: str = None,
    deduplicate: bool = True,
    group_mode: str = "path_prefix",
    input_type: str = "xml",
    pentest: bool = False,
    pentest_table: bool = False
):
    """Convert Burp Suite XML or HAR to OpenAPI Specification with tags and enhanced docs."""
    items = []
    if input_type == "har":
        for item in parse_har_file(xml_file):
            items.append(item)
    else:
        tree = parse_xml_safely(xml_file)
        root = tree.getroot()
        xml_items = root.findall(".//item")
        for item in xml_items:
            url_element = item.find("url")
            method_element = item.find("method")
            request_element = item.find("request")
            status_element = item.find("status")
            response_element = item.find("response")
            if url_element is None or request_element is None:
                continue
            url = url_element.text
            method = method_element.text if method_element is not None else "GET"
            is_request_base64 = request_element.get("base64", "false")
            raw_request = decode_base64(request_element.text or "", is_request_base64)
            request_lines = raw_request.split('\n')
            first_line = request_lines[0] if request_lines else ""
            req_method, req_path = parse_request_line(first_line)
            if req_method:
                method = req_method
            headers = parse_headers(raw_request)
            body = extract_request_body(raw_request)
            status = status_element.text if status_element is not None else ""
            resp = decode_base64(response_element.text or "", response_element.get("base64", "false")) if response_element is not None else ""
            items.append({
                "url": url,
                "method": method,
                "headers": headers,
                "body": body,
                "status": status,
                "response": resp
            })
    # Pentest detection
    if pentest:
        candidates = detect_pentest_candidates(items)
        print("\n[Pentest Candidates]")
        print_pentest_candidates(candidates, len(items), as_table=pentest_table)
    grouped = group_by_path(items, mode=group_mode)
    openapi_spec = {
        "openapi": "3.0.0",
        "info": {
            "title": f"API from {os.path.basename(xml_file)}",
            "description": "Converted from Burp Suite XML export",
            "version": "1.0.0"
        },
        "servers": [],
        "paths": {},
        "tags": []
    }
    servers = set()
    tag_set = set()
    for folder, group_items in grouped.items():
        tag_set.add(folder)
        for entry in group_items:
            url = entry["url"]
            method = entry["method"].lower()
            headers = entry.get("headers", {}) or {}
            body = entry.get("body", "")
            status = entry.get("status", "")
            resp = entry.get("response", "")
            parsed_url = urlparse(url)
            server_url = f"{parsed_url.scheme}://{parsed_url.netloc}"
            if server_url not in servers:
                servers.add(server_url)
                openapi_spec["servers"].append({"url": server_url})
            path, path_vars = extract_variables_from_path(parsed_url.path)
            # Path variable OpenAPI: replace :var with {var} but avoid double-leading slashes
            openapi_path = re.sub(r":(\w+)", r"{\1}", path)
            if not openapi_path.startswith("/"):
                openapi_path = "/" + openapi_path
            if openapi_path not in openapi_spec["paths"]:
                openapi_spec["paths"][openapi_path] = {}
            parameters = []
            for var in path_vars:
                parameters.append({
                    "name": var,
                    "in": "path",
                    "required": True,
                    "schema": {"type": "string"}
                })
            if parsed_url.query:
                query_params = parse_qs(parsed_url.query)
                for param_name, param_values in query_params.items():
                    parameters.append({
                        "name": param_name,
                        "in": "query",
                        "required": False,
                        "schema": {"type": "string"},
                        "example": param_values[0] if param_values else ""
                    })
            content_type = headers.get("Content-Type", headers.get("content-type", "")) or ""
            request_body = None
            if method not in ["get", "head"] and body:
                if "application/json" in content_type:
                    try:
                        json_body = json.loads(body)
                        request_body = {
                            "content": {
                                "application/json": {
                                    "schema": {"type": "object"},
                                    "example": json_body
                                }
                            }
                        }
                    except Exception:
                        request_body = {
                            "content": {
                                "text/plain": {
                                    "schema": {"type": "string"},
                                    "example": body
                                }
                            }
                        }
                else:
                    request_body = {
                        "content": {
                            content_type or "text/plain": {
                                "schema": {"type": "string"},
                                "example": body
                            }
                        }
                    }
            # Multiple response example support
            responses = {}
            if resp:
                responses[status or "default"] = {
                    "description": f"Status {status} response",
                    "content": {
                        content_type or "application/json": {
                            "schema": {"type": "string"},
                            "example": resp
                        }
                    }
                }
            else:
                responses["default"] = {"description": "Default response"}
            path_item = {
                "summary": f"{method.upper()} {openapi_path}",
                "description": f"Auto-generated endpoint for `{method.upper()} {openapi_path}`.",
                "tags": [folder],
                "parameters": parameters,
                "responses": responses
            }
            if request_body:
                path_item["requestBody"] = request_body
            openapi_spec["paths"][openapi_path][method] = path_item

    # Finalize tags and write output file atomically
    openapi_spec["tags"] = [{"name": t} for t in tag_set]
    if output_file is None:
        base_name = os.path.splitext(os.path.basename(xml_file))[0]
        output_file = f"{base_name}_openapi.json"
    try:
        json_text = json.dumps(openapi_spec, indent=2)
        atomic_write(output_file, json_text)
    except Exception as e:
        logging.error(f"Failed to write OpenAPI file: {e}")
        raise
    print(f"Successfully converted to OpenAPI specification: {output_file}")
    return output_file

def atomic_write(filename, data):
    """Write data to a file atomically to avoid partial writes."""
    import tempfile
    import shutil
    dir_name = os.path.dirname(os.path.abspath(filename)) or "."
    with tempfile.NamedTemporaryFile("w", dir=dir_name, delete=False, encoding="utf-8") as tf:
        tf.write(data)
        tempname = tf.name
    try:
        shutil.move(tempname, filename)
    except Exception:
        os.remove(tempname)
        raise


def initialize_environment():
    """Check for required libraries and validate the environment."""
    missing_libraries = []
    try:
        import tabulate  # Check if tabulate is installed
    except ImportError:
        missing_libraries.append("tabulate")

    if missing_libraries:
        print("Warning: The following libraries are missing:")
        for lib in missing_libraries:
            print(f"  - {lib}")
        print("You can install them using:")
        print(f"  pip install {' '.join(missing_libraries)}")
    
    # Check Python version
    import sys
    if sys.version_info < (3, 6):
        print("Error: Python 3.6 or higher is required to run this script.")
        sys.exit(1)

    # Check if required directories or files exist (if applicable)
    print("Environment initialized successfully.")

def main_entry():
    """Entry point for CLI and import."""
    parser = argparse.ArgumentParser(description="Convert Burp Suite XML/HAR to Postman, OpenAPI, or Insomnia")
    parser.add_argument("--check-env", action="store_true", help="Check environment for required libraries and Python version")
    parser.add_argument("input_file", nargs="*", help="Input Burp Suite XML/HAR file(s) (wildcard supported)")
    parser.add_argument("--format", choices=["postman", "openapi", "insomnia"], default="postman", help="Output format")
    parser.add_argument("--output", help="Output file name (default: auto-generated based on input file)")
    parser.add_argument("--output-folder", help="Output folder for result files")
    parser.add_argument("--no-deduplicate", dest="deduplicate", action="store_false", help="Disable deduplication")
    parser.add_argument("--group", choices=["domain", "path_prefix", "flat"], default="path_prefix", help="Grouping mode")
    parser.add_argument("--input-type", choices=["xml", "har"], help="Input file type (auto-detect if not set)")
    parser.add_argument("--update", action="store_true", help="Update existing collection instead of overwrite")
    parser.add_argument("--pentest", action="store_true", help="Detect potentially weak endpoints for pentest")
    parser.add_argument("--pentest-output", help="Save pentest candidates to file (JSON, CSV, or TXT)")
    parser.add_argument("--pentest-table", action="store_true", help="Show pentest candidates as table (requires tabulate)")
    parser.add_argument("--exclude-header", action="append", help="Header(s) to exclude from export (repeatable)", default=[])
    parser.add_argument("--collection-title", help="Custom title/name for the collection")
    parser.add_argument("--show-stats", action="store_true", help="Show summary statistics of endpoints")
    parser.add_argument("--show-progress", action="store_true", help="Show progress bar (requires tqdm)")
    parser.add_argument("--verbose", action="store_true", help="Enable verbose/debug logging")
    parser.set_defaults(deduplicate=True)
    args = parser.parse_args()

    if args.check_env:
        initialize_environment()
        return  # Exit after environment check if the flag is used

    if not args.input_file:
        parser.error("the following arguments are required: input_file")

    setup_logging(args.verbose)
    files = []
    for pattern in args.input_file:
        files.extend(glob.glob(pattern))
    for f in files:
        if not os.path.isfile(f):
            logging.error(f"Input file not found: {f}")
            continue
        if args.format == "postman":
            xml_to_postman(
                f, args.output, args.deduplicate, group_mode=args.group,
                update=args.update, input_type=args.input_type,
                pentest=args.pentest, pentest_output=args.pentest_output,
                pentest_table=args.pentest_table,
                exclude_headers=[h.lower() for h in args.exclude_header] if args.exclude_header else None,
                output_folder=args.output_folder,
                collection_title=args.collection_title,
                show_stats=args.show_stats,
                show_progress=args.show_progress
            )
        elif args.format == "openapi":
            xml_to_openapi(
                f, args.output, args.deduplicate, group_mode=args.group,
                input_type=args.input_type or auto_detect_input_type(f), pentest=args.pentest,
                pentest_table=args.pentest_table
            )
        elif args.format == "insomnia":
            pm_file = xml_to_postman(
                f, None, args.deduplicate, group_mode=args.group,
                input_type=args.input_type or auto_detect_input_type(f), pentest=args.pentest,
                pentest_table=args.pentest_table,
                exclude_headers=[h.lower() for h in args.exclude_header] if args.exclude_header else None,
                output_folder=args.output_folder,
                collection_title=args.collection_title,
                show_stats=args.show_stats,
                show_progress=args.show_progress
            )
            with open(pm_file, "r", encoding="utf-8") as pf:
                pm = json.load(pf)
            items = []
            for folder in pm.get("item", []):
                if "item" in folder:
                    items.extend(folder["item"])
                else:
                    items.append(folder)
            export_insomnia(items, args.output or f"{os.path.splitext(os.path.basename(f))[0]}_insomnia.json")

def main():
    main_entry()

if __name__ == "__main__":
    main()