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

def decode_base64(data, is_base64):
    """Decode base64 data if necessary"""
    if is_base64 == "true":
        try:
            return base64.b64decode(data).decode('utf-8')
        except Exception as e:
            print(f"Warning: Could not decode base64 data: {e}")
            return data
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

def extract_request_body(raw_request):
    """Extract request body from raw HTTP request"""
    parts = raw_request.split('\n\n', 1)
    if len(parts) > 1:
        return parts[1].strip()
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
    return "/".join(new_segments), variables

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
        yield {
            "url": url,
            "method": method,
            "headers": headers,
            "body": body,
            "status": status,
            "response": resp_body,
            "response_headers": resp_headers
        }

def update_postman_collection(existing_file, new_items):
    """Update existing Postman collection with new items (avoid duplicates)."""
    with open(existing_file, "r", encoding="utf-8") as f:
        collection = json.load(f)
    existing_hashes = set()
    for item in collection.get("item", []):
        if "request" in item:
            req = item["request"]
            url = req["url"]["raw"] if isinstance(req["url"], dict) else req["url"]
            method = req["method"]
            headers = {h["key"]: h["value"] for h in req.get("header", [])}
            body = req.get("body", {}).get("raw", "")
            h = generate_request_hash(method, url, headers, body)
            existing_hashes.add(h)
    for item in new_items:
        h = generate_request_hash(item["request"]["method"], item["request"]["url"]["raw"], {h["key"]: h["value"] for h in item["request"].get("header", [])}, item["request"].get("body", {}).get("raw", ""))
        if h not in existing_hashes:
            collection["item"].append(item)
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

def xml_to_postman(xml_file, output_file=None, deduplicate=True, group_mode="path_prefix", update=False, input_type="xml"):
    """Convert Burp Suite XML or HAR to Postman Collection with grouping and enhanced features."""
    items = []
    if input_type == "har":
        for item in parse_har_file(xml_file):
            items.append(item)
    else:
        try:
            tree = ET.parse(xml_file)
            root = tree.getroot()
        except Exception as e:
            print(f"Error parsing XML file: {e}")
            return
        for item in root.findall(".//item"):
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
            raw_request = decode_base64(request_element.text, is_request_base64)
            request_lines = raw_request.split('\n')
            first_line = request_lines[0] if request_lines else ""
            req_method, req_path = parse_request_line(first_line)
            if req_method:
                method = req_method
            headers = parse_headers(raw_request)
            body = extract_request_body(raw_request)
            status = status_element.text if status_element is not None else ""
            resp = decode_base64(response_element.text, response_element.get("base64", "false")) if response_element is not None else ""
            items.append({
                "url": url,
                "method": method,
                "headers": headers,
                "body": body,
                "status": status,
                "response": resp
            })

    # Grouping
    grouped = group_by_path(items, mode=group_mode)
    postman_collection = {
        "info": {
            "name": f"Converted from {os.path.basename(xml_file)}",
            "description": "Converted from Burp Suite XML export",
            "schema": "https://schema.getpostman.com/json/collection/v2.1.0/collection.json"
        },
        "item": []
    }
    global_vars = {}
    request_hashes = set()
    duplicate_count = 0

    # Sort folder/group keys for consistent order
    sorted_folders = sorted(grouped.keys()) if group_mode != "flat" else ["All"]

    # Folder structure
    if group_mode == "flat":
        flat_items = []
        for entry in grouped.get("All", []) if "All" in grouped else [i for g in grouped.values() for i in g]:
            url = entry["url"]
            method = entry["method"]
            headers = entry["headers"]
            body = entry["body"]
            status = entry.get("status", "")
            resp = entry.get("response", "")
            auth_vars = detect_auth_headers(headers)
            global_vars.update(auth_vars)
            parsed_url = urlparse(url)
            path, path_vars = extract_variables_from_path(parsed_url.path)
            protocol = parsed_url.scheme
            host = parsed_url.netloc.split('.')
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
                        "path": path.strip('/').split('/') if path else [],
                    }
                },
                "description": f"Auto-generated endpoint for `{method} {parsed_url.path}`.\n\nStatus: {status}"
            }
            if query:
                query_params = parse_qs(query)
                pm_item["request"]["url"]["query"] = [
                    {"key": k, "value": v[0]} for k, v in query_params.items()
                ]
            if body and method not in ["GET", "HEAD"]:
                content_type = headers.get("Content-Type", "")
                if "application/json" in content_type:
                    try:
                        json_body = json.loads(body)
                        pm_item["request"]["body"] = {
                            "mode": "raw",
                            "raw": json.dumps(json_body, indent=2),
                            "options": {"raw": {"language": "json"}}
                        }
                    except:
                        pm_item["request"]["body"] = {"mode": "raw", "raw": body}
                elif "application/x-www-form-urlencoded" in content_type:
                    form_data = []
                    for param in body.split('&'):
                        if '=' in param:
                            key, value = param.split('=', 1)
                            form_data.append({"key": key, "value": value})
                    pm_item["request"]["body"] = {"mode": "urlencoded", "urlencoded": form_data}
                else:
                    pm_item["request"]["body"] = {"mode": "raw", "raw": body}
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
            req_hash = generate_request_hash(method, url, headers, body)
            if deduplicate:
                if req_hash in request_hashes:
                    duplicate_count += 1
                    continue
                request_hashes.add(req_hash)
            flat_items.append(pm_item)
        # Sort flat_items by method then path
        flat_items.sort(key=lambda x: (x["request"]["method"], "/".join(x["request"]["url"].get("path", []))))
        postman_collection["item"].extend(flat_items)
    else:
        for folder in sorted_folders:
            group_items = grouped[folder]
            folder_item = {"name": folder, "item": []}
            pm_items = []
            for entry in group_items:
                url = entry["url"]
                method = entry["method"]
                headers = entry["headers"]
                body = entry["body"]
                status = entry.get("status", "")
                resp = entry.get("response", "")
                auth_vars = detect_auth_headers(headers)
                global_vars.update(auth_vars)
                parsed_url = urlparse(url)
                path, path_vars = extract_variables_from_path(parsed_url.path)
                protocol = parsed_url.scheme
                host = parsed_url.netloc.split('.')
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
                            "path": path.strip('/').split('/') if path else [],
                        }
                    },
                    "description": f"Auto-generated endpoint for `{method} {parsed_url.path}`.\n\nStatus: {status}"
                }
                if query:
                    query_params = parse_qs(query)
                    pm_item["request"]["url"]["query"] = [
                        {"key": k, "value": v[0]} for k, v in query_params.items()
                    ]
                if body and method not in ["GET", "HEAD"]:
                    content_type = headers.get("Content-Type", "")
                    if "application/json" in content_type:
                        try:
                            json_body = json.loads(body)
                            pm_item["request"]["body"] = {
                                "mode": "raw",
                                "raw": json.dumps(json_body, indent=2),
                                "options": {"raw": {"language": "json"}}
                            }
                        except:
                            pm_item["request"]["body"] = {"mode": "raw", "raw": body}
                    elif "application/x-www-form-urlencoded" in content_type:
                        form_data = []
                        for param in body.split('&'):
                            if '=' in param:
                                key, value = param.split('=', 1)
                                form_data.append({"key": key, "value": value})
                        pm_item["request"]["body"] = {"mode": "urlencoded", "urlencoded": form_data}
                    else:
                        pm_item["request"]["body"] = {"mode": "raw", "raw": body}
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
                req_hash = generate_request_hash(method, url, headers, body)
                if deduplicate:
                    if req_hash in request_hashes:
                        duplicate_count += 1
                        continue
                    request_hashes.add(req_hash)
                pm_items.append(pm_item)
            # Sort pm_items by method then path
            pm_items.sort(key=lambda x: (x["request"]["method"], "/".join(x["request"]["url"].get("path", []))))
            if pm_items:
                folder_item["item"] = pm_items
                postman_collection["item"].append(folder_item)

    # Add global variables
    if global_vars:
        postman_collection["variable"] = [{"key": k, "value": v} for k, v in global_vars.items()]
    # Output/update
    if output_file is None:
        base_name = os.path.splitext(os.path.basename(xml_file))[0]
        output_file = f"{base_name}_postman_collection.json"
    if update and os.path.exists(output_file):
        postman_collection = update_postman_collection(output_file, [i for f in postman_collection["item"] for i in (f["item"] if "item" in f else [f])])
    with open(output_file, 'w', encoding='utf-8') as f:
        json.dump(postman_collection, f, indent=2)
    if deduplicate and duplicate_count > 0:
        print(f"Removed {duplicate_count} duplicate request(s)")
    print(f"Successfully converted to Postman collection: {output_file}")
    return output_file

def xml_to_openapi(xml_file, output_file=None, deduplicate=True, group_mode="path_prefix", input_type="xml"):
    """Convert Burp Suite XML or HAR to OpenAPI Specification with tags and enhanced docs."""
    # ...existing code...
    # Replace the main loop with grouping and tag support
    items = []
    if input_type == "har":
        for item in parse_har_file(xml_file):
            items.append(item)
    else:
        try:
            tree = ET.parse(xml_file)
            root = tree.getroot()
        except Exception as e:
            print(f"Error parsing XML file: {e}")
            return
        for item in root.findall(".//item"):
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
            raw_request = decode_base64(request_element.text, is_request_base64)
            request_lines = raw_request.split('\n')
            first_line = request_lines[0] if request_lines else ""
            req_method, req_path = parse_request_line(first_line)
            if req_method:
                method = req_method
            headers = parse_headers(raw_request)
            body = extract_request_body(raw_request)
            status = status_element.text if status_element is not None else ""
            resp = decode_base64(response_element.text, response_element.get("base64", "false")) if response_element is not None else ""
            items.append({
                "url": url,
                "method": method,
                "headers": headers,
                "body": body,
                "status": status,
                "response": resp
            })
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
            headers = entry["headers"]
            body = entry["body"]
            status = entry.get("status", "")
            resp = entry.get("response", "")
            parsed_url = urlparse(url)
            server_url = f"{parsed_url.scheme}://{parsed_url.netloc}"
            if server_url not in servers:
                servers.add(server_url)
                openapi_spec["servers"].append({"url": server_url})
            path, path_vars = extract_variables_from_path(parsed_url.path)
            # Path variable OpenAPI
            openapi_path = "/" + re.sub(r":(\w+)", r"{\1}", path)
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
            content_type = headers.get("Content-Type", "")
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
                    except:
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
    openapi_spec["tags"] = [{"name": t} for t in tag_set]
    if output_file is None:
        base_name = os.path.splitext(os.path.basename(xml_file))[0]
        output_file = f"{base_name}_openapi.json"
    with open(output_file, 'w', encoding='utf-8') as f:
        json.dump(openapi_spec, f, indent=2)
    print(f"Successfully converted to OpenAPI specification: {output_file}")
    return output_file

def main():
    parser = argparse.ArgumentParser(description="Convert Burp Suite XML/HAR to Postman, OpenAPI, or Insomnia")
    parser.add_argument("input_file", nargs="+", help="Input Burp Suite XML/HAR file(s) (wildcard supported)")
    parser.add_argument("--format", choices=["postman", "openapi", "insomnia"], default="postman", help="Output format")
    parser.add_argument("--output", help="Output file name (default: auto-generated based on input file)")
    parser.add_argument("--no-deduplicate", dest="deduplicate", action="store_false", help="Disable deduplication")
    parser.add_argument("--group", choices=["domain", "path_prefix", "flat"], default="path_prefix", help="Grouping mode")
    parser.add_argument("--input-type", choices=["xml", "har"], default="xml", help="Input file type")
    parser.add_argument("--update", action="store_true", help="Update existing collection instead of overwrite")
    parser.set_defaults(deduplicate=True)
    args = parser.parse_args()
    files = []
    for pattern in args.input_file:
        files.extend(glob.glob(pattern))
    for f in files:
        if args.format == "postman":
            xml_to_postman(f, args.output, args.deduplicate, group_mode=args.group, update=args.update, input_type=args.input_type)
        elif args.format == "openapi":
            xml_to_openapi(f, args.output, args.deduplicate, group_mode=args.group, input_type=args.input_type)
        elif args.format == "insomnia":
            # Convert to Postman first, then to Insomnia
            pm_file = xml_to_postman(f, None, args.deduplicate, group_mode=args.group, input_type=args.input_type)
            with open(pm_file, "r", encoding="utf-8") as pf:
                pm = json.load(pf)
            items = []
            for folder in pm.get("item", []):
                if "item" in folder:
                    items.extend(folder["item"])
                else:
                    items.append(folder)
            export_insomnia(items, args.output or f"{os.path.splitext(os.path.basename(f))[0]}_insomnia.json")

if __name__ == "__main__":
    main()

# -------------------------------
# Contoh Penggunaan:
#
# 1. Konversi satu file XML Burp ke Postman, otomatis folder per prefix path:
#    python burpapi.py hasil.xml --format postman
#
# 2. Konversi beberapa file sekaligus (wildcard), hasilkan OpenAPI, group per domain:
#    python burpapi.py hasil*.xml --format openapi --group domain
#
# 3. Import file HAR dan ekspor ke Insomnia:
#    python burpapi.py traffic.har --input-type har --format insomnia
#
# 4. Update koleksi Postman yang sudah ada:
#    python burpapi.py hasil.xml --format postman --update --output koleksi.json
#
# 5. Group flat (semua endpoint dalam satu folder):
#    python burpapi.py hasil.xml --group flat
#
# 6. Konversi dengan variabel header/token otomatis:
#    python burpapi.py hasil.xml --format postman
#
# Lihat --help untuk opsi lengkap:
#    python burpapi.py --help
# -------------------------------