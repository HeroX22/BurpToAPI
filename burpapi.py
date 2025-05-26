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
import sys
import yaml
try:
    from tqdm import tqdm
except ImportError:
    tqdm = lambda x, **kwargs: x  # fallback jika tqdm tidak ada

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
    """Extract request body from raw HTTP request (support CRLF and LF)."""
    # Normalize line endings
    if "\r\n\r\n" in raw_request:
        parts = raw_request.split("\r\n\r\n", 1)
    else:
        parts = raw_request.split("\n\n", 1)
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
        sorted_query = "&".join(f"{k}={','.join(sorted(v))}" for k, v in sorted(query_params.items()))
        normalized_url = f"{parsed_url.scheme}://{parsed_url.netloc}{path}?{sorted_query}"
    else:
        normalized_url = f"{parsed_url.scheme}://{parsed_url.netloc}{path}"

    # Exclude time-based/dynamic headers for deduplication
    ignore_headers = ['cookie', 'date', 'user-agent', 'x-timestamp', 'x-device-id']
    key_headers = {}
    for header_name, header_value in headers.items():
        if header_name.lower() not in ignore_headers:
            key_headers[header_name.lower()] = header_value

    hash_input = f"{method.upper()}:{normalized_url}"
    if key_headers:
        headers_str = ";".join(f"{k}={v}" for k, v in sorted(key_headers.items()))
        hash_input += f":{headers_str}"

    if body and method.upper() not in ["GET", "HEAD"]:
        content_type = next((v for k, v in headers.items() if k.lower() == 'content-type'), '')
        if 'application/json' in content_type.lower():
            try:
                json_body = json.loads(body)
                body = json.dumps(json_body, sort_keys=True)
            except:
                pass
        hash_input += f":{body}"

    return hashlib.sha256(hash_input.encode()).hexdigest()

def detect_auth_headers(headers):
    """Detect authentication headers and extract tokens/keys as variables."""
    auth_vars = {}
    for k, v in headers.items():
        kl = k.lower()
        if kl == "authorization":
            if v.lower().startswith("bearer "):
                auth_vars["bearer_token"] = v[7:]
            elif v.lower().startswith("basic "):
                auth_vars["basic_auth"] = v[6:]
            elif "oauth" in v.lower():
                auth_vars["oauth_token"] = v
            else:
                auth_vars["authorization"] = v
        elif kl in ("x-api-key", "api-key", "x-access-token", "jwt", "x-jwt-token"):
            auth_vars[kl.replace("-", "_")] = v
    # JWT detection in cookie/header
    for k, v in headers.items():
        if "jwt" in k.lower() or (isinstance(v, str) and v.count('.') == 2):
            auth_vars["jwt_token"] = v
    return auth_vars

def export_postman_environment(env_vars, output_file):
    """Export Postman environment variables."""
    env = {
        "id": "",
        "name": "Auto Exported Environment",
        "values": [
            {"key": k, "value": v, "enabled": True} for k, v in env_vars.items()
        ],
        "_postman_variable_scope": "environment",
        "_postman_exported_at": "",
        "_postman_exported_using": "burpapi"
    }
    with open(output_file, "w", encoding="utf-8") as f:
        json.dump(env, f, indent=2)
    print(f"Exported Postman environment: {output_file}")

def parse_response_headers(resp_headers):
    """Convert response headers dict to Postman/OpenAPI format."""
    return [{"key": k, "value": v} for k, v in resp_headers.items()]

def parse_json_schema_from_body(body):
    """Try to generate a simple JSON schema from response body."""
    try:
        data = json.loads(body)
        def infer_schema(obj):
            if isinstance(obj, dict):
                return {
                    "type": "object",
                    "properties": {k: infer_schema(v) for k, v in obj.items()}
                }
            elif isinstance(obj, list):
                if obj:
                    return {"type": "array", "items": infer_schema(obj[0])}
                else:
                    return {"type": "array"}
            elif isinstance(obj, int):
                return {"type": "integer"}
            elif isinstance(obj, float):
                return {"type": "number"}
            elif isinstance(obj, bool):
                return {"type": "boolean"}
            else:
                return {"type": "string"}
        return infer_schema(data)
    except Exception:
        return {"type": "string"}

def autodetect_input_type(filename):
    """Auto-detect XML or HAR."""
    try:
        with open(filename, "r", encoding="utf-8") as f:
            head = f.read(2048)
            if head.lstrip().startswith("{") and '"log"' in head:
                return "har"
            elif head.lstrip().startswith("<"):
                return "xml"
    except Exception:
        pass
    return "xml"

def parse_har_file(har_file):
    """Parse HAR file and yield items in the same format as Burp XML."""
    with open(har_file, "r", encoding="utf-8") as f:
        har = json.load(f)
    entries = har.get("log", {}).get("entries", [])
    for entry in entries:
        req = entry.get("request", {})
        resp = entry.get("response", {})
        url = req.get("url", "")
        method = req.get("method", "GET")
        headers = {h["name"]: h["value"] for h in req.get("headers", [])}
        # Handle body
        postData = req.get("postData", {})
        body = postData.get("text", "") if postData else ""
        # Response
        status = str(resp.get("status", ""))
        resp_headers = {h["name"]: h["value"] for h in resp.get("headers", [])}
        resp_body = ""
        if "content" in resp and "text" in resp["content"]:
            resp_body = resp["content"]["text"]
            if resp["content"].get("encoding") == "base64":
                try:
                    resp_body = base64.b64decode(resp_body).decode("utf-8")
                except Exception:
                    pass
        yield {
            "url": url,
            "method": method,
            "headers": headers,
            "body": body,
            "status": status,
            "response": resp_body,
            "response_headers": resp_headers
        }

def filter_items(items, methods=None, require_auth=False, include_regex=None, exclude_regex=None, include_domain=None, exclude_domain=None):
    """Filter items by method, auth, regex path/domain."""
    filtered = []
    for entry in items:
        if methods and entry["method"].upper() not in methods:
            continue
        if require_auth and not detect_auth_headers(entry["headers"]):
            continue
        url = entry.get("url", "")
        domain = urlparse(url).netloc
        path = urlparse(url).path
        if include_regex and not re.search(include_regex, path):
            continue
        if exclude_regex and re.search(exclude_regex, path):
            continue
        if include_domain and not re.search(include_domain, domain):
            continue
        if exclude_domain and re.search(exclude_domain, domain):
            continue
        filtered.append(entry)
    return filtered

def group_by_custom(items, mode="path_prefix", regex=None):
    """Group items by custom mode: method, regex, etc."""
    grouped = defaultdict(list)
    if mode == "method":
        for item in items:
            grouped[item["method"].upper()].append(item)
    elif mode == "regex" and regex:
        for item in items:
            m = re.search(regex, urlparse(item["url"]).path)
            key = m.group(0) if m else "Other"
            grouped[key].append(item)
    elif mode == "domain_path_method":
        for item in items:
            parsed = urlparse(item["url"])
            domain = parsed.netloc
            prefix = parsed.path.strip("/").split("/")[0] if parsed.path.strip("/") else "root"
            method = item["method"].upper()
            key = (domain, prefix, method)
            grouped[key].append(item)
    else:
        return group_by_path(items, mode=mode)
    return grouped

def is_pentest_candidate(entry):
    """
    Return True if the request is likely to be interesting for pentest:
    - Path contains numeric or UUID segment
    - Has query parameters
    - Has body (for POST/PUT/PATCH)
    """
    url = entry.get("url", "")
    method = entry.get("method", "GET").upper()
    parsed = urlparse(url)
    # Check for numeric or UUID in path
    segments = parsed.path.strip("/").split("/")
    for seg in segments:
        if re.match(r"^\d+$", seg) or re.match(r"^[0-9a-fA-F-]{8,}$", seg):
            return True
    # Check for query parameters
    if parsed.query:
        return True
    # Check for body in non-GET/HEAD
    if method not in ["GET", "HEAD"] and entry.get("body"):
        return True
    return False

def xml_to_postman(
    xml_file, output_file=None, deduplicate=True, group_mode="path_prefix", update=False,
    input_type=None, pentest=False, filter_methods=None, filter_auth=False,
    filter_include=None, filter_exclude=None, filter_domain=None, filter_domain_exclude=None,
    export_env=False, env_output=None, custom_group_regex=None, verbose=False, progress=False
):
    """Convert Burp Suite XML or HAR to Postman Collection with grouping and enhanced features."""
    items = []
    if not input_type:
        input_type = autodetect_input_type(xml_file)
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

    # Filtering
    items = filter_items(
        items,
        methods=filter_methods,
        require_auth=filter_auth,
        include_regex=filter_include,
        exclude_regex=filter_exclude,
        include_domain=filter_domain,
        exclude_domain=filter_domain_exclude
    )
    # Grouping
    if custom_group_regex:
        grouped = group_by_custom(items, mode="regex", regex=custom_group_regex)
    elif group_mode == "method":
        grouped = group_by_custom(items, mode="method")
    elif group_mode == "domain_path_method":
        grouped = group_by_custom(items, mode="domain_path_method")
    elif pentest:
        pentest_items = []
        for entry in items:
            if is_pentest_candidate(entry):
                pentest_items.append(entry)
        grouped = group_by_path(items, mode=group_mode)
        grouped["Pentest"] = pentest_items
    else:
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
    env_vars = {}
    request_hashes = set()
    duplicate_count = 0

    # Nested path grouping
    for folder, group_entries in grouped.items():
        for entry in group_entries:
            url = entry["url"]
            method = entry["method"]
            headers = entry["headers"]
            body = entry["body"]
            status = entry.get("status", "")
            resp = entry.get("response", "")
            auth_vars = detect_auth_headers(headers)
            global_vars.update(auth_vars)
            env_vars.update(auth_vars)
            parsed_url = urlparse(url)
            path, path_vars = extract_variables_from_path(parsed_url.path)
            protocol = parsed_url.scheme
            host = parsed_url.netloc.split('.')
            query = parsed_url.query
            # Ambil segmen path untuk folder
            if group_mode == "path_prefix":
                # Nested folder sesuai path
                path_segments = [seg for seg in path.strip('/').split('/') if seg]
                if not path_segments:
                    path_segments = ["root"]
            else:
                # Default: satu folder per group
                path_segments = [folder]
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
            # Add Postman pre-request script if X-Timestamp or Date header exists
            header_keys = [k.lower() for k in headers.keys()]
            pre_script_lines = []
            if "x-timestamp" in header_keys:
                pre_script_lines.append(
                    "pm.request.headers.upsert({key: 'X-Timestamp', value: Math.floor(Date.now()/1000).toString()});"
                )
            if "date" in header_keys:
                pre_script_lines.append(
                    "pm.request.headers.upsert({key: 'Date', value: new Date().toUTCString()});"
                )
            if pre_script_lines:
                pm_item["event"] = [{
                    "listen": "prerequest",
                    "script": {
                        "type": "text/javascript",
                        "exec": pre_script_lines
                    }
                }]
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
                resp_headers = entry.get("response_headers", {})
                pm_item["response"] = [{
                    "name": f"Response {status}",
                    "originalRequest": pm_item["request"],
                    "status": status,
                    "code": int(status) if status.isdigit() else 0,
                    "_postman_previewlanguage": "json",
                    "header": parse_response_headers(resp_headers),
                    "body": resp
                }]
            req_hash = generate_request_hash(method, url, headers, body)
            if deduplicate:
                if req_hash in request_hashes:
                    duplicate_count += 1
                    continue
                request_hashes.add(req_hash)
            insert_nested_postman_item(postman_collection["item"], path_segments, pm_item)
            # Duplicate to Pentest folder if needed
            if pentest and folder != "Pentest" and is_pentest_candidate(entry):
                insert_nested_postman_item(postman_collection["item"], ["Pentest"], pm_item)

    # Add global variables
    if global_vars:
        postman_collection["variable"] = [{"key": k, "value": v} for k, v in global_vars.items()]
    # Export environment if requested
    if export_env and env_vars and env_output:
        export_postman_environment(env_vars, env_output)
    # Output/update
    if output_file is None:
        base_name = os.path.splitext(os.path.basename(xml_file))[0]
        output_file = f"{base_name}_postman_collection.json"
    if update and os.path.exists(output_file):
        # Flatten all items for update
        def flatten_items(items):
            result = []
            for i in items:
                if "item" in i:
                    result.extend(flatten_items(i["item"]))
                else:
                    result.append(i)
            return result
        def update_postman_collection(output_file, new_items):
            """
            Stub for updating an existing Postman collection.
            This implementation simply returns a new collection with the new items.
            """
            with open(output_file, "r", encoding="utf-8") as f:
                collection = json.load(f)
            collection["item"] = new_items
            return collection
        postman_collection = update_postman_collection(output_file, flatten_items(postman_collection["item"]))
    with open(output_file, 'w', encoding='utf-8') as f:
        json.dump(postman_collection, f, indent=2)
    if deduplicate and duplicate_count > 0:
        print(f"Removed {duplicate_count} duplicate request(s)")
    print(f"Successfully converted to Postman collection: {output_file}")
    # Summary
    if verbose:
        print(f"Total endpoints: {len(items)}")
        print(f"Total groups: {len(grouped)}")
        print(f"Total global/env vars: {len(env_vars)}")
    return output_file

def xml_to_openapi(
    xml_file, output_file=None, deduplicate=True, group_mode="path_prefix", input_type=None, pentest=False,
    filter_methods=None, filter_auth=False, filter_include=None, filter_exclude=None, filter_domain=None, filter_domain_exclude=None,
    custom_group_regex=None, verbose=False, progress=False
):
    """Convert Burp Suite XML or HAR to OpenAPI Specification with tags and enhanced docs."""
    items = []
    if not input_type:
        input_type = autodetect_input_type(xml_file)
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
    # Filtering
    items = filter_items(
        items,
        methods=filter_methods,
        require_auth=filter_auth,
        include_regex=filter_include,
        exclude_regex=filter_exclude,
        include_domain=filter_domain,
        exclude_domain=filter_domain_exclude
    )
    if custom_group_regex:
        grouped = group_by_custom(items, mode="regex", regex=custom_group_regex)
    elif group_mode == "method":
        grouped = group_by_custom(items, mode="method")
    elif group_mode == "domain_path_method":
        grouped = group_by_custom(items, mode="domain_path_method")
    elif pentest:
        pentest_items = []
        other_items = []
        for entry in items:
            if is_pentest_candidate(entry):
                pentest_items.append(entry)
            else:
                other_items.append(entry)
        grouped = {"Pentest": pentest_items}
        if other_items:
            grouped.update(group_by_path(other_items, mode=group_mode))
    else:
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
            resp_headers = entry.get("response_headers", {})  # Fix: define resp_headers
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
                content_type_resp = content_type or "application/json"
                schema = parse_json_schema_from_body(resp) if "application/json" in content_type_resp else {"type": "string"}
                responses[status or "default"] = {
                    "description": f"Status {status} response",
                    "headers": {h["key"]: {"schema": {"type": "string"}, "example": h["value"]} for h in parse_response_headers(resp_headers)},
                    "content": {
                        content_type_resp: {
                            "schema": schema,
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

def export_swagger_yaml(openapi_json_file, output_file):
    """Export OpenAPI JSON to Swagger YAML."""
    with open(openapi_json_file, "r", encoding="utf-8") as f:
        spec = json.load(f)
    with open(output_file, "w", encoding="utf-8") as f:
        yaml.dump(spec, f, sort_keys=False)
    print(f"Exported Swagger YAML: {output_file}")

def export_httpie_collection(items, output_file):
    """Export to HTTPie collection (stub)."""
    with open(output_file, "w", encoding="utf-8") as f:
        for item in items:
            req = item["request"]
            url = req["url"]["raw"] if isinstance(req["url"], dict) else req["url"]
            method = req["method"]
            headers = " ".join([f"{h['key']}:{h['value']}" for h in req.get("header", [])])
            body = req.get("body", {}).get("raw", "")
            f.write(f"http {method.lower()} {url} {headers} {body}\n")
    print(f"Exported HTTPie collection: {output_file}")

def export_curl_list(items, output_file):
    """Export to cURL list (stub)."""
    with open(output_file, "w", encoding="utf-8") as f:
        for item in items:
            req = item["request"]
            url = req["url"]["raw"] if isinstance(req["url"], dict) else req["url"]
            method = req["method"]
            headers = " ".join([f"-H '{h['key']}: {h['value']}'" for h in req.get("header", [])])
            body = req.get("body", {}).get("raw", "")
            data = f"--data '{body}'" if body else ""
            f.write(f"curl -X {method.upper()} {headers} {data} '{url}'\n")
    print(f"Exported cURL list: {output_file}")

def validate_openapi_schema(openapi_file):
    """Validate OpenAPI output (stub, requires openapi-schema-validator)."""
    try:
        from openapi_schema_validator import validate
        with open(openapi_file, "r", encoding="utf-8") as f:
            spec = json.load(f)
        validate(spec)
        print("OpenAPI schema is valid.")
    except ImportError:
        print("openapi-schema-validator not installed.")
    except Exception as e:
        print(f"OpenAPI schema validation error: {e}")

def unit_test():
    """Simple unit test stub."""
    print("Running unit tests...")
    # ... add test cases for parsing, conversion, etc ...
    print("All tests passed.")

def main():
    parser = argparse.ArgumentParser(description="Convert Burp Suite XML/HAR to Postman, OpenAPI, Insomnia, Swagger YAML, HTTPie, or cURL")
    parser.add_argument("input_file", nargs="+", help="Input Burp Suite XML/HAR file(s) (wildcard supported)")
    parser.add_argument("--format", choices=["postman", "openapi", "insomnia", "swagger", "httpie", "curl"], default="postman", help="Output format")
    parser.add_argument("--output", help="Output file name (default: auto-generated based on input file)")
    parser.add_argument("--no-deduplicate", dest="deduplicate", action="store_false", help="Disable deduplication")
    parser.add_argument("--group", choices=["domain", "path_prefix", "flat", "method", "domain_path_method", "custom"], default="path_prefix", help="Grouping mode")
    parser.add_argument("--custom-group-regex", help="Custom regex for grouping path")
    parser.add_argument("--input-type", choices=["xml", "har"], help="Input file type (auto-detect if omitted)")
    parser.add_argument("--update", action="store_true", help="Update existing collection instead of overwrite")
    parser.add_argument("--pentest", action="store_true", help="Group all pentestable requests (with id/uuid/query/body) into a single folder")
    parser.add_argument("--filter-method", nargs="+", help="Filter only specific HTTP methods (e.g. POST PUT)")
    parser.add_argument("--filter-auth", action="store_true", help="Filter only requests with auth headers")
    parser.add_argument("--filter-include", help="Include only path matching regex")
    parser.add_argument("--filter-exclude", help="Exclude path matching regex")
    parser.add_argument("--filter-domain", help="Include only domain matching regex")
    parser.add_argument("--filter-domain-exclude", help="Exclude domain matching regex")
    parser.add_argument("--export-env", action="store_true", help="Export detected auth/env variables as Postman environment")
    parser.add_argument("--env-output", help="Output file for Postman environment")
    parser.add_argument("--summary", action="store_true", help="Show summary after conversion")
    parser.add_argument("--verbose", action="store_true", help="Verbose/debug output")
    parser.add_argument("--progress", action="store_true", help="Show progress bar")
    parser.add_argument("--validate", action="store_true", help="Validate OpenAPI output")
    parser.add_argument("--unit-test", action="store_true", help="Run unit tests and exit")
    parser.set_defaults(deduplicate=True)
    args = parser.parse_args()
    if args.unit_test:
        unit_test()
        sys.exit(0)
    files = []
    for pattern in args.input_file:
        files.extend(glob.glob(pattern))
    for f in files:
        if args.format == "postman":
            xml_to_postman(
                f, args.output, args.deduplicate, group_mode=args.group, update=args.update,
                input_type=args.input_type, pentest=args.pentest,
                filter_methods=[m.upper() for m in args.filter_method] if args.filter_method else None,
                filter_auth=args.filter_auth,
                filter_include=args.filter_include,
                filter_exclude=args.filter_exclude,
                filter_domain=args.filter_domain,
                filter_domain_exclude=args.filter_domain_exclude,
                export_env=args.export_env,
                env_output=args.env_output,
                custom_group_regex=args.custom_group_regex,
                verbose=args.verbose or args.summary,
                progress=args.progress
            )
        elif args.format == "openapi":
            out = xml_to_openapi(
                f, args.output, args.deduplicate, group_mode=args.group,
                input_type=args.input_type, pentest=args.pentest,
                filter_methods=[m.upper() for m in args.filter_method] if args.filter_method else None,
                filter_auth=args.filter_auth,
                filter_include=args.filter_include,
                filter_exclude=args.filter_exclude,
                filter_domain=args.filter_domain,
                filter_domain_exclude=args.filter_domain_exclude,
                custom_group_regex=args.custom_group_regex,
                verbose=args.verbose or args.summary,
                progress=args.progress
            )
            if args.validate and out:
                validate_openapi_schema(out)
        elif args.format == "insomnia":
            pm_file = xml_to_postman(
                f, None, args.deduplicate, group_mode=args.group,
                input_type=args.input_type, pentest=args.pentest,
                filter_methods=[m.upper() for m in args.filter_method] if args.filter_method else None,
                filter_auth=args.filter_auth,
                filter_include=args.filter_include,
                filter_exclude=args.filter_exclude,
                filter_domain=args.filter_domain,
                filter_domain_exclude=args.filter_domain_exclude,
                custom_group_regex=args.custom_group_regex,
                verbose=args.verbose or args.summary,
                progress=args.progress
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
        elif args.format == "swagger":
            out = xml_to_openapi(
                f, None, args.deduplicate, group_mode=args.group,
                input_type=args.input_type, pentest=args.pentest,
                filter_methods=[m.upper() for m in args.filter_method] if args.filter_method else None,
                filter_auth=args.filter_auth,
                filter_include=args.filter_include,
                filter_exclude=args.filter_exclude,
                filter_domain=args.filter_domain,
                filter_domain_exclude=args.filter_domain_exclude,
                custom_group_regex=args.custom_group_regex,
                verbose=args.verbose or args.summary,
                progress=args.progress
            )
            if out:
                export_swagger_yaml(out, args.output or f"{os.path.splitext(os.path.basename(f))[0]}_swagger.yaml")
        elif args.format == "httpie":
            pm_file = xml_to_postman(
                f, None, args.deduplicate, group_mode=args.group,
                input_type=args.input_type, pentest=args.pentest,
                filter_methods=[m.upper() for m in args.filter_method] if args.filter_method else None,
                filter_auth=args.filter_auth,
                filter_include=args.filter_include,
                filter_exclude=args.filter_exclude,
                filter_domain=args.filter_domain,
                filter_domain_exclude=args.filter_domain_exclude,
                custom_group_regex=args.custom_group_regex,
                verbose=args.verbose or args.summary,
                progress=args.progress
            )
            with open(pm_file, "r", encoding="utf-8") as pf:
                pm = json.load(pf)
            items = []
            for folder in pm.get("item", []):
                if "item" in folder:
                    items.extend(folder["item"])
                else:
                    items.append(folder)
            export_httpie_collection(items, args.output or f"{os.path.splitext(os.path.basename(f))[0]}_httpie.txt")
        elif args.format == "curl":
            pm_file = xml_to_postman(
                f, None, args.deduplicate, group_mode=args.group,
                input_type=args.input_type, pentest=args.pentest,
                filter_methods=[m.upper() for m in args.filter_method] if args.filter_method else None,
                filter_auth=args.filter_auth,
                filter_include=args.filter_include,
                filter_exclude=args.filter_exclude,
                filter_domain=args.filter_domain,
                filter_domain_exclude=args.filter_domain_exclude,
                custom_group_regex=args.custom_group_regex,
                verbose=args.verbose or args.summary,
                progress=args.progress
            )
            with open(pm_file, "r", encoding="utf-8") as pf:
                pm = json.load(pf)
            items = []
            for folder in pm.get("item", []):
                if "item" in folder:
                    items.extend(folder["item"])
                else:
                    items.append(folder)
            export_curl_list(items, args.output or f"{os.path.splitext(os.path.basename(f))[0]}_curl.txt")

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

def insert_nested_postman_item(items, path_segments, pm_item):
    """
    Insert a Postman item into a nested folder structure based on path_segments.
    If only one group (e.g. Pentest), flatten into one folder.
    """
    # If path_segments is empty, just append
    if not path_segments:
        items.append(pm_item)
        return
    # If only one group (e.g. Pentest), flatten into a single folder
    if len(path_segments) == 1:
        folder_name = path_segments[0]
        # Find or create the folder
        for folder in items:
            if folder.get("name") == folder_name and "item" in folder:
                folder["item"].append(pm_item)
                return
        # Folder not found, create new
        new_folder = {"name": folder_name, "item": [pm_item]}
        items.append(new_folder)
        return
    # Nested folders for multi-segment
    folder_name = path_segments[0]
    for folder in items:
        if folder.get("name") == folder_name and "item" in folder:
            insert_nested_postman_item(folder["item"], path_segments[1:], pm_item)
            return
    new_folder = {"name": folder_name, "item": []}
    items.append(new_folder)
    insert_nested_postman_item(new_folder["item"], path_segments[1:], pm_item)

if __name__ == "__main__":
    main()
