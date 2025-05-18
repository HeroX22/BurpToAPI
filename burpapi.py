#!/usr/bin/env python3
import xml.etree.ElementTree as ET
import base64
import json
import argparse
import re
import os
import hashlib
from urllib.parse import urlparse, parse_qs

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

def xml_to_postman(xml_file, output_file=None, deduplicate=True):
    """Convert Burp Suite XML to Postman Collection"""
    try:
        tree = ET.parse(xml_file)
        root = tree.getroot()
    except Exception as e:
        print(f"Error parsing XML file: {e}")
        return

    # Create Postman collection structure
    postman_collection = {
        "info": {
            "name": f"Converted from {os.path.basename(xml_file)}",
            "description": "Converted from Burp Suite XML export",
            "schema": "https://schema.getpostman.com/json/collection/v2.1.0/collection.json"
        },
        "item": []
    }

    # Track request hashes to avoid duplicates if deduplication is enabled
    request_hashes = set()
    duplicate_count = 0

    # Process each item in the Burp Suite XML
    for item in root.findall(".//item"):
        try:
            url_element = item.find("url")
            host_element = item.find("host")
            method_element = item.find("method")
            path_element = item.find("path")
            request_element = item.find("request")
            status_element = item.find("status")
            response_element = item.find("response")
            
            if url_element is None or request_element is None:
                print("Warning: Missing required elements, skipping item")
                continue
                
            url = url_element.text
            method = method_element.text if method_element is not None else "GET"
            
            # Process request
            is_request_base64 = request_element.get("base64", "false")
            raw_request = decode_base64(request_element.text, is_request_base64)
            
            # Parse request
            request_lines = raw_request.split('\n')
            first_line = request_lines[0] if request_lines else ""
            req_method, req_path = parse_request_line(first_line)
            
            # Use parsed method if available, fallback to XML method
            if req_method:
                method = req_method
                
            headers = parse_headers(raw_request)
            body = extract_request_body(raw_request)
            
            # Check for duplicates if deduplication is enabled
            if deduplicate:
                request_hash = generate_request_hash(method, url, headers, body)
                if request_hash in request_hashes:
                    duplicate_count += 1
                    continue  # Skip this duplicate request
                request_hashes.add(request_hash)
            
            # Parse URL components
            parsed_url = urlparse(url)
            protocol = parsed_url.scheme
            host = parsed_url.netloc
            path = parsed_url.path
            query = parsed_url.query
            
            # Create Postman request item
            postman_item = {
                "name": f"{method} {path}",
                "request": {
                    "method": method,
                    "header": [{"key": k, "value": v} for k, v in headers.items()],
                    "url": {
                        "raw": url,
                        "protocol": protocol,
                        "host": host.split('.'),
                        "path": path.strip('/').split('/') if path else [],
                    }
                }
            }
            
            # Add query parameters if present
            if query:
                query_params = parse_qs(query)
                postman_item["request"]["url"]["query"] = [
                    {"key": k, "value": v[0]} for k, v in query_params.items()
                ]
            
            # Add request body if present
            if body and method not in ["GET", "HEAD"]:
                content_type = headers.get("Content-Type", "")
                if "application/json" in content_type:
                    try:
                        json_body = json.loads(body)
                        postman_item["request"]["body"] = {
                            "mode": "raw",
                            "raw": json.dumps(json_body, indent=2),
                            "options": {
                                "raw": {
                                    "language": "json"
                                }
                            }
                        }
                    except:
                        # Fallback to raw if not valid JSON
                        postman_item["request"]["body"] = {
                            "mode": "raw",
                            "raw": body
                        }
                elif "application/x-www-form-urlencoded" in content_type:
                    form_data = []
                    for param in body.split('&'):
                        if '=' in param:
                            key, value = param.split('=', 1)
                            form_data.append({"key": key, "value": value})
                    postman_item["request"]["body"] = {
                        "mode": "urlencoded",
                        "urlencoded": form_data
                    }
                elif "multipart/form-data" in content_type:
                    # Simplified handling - multipart boundaries would need more complex parsing
                    postman_item["request"]["body"] = {
                        "mode": "formdata",
                        "formdata": []
                    }
                else:
                    postman_item["request"]["body"] = {
                        "mode": "raw",
                        "raw": body
                    }
            
            # Add response if available
            if response_element is not None and status_element is not None:
                is_response_base64 = response_element.get("base64", "false")
                raw_response = decode_base64(response_element.text, is_response_base64)
                
                postman_item["response"] = [{
                    "name": f"Response {status_element.text}",
                    "originalRequest": postman_item["request"],
                    "status": status_element.text,
                    "code": int(status_element.text) if status_element.text.isdigit() else 0,
                    "_postman_previewlanguage": "json",
                    "header": [],  # Would need to parse from raw_response
                    "body": raw_response
                }]
            
            postman_collection["item"].append(postman_item)
            
        except Exception as e:
            print(f"Error processing item: {e}")
            continue

    # Save to file
    if output_file is None:
        base_name = os.path.splitext(os.path.basename(xml_file))[0]
        output_file = f"{base_name}_postman_collection.json"
    
    with open(output_file, 'w', encoding='utf-8') as f:
        json.dump(postman_collection, f, indent=2)
    
    if deduplicate and duplicate_count > 0:
        print(f"Removed {duplicate_count} duplicate request(s)")
        
    print(f"Successfully converted to Postman collection: {output_file}")
    return output_file

def xml_to_openapi(xml_file, output_file=None, deduplicate=True):
    """Convert Burp Suite XML to OpenAPI Specification"""
    try:
        tree = ET.parse(xml_file)
        root = tree.getroot()
    except Exception as e:
        print(f"Error parsing XML file: {e}")
        return

    # Create OpenAPI specification structure
    openapi_spec = {
        "openapi": "3.0.0",
        "info": {
            "title": f"API from {os.path.basename(xml_file)}",
            "description": "Converted from Burp Suite XML export",
            "version": "1.0.0"
        },
        "servers": [],
        "paths": {}
    }
    
    # Track unique server URLs
    servers = set()
    
    # Track request hashes to avoid duplicates if deduplication is enabled
    request_hashes = set()
    duplicate_count = 0
    endpoint_methods = set()  # Track endpoint+method combinations for OpenAPI

    # Process each item in the Burp Suite XML
    for item in root.findall(".//item"):
        try:
            url_element = item.find("url")
            method_element = item.find("method")
            request_element = item.find("request")
            response_element = item.find("response")
            status_element = item.find("status")
            
            if url_element is None or method_element is None:
                continue
                
            url = url_element.text
            method = method_element.text.lower()
            
            # Parse URL to get base URL and path
            parsed_url = urlparse(url)
            server_url = f"{parsed_url.scheme}://{parsed_url.netloc}"
            path = parsed_url.path
            
            # Process request to check for duplicates
            headers = {}
            body = ""
            if request_element is not None:
                is_request_base64 = request_element.get("base64", "false")
                raw_request = decode_base64(request_element.text, is_request_base64)
                headers = parse_headers(raw_request)
                body = extract_request_body(raw_request)
            
            # Skip duplicate requests if deduplication is enabled
            if deduplicate:
                request_hash = generate_request_hash(method, url, headers, body)
                if request_hash in request_hashes:
                    duplicate_count += 1
                    continue  # Skip this duplicate request
                request_hashes.add(request_hash)
            
            # For OpenAPI, handle path+method combination deduplication
            endpoint_key = f"{method}:{path}"
            if endpoint_key in endpoint_methods:
                continue  # Skip if we already have this path+method combination
            endpoint_methods.add(endpoint_key)
            
            # Add server if new
            if server_url not in servers:
                servers.add(server_url)
                openapi_spec["servers"].append({"url": server_url})
            
            # Process request
            parameters = []
            request_body = None
            
            if request_element is not None:
                is_request_base64 = request_element.get("base64", "false")
                raw_request = decode_base64(request_element.text, is_request_base64)
                
                # Extract query parameters
                if parsed_url.query:
                    query_params = parse_qs(parsed_url.query)
                    for param_name, param_values in query_params.items():
                        parameters.append({
                            "name": param_name,
                            "in": "query",
                            "required": False,
                            "schema": {
                                "type": "string"
                            },
                            "example": param_values[0] if param_values else ""
                        })
                
                # Parse headers for content type
                headers = parse_headers(raw_request)
                content_type = headers.get("Content-Type", "")
                
                # Extract request body for non-GET methods
                if method not in ["get", "head"]:
                    body = extract_request_body(raw_request)
                    if body:
                        if "application/json" in content_type:
                            try:
                                json_body = json.loads(body)
                                request_body = {
                                    "content": {
                                        "application/json": {
                                            "schema": {
                                                "type": "object"
                                            },
                                            "example": json_body
                                        }
                                    }
                                }
                            except:
                                # Fallback for invalid JSON
                                request_body = {
                                    "content": {
                                        "text/plain": {
                                            "schema": {
                                                "type": "string"
                                            },
                                            "example": body
                                        }
                                    }
                                }
                        elif "application/x-www-form-urlencoded" in content_type:
                            form_params = {}
                            for param in body.split('&'):
                                if '=' in param:
                                    key, value = param.split('=', 1)
                                    form_params[key] = value
                                    
                            request_body = {
                                "content": {
                                    "application/x-www-form-urlencoded": {
                                        "schema": {
                                            "type": "object",
                                            "properties": {k: {"type": "string"} for k in form_params.keys()}
                                        },
                                        "example": form_params
                                    }
                                }
                            }
                        else:
                            request_body = {
                                "content": {
                                    content_type or "text/plain": {
                                        "schema": {
                                            "type": "string"
                                        }
                                    }
                                }
                            }
            
            # Set up response structure
            responses = {
                "default": {
                    "description": "Default response"
                }
            }
            
            # Add actual response if available
            if response_element is not None and status_element is not None:
                status_code = status_element.text
                is_response_base64 = response_element.get("base64", "false")
                raw_response = decode_base64(response_element.text, is_response_base64)
                
                # Parse response content type
                response_content_type = "application/json"  # Default
                response_lines = raw_response.split('\n')
                for line in response_lines:
                    if line.lower().startswith("content-type:"):
                        response_content_type = line.split(':', 1)[1].strip()
                        break
                
                # Try to extract JSON from response body
                response_body = raw_response.split('\n\n', 1)[-1] if '\n\n' in raw_response else raw_response
                
                if "application/json" in response_content_type:
                    try:
                        # Try to find JSON content in the response
                        json_match = re.search(r'(\{.*\}|\[.*\])', response_body, re.DOTALL)
                        if json_match:
                            json_body = json.loads(json_match.group(0))
                            example = json_body
                        else:
                            example = response_body
                    except:
                        example = response_body
                        
                    responses[status_code] = {
                        "description": f"Status {status_code} response",
                        "content": {
                            "application/json": {
                                "schema": {
                                    "type": "object"
                                },
                                "example": example
                            }
                        }
                    }
                else:
                    responses[status_code] = {
                        "description": f"Status {status_code} response",
                        "content": {
                            response_content_type: {
                                "schema": {
                                    "type": "string"
                                },
                                "example": response_body
                            }
                        }
                    }
            
            # Create path item
            if path not in openapi_spec["paths"]:
                openapi_spec["paths"][path] = {}
                
            # Add method to path
            path_item = {
                "summary": f"{method.upper()} {path}",
                "parameters": parameters,
                "responses": responses
            }
            
            if request_body:
                path_item["requestBody"] = request_body
                
            openapi_spec["paths"][path][method] = path_item
            
        except Exception as e:
            print(f"Error processing item for OpenAPI: {e}")
            continue

    # Save to file
    if output_file is None:
        base_name = os.path.splitext(os.path.basename(xml_file))[0]
        output_file = f"{base_name}_openapi.json"
    
    with open(output_file, 'w', encoding='utf-8') as f:
        json.dump(openapi_spec, f, indent=2)
    
    if deduplicate and duplicate_count > 0:
        print(f"Removed {duplicate_count} duplicate request(s)")
        
    print(f"Successfully converted to OpenAPI specification: {output_file}")
    return output_file

def main():
    parser = argparse.ArgumentParser(description="Convert Burp Suite XML to Postman Collection or OpenAPI Specification")
    parser.add_argument("input_file", help="Input Burp Suite XML file")
    parser.add_argument("--format", choices=["postman", "openapi"], default="postman", help="Output format (default: postman)")
    parser.add_argument("--output", help="Output file name (default: auto-generated based on input file)")
    parser.add_argument("--no-deduplicate", dest="deduplicate", action="store_false", 
                      help="Disable deduplication of similar requests (default: deduplication enabled)")
    parser.set_defaults(deduplicate=True)
    
    args = parser.parse_args()
    
    if args.format == "postman":
        xml_to_postman(args.input_file, args.output, args.deduplicate)
    else:
        xml_to_openapi(args.input_file, args.output, args.deduplicate)

if __name__ == "__main__":
    main()