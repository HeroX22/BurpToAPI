# test_integration_burpapi.py
import json
import os
from burpapi import (
    parse_burp_or_har,
    parse_har_file,
    xml_to_postman,
    xml_to_openapi,
    auto_detect_input_type
)

def make_burp_xml(path):
    """Create a minimal Burp XML file with one item for integration testing."""
    content = """<?xml version="1.0" encoding="UTF-8"?>
<items>
  <item>
    <url>https://example.com/api/users/123</url>
    <method>GET</method>
    <request base64="false">GET /api/users/123 HTTP/1.1
Host: example.com
User-Agent: pytest

</request>
    <response base64="false">HTTP/1.1 200 OK
Content-Type: application/json

{"id": 123, "name": "alice"}</response>
    <status>200</status>
  </item>
</items>
"""
    path.write_text(content, encoding="utf-8")
    return str(path)

def make_har(path):
    """Create a minimal HAR file with one entry."""
    har = {
        "log": {
            "version": "1.2",
            "creator": {"name": "pytest", "version": "1.0"},
            "entries": [
                {
                    "request": {
                        "method": "POST",
                        "url": "https://api.example.com/login?next=/",
                        "headers": [{"name": "Content-Type", "value": "application/json"}],
                        "postData": {"mimeType": "application/json", "text": '{"username":"bob","password":"sekret"}'}
                    },
                    "response": {
                        "status": 200,
                        "headers": [{"name": "Content-Type", "value": "application/json"}],
                        "content": {"text": '{"token":"abcd"}'}
                    }
                }
            ]
        }
    }
    path.write_text(json.dumps(har), encoding="utf-8")
    return str(path)

def test_parse_burp_xml_and_convert_to_postman_and_openapi(tmp_path):
    # Create minimal burp xml
    xml_file = tmp_path / "sample_burp.xml"
    make_burp_xml(xml_file)

    # parse_burp_or_har should return a list with one item
    items = parse_burp_or_har(str(xml_file), input_type="xml", exclude_headers=None, show_progress=False)
    assert isinstance(items, list)
    assert len(items) == 1
    it = items[0]
    assert "https://example.com/api/users/123" in it["url"]
    assert it["method"] in ("GET", "get", "GET")  # parser may normalize

    # Convert to Postman collection file (explicit output file in tmp_path)
    out_postman = tmp_path / "out_postman.json"
    # xml_to_postman writes file when output_file is None; pass output_file param by calling the function and letting it default
    produced = xml_to_postman(str(xml_file), output_file=str(out_postman), deduplicate=True, group_mode="path_prefix", input_type="xml", pentest=False, pentest_table=False, exclude_headers=None, output_folder=None, collection_title="Test Collection", show_stats=False, show_progress=False)
    # xml_to_postman returns output filename when output_file was None; but when we pass output_file it may return None; check file exists
    assert out_postman.exists(), "Postman output file was not created"
    content = json.loads(out_postman.read_text(encoding="utf-8"))
    assert "info" in content and "item" in content
    assert content["info"]["name"] == "Test Collection" or "Converted from" in content["info"]["name"]

    # Convert to OpenAPI
    out_openapi = tmp_path / "out_openapi.json"
    xml_to_openapi(str(xml_file), output_file=str(out_openapi), deduplicate=True, group_mode="path_prefix", input_type="xml", pentest=False, pentest_table=False)
    assert out_openapi.exists()
    openapi = json.loads(out_openapi.read_text(encoding="utf-8"))
    assert openapi.get("openapi", "").startswith("3.0")
    assert "/api/users/{id}" in openapi.get("paths", {}) or any(k.startswith("/api/users") for k in openapi.get("paths", {}).keys())

def test_parse_har_and_parse_har_file_and_postman_export(tmp_path):
    har_file = tmp_path / "sample.har"
    make_har(har_file)

    # auto_detect_input_type should detect .har
    assert auto_detect_input_type(str(har_file)) == "har"

    # parse_har_file yields entries
    entries = list(parse_har_file(str(har_file)))
    assert len(entries) == 1
    e = entries[0]
    assert e["method"].upper() == "POST"
    assert "login" in e["url"]

    # Use xml_to_postman by passing input_type har (create a tiny XML-style wrapper is not needed because xml_to_postman accepts input_type)
    # Create a tiny wrapper that calls parse_har_file via xml_to_postman by pretending it's a HAR input (we call xml_to_postman with input_type='har')
    out_postman2 = tmp_path / "out_postman_from_har.json"
    # xml_to_postman checks file size and input_type; it relies on parse_burp_or_har which understands 'har' input
    produced = xml_to_postman(str(har_file), output_file=str(out_postman2), deduplicate=True, group_mode="path_prefix", input_type="har", pentest=True, pentest_table=False, exclude_headers=None, output_folder=None, collection_title="HAR Collection", show_stats=False, show_progress=False)
    assert out_postman2.exists()
    pm = json.loads(out_postman2.read_text(encoding="utf-8"))
    assert "item" in pm
    # Ensure the exported collection contains at least one request referencing api.example.com
    raw = json.dumps(pm)
    assert "api.example.com" in raw or "login" in raw
