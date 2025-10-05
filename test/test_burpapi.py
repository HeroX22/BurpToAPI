# test_burpapi_combined.py
import pytest
import json
import base64
import re
import os
import tempfile

from burpapi import (
    sanitize_for_logging,
    safe_join_path,
    decode_base64,
    parse_headers,
    parse_request_line,
    extract_request_body,
    generate_request_hash,
    detect_auth_headers,
    extract_variables_from_path,
    group_by_path,
    is_sensitive_key,
    detect_pentest_candidates,
    filter_headers,
    extract_cookies,
    safe_json_loads,
    auto_detect_input_type,
    build_postman_item,
    atomic_write,
    parse_burp_or_har
)

# -------------------------
# Tests (from first file)
# -------------------------

def test_sanitize_for_logging_basic():
    data = "Authorization: Bearer ABCDEFGHIJKLMNOP"
    result = sanitize_for_logging(data)
    assert "[REDACTED]" in result
    assert "ABCDEFGHIJKLMNOP" not in result

def test_safe_join_path_prevents_traversal(tmp_path):
    good = safe_join_path(str(tmp_path), "file.txt")
    assert str(tmp_path) in good
    with pytest.raises(ValueError):
        safe_join_path(str(tmp_path), "../evil.txt")

def test_decode_base64_success():
    encoded = base64.b64encode(b"hello").decode()
    decoded = decode_base64(encoded, "true")
    assert decoded == "hello"

def test_decode_base64_failure_logs(monkeypatch):
    import burpapi
    monkeypatch.setattr(burpapi.logging, "warning", lambda msg: None)
    assert burpapi.decode_base64("???", "true") == "???"

def test_parse_headers():
    raw = "GET / HTTP/1.1\nHost: example.com\nUser-Agent: test\n\nbody"
    headers = parse_headers(raw)
    assert headers["Host"] == "example.com"
    assert "User-Agent" in headers

def test_parse_request_line():
    method, path = parse_request_line("POST /login HTTP/1.1")
    assert method == "POST"
    assert path == "/login"

def test_extract_request_body():
    raw = "POST / HTTP/1.1\nHost: x\n\nname=test"
    assert extract_request_body(raw) == "name=test"

def test_generate_request_hash_consistent():
    h1 = generate_request_hash("GET", "https://x.com/path?a=1&b=2", {"Header": "v"})
    h2 = generate_request_hash("get", "https://x.com/path?b=2&a=1", {"header": "v"})
    assert h1 == h2  # should be order-insensitive

def test_detect_auth_headers():
    headers = {"Authorization": "Bearer token123", "X-API-Key": "secret"}
    result = detect_auth_headers(headers)
    # result may contain keys like 'bearer_token' or snake_cased header names
    assert result.get("bearer_token") == "token123"
    assert any(k.startswith("x_api_key") or "x_api_key" == k for k in result.keys())

def test_extract_variables_from_path():
    path, vars = extract_variables_from_path("/users/1234/orders/abcd-1234")
    # Expect placeholders and variable names present
    assert ":id" in path or ":uuid" in path
    assert set(vars).intersection({"id", "uuid"})

def test_group_by_path_and_domain():
    items = [{"url": "https://site.com/a/b"}, {"url": "https://x.com/"}]
    g1 = group_by_path(items)
    g2 = group_by_path(items, mode="domain")
    assert any("site.com" in k for k in g2)
    # depending on grouping implementation, check that 'a' appears in keys or values
    assert any("a" in k or any('/a' in it.get('url','') for it in g1.get(k, [])) for k in g1)

@pytest.mark.parametrize("key,expected", [
    ("password", True),
    ("api-key", True),
    ("normal", False),
])
def test_is_sensitive_key(key, expected):
    assert is_sensitive_key(key) == expected

def test_detect_pentest_candidates_basic():
    items = [{
        "url": "https://api.com/login",
        "method": "POST",
        "headers": {"Authorization": "Bearer 123"},
        "body": '{"password":"secret"}'
    }]
    cands = detect_pentest_candidates(items)
    assert any("password" in c.get("reason", "") or "auth" in c.get("reason", "").lower() for c in cands)

def test_filter_headers_exclusion():
    headers = {"Auth": "1", "Cookie": "2"}
    result = filter_headers(headers, ["cookie"])
    assert "Cookie" not in result and "Auth" in result

def test_extract_cookies_function():
    headers = {"Cookie": "a=1; b=2"}
    cookies = extract_cookies(headers)
    assert cookies == {"a": "1", "b": "2"}

# -------------------------
# Tests (from second file, structured classes)
# -------------------------

class TestSanitizeForLogging:
    def test_sanitize_bearer_token(self):
        input_data = "Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9"
        result = sanitize_for_logging(input_data)
        assert "Bearer [REDACTED]" in result
        assert "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9" not in result

    def test_sanitize_password(self):
        input_data = '{"password": "secret123", "user": "admin"}'
        result = sanitize_for_logging(input_data)
        assert "password" in result
        assert "secret123" not in result

    def test_sanitize_base64_long_string(self):
        base64_string = "aGVsbG8gd29ybGQgdGhpcyBpcyBhIHZlcnkgbG9uZyBzdHJpbmcgdGhhdCBzaG91bGQgYmUgcmVkYWN0ZWQ="
        result = sanitize_for_logging(f"token={base64_string}")
        assert "[BASE64_REDACTED]" in result
        assert base64_string not in result

    def test_sanitize_jwt(self):
        jwt = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
        result = sanitize_for_logging(jwt)
        assert "[JWT_REDACTED]" in result
        assert jwt not in result

    def test_sanitize_non_string_input(self):
        result = sanitize_for_logging(12345)
        assert isinstance(result, str)

class TestSafeJoinPath:
    def test_valid_filename(self, tmp_path):
        folder = str(tmp_path)
        filename = "test_file.txt"
        result = safe_join_path(folder, filename)
        expected = os.path.join(folder, filename)
        assert result == expected

    def test_traversal_attempt(self, tmp_path):
        folder = str(tmp_path)
        with pytest.raises(ValueError, match="Suspicious filename detected"):
            safe_join_path(folder, "../../etc/passwd")

    def test_absolute_path(self, tmp_path):
        folder = str(tmp_path)
        with pytest.raises(ValueError, match="Suspicious filename detected"):
            safe_join_path(folder, "/etc/passwd")

    def test_null_byte(self, tmp_path):
        folder = str(tmp_path)
        with pytest.raises(ValueError, match="Invalid filename"):
            safe_join_path(folder, "test\x00file.txt")

    def test_empty_filename(self, tmp_path):
        folder = str(tmp_path)
        with pytest.raises(ValueError, match="Invalid filename"):
            safe_join_path(folder, "")

class TestDecodeBase64:
    def test_valid_base64(self):
        original = "hello world"
        encoded = base64.b64encode(original.encode()).decode()
        result = decode_base64(encoded, "true")
        assert result == original

    def test_invalid_base64(self):
        invalid_base64 = "not-valid-base64!!"
        result = decode_base64(invalid_base64, "true")
        assert result == invalid_base64

    def test_not_base64_flag(self):
        text = "plain text"
        result = decode_base64(text, "false")
        assert result == text

    def test_empty_input(self):
        result = decode_base64("", "true")
        assert result == ""

class TestParseHTTP:
    def test_parse_headers(self):
        raw_request = """GET /test HTTP/1.1
Host: example.com
Content-Type: application/json
Authorization: Bearer token123

{"data": "test"}"""
        headers = parse_headers(raw_request)
        assert headers["Host"] == "example.com"
        assert headers["Content-Type"] == "application/json"
        assert headers["Authorization"] == "Bearer token123"

    def test_parse_request_line(self):
        first_line = "POST /api/v1/users HTTP/1.1"
        method, path = parse_request_line(first_line)
        assert method == "POST"
        assert path == "/api/v1/users"

    def test_extract_request_body(self):
        raw_request = """POST /test HTTP/1.1
Content-Type: application/json

{"username": "admin", "password": "secret"}"""
        body = extract_request_body(raw_request)
        assert "username" in body
        assert "password" in body

class TestHashGeneration:
    def test_generate_request_hash_consistency(self):
        method = "GET"
        url = "https://api.example.com/users?id=1&name=test"
        headers = {"Content-Type": "application/json"}
        body = ""
        
        hash1 = generate_request_hash(method, url, headers, body)
        hash2 = generate_request_hash(method, url, headers, body)
        
        assert hash1 == hash2

    def test_generate_request_hash_different_query_order(self):
        method = "GET"
        url1 = "https://api.example.com/users?name=test&id=1"
        url2 = "https://api.example.com/users?id=1&name=test"
        headers = {"Content-Type": "application/json"}
        body = ""
        
        hash1 = generate_request_hash(method, url1, headers, body)
        hash2 = generate_request_hash(method, url2, headers, body)
        
        assert hash1 == hash2  # Should be same due to query normalization

class TestAuthDetection:
    def test_detect_bearer_token(self):
        headers = {
            "Authorization": "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9",
            "Content-Type": "application/json"
        }
        auth_vars = detect_auth_headers(headers)
        assert auth_vars.get("bearer_token") == "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9"

    def test_detect_api_key(self):
        headers = {
            "X-API-Key": "12345",
            "API-Key": "67890"
        }
        auth_vars = detect_auth_headers(headers)
        assert auth_vars.get("x_api_key") == "12345"
        assert "api_key" in auth_vars or any(k == "api_key" for k in auth_vars.keys())

class TestPathVariableExtraction:
    def test_extract_numeric_variables(self):
        path = "/api/v1/users/12345/profile"
        new_path, variables = extract_variables_from_path(path)
        assert ":id" in new_path or any(v == "id" for v in variables)

    def test_extract_uuid_variables(self):
        path = "/api/v1/resources/550e8400-e29b-41d4-a716-446655440000"
        new_path, variables = extract_variables_from_path(path)
        assert ":uuid" in new_path or any(v == "uuid" for v in variables)

class TestGrouping:
    def test_group_by_domain(self):
        items = [
            {"url": "https://api1.example.com/users"},
            {"url": "https://api2.example.com/products"},
            {"url": "https://api1.example.com/orders"}
        ]
        grouped = group_by_path(items, "domain")
        assert "api1.example.com" in grouped
        assert "api2.example.com" in grouped
        assert len(grouped["api1.example.com"]) == 2

    def test_group_by_path_prefix(self):
        items = [
            {"url": "https://example.com/api/users"},
            {"url": "https://example.com/api/products"},
            {"url": "https://example.com/admin/dashboard"}
        ]
        grouped = group_by_path(items, "path_prefix")
        assert "api" in grouped
        assert "admin" in grouped
        assert len(grouped["api"]) == 2

class TestSensitiveData:
    def test_sensitive_key_detection(self):
        assert is_sensitive_key("password") == True
        assert is_sensitive_key("api_key") == True
        assert is_sensitive_key("username") == True
        assert is_sensitive_key("email") == True
        assert is_sensitive_key("normal_field") == False

    def test_safe_json_loads(self):
        valid_json = '{"key": "value"}'
        invalid_json = '{"key": "value"'
        
        result_valid = safe_json_loads(valid_json)
        result_invalid = safe_json_loads(invalid_json)
        
        assert result_valid == {"key": "value"}
        assert result_invalid is None

class TestFilterHeaders:
    def test_header_filtering(self):
        headers = {
            "Authorization": "Bearer token",
            "Content-Type": "application/json",
            "User-Agent": "Mozilla/5.0",
            "Cookie": "session=abc123"
        }
        exclude_headers = ["authorization", "cookie"]
        filtered = filter_headers(headers, exclude_headers)
        
        assert "Authorization" not in filtered
        assert "Cookie" not in filtered
        assert "Content-Type" in filtered
        assert "User-Agent" in filtered

class TestInputTypeDetection:
    def test_xml_extension(self):
        assert auto_detect_input_type("test.xml") == "xml"

    def test_har_extension(self):
        assert auto_detect_input_type("test.har") == "har"

class TestCookieExtraction:
    def test_extract_cookies(self):
        headers = {
            "Cookie": "session=abc123; user=admin; token=xyz789"
        }
        cookies = extract_cookies(headers)
        assert cookies["session"] == "abc123"
        assert cookies["user"] == "admin"
        assert cookies["token"] == "xyz789"

class TestBuildPostmanItem:
    def test_basic_postman_item(self):
        entry = {
            "url": "https://api.example.com/users",
            "method": "GET",
            "headers": {"Content-Type": "application/json"},
            "body": "",
            "status": "200",
            "response": '{"users": []}'
        }
        global_vars = {}
        
        item = build_postman_item(entry, global_vars)
        
        assert item["name"] == "GET /users"
        assert item["request"]["method"] == "GET"
        assert item["request"]["url"]["raw"] == "https://api.example.com/users"
        assert len(item["request"]["header"]) == 1

    def test_postman_item_with_body(self):
        entry = {
            "url": "https://api.example.com/users",
            "method": "POST",
            "headers": {"Content-Type": "application/json"},
            "body": '{"name": "John", "email": "john@example.com"}',
            "status": "201",
            "response": '{"id": 123}'
        }
        global_vars = {}
        
        item = build_postman_item(entry, global_vars)
        
        assert item["request"]["method"] == "POST"
        assert "body" in item["request"]
        assert item["request"]["body"]["mode"] == "raw"

class TestAtomicWrite:
    def test_atomic_write(self, tmp_path):
        test_file = tmp_path / "test.txt"
        content = "Hello, World!"
        
        atomic_write(str(test_file), content)
        
        assert test_file.exists()
        with open(test_file, 'r') as f:
            assert f.read() == content

# Test dengan file XML dan HAR contoh
class TestWithFiles:
    def create_sample_burp_xml(self, tmp_path):
        xml_content = """<?xml version="1.0" encoding="UTF-8"?>
<items>
    <item>
        <time>Wed Jan 01 2020 12:00:00 GMT+0000</time>
        <url><![CDATA[https://api.example.com/users]]></url>
        <method>GET</method>
        <status>200</status>
        <response base64="false"><![CDATA[HTTP/1.1 200 OK
Content-Type: application/json

{"users": []}]]></response>
        <request base64="false"><![CDATA[GET /users HTTP/1.1
Host: api.example.com
Content-Type: application/json

]]></request>
    </item>
</items>"""
        xml_file = tmp_path / "test_burp.xml"
        xml_file.write_text(xml_content)
        return str(xml_file)

    def create_sample_har(self, tmp_path):
        har_content = {
            "log": {
                "version": "1.2",
                "creator": {"name": "Browser", "version": "1.0"},
                "entries": [
                    {
                        "request": {
                            "method": "GET",
                            "url": "https://api.example.com/products",
                            "headers": [
                                {"name": "Content-Type", "value": "application/json"}
                            ],
                            "postData": {"text": ""}
                        },
                        "response": {
                            "status": 200,
                            "headers": [
                                {"name": "Content-Type", "value": "application/json"}
                            ],
                            "content": {"text": '{"products": []}'}
                        }
                    }
                ]
            }
        }
        har_file = tmp_path / "test_har.har"
        har_file.write_text(json.dumps(har_content))
        return str(har_file)

    def test_parse_burp_xml(self, tmp_path):
        xml_file = self.create_sample_burp_xml(tmp_path)
        items = parse_burp_or_har(xml_file, "xml")
        assert len(items) == 1
        assert items[0]["url"] == "https://api.example.com/users"
        assert items[0]["method"] == "GET"

    def test_parse_har(self, tmp_path):
        har_file = self.create_sample_har(tmp_path)
        items = parse_burp_or_har(har_file, "har")
        assert len(items) == 1
        assert items[0]["url"] == "https://api.example.com/products"
        assert items[0]["method"] == "GET"

# Optional: allow running this file directly
if __name__ == "__main__":
    pytest.main([__file__, "-q"])
