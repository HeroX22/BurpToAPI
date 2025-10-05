# BurpToAPI
BurpToAPI is a comprehensive Python tool for converting Burp Suite XML or HAR files into Postman collections, OpenAPI specifications, or Insomnia exports. It includes advanced features for security testing and API documentation generation.

## Features

- **Multi-format Conversion**: Convert Burp Suite XML or HAR files to:
  - Postman collections (v2.1)
  - OpenAPI specifications (3.0.0)
  - Insomnia exports
- **Smart Grouping**: Organize endpoints by domain, path prefix, or flat structure
- **Pentest Detection**: Automatically detect potentially weak or interesting endpoints for security testing
- **Deduplication**: Remove duplicate requests based on method, URL, headers, and body
- **Security Features**:
  - Sensitive data redaction in logs
  - Path traversal protection
  - XXE attack prevention in XML parsing
  - Automatic extraction of authentication tokens as variables
- **Performance Optimizations**:
  - Streaming XML parser for large files (>50MB)
  - Parallel processing for multiple files
  - Cached hashing for faster deduplication
- **Flexible Output**: Support for JSON, CSV, and TXT formats for pentest results

## Requirements

- Python 3.6 or higher
- Recommended optional libraries:
  - `tabulate` - for table formatting of pentest candidates
  - `tqdm` - for progress bars
  - `defusedxml` - for secure XML parsing

Install optional dependencies:
```bash
pip install tabulate tqdm defusedxml
```

## Installation

```bash
git clone <repository-url>
cd burptoapi
```

## Usage

### Basic Command Structure

```bash
python burpapi.py [input_file(s)] [options]
```

### Main Options

| Option | Description |
|--------|-------------|
| `input_file` | Input Burp Suite XML/HAR file(s) (supports wildcards) |
| `--format` | Output format: `postman`, `openapi`, or `insomnia` (default: postman) |
| `--output` | Output file name (auto-generated if not specified) |
| `--output-folder` | Output folder for result files |
| `--input-type` | Input file type: `xml` or `har` (auto-detected if not set) |
| `--collection-title` | Custom title/name for the collection |

### Processing Options

| Option | Description |
|--------|-------------|
| `--no-deduplicate` | Disable request deduplication |
| `--group` | Grouping mode: `domain`, `path_prefix`, or `flat` (default: path_prefix) |
| `--update` | Update existing Postman collection instead of overwriting |
| `--exclude-header` | Header(s) to exclude from export (repeatable) |
| `--show-stats` | Show summary statistics of endpoints |
| `--show-progress` | Show progress bar (requires tqdm) |

### Security Testing Options

| Option | Description |
|--------|-------------|
| `--pentest` | Detect potentially weak endpoints for pentesting |
| `--pentest-output` | Save pentest candidates to file (JSON, CSV, or TXT) |
| `--pentest-table` | Show pentest candidates as table (requires tabulate) |

### Utility Options

| Option | Description |
|--------|-------------|
| `--check-env` | Check environment for required libraries and Python version |
| `--verbose` | Enable verbose/debug logging with sensitive data redaction |

## Examples

### Basic Conversions

1. **Convert Burp XML to Postman collection**:
   ```bash
   python burpapi.py scan_results.xml --format postman
   ```

2. **Convert HAR to OpenAPI specification**:
   ```bash
   python burpapi.py traffic.har --format openapi --input-type har
   ```

3. **Export to Insomnia**:
   ```bash
   python burpapi.py scan_results.xml --format insomnia
   ```

### Advanced Usage

4. **Group endpoints by domain with custom title**:
   ```bash
   python burpapi.py scan.xml --format postman --group domain --collection-title "My API"
   ```

5. **Update existing Postman collection**:
   ```bash
   python burpapi.py new_scan.xml --format postman --update --output existing_collection.json
   ```

6. **Process multiple files with progress bar**:
   ```bash
   python burpapi.py scan*.xml --format postman --show-progress --output-folder ./exports
   ```

### Security Testing

7. **Detect pentest candidates and display as table**:
   ```bash
   python burpapi.py scan.xml --pentest --pentest-table
   ```

8. **Save pentest candidates to JSON file**:
   ```bash
   python burpapi.py scan.xml --pentest --pentest-output candidates.json
   ```

9. **Exclude specific headers from export**:
   ```bash
   python burpapi.py scan.xml --format postman --exclude-header Cookie --exclude-header User-Agent
   ```

10. **Show detailed statistics**:
    ```bash
    python burpapi.py scan.xml --format postman --show-stats
    ```

### Environment Check

11. **Verify environment setup**:
    ```bash
    python burpapi.py --check-env
    ```

## Output Details

### Postman Collection
- Compatible with Postman v2.1 schema
- Organized folders based on grouping mode
- Authentication tokens extracted as variables
- Request/response examples preserved
- Smart body handling for JSON and form data

### OpenAPI Specification
- OpenAPI 3.0.0 compliant
- Path parameters automatically detected
- Query parameters documented
- Request/response schemas and examples
- Tag-based organization

### Insomnia Export
- Compatible with Insomnia REST client
- Preserves all request details
- Maintains authentication information

### Pentest Detection
The tool identifies potentially weak endpoints based on:
- Sensitive parameters in path, query, or body
- Authentication headers (Basic, Bearer, API keys)
- Numeric/UUID path segments
- JSON bodies with sensitive field names
- HTTP methods with request bodies

## Security Features

- **Safe XML Parsing**: Uses defusedxml when available, with XXE protection fallbacks
- **Path Traversal Prevention**: Enhanced safe path joining with suspicious filename detection
- **Sensitive Data Redaction**: Multi-layer logging filter to prevent secret leakage
- **Base64 Validation**: Safe base64 decoding with proper error handling
- **Atomic Writes**: Prevents partial file writes during export

## Performance

- **Streaming Parser**: Handles large XML files (>50MB) efficiently
- **Parallel Processing**: Processes multiple files concurrently
- **Cached Hashing**: Speeds up duplicate detection
- **Memory Efficient**: Clears XML elements during streaming parse

## Troubleshooting

### Common Issues

1. **Missing Dependencies**:
   ```bash
   pip install tabulate tqdm defusedxml
   ```

2. **Large File Processing**:
   - Use `--show-progress` to monitor parsing
   - The script automatically uses streaming for files >50MB

3. **Permission Errors**:
   - Ensure write permissions for output directory
   - Use `--output-folder` to specify writable location

4. **Encoding Issues**:
   - Script handles UTF-8, Latin-1, and CP1252 encodings
   - Uses replacement strategies for malformed data

Key updates made to match `burpapi.py`:
1. Added all new command-line options (`--check-env`, `--output-folder`, `--exclude-header`, `--collection-title`, `--show-stats`, `--show-progress`)
2. Documented security features (XXE protection, path traversal prevention, sensitive data redaction)
3. Added performance optimizations section
4. Included examples for all major features
5. Updated requirements with optional dependencies
6. Added troubleshooting section
7. Enhanced feature descriptions to match current implementation
8. Included atomic writes and streaming parser details
9. Added environment check utility
10. Enhanced pentest detection documentation