# BurpToAPI

BurpToAPI is a Python tool for converting Burp Suite XML or HAR files into Postman collections, OpenAPI specifications, or Insomnia exports. It also includes features for detecting potentially weak endpoints for pentesting.

## Features

- Convert Burp Suite XML or HAR files to:
  - Postman collections
  - OpenAPI specifications
  - Insomnia exports
- Group endpoints by domain, path prefix, or flat structure.
- Detect potentially weak or interesting endpoints for pentesting.
- Deduplicate requests to avoid duplicates in the output.
- Automatically extract and replace sensitive headers or tokens with variables.

## Requirements

- Python 3.6 or higher
- Optional: `tabulate` library for displaying pentest candidates in table format.

Install `tabulate` using:

```bash
pip install tabulate
```

## Usage

Run the script using the command line:

```bash
python burpapi.py [input_file(s)] [options]
```

### Options

| Option                  | Description                                                                 |
|-------------------------|-----------------------------------------------------------------------------|
| `--format`              | Output format: `postman`, `openapi`, or `insomnia`. Default: `postman`.    |
| `--output`              | Output file name. Default: auto-generated based on the input file.         |
| `--no-deduplicate`      | Disable deduplication of requests.                                         |
| `--group`               | Grouping mode: `domain`, `path_prefix`, or `flat`. Default: `path_prefix`. |
| `--input-type`          | Input file type: `xml` or `har`. Default: `xml`.                          |
| `--update`              | Update an existing Postman collection instead of overwriting it.          |
| `--pentest`             | Detect potentially weak endpoints for pentesting.                         |
| `--pentest-output`      | Save pentest candidates to a file (JSON or TXT).                          |
| `--pentest-table`       | Display pentest candidates as a table (requires `tabulate`).              |
| `--verbose`             | Enable verbose/debug logging.                                             |

### Examples

1. **Convert a single Burp XML file to Postman collection**:
   ```bash
   python burpapi.py hasil.xml --format postman
   ```

2. **Convert multiple files to OpenAPI, grouped by domain**:
   ```bash
   python burpapi.py hasil*.xml --format openapi --group domain
   ```

3. **Import a HAR file and export to Insomnia**:
   ```bash
   python burpapi.py traffic.har --input-type har --format insomnia
   ```

4. **Update an existing Postman collection**:
   ```bash
   python burpapi.py hasil.xml --format postman --update --output koleksi.json
   ```

5. **Group all endpoints into a single folder**:
   ```bash
   python burpapi.py hasil.xml --group flat
   ```

6. **Detect pentest candidates and save to a file**:
   ```bash
   python burpapi.py hasil.xml --pentest --pentest-output candidates.json
   ```

7. **Show pentest candidates as a table**:
   ```bash
   python burpapi.py hasil.xml --pentest --pentest-table
   ```

### Help

For a full list of options, run:

```bash
python burpapi.py --help
```

## Output Formats

### Postman Collection

The tool generates a Postman collection in JSON format, compatible with Postman v2.1 schema.

### OpenAPI Specification

The tool generates an OpenAPI 3.0 specification with detailed paths, parameters, and responses.

### Insomnia Export

The tool generates an Insomnia export file, compatible with Insomnia REST client.

## License

This project is licensed under the MIT License. See the `LICENSE` file for details.

## Contributing

Contributions are welcome! Feel free to submit issues or pull requests to improve the tool.