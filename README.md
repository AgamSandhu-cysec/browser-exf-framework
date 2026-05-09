# Browser Extension Attack Framework (ext-attack-framework)

An advanced, multi-stage offensive security tool designed to audit Chrome browser extensions. The framework combines deep static analysis (AST parsing, manifest auditing, secret scanning), dynamic execution (Puppeteer-driven behavioral probes), and machine-learning-based false positive filtering to uncover vulnerabilities.

It detects DOM XSS sinks, hardcoded secrets, dangerous permissions, `postMessage` vulnerabilities, external API exposure (`externally_connectable`), and CORS bypass vectors.

## Features

- **Deep Static Analysis**: regex and AST-oriented scanning for sensitive APIs (`eval`, `innerHTML`, `chrome.storage.local.set`), overly broad manifest permissions, and subdomain takeover risks.
- **Dynamic Analysis (Puppeteer Harness)**: Instantiates the extension in a headless/headed Chrome browser to actively exploit findings (XSS, CORS proxy checks, `postMessage` probes).
- **Machine Learning False Positive Filter**: Utilizes a trained Gradient Boosting Classifier to score the exploitability and confidence of findings based on an extracted 30-feature vector.
- **Automated PoC Generation**: Automatically creates standalone HTML Proof-of-Concept exploits for confirmed vulnerabilities (like `postMessage` injections).
- **Reporting**: Generates rich terminal output, structured JSON, and detailed HTML reports.

## Architecture & Modules

The framework consists of four primary subsystems:

1. **`core/`**: Orchestrates extension unpacking (handles `.crx`, IDs, or folders), static finding aggregation, and the underlying `Finding` data model.
2. **`static/`**: 
   - `ast_scanner`: Multi-line regex heuristics to detect unsafe sinks and `postMessage` vulnerabilities.
   - `manifest_parser`: Audits `manifest.json` for dangerous permissions (e.g., `webRequestBlocking`), CSP weaknesses (`unsafe-eval`), and excessive web exposure.
   - `secrets_scanner`: Uses Shannon entropy analysis and pattern matching to extract hardcoded API keys and credentials.
   - `ext_connectable`: Analyzes `externally_connectable` rules and correlates them with `onMessageExternal` listeners to identify broad web exposure and subdomain takeover vectors.
3. **`dynamic/`**: A Node.js Puppeteer harness that loads the extension and dynamically probes for vulnerabilities. Validates static findings and upgrades them (e.g., confirming DOM XSS).
4. **`ml/`**: Exploitability scoring engine. Extracts 30 features from findings and extension structure to predict the likelihood of a false positive. Falls back to a heuristic scorer if the model is unavailable.

## Quick Start

```bash
pip install ext-attack-framework
ext-attack scan --input <ext_id_or_path>
```

## Installation

```bash
# Clone the repository
git clone https://github.com/AgamSandhu-cysec/browser-exf-framework.git
cd browser-exf-framework

# Setup Python virtual environment
python3 -m venv .venv
source .venv/bin/activate

# Install with development and ML dependencies
pip install -e ".[dev,ml]"

# Install Node.js dependencies for dynamic analysis
cd dynamic/harness && npm install && cd ../..
```

## Usage

```bash
ext-attack scan --input <ext_id|crx_file|folder> [OPTIONS]
```

### Key Options

- `--format` `terminal|json|html|all` [default: `terminal`]
- `--output` `<PATH>` Directory for reports [default: `./output`]
- `--dynamic` Enable Puppeteer-based dynamic testing
- `--poc` Generate PoC HTML files (requires `--format html`)
- `--min-confidence` Filter findings below a confidence score (0.0 - 1.0)
- `--show-fp` Include findings marked as likely false positives by the ML scorer
- `--severity` Filter by minimum severity (critical, high, medium, low, info)
- `--module` Run specific modules (`manifest`, `ast`, `secrets`, `dynamic`, `all`)

### Examples

**Quick static scan against a Web Store extension:**
```bash
ext-attack scan --input hdokiejnpimakedhajhdlcegeplioahd
```

**Full analysis with HTML report and PoC generation:**
```bash
ext-attack scan --input /path/to/unpacked_ext --format all --poc --output ./reports
```

**Run dynamic execution harness (requires Chrome):**
```bash
xvfb-run -a ext-attack scan --input /path/to/ext --dynamic
```

## Development & Testing

```bash
# View available scan modules
ext-attack list-modules

# Run unit tests
pytest tests/ -v -m "not slow"

# Run integration/dynamic tests (requires Chrome/xvfb)
xvfb-run -a pytest tests/test_dynamic_orchestrator.py -v -m slow
```

## Exit Codes

For integration into CI/CD pipelines:
- `0` — Success, no findings at or above the threshold
- `1` — At least one `critical` or `high` severity finding identified
- `2` — Fatal error (e.g., extension unpack failure, invalid arguments)

## Note on Legal & Terms of Service

Downloading an extension via ID utilizes Google's CRX update endpoint. Please respect their terms of service and only analyze extensions you are authorized to test.

## License

MIT License
