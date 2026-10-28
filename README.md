# Dependency Risk Radar 

**Find the risky dependencies. Understand why they're risky. Know what to fix.**

Every project leans on code written by people we've never met. Most of it is fine, but sometimes a package has a known security hole and nobody notices until it matters.

Dependency Risk Radar is a Streamlit app that checks your Python and npm dependencies against the [OSV.dev](https://osv.dev/) vulnerability database. Give it a list of packages or a `package-lock.json`, and it shows you which ones have known vulnerabilities, how serious they are, which versions fix them, and lets you export everything as a report.

<img width="2736" height="1496" alt="Dependency Risk Radar dashboard" src="https://github.com/user-attachments/assets/538a347f-6ad8-43cd-96aa-9091530a05cd" />

## What it can do

- **Scan Python packages (PyPI).** Enter one `name==version` per line.
- **Scan npm projects.** Upload a `package-lock.json` (lockfile v2 or v3) and every resolved dependency gets checked, transitive ones included.
- **Work out severity for each finding.** Critical, High, Medium, Low or Unknown, based on what OSV actually returns.
- **Show fix guidance.** You'll see the fixed versions and affected version ranges from the OSV record, or a clear note when the record doesn't mention a fix.
- **Organize results into four tabs.** Overview, Vulnerability Findings, Dependencies and Reports.
- **Help you find things fast.** Filter findings by severity and search them, and filter dependencies by scan status.
- **Export a report.** Download JSON or CSV with severity, CVSS score, fixed versions, affected ranges and a remediation status, with findings sorted by severity.
- **Stay honest about failures.** If a package can't be scanned, it's marked as failed, never quietly treated as safe.

### Still on the to-do list

- Dependency graph
- npm Registry checks (deprecation, publish history, license)
- Upgrade suggestions that respect your project's version constraints
- `package.json` support

## How it works

```mermaid
flowchart TD
    A{Scan mode} -->|Python| B[Enter name==version list]
    A -->|Node.js| C[Upload package-lock.json]
    C --> D[Parse resolved dependencies]
    B --> E[Query OSV.dev API]
    D --> E
    E --> F{Request succeeded?}
    F -->|Yes| G[Matching vulnerability records]
    F -->|No| H[Mark as scan failed]
    G --> I[Work out severity and fix info for each record]
    I --> J[Dashboard tabs]
    H --> J
    J --> K[Download JSON / CSV report]
```

### How severity is decided

We don't guess. For each OSV record, the app checks these in order:

1. **A CVSS v3 or v4 vector in the record.** The score is calculated with the [`cvss`](https://pypi.org/project/cvss/) library and mapped to Low, Medium, High or Critical.
2. **A severity label from the database**, such as a GitHub advisory label.
3. **Otherwise, Unknown.**

### Where fix information comes from

Fixed versions are read from the affected ranges in each OSV record. If a record doesn't list a fix, the app tells you so and points you to the advisory instead of making one up. A listed fix is simply the version OSV reports, so check that it plays nicely with the rest of your project before upgrading.

## Tech stack

Python, Streamlit, pandas, `requests`, `cvss`, and the OSV.dev API.

## Project structure

```text
DepenDency-Risk-RaDar/
├── app.py                 # Streamlit app: pages, scan workflow, dashboard
├── node_scanner.py        # package-lock.json parser
├── osv_client.py          # OSV.dev API client
├── severity_analyzer.py   # CVSS parsing and severity classification
├── report_generator.py    # Summary metrics, fix info, prioritization, JSON and CSV reports
├── requirements.txt
└── tests/
    ├── test_node_scanner.py
    ├── test_osv_client.py
    ├── test_remediation.py
    ├── test_report_generator.py
    └── test_severity_analyzer.py
```

## Run it locally

You'll need Python 3.10 or newer.

```bash
git clone https://github.com/Nandanpatgar/DepenDency-Risk-RaDar.git
cd DepenDency-Risk-RaDar

python -m venv .venv
source .venv/bin/activate      # on Windows: .venv\Scripts\activate

pip install -r requirements.txt
streamlit run app.py
```

The app opens in your browser, usually at `http://localhost:8501`.

Want a quick test? Paste this into the Python scanner:

```text
requests==2.19.0
flask==0.12.2
```

### Tests

```bash
pip install pytest
python -m pytest
```

Run this from the repository root. Heads up: `tests/test_osv_client.py` is a manual script that calls the live OSV API rather than a pytest test, so pytest skips it.

## Reading the results

- **Vulnerable:** at least one OSV record matches that package version.
- **No matching records:** OSV returned nothing for that version.
- **Failed:** the lookup didn't complete, so that package's status is unknown.

A few things worth remembering:

- The counts are OSV *records*, not necessarily separate security issues, since one issue can have several records.
- "No matching records" doesn't prove a package is safe. Results depend on what OSV.dev covers and how fresh its data is.

## Security notes

- Uploaded lockfiles are read as JSON only. No project code or install scripts are ever run.
- API and network errors are shown in the results, never hidden.

## Team

Built by **Clutch Crew** for **BYTE RACE 2026**. 
