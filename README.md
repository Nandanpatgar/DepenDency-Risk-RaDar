# DepenDency Risk RaDar

**Dependency Risk Radar** is a dependency vulnerability analysis tool developed to help developers identify risky software dependencies, understand why they pose a security risk, and investigate possible remediation steps.

The project was developed in response to a problem statement presented at the **BYTE RACE Hackathon**, organized at Vivekananda College of Engineering and Technology (VCET), Puttur, Karnataka.

The tool supports Python package scanning and Node.js dependency analysis, using the Open Source Vulnerabilities (OSV) database to retrieve known vulnerability information. It presents findings through an interactive dashboard with severity analysis, affected and fixed version details, remediation information, and advisory references when available.

## Problem Statement

> Build tool that analyzes Node.js project's dependencies and tells the developer which packages are risky, why, and what to do about it.

## Project Objective

The objective of Dependency Risk Radar is to simplify dependency security analysis by bringing vulnerability identification, severity interpretation, remediation information, and reporting into a single workflow.

Rather than simply reporting that a vulnerability exists, the tool helps developers investigate the affected package, understand the available security information, and identify potential next steps.

## Key Features

* **Multi-ecosystem scanning:** Supports Python package/version checks and Node.js dependency scanning.
* **Node.js lockfile analysis:** Parses `package-lock.json` to extract package names and resolved versions, including transitive dependencies represented in the lockfile.
* **OSV vulnerability lookup:** Queries OSV.dev for known vulnerabilities associated with the scanned packages and versions.
* **Severity analysis:** Interprets available CVSS scores and severity information.
* **Affected and fixed version information:** Displays version details when provided by vulnerability records.
* **Remediation support:** Presents available fix information to help developers investigate corrective actions.
* **Advisory references:** Provides links to additional vulnerability information when available.
* **Interactive dashboard:** Summarizes findings and helps developers review vulnerability severity and prioritize investigation.
* **Report generation:** Supports exporting scan results in JSON and CSV formats.
* **Automated testing:** Includes tests for dependency parsing, vulnerability lookup, severity analysis, remediation, and report generation.

## Project Structure

```text
DepenDency-Risk-RaDar/
├── app.py                      # Streamlit interface, scan workflow, and dashboard
├── node_scanner.py             # package-lock.json parser
├── osv_client.py               # OSV.dev API client
├── severity_analyzer.py        # CVSS parsing and severity classification
├── report_generator.py         # Summary metrics, fix information, prioritization, JSON/CSV reports
├── requirements.txt            # Python dependencies
└── tests/
    ├── test_node_scanner.py
    ├── test_osv_client.py
    ├── test_remediation.py
    ├── test_report_generator.py
    └── test_severity_analyzer.py
```

## System Workflow

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


### Workflow Explanation

1. **Input:** The developer enters a Python package name and version or uploads a Node.js `package-lock.json` file.
2. **Dependency processing:** The application extracts package names and versions for vulnerability checking.
3. **Vulnerability lookup:** The OSV client queries OSV.dev for matching vulnerability records.
4. **Severity analysis:** Available CVSS scores and severity information are interpreted to help assess the reported issues.
5. **Remediation analysis:** Available affected versions, fixed versions, and remediation details are extracted.
6. **Results presentation:** The dashboard displays findings, severity summaries, and supporting advisory references.
7. **Report export:** Developers can download results in JSON or CSV format for further analysis.

## Technology Stack

| Component                  | Technology                           | Purpose                                          |
| -------------------------- | ------------------------------------ | ------------------------------------------------ |
| Frontend and dashboard     | Streamlit                            | Interactive user interface and results dashboard |
| Application logic          | Python                               | Coordinates scanning, analysis, and reporting    |
| Vulnerability intelligence | OSV.dev API                          | Retrieves known vulnerability records            |
| Python ecosystem           | PyPI packages                        | Supports Python package/version scanning         |
| Node.js ecosystem          | npm packages and `package-lock.json` | Supports Node.js dependency scanning             |
| Severity analysis          | CVSS data, when available            | Supports vulnerability severity interpretation   |
| Reporting                  | JSON and CSV                         | Enables exporting scan results                   |
| Testing                    | pytest                               | Runs automated tests                             |

## Getting Started

### Prerequisites

* Python 3.10 or newer
* pip
* Internet connectivity to access the OSV.dev API

Node.js and npm are only required if you want to generate a real `package-lock.json` file for testing.

### 1. Clone the Repository

```bash
git clone https://github.com/Nandanpatgar/DepenDency-Risk-RaDar.git
cd DepenDency-Risk-RaDar
```

### 2. Create a Virtual Environment

**Windows PowerShell**

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
```

**macOS / Linux**

```bash
python3 -m venv .venv
source .venv/bin/activate
```

### 3. Install Dependencies

```bash
pip install -r requirements.txt
```

### 4. Run the Application

```bash
streamlit run app.py
```

Open the local URL displayed in the terminal. Streamlit commonly uses:

```text
http://localhost:8501
```

## Example Usage

### Python Package Scanning

Enter a package name and its exact version into the Python scanner.

Example inputs:

```text
requests==2.19.0
flask==0.12.2
```

These are example test inputs, not guaranteed vulnerability findings. Actual results depend on the records returned by OSV.dev.

### Node.js Dependency Scanning

Upload a Node.js project's `package-lock.json` file to scan the resolved dependency versions represented in the lockfile.

To generate a test lockfile using npm:

```bash
mkdir radar-node-test
cd radar-node-test
npm init -y
npm install lodash@4.17.20 minimist@1.2.5
```

Upload the generated `package-lock.json` through the application's Node.js scanning interface.

The scanner reads the lockfile as JSON. It does not need to install the scanned dependencies to analyze their recorded package names and versions.

## Understanding the Results

* **Vulnerable:** At least one matching OSV vulnerability record was returned for the package version according to the application's lookup logic.
* **No matching records:** OSV returned no matching vulnerability records for the package version. This does not guarantee that the package is secure.
* **Failed:** The lookup did not complete successfully. The package's vulnerability status remains unknown.
* **Severity and CVSS:** Available severity information helps developers understand the reported vulnerability's potential impact.
* **Affected versions:** Package versions identified as affected by a vulnerability, when provided.
* **Fixed versions:** Versions identified as containing a fix, when provided.
* **Remediation information:** Available details that help developers investigate possible corrective actions.
* **Advisory references:** Links to additional information about the reported vulnerability.
* **JSON and CSV reports:** Exportable results for record keeping and further analysis.

The number of OSV records returned should not automatically be interpreted as the number of unique security issues, because multiple records can sometimes describe related vulnerability information.

## Testing

Install pytest if it is not already available:

```bash
pip install pytest
```

Run the test suite from the repository root:

```bash
python -m pytest
```

The project includes tests covering:

* Node.js lockfile parsing
* OSV client behavior
* Remediation information
* Report generation
* Severity analysis

Note: `tests/test_osv_client.py` may require separate execution if it is implemented as a manual script rather than a test file collected by pytest. Check the test output and the file's implementation to confirm its behavior.

## Security Considerations and Limitations

* The application identifies known vulnerabilities represented in OSV.dev records; it does not guarantee that a dependency is free of security flaws.
* Results depend on the coverage and freshness of the vulnerability database.
* Some records may not provide CVSS scores, fixed versions, or detailed remediation guidance.
* A vulnerability's practical risk depends on the issue and how the affected dependency is used by the application.
* Recommended upgrades should be reviewed and tested for compatibility before deployment.
* Uploaded lockfiles are parsed as JSON; the application does not need to execute the uploaded project's code or installation scripts.
* Network and API failures should be treated as unknown results rather than evidence that a package is safe.

Dependency Risk Radar is intended to support vulnerability investigation and remediation decisions, not replace a comprehensive security review.

## Hackathon Details

**Event:** BYTE RACE Hackathon
**Institution:** Vivekananda College of Engineering and Technology (VCET)
**Location:** Puttur, Karnataka, India
**Problem Statement:** Build a tool that analyzes a Node.js project's dependencies and tells the developer which packages are risky, why, and what to do about it.

## Team

**Team Name:** Clutch Crew

Developed as a solution to the dependency security problem statement presented at BYTE RACE Hackathon.


