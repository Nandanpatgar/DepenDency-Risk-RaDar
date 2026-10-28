# Dependency Risk Radar 

**Do you actually know what's hiding in your dependencies?**

Every project pulls in code written by people we've never met. Most of the time that's fine. Sometimes one of those packages has a known security hole, and nobody notices until it's too late.

Dependency Risk Radar is a small web app that checks your packages against [OSV.dev](https://osv.dev/), a public database of known vulnerabilities, and shows you what it found in plain, readable form. No account, no setup beyond a few commands, and no code from your project is ever run.

<img width="2862" height="1472" alt="Screenshot 2026-10-28 135243" src="https://github.com/user-attachments/assets/32870995-42bb-4804-a642-d435d0f04556" />

## What it can do

- **Check a single Python package.** Type in a name and version (say, `requests` `2.31.0`) and see whether OSV has any matching vulnerability records.
- **Scan a whole Node.js project.** Upload your `package-lock.json` and the app checks every resolved npm dependency, with a progress bar so you're not left guessing.
- **Show the evidence.** For each finding you get the ID, summary, aliases (like CVE numbers), details, and links to references. You see *why* something was flagged, not just a scary number.
- **Give you a quick report.** Total dependencies, how many were scanned successfully, how many have findings, and how many vulnerability records were found overall.
- **Be honest when something goes wrong.** If a lookup fails (network hiccup, API error), that package is marked **"Scan failed"**, not "safe". Unknown means unknown.

## How it works

1. You pick a mode: Python package or Node.js project.
2. For Node.js, the app reads your `package-lock.json` as plain data and pulls out each package name and version.
3. Each package and version is sent to the OSV API, using the right ecosystem (`PyPI` or `npm`).
4. Results come back and are shown in an expandable list, so you can open only the packages you care about.

## Try it yourself

You'll need Python (a recent 3.x version; 3.11 or newer is a safe bet) and Git.

```bash
# 1. Clone the repo
git clone https://github.com/Nandanpatgar/DepenDency-Risk-RaDar.git
cd DepenDency-Risk-RaDar

# 2. (Optional but recommended) create a virtual environment
python -m venv venv
source venv/bin/activate        # on Windows: venv\Scripts\activate

# 3. Install the dependencies
pip install -r requirements.txt

# 4. Start the app
streamlit run app.py
```

Streamlit will open the app in your browser, usually at `http://localhost:8501`.

> The app talks to the OSV API, so you'll need an internet connection while scanning.

## Reading the results

- **Vulnerability records found:** OSV has at least one entry matching that package and version. Open the expander to read the details.
- **No matching records:** OSV didn't find anything for that exact version.
- **Scan failed:** the lookup didn't complete, so we can't say anything about that package. Worth re-running.

A couple of things to keep in mind:

- The counts are *records*, not necessarily unique security issues. The same problem can show up under more than one ID.
- Severity isn't guessed or scored. The app only reports what OSV returns.
- A clean result is not a guarantee of safety. It only means the database had nothing on file for that version at the time of the scan.

## What's in the repo

| File | What it does |
|------|--------------|
| `app.py` | The Streamlit interface: scan modes, progress, and result display |
| `node_scanner.py` | Reads a `package-lock.json` and extracts package names and versions |
| `osv_client.py` | Talks to the OSV API and returns vulnerability records |
| `tests/` | Tests for the project |
| `requirements.txt` | Python dependencies |

## Privacy and safety

- Uploaded lockfiles are only read as data. Nothing from your project is installed or executed.
- Package names and versions are sent to OSV.dev to look up vulnerabilities, and nothing else.

## Ideas for what's next

- Support for more ecosystems and lockfile formats
- Severity information and smarter prioritization
- Safer-version upgrade suggestions
- Package health signals (deprecated, abandoned, license issues)
- Exportable reports
- A dependency graph view

## The team

Built by **Clutch Crew** for **BYTE RACE 2026**.
