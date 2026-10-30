# BREAKPOINT Student Information System (BP-SIS)

BP-SIS is a fictional university portal for the BREAKPOINT cybersecurity workshop. This package contains the student-facing Blue Team target with three scoped weaknesses.

The application is for isolated, authorized training only. Both versions bind to `127.0.0.1` by default. Do not expose either version to the public internet.

## Requirements

- Python 3.11+
- A browser

## Install and run on Windows

From this folder:

```powershell
py -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r requirements.txt
.\run-vulnerable.bat
```

The Windows launcher automatically uses `.venv` when it exists. If you prefer not to create a virtual environment, install the dependency for the active Python and run the launcher:

```powershell
py -m pip install -r requirements.txt
.\run-vulnerable.bat
```

Open `http://127.0.0.1:8765`.

Set another local port if needed:

```powershell
$env:BP_SIS_PORT = "8766"
py vulnerable\app.py
```

## Demo accounts

All data is fictional.

| Role | Username | Password |
|---|---|---|
| Student | `alex.rivera` | `BlueTeam101!` |
| Student | `bea.santos` | `BlueTeam102!` |
| Faculty | `morgan.lee` | `Faculty2026!` |
| Administrator | `jordan.reyes` | `Admin2026!` |

## Resetting data

The app creates or refreshes its fictional SQLite database in `vulnerable/data/bp_sis.sqlite3`. Stop the server and delete that file to reseed it.

## Tests

From the project root:

```powershell
py -m unittest discover -s tests -v
```

The tests use temporary databases and do not modify the demo databases.
