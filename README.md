# js_secret_scanner_gui
Good. Now I have a full picture of the tool. I'll build a complete desktop GUI using Python's `tkinter` (zero dependencies, ships with Python, works on Kali/Linux) — a dark hacker-aesthetic terminal-style GUI that wraps every feature of the scanner.Here's what the GUI gives you — both files must be in the same folder:

```bash
# Install tkinter if not present on Kali
sudo apt install python3-tk -y

# Run the GUI
python3 js_secret_scanner_gui.py
```

---

## GUI Features

**Left sidebar — Config Panel**
- Mode selector: JS Files only / Endpoints only / Both at once
- File browser for `js_files.txt` and `ALL_secret_endpoints.txt`
- Thread count spinner (1–30)
- HTTP method checkboxes (GET, POST, OPTIONS, HEAD)
- Output path selector
- `▶ START SCAN` / `■ STOP` / `◉ OPEN REPORT` buttons
- Live progress bar with status messages

**Top bar**
- `Paste JS URLs` — opens a dialog to paste URLs directly without needing a file
- `Paste Endpoints` — same for endpoints; auto-saves to a temp `.txt` and uses it

**Stats bar** — live counters for Total / JS Files / Endpoints / Critical / High / Medium / Low / Total Findings

**Tab 1 — RESULTS**
- Sortable table: URL, Mode, Status, Snapshots, Findings, Severity
- Filter by text search or severity badge buttons (ALL / CRITICAL / HIGH / MEDIUM / FINDINGS)
- Click any row → bottom detail pane shows full breakdown: DNS, snapshots with Wayback links, all findings with redacted matches, CDX debug log

**Tab 2 — LIVE LOG**
- Real-time colour-coded output streamed from the scanner process
- Cyan = JS URLs, Green = endpoints, Red = findings, Yellow = warnings, Dim = CDX strategy debug

**Tab 3 — PATTERNS**
- Browse all 70+ detection patterns sorted by severity with colour coding
