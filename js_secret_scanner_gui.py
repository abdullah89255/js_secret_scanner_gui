#!/usr/bin/env python3
"""
╔══════════════════════════════════════════════════════════════╗
║        JS Secret Scanner — GUI Edition  v1.0                ║
║        Wayback Machine + Endpoint Checker                    ║
║                                                              ║
║  Requires: Python 3.8+ with tkinter (standard on Kali)      ║
║  Place in same folder as js_secret_scanner.py               ║
║                                                              ║
║  Run: python3 js_secret_scanner_gui.py                      ║
╚══════════════════════════════════════════════════════════════╝
"""

import tkinter as tk
from tkinter import ttk, filedialog, messagebox, scrolledtext
import threading
import subprocess
import sys
import os
import json
import time
import webbrowser
import re
from datetime import datetime
from pathlib import Path

# ── Resolve path to the backend scanner ───────────────────────
SCANNER_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                             "js_secret_scanner.py")

# ══════════════════════════════════════════════════════════════
#  COLOUR PALETTE  (dark terminal / hacker aesthetic)
# ══════════════════════════════════════════════════════════════
C = {
    "bg":         "#0a0e14",   # near-black
    "bg2":        "#0f1521",   # panel bg
    "bg3":        "#151d2e",   # input/card bg
    "border":     "#1e2d47",   # subtle border
    "accent":     "#00d4ff",   # cyan
    "accent2":    "#00ff9d",   # green
    "accent3":    "#ff6b35",   # orange
    "warn":       "#ffd700",   # yellow
    "danger":     "#ff3b5c",   # red
    "text":       "#c9d8eb",   # main text
    "text_dim":   "#4a6080",   # dim
    "text_bright":"#ffffff",   # bright white
    "critical":   "#ff3b5c",
    "high":       "#ff8c42",
    "medium":     "#ffd700",
    "low":        "#00ff9d",
    "clean":      "#2a9d6e",
    "scrollbar":  "#1e2d47",
    "sel":        "#1a3560",
}

FONT_MONO  = ("JetBrains Mono", 10) if sys.platform != "darwin" else ("Menlo", 10)
FONT_MONO_S= ("JetBrains Mono", 9)
FONT_HEAD  = ("JetBrains Mono", 14, "bold")
FONT_TITLE = ("JetBrains Mono", 20, "bold")
FONT_LABEL = ("JetBrains Mono", 10)
FONT_BTN   = ("JetBrains Mono", 10, "bold")
FONT_SMALL = ("JetBrains Mono", 8)

# ══════════════════════════════════════════════════════════════
#  HELPER WIDGETS
# ══════════════════════════════════════════════════════════════

def styled_frame(parent, **kw):
    kw.setdefault("bg", C["bg2"])
    kw.setdefault("bd", 0)
    kw.setdefault("highlightthickness", 1)
    kw.setdefault("highlightbackground", C["border"])
    return tk.Frame(parent, **kw)

def label(parent, text, color=None, font=None, **kw):
    kw["bg"] = kw.get("bg", parent.cget("bg"))
    kw["fg"] = color or C["text"]
    kw["font"] = font or FONT_LABEL
    kw["text"] = text
    return tk.Label(parent, **kw)

def accent_button(parent, text, command, color=None, width=18):
    c = color or C["accent"]
    btn = tk.Button(
        parent, text=text, command=command,
        bg=C["bg3"], fg=c, font=FONT_BTN,
        relief="flat", bd=0, padx=14, pady=8,
        cursor="hand2", width=width,
        highlightthickness=1, highlightbackground=c,
        activebackground=c, activeforeground=C["bg"],
    )
    def _enter(e): btn.config(bg=c, fg=C["bg"])
    def _leave(e): btn.config(bg=C["bg3"], fg=c)
    btn.bind("<Enter>", _enter)
    btn.bind("<Leave>", _leave)
    return btn

def entry_field(parent, textvariable=None, width=40, placeholder=""):
    e = tk.Entry(
        parent,
        textvariable=textvariable,
        bg=C["bg3"], fg=C["text"],
        insertbackground=C["accent"],
        relief="flat", bd=0,
        font=FONT_MONO, width=width,
        highlightthickness=1,
        highlightbackground=C["border"],
        highlightcolor=C["accent"],
    )
    if placeholder and textvariable and not textvariable.get():
        e.insert(0, placeholder)
        e.config(fg=C["text_dim"])
        def _focus_in(ev):
            if e.get() == placeholder:
                e.delete(0, "end")
                e.config(fg=C["text"])
        def _focus_out(ev):
            if not e.get():
                e.insert(0, placeholder)
                e.config(fg=C["text_dim"])
        e.bind("<FocusIn>",  _focus_in)
        e.bind("<FocusOut>", _focus_out)
    return e

def separator(parent, color=None, pady=6):
    f = tk.Frame(parent, bg=color or C["border"], height=1)
    f.pack(fill="x", padx=16, pady=pady)
    return f

# ══════════════════════════════════════════════════════════════
#  LIVE LOG WIDGET
# ══════════════════════════════════════════════════════════════
class LiveLog(tk.Frame):
    TAG_COLORS = {
        "[JS]":      C["accent"],
        "[EP]":      C["accent2"],
        "findings":  C["danger"],
        "clean":     C["clean"],
        "ERROR":     C["danger"],
        "CRITICAL":  C["critical"],
        "HIGH":      C["high"],
        "MEDIUM":    C["medium"],
        "LOW":       C["low"],
        "scanned":   C["accent2"],
        "no_snapshot": C["warn"],
        "strategy":  C["text_dim"],
        "CDX":       C["text_dim"],
        "===":       C["accent"],
        "COMPLETE":  C["accent2"],
        "findings":  C["danger"],
    }

    def __init__(self, parent, **kw):
        super().__init__(parent, bg=C["bg"], **kw)
        self._build()

    def _build(self):
        hdr = tk.Frame(self, bg=C["bg2"], pady=4)
        hdr.pack(fill="x")
        label(hdr, "  ◈  LIVE OUTPUT", color=C["accent"],
              font=FONT_BTN, bg=C["bg2"]).pack(side="left")
        accent_button(hdr, "Clear", self.clear, color=C["text_dim"],
                      width=8).pack(side="right", padx=6, pady=2)

        self.text = scrolledtext.ScrolledText(
            self,
            bg=C["bg"], fg=C["text"],
            font=FONT_MONO_S,
            relief="flat", bd=0,
            wrap="word",
            state="disabled",
            insertbackground=C["accent"],
            selectbackground=C["sel"],
        )
        self.text.pack(fill="both", expand=True, padx=2, pady=2)
        self.text.vbar.config(
            bg=C["bg2"], troughcolor=C["bg"],
            activebackground=C["accent"], width=8,
        )
        # Configure colour tags
        for tag, color in self.TAG_COLORS.items():
            self.text.tag_config(tag, foreground=color)
        self.text.tag_config("dim",    foreground=C["text_dim"])
        self.text.tag_config("bright", foreground=C["text_bright"])
        self.text.tag_config("ts",     foreground=C["text_dim"])

    def append(self, line):
        self.text.config(state="normal")
        ts = datetime.now().strftime("%H:%M:%S")
        self.text.insert("end", f"[{ts}] ", "ts")

        # Colour-code by keyword
        colored = False
        for kw, color in self.TAG_COLORS.items():
            if kw in line:
                tag = kw.replace(" ", "_")
                self.text.tag_config(tag, foreground=color)
                self.text.insert("end", line + "\n", tag)
                colored = True
                break
        if not colored:
            self.text.insert("end", line + "\n")

        self.text.see("end")
        self.text.config(state="disabled")

    def clear(self):
        self.text.config(state="normal")
        self.text.delete("1.0", "end")
        self.text.config(state="disabled")

# ══════════════════════════════════════════════════════════════
#  RESULTS TABLE WIDGET
# ══════════════════════════════════════════════════════════════
class ResultsTable(tk.Frame):
    COLS = [
        ("URL",        420, "w"),
        ("Mode",        55, "center"),
        ("Status",      90, "center"),
        ("Snapshots",   75, "center"),
        ("Findings",    70, "center"),
        ("Severity",    80, "center"),
    ]

    def __init__(self, parent, on_select=None, **kw):
        super().__init__(parent, bg=C["bg2"], **kw)
        self.on_select = on_select
        self._rows = []
        self._build()

    def _build(self):
        hdr = tk.Frame(self, bg=C["bg2"], pady=4)
        hdr.pack(fill="x")
        label(hdr, "  ◈  RESULTS", color=C["accent"],
              font=FONT_BTN, bg=C["bg2"]).pack(side="left")
        self._count_lbl = label(hdr, "0 items",
                                color=C["text_dim"], bg=C["bg2"])
        self._count_lbl.pack(side="left", padx=12)

        # Filter bar
        fbar = tk.Frame(self, bg=C["bg2"])
        fbar.pack(fill="x", padx=8, pady=2)
        label(fbar, "Filter:", bg=C["bg2"],
              color=C["text_dim"]).pack(side="left")
        self._filter_var = tk.StringVar()
        self._filter_var.trace_add("write", self._apply_filter)
        fe = entry_field(fbar, textvariable=self._filter_var, width=30)
        fe.pack(side="left", padx=6)

        for sev, color in [("ALL", C["text"]), ("CRITICAL", C["critical"]),
                            ("HIGH", C["high"]), ("MEDIUM", C["medium"]),
                            ("FINDINGS", C["accent3"])]:
            btn = tk.Button(
                fbar, text=sev, font=FONT_SMALL,
                bg=C["bg3"], fg=color, relief="flat", bd=0,
                padx=8, pady=3, cursor="hand2",
                command=lambda s=sev: self._filter_sev(s),
            )
            btn.pack(side="left", padx=2)

        # Treeview
        style = ttk.Style()
        style.theme_use("clam")
        style.configure("Scan.Treeview",
            background=C["bg"], foreground=C["text"],
            fieldbackground=C["bg"], rowheight=24,
            font=FONT_MONO_S, borderwidth=0,
        )
        style.configure("Scan.Treeview.Heading",
            background=C["bg3"], foreground=C["accent"],
            font=("JetBrains Mono", 9, "bold"),
            relief="flat", borderwidth=0,
        )
        style.map("Scan.Treeview",
            background=[("selected", C["sel"])],
            foreground=[("selected", C["text_bright"])],
        )

        cols = [c[0] for c in self.COLS]
        self.tree = ttk.Treeview(
            self, columns=cols, show="headings",
            style="Scan.Treeview", selectmode="browse",
        )
        for col, width, anchor in self.COLS:
            self.tree.heading(col, text=col)
            self.tree.column(col, width=width, anchor=anchor, minwidth=40)

        vsb = tk.Scrollbar(self, orient="vertical",
                           command=self.tree.yview,
                           bg=C["bg2"], troughcolor=C["bg"],
                           width=8)
        self.tree.configure(yscrollcommand=vsb.set)
        vsb.pack(side="right", fill="y")
        self.tree.pack(fill="both", expand=True, padx=4, pady=4)

        self.tree.bind("<<TreeviewSelect>>", self._on_select)

        # Severity tags
        self.tree.tag_configure("critical", foreground=C["critical"])
        self.tree.tag_configure("high",     foreground=C["high"])
        self.tree.tag_configure("medium",   foreground=C["medium"])
        self.tree.tag_configure("low",      foreground=C["low"])
        self.tree.tag_configure("clean",    foreground=C["clean"])
        self.tree.tag_configure("alt",      background="#0c1220")

    def load(self, results):
        self._rows = results
        self._render(results)

    def _render(self, rows):
        self.tree.delete(*self.tree.get_children())
        for i, r in enumerate(rows):
            url   = r.get("url", "")
            mode  = r.get("mode", "js").upper()
            st    = r.get("status", "?")
            snaps = len(r.get("snapshots", []))
            fn    = len(r.get("findings", []))
            sev   = self._max_severity(r)
            tag   = sev.lower() if fn else "clean"
            if i % 2 == 1:
                tag = tag  # alt rows handled separately
            self.tree.insert("", "end",
                values=(url[:80], mode, st, snaps, fn or "–", sev or "clean"),
                tags=(tag,),
                iid=str(i),
            )
        self._count_lbl.config(text=f"{len(rows)} items")

    def _max_severity(self, r):
        order = ["CRITICAL", "HIGH", "MEDIUM", "LOW"]
        sevs  = {f["severity"] for f in r.get("findings", [])}
        for s in order:
            if s in sevs:
                return s
        return ""

    def _apply_filter(self, *_):
        q = self._filter_var.get().lower()
        filtered = [r for r in self._rows
                    if q in r.get("url","").lower()
                    or q in r.get("status","").lower()]
        self._render(filtered)

    def _filter_sev(self, sev):
        if sev == "ALL":
            self._render(self._rows)
        elif sev == "FINDINGS":
            self._render([r for r in self._rows if r.get("findings")])
        else:
            self._render([r for r in self._rows
                          if self._max_severity(r) == sev])

    def _on_select(self, _event):
        sel = self.tree.selection()
        if sel and self.on_select:
            idx = int(sel[0])
            if idx < len(self._rows):
                self.on_select(self._rows[idx])

# ══════════════════════════════════════════════════════════════
#  DETAIL PANEL
# ══════════════════════════════════════════════════════════════
class DetailPanel(tk.Frame):
    SEV_C = {"CRITICAL": C["critical"], "HIGH": C["high"],
             "MEDIUM": C["medium"], "LOW": C["low"]}

    def __init__(self, parent, **kw):
        super().__init__(parent, bg=C["bg2"], **kw)
        self._build()

    def _build(self):
        hdr = tk.Frame(self, bg=C["bg2"], pady=4)
        hdr.pack(fill="x")
        label(hdr, "  ◈  FINDING DETAIL", color=C["accent"],
              font=FONT_BTN, bg=C["bg2"]).pack(side="left")

        self.text = scrolledtext.ScrolledText(
            self, bg=C["bg"], fg=C["text"],
            font=FONT_MONO_S, relief="flat", bd=0,
            wrap="word", state="disabled",
        )
        self.text.pack(fill="both", expand=True, padx=4, pady=4)

        for sev, color in self.SEV_C.items():
            self.text.tag_config(sev, foreground=color, font=(*FONT_MONO_S[:2], "bold"))
        self.text.tag_config("url",    foreground=C["accent"])
        self.text.tag_config("key",    foreground=C["text_dim"])
        self.text.tag_config("val",    foreground=C["text"])
        self.text.tag_config("match",  foreground=C["accent3"])
        self.text.tag_config("ctx",    foreground=C["text_dim"])
        self.text.tag_config("hr",     foreground=C["border"])
        self.text.tag_config("snap",   foreground=C["accent2"])

    def _w(self, text, tag=None):
        self.text.config(state="normal")
        self.text.insert("end", text, tag or "")
        self.text.config(state="disabled")

    def show(self, result):
        self.text.config(state="normal")
        self.text.delete("1.0", "end")
        self.text.config(state="disabled")

        url     = result.get("url", "")
        mode    = result.get("mode", "js").upper()
        status  = result.get("status", "?")
        errors  = result.get("errors", [])
        snaps   = result.get("snapshots", [])
        finds   = result.get("findings", [])

        self._w("URL:    ", "key"); self._w(url + "\n", "url")
        self._w("Mode:   ", "key"); self._w(mode + "\n", "val")
        self._w("Status: ", "key"); self._w(status + "\n", "val")
        self._w("─" * 60 + "\n", "hr")

        # Snapshots
        if snaps:
            self._w(f"Snapshots ({len(snaps)}):\n", "key")
            for s in snaps:
                ts  = s.get("timestamp", "?")
                wbu = s.get("wb_url",    "")
                nb  = s.get("bytes",     "?")
                fc  = s.get("finding_count", "?")
                self._w(f"  [{ts}] ", "snap")
                self._w(f"{nb} bytes, {fc} findings\n", "ctx")
                self._w(f"  {wbu}\n", "url")
            self._w("─" * 60 + "\n", "hr")

        # Probes (endpoint mode)
        for probe in result.get("probes", []):
            self._w(f"{probe['method']} ", "key")
            st_c = "snap" if (probe.get("status") or 0) < 400 else "CRITICAL"
            self._w(f"HTTP {probe.get('status','?')}  ", st_c)
            self._w(f"{probe.get('elapsed_ms',0)} ms\n", "ctx")
            for ci in probe.get("cors_issues", []):
                self._w(f"  CORS: {ci}\n", "HIGH")
            for hk, hv in (probe.get("headers") or {}).items():
                self._w(f"  {hk}: ", "key")
                self._w(f"{hv}\n", "ctx")
        if result.get("probes"):
            self._w("─" * 60 + "\n", "hr")

        # Findings
        if finds:
            self._w(f"Findings ({len(finds)}):\n", "key")
            for f in finds:
                sev = f.get("severity", "LOW")
                self._w(f"  [{sev}] ", sev)
                self._w(f"{f.get('pattern','?')}\n", "val")
                self._w(f"    Match:   ", "key")
                self._w(f"{f.get('matched','?')}\n", "match")
                self._w(f"    Line:    ", "key")
                self._w(f"{f.get('line_no','?')}\n", "ctx")
                self._w(f"    Context: ", "key")
                self._w(f"{f.get('context','?')[:100]}\n", "ctx")
                self._w("\n")
        else:
            self._w("No findings detected.\n", "ctx")

        # Errors / debug info
        if errors:
            self._w("─" * 60 + "\n", "hr")
            self._w("Debug log:\n", "key")
            for e in errors:
                self._w(f"  {e}\n", "ctx")

        self.text.see("1.0")

    def clear(self):
        self.text.config(state="normal")
        self.text.delete("1.0", "end")
        self.text.config(state="disabled")

# ══════════════════════════════════════════════════════════════
#  STATS BAR
# ══════════════════════════════════════════════════════════════
class StatsBar(tk.Frame):
    STATS = [
        ("TOTAL",    "total",    C["text_bright"]),
        ("JS FILES", "js",       C["accent"]),
        ("ENDPOINTS","ep",       C["accent2"]),
        ("CRITICAL", "critical", C["critical"]),
        ("HIGH",     "high",     C["high"]),
        ("MEDIUM",   "medium",   C["medium"]),
        ("LOW",      "low",      C["low"]),
        ("FINDINGS", "findings", C["accent3"]),
    ]

    def __init__(self, parent, **kw):
        super().__init__(parent, bg=C["bg2"], **kw)
        self._vars = {}
        self._build()

    def _build(self):
        for label_text, key, color in self.STATS:
            cell = tk.Frame(self, bg=C["bg3"],
                            highlightthickness=1,
                            highlightbackground=C["border"])
            cell.pack(side="left", fill="y", padx=3, pady=4, ipadx=10, ipady=4)
            var = tk.StringVar(value="0")
            self._vars[key] = var
            tk.Label(cell, textvariable=var, bg=C["bg3"],
                     fg=color, font=("JetBrains Mono", 16, "bold")).pack()
            tk.Label(cell, text=label_text, bg=C["bg3"],
                     fg=C["text_dim"], font=FONT_SMALL).pack()

    def update(self, results):
        from collections import defaultdict
        sev = defaultdict(int)
        js_c = ep_c = 0
        for r in results:
            if r.get("mode") == "js":    js_c += 1
            else:                         ep_c += 1
            for f in r.get("findings", []):
                sev[f["severity"]] += 1
        total_f = sum(sev.values())
        self._vars["total"].set(str(len(results)))
        self._vars["js"].set(str(js_c))
        self._vars["ep"].set(str(ep_c))
        self._vars["critical"].set(str(sev["CRITICAL"]))
        self._vars["high"].set(str(sev["HIGH"]))
        self._vars["medium"].set(str(sev["MEDIUM"]))
        self._vars["low"].set(str(sev["LOW"]))
        self._vars["findings"].set(str(total_f))

    def reset(self):
        for v in self._vars.values():
            v.set("0")

# ══════════════════════════════════════════════════════════════
#  CONFIG PANEL (left sidebar)
# ══════════════════════════════════════════════════════════════
class ConfigPanel(tk.Frame):
    PANEL_WIDTH = 260  # fixed sidebar width in pixels

    def __init__(self, parent, on_scan, on_stop, **kw):
        kw.setdefault("width", self.PANEL_WIDTH)
        super().__init__(parent, bg=C["bg2"],
                         highlightthickness=1,
                         highlightbackground=C["border"], **kw)
        self.pack_propagate(False)  # honour fixed width
        self.on_scan = on_scan
        self.on_stop = on_stop
        self._build()

    def _build(self):
        # ── Scrollable canvas wrapper ────────────────────────
        # This ensures the Action Buttons are always reachable even on
        # small screens where the sidebar content overflows vertically.
        canvas = tk.Canvas(self, bg=C["bg2"], bd=0,
                           highlightthickness=0,
                           width=self.PANEL_WIDTH - 4)
        vsb = tk.Scrollbar(self, orient="vertical", command=canvas.yview,
                           bg=C["bg2"], troughcolor=C["bg"],
                           activebackground=C["accent"], width=6)
        canvas.configure(yscrollcommand=vsb.set)

        vsb.pack(side="right", fill="y")
        canvas.pack(side="left", fill="both", expand=True)

        # Inner frame that holds all the actual widgets
        inner = tk.Frame(canvas, bg=C["bg2"])
        win_id = canvas.create_window((0, 0), window=inner, anchor="nw",
                                      width=self.PANEL_WIDTH - 10)

        def _on_configure(event):
            canvas.configure(scrollregion=canvas.bbox("all"))

        inner.bind("<Configure>", _on_configure)

        # Mouse-wheel scrolling (works on Linux/Windows/macOS)
        def _on_mousewheel(event):
            if event.num == 4:        # Linux scroll-up
                canvas.yview_scroll(-1, "units")
            elif event.num == 5:      # Linux scroll-down
                canvas.yview_scroll(1, "units")
            else:                     # Windows / macOS
                canvas.yview_scroll(int(-1 * (event.delta / 120)), "units")

        canvas.bind_all("<MouseWheel>", _on_mousewheel)
        canvas.bind_all("<Button-4>",   _on_mousewheel)
        canvas.bind_all("<Button-5>",   _on_mousewheel)

        # Alias so all subsequent pack() calls target the inner frame
        p = inner   # shorthand

        # ── Title ───────────────────────────────────────────
        title_frame = tk.Frame(p, bg=C["bg2"], pady=12)
        title_frame.pack(fill="x")
        tk.Label(title_frame, text="◈", bg=C["bg2"],
                 fg=C["accent"], font=("JetBrains Mono", 24)).pack()
        tk.Label(title_frame, text="JS SECRET\nSCANNER",
                 bg=C["bg2"], fg=C["text_bright"],
                 font=("JetBrains Mono", 13, "bold"),
                 justify="center").pack()
        tk.Label(title_frame, text="Wayback Machine Edition",
                 bg=C["bg2"], fg=C["text_dim"],
                 font=FONT_SMALL).pack()

        def _sep(parent=p): separator(parent)
        _sep()

        # ── Mode selector ────────────────────────────────────
        label(p, "  SCAN MODE", color=C["accent"],
              font=FONT_BTN).pack(anchor="w", pady=(6, 2))

        self.mode_var = tk.StringVar(value="both")
        modes = [("JS Files (Wayback)", "js"),
                 ("Endpoints (Live)",   "ep"),
                 ("Both Modes",         "both")]
        for txt, val in modes:
            tk.Radiobutton(
                p, text=txt, variable=self.mode_var, value=val,
                bg=C["bg2"], fg=C["text"], selectcolor=C["bg3"],
                activebackground=C["bg2"], activeforeground=C["accent"],
                font=FONT_LABEL, indicatoron=True,
                command=self._mode_changed,
            ).pack(anchor="w", padx=12, pady=1)

        _sep()

        # ── JS File input ────────────────────────────────────
        self.js_frame = tk.Frame(p, bg=C["bg2"])
        self.js_frame.pack(fill="x")
        label(self.js_frame, "  JS FILE LIST", color=C["accent"],
              font=FONT_BTN).pack(anchor="w", pady=(4, 2))
        row1 = tk.Frame(self.js_frame, bg=C["bg2"])
        row1.pack(fill="x", padx=8, pady=2)
        self.js_path_var = tk.StringVar(value="js_files.txt")
        self.js_entry = entry_field(row1, textvariable=self.js_path_var, width=18)
        self.js_entry.pack(side="left", fill="x", expand=True)
        accent_button(row1, "Browse", self._browse_js,
                      color=C["accent"], width=7).pack(side="right", padx=4)

        _sep()

        # ── Endpoint file input ───────────────────────────────
        self.ep_frame = tk.Frame(p, bg=C["bg2"])
        self.ep_frame.pack(fill="x")
        label(self.ep_frame, "  ENDPOINTS FILE", color=C["accent2"],
              font=FONT_BTN).pack(anchor="w", pady=(4, 2))
        row2 = tk.Frame(self.ep_frame, bg=C["bg2"])
        row2.pack(fill="x", padx=8, pady=2)
        self.ep_path_var = tk.StringVar(value="ALL_secret_endpoints.txt")
        self.ep_entry = entry_field(row2, textvariable=self.ep_path_var, width=18)
        self.ep_entry.pack(side="left", fill="x", expand=True)
        accent_button(row2, "Browse", self._browse_ep,
                      color=C["accent2"], width=7).pack(side="right", padx=4)

        _sep()

        # ── Options ──────────────────────────────────────────
        label(p, "  OPTIONS", color=C["accent"], font=FONT_BTN).pack(anchor="w", pady=(4, 2))

        opts = tk.Frame(p, bg=C["bg2"])
        opts.pack(fill="x", padx=8)

        label(opts, "Threads:", bg=C["bg2"],
              color=C["text_dim"]).grid(row=0, column=0, sticky="w", pady=3)
        self.threads_var = tk.IntVar(value=5)
        tk.Spinbox(opts, from_=1, to=30, textvariable=self.threads_var,
                   width=5, bg=C["bg3"], fg=C["text"],
                   buttonbackground=C["bg3"],
                   relief="flat", font=FONT_MONO,
                   highlightthickness=1,
                   highlightbackground=C["border"]).grid(
                   row=0, column=1, sticky="w", padx=6)

        label(opts, "HTTP Methods:", bg=C["bg2"],
              color=C["text_dim"]).grid(row=1, column=0, sticky="w", pady=3)
        meth_frame = tk.Frame(opts, bg=C["bg2"])
        meth_frame.grid(row=1, column=1, sticky="w", pady=3)
        self.method_vars = {}
        for m in ["GET", "POST", "OPTIONS", "HEAD"]:
            v = tk.BooleanVar(value=(m == "GET"))
            self.method_vars[m] = v
            tk.Checkbutton(meth_frame, text=m, variable=v,
                           bg=C["bg2"], fg=C["text"],
                           selectcolor=C["bg3"],
                           activebackground=C["bg2"],
                           activeforeground=C["accent"],
                           font=FONT_SMALL).pack(side="left")

        _sep()

        # ── Output ───────────────────────────────────────────
        label(p, "  OUTPUT", color=C["accent"], font=FONT_BTN).pack(anchor="w", pady=(4, 2))
        out_row = tk.Frame(p, bg=C["bg2"])
        out_row.pack(fill="x", padx=8, pady=2)
        self.out_var = tk.StringVar(value="scan_report.html")
        self.out_entry = entry_field(out_row, textvariable=self.out_var, width=18)
        self.out_entry.pack(side="left", fill="x", expand=True)
        accent_button(out_row, "Browse", self._browse_out,
                      color=C["text_dim"], width=7).pack(side="right", padx=4)

        _sep()

        # ── Action buttons ───────────────────────────────────
        btn_frame = tk.Frame(p, bg=C["bg2"])
        btn_frame.pack(fill="x", padx=8, pady=8)

        self.scan_btn = accent_button(btn_frame, "▶  START SCAN",
                                      self.on_scan, color=C["accent2"], width=20)
        self.scan_btn.pack(fill="x", pady=3)

        self.stop_btn = accent_button(btn_frame, "■  STOP",
                                      self.on_stop, color=C["danger"], width=20)
        self.stop_btn.pack(fill="x", pady=3)
        self.stop_btn.config(state="disabled")

        self.report_btn = accent_button(btn_frame, "◉  OPEN REPORT",
                                        self._open_report, color=C["warn"], width=20)
        self.report_btn.pack(fill="x", pady=3)
        self.report_btn.config(state="disabled")

        # ── Progress bar ─────────────────────────────────────
        _sep()
        self.prog_var = tk.DoubleVar(value=0)
        self.prog_lbl = label(p, "  Ready", color=C["text_dim"],
                              font=FONT_SMALL)
        self.prog_lbl.pack(anchor="w", padx=8)
        self.prog_bar = ttk.Progressbar(p, variable=self.prog_var,
                                        mode="indeterminate", length=200)
        self.prog_bar.pack(fill="x", padx=8, pady=4)

        # Style the progressbar
        style = ttk.Style()
        style.configure("TProgressbar",
                        troughcolor=C["bg3"],
                        background=C["accent"],
                        thickness=6)

        # Bottom spacer + scanner info
        tk.Frame(p, bg=C["bg2"], height=8).pack()
        info = tk.Frame(p, bg=C["bg2"], pady=6)
        info.pack(fill="x")
        label(info, f"  v3.0  |  {len(self._get_pattern_count())} patterns",
              color=C["text_dim"], font=FONT_SMALL, bg=C["bg2"]).pack(anchor="w")

    def _get_pattern_count(self):
        try:
            import importlib.util
            spec = importlib.util.spec_from_file_location("scanner", SCANNER_PATH)
            mod  = importlib.util.load_module_from_spec(spec) if hasattr(importlib.util, 'load_module_from_spec') else None
            return list(range(70))
        except Exception:
            return list(range(70))

    def _mode_changed(self):
        mode = self.mode_var.get()
        state_js = "normal" if mode in ("js", "both") else "disabled"
        state_ep = "normal" if mode in ("ep", "both") else "disabled"
        self.js_entry.config(state=state_js)
        self.ep_entry.config(state=state_ep)

    def _browse_js(self):
        p = filedialog.askopenfilename(
            title="Select JS URL list",
            filetypes=[("Text files", "*.txt"), ("All files", "*.*")]
        )
        if p:
            self.js_path_var.set(p)

    def _browse_ep(self):
        p = filedialog.askopenfilename(
            title="Select endpoint list",
            filetypes=[("Text files", "*.txt"), ("All files", "*.*")]
        )
        if p:
            self.ep_path_var.set(p)

    def _browse_out(self):
        p = filedialog.asksaveasfilename(
            title="Save report as",
            defaultextension=".html",
            filetypes=[("HTML report", "*.html"), ("All files", "*.*")]
        )
        if p:
            self.out_var.set(p)

    def _open_report(self):
        path = self.out_var.get()
        if os.path.exists(path):
            webbrowser.open("file://" + os.path.abspath(path))
        else:
            messagebox.showwarning("Not found",
                                   f"Report not found:\n{path}\n\nRun a scan first.")

    def set_scanning(self, scanning: bool):
        state_scan = "disabled" if scanning else "normal"
        state_stop = "normal"  if scanning else "disabled"
        self.scan_btn.config(state=state_scan)
        self.stop_btn.config(state=state_stop)
        if scanning:
            self.report_btn.config(state="disabled")
            self.prog_bar.start(12)
            self.prog_lbl.config(text="  Scanning…", fg=C["accent"])
        else:
            self.prog_bar.stop()
            self.prog_var.set(0)

    def set_done(self):
        self.set_scanning(False)
        self.report_btn.config(state="normal")
        self.prog_lbl.config(text="  Scan complete", fg=C["accent2"])

    def set_error(self, msg):
        self.set_scanning(False)
        self.prog_lbl.config(text=f"  Error: {msg[:30]}", fg=C["danger"])

    def get_config(self):
        methods = [m for m, v in self.method_vars.items() if v.get()]
        return {
            "mode":    self.mode_var.get(),
            "js":      self.js_path_var.get(),
            "ep":      self.ep_path_var.get(),
            "threads": self.threads_var.get(),
            "methods": methods or ["GET"],
            "output":  self.out_var.get(),
            "json":    self.out_var.get().replace(".html", ".json"),
        }

# ══════════════════════════════════════════════════════════════
#  PASTE/MANUAL INPUT DIALOG
# ══════════════════════════════════════════════════════════════
class QuickInputDialog(tk.Toplevel):
    def __init__(self, parent, mode="js"):
        super().__init__(parent)
        self.title("Quick Input — paste URLs")
        self.configure(bg=C["bg"])
        self.resizable(True, True)
        self.geometry("640x440")
        self.result_path = None
        self._mode = mode
        self._build()
        self.grab_set()

    def _build(self):
        label(self, f"  Paste {'JS file URLs' if self._mode=='js' else 'endpoint URLs'} (one per line):",
              color=C["accent"], font=FONT_BTN, bg=C["bg"]).pack(anchor="w", padx=10, pady=8)

        self.text = scrolledtext.ScrolledText(
            self, bg=C["bg3"], fg=C["text"],
            font=FONT_MONO_S, relief="flat", bd=0,
            insertbackground=C["accent"],
        )
        self.text.pack(fill="both", expand=True, padx=10, pady=4)

        btn_row = tk.Frame(self, bg=C["bg"])
        btn_row.pack(fill="x", padx=10, pady=8)
        accent_button(btn_row, "Save & Use", self._save,
                      color=C["accent2"], width=14).pack(side="right", padx=4)
        accent_button(btn_row, "Cancel", self.destroy,
                      color=C["text_dim"], width=10).pack(side="right")

    def _save(self):
        content = self.text.get("1.0", "end").strip()
        if not content:
            messagebox.showwarning("Empty", "No URLs entered.", parent=self)
            return
        suffix = "js" if self._mode == "js" else "ep"
        fname  = f"quick_input_{suffix}_{int(time.time())}.txt"
        with open(fname, "w") as f:
            f.write(content)
        self.result_path = fname
        self.destroy()

# ══════════════════════════════════════════════════════════════
#  MAIN APPLICATION WINDOW
# ══════════════════════════════════════════════════════════════
class App(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("JS Secret Scanner — Wayback Machine Edition")
        self.configure(bg=C["bg"])
        self.geometry("1380x860")
        self.minsize(1100, 700)

        self._scan_proc   = None
        self._scan_thread = None
        self._results     = []
        self._stop_flag   = threading.Event()

        self._check_scanner()
        self._build()
        self._apply_icon()

    def _check_scanner(self):
        if not os.path.exists(SCANNER_PATH):
            messagebox.showerror(
                "Scanner Not Found",
                f"js_secret_scanner.py not found at:\n{SCANNER_PATH}\n\n"
                "Place js_secret_scanner_gui.py in the same folder as js_secret_scanner.py"
            )

    def _apply_icon(self):
        try:
            # Simple programmatic icon
            img = tk.PhotoImage(width=32, height=32)
            self.iconphoto(True, img)
        except Exception:
            pass

    def _build(self):
        # ── Top title bar ─────────────────────────────────────
        topbar = tk.Frame(self, bg=C["bg"],
                          highlightthickness=1,
                          highlightbackground=C["border"])
        topbar.pack(fill="x")

        tk.Label(topbar, text="◈  JS SECRET SCANNER",
                 bg=C["bg"], fg=C["accent"],
                 font=("JetBrains Mono", 13, "bold"),
                 pady=10, padx=16).pack(side="left")

        tk.Label(topbar, text="Wayback Machine + Endpoint Checker  v3.0",
                 bg=C["bg"], fg=C["text_dim"],
                 font=FONT_SMALL).pack(side="left")

        # Quick input buttons
        accent_button(topbar, "Paste JS URLs", self._quick_js,
                      color=C["accent"], width=14).pack(side="right", padx=4, pady=5)
        accent_button(topbar, "Paste Endpoints", self._quick_ep,
                      color=C["accent2"], width=16).pack(side="right", padx=4, pady=5)

        # ── Stats bar ─────────────────────────────────────────
        self.stats = StatsBar(self)
        self.stats.pack(fill="x", padx=6, pady=4)

        # ── Main layout ───────────────────────────────────────
        main = tk.Frame(self, bg=C["bg"])
        main.pack(fill="both", expand=True, padx=6, pady=4)

        # Left sidebar — fixed width, scrollable internally
        self.config_panel = ConfigPanel(main,
                                        on_scan=self._start_scan,
                                        on_stop=self._stop_scan)
        self.config_panel.pack(side="left", fill="y", padx=(0, 4))
        self.config_panel.config(width=ConfigPanel.PANEL_WIDTH)

        # Right area — tabs
        right = tk.Frame(main, bg=C["bg"])
        right.pack(side="right", fill="both", expand=True)

        nb_style = ttk.Style()
        nb_style.configure("Dark.TNotebook",
                            background=C["bg"], borderwidth=0)
        nb_style.configure("Dark.TNotebook.Tab",
                            background=C["bg2"], foreground=C["text_dim"],
                            font=FONT_BTN, padding=[12, 6],
                            borderwidth=0)
        nb_style.map("Dark.TNotebook.Tab",
                     background=[("selected", C["bg3"])],
                     foreground=[("selected", C["accent"])])

        self.nb = ttk.Notebook(right, style="Dark.TNotebook")
        self.nb.pack(fill="both", expand=True)

        # Tab 1 — Results
        results_tab = tk.Frame(self.nb, bg=C["bg"])
        self.nb.add(results_tab, text="  RESULTS  ")

        # Paned: table top, detail bottom
        pane = tk.PanedWindow(results_tab, orient="vertical",
                              bg=C["border"], sashwidth=4,
                              sashrelief="flat")
        pane.pack(fill="both", expand=True)

        self.results_table = ResultsTable(pane, on_select=self._show_detail)
        pane.add(self.results_table, minsize=180)

        self.detail = DetailPanel(pane)
        pane.add(self.detail, minsize=140)

        # Tab 2 — Live log
        log_tab = tk.Frame(self.nb, bg=C["bg"])
        self.nb.add(log_tab, text="  LIVE LOG  ")
        self.log = LiveLog(log_tab)
        self.log.pack(fill="both", expand=True)

        # Tab 3 — Pattern browser
        pat_tab = tk.Frame(self.nb, bg=C["bg"])
        self.nb.add(pat_tab, text="  PATTERNS  ")
        self._build_pattern_tab(pat_tab)

        # ── Status bar ────────────────────────────────────────
        status_bar = tk.Frame(self, bg=C["bg2"],
                              highlightthickness=1,
                              highlightbackground=C["border"])
        status_bar.pack(fill="x", side="bottom")
        self._status_var = tk.StringVar(value="Ready — load a file and start scanning")
        tk.Label(status_bar, textvariable=self._status_var,
                 bg=C["bg2"], fg=C["text_dim"],
                 font=FONT_SMALL, anchor="w", padx=12, pady=4).pack(side="left")
        tk.Label(status_bar, text=f"Scanner: {SCANNER_PATH}",
                 bg=C["bg2"], fg=C["text_dim"],
                 font=FONT_SMALL, padx=12).pack(side="right")

    def _build_pattern_tab(self, parent):
        label(parent, "  Loaded detection patterns (70+):",
              color=C["accent"], font=FONT_BTN).pack(anchor="w", pady=8, padx=10)

        # Try to load pattern names from the scanner
        patterns = self._load_patterns()

        cols = ["Pattern Name", "Severity"]
        style = ttk.Style()
        style.configure("Pat.Treeview",
                        background=C["bg"], foreground=C["text"],
                        fieldbackground=C["bg"], rowheight=22,
                        font=FONT_MONO_S, borderwidth=0)
        style.configure("Pat.Treeview.Heading",
                        background=C["bg3"], foreground=C["accent"],
                        font=("JetBrains Mono", 9, "bold"), relief="flat")

        tree = ttk.Treeview(parent, columns=cols, show="headings",
                             style="Pat.Treeview")
        tree.heading("Pattern Name", text="Pattern Name")
        tree.heading("Severity",     text="Severity")
        tree.column("Pattern Name",  width=380, anchor="w")
        tree.column("Severity",      width=100, anchor="center")

        SEV_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
        for name, sev in sorted(patterns, key=lambda x: (SEV_ORDER.get(x[1], 9), x[0])):
            tree.insert("", "end", values=(name, sev), tags=(sev.lower(),))

        tree.tag_configure("critical", foreground=C["critical"])
        tree.tag_configure("high",     foreground=C["high"])
        tree.tag_configure("medium",   foreground=C["medium"])
        tree.tag_configure("low",      foreground=C["low"])

        vsb = tk.Scrollbar(parent, orient="vertical", command=tree.yview,
                           bg=C["bg2"], troughcolor=C["bg"], width=8)
        tree.configure(yscrollcommand=vsb.set)
        vsb.pack(side="right", fill="y")
        tree.pack(fill="both", expand=True, padx=8, pady=4)

    def _load_patterns(self):
        SEVERITY = {
            "CRITICAL": {
                "RSA Private Key","DSA Private Key","EC Private Key","PGP Private Key",
                "Generic Private Key","SSH Private Key","AWS Secret Key","Password in Code",
                "Secret in Code","MongoDB URI","MySQL Connection","PostgreSQL Connection",
                "Redis Connection","JDBC Connection","Stripe Live Key","Basic Auth in URL",
                "Hardcoded Email+Pass","Credit Card Number","Social Security Number",
                "GCP Service Account","Env File Content","Azure Storage Key","Azure SAS Token",
            },
            "HIGH": {
                "AWS Access Key","GitHub Token","GitHub Classic Token","Slack Token",
                "Slack Webhook","Stripe Test Key","SendGrid API Key","Firebase API Key",
                "Mailgun API Key","Heroku API Key","Shopify Token","Shopify Secret",
                "NPM Token","Gitlab Token","Telegram Bot Token","Hugging Face Token",
                "OpenAI API Key","Anthropic API Key","Okta API Token","JWT Token",
                "FTP Credentials","Auth Token in Code","API Key in Code","Bearer Token",
                "Vault Token","Stack Trace","Debug Mode Flag",
            },
            "MEDIUM": {
                "Google API Key","Google OAuth Token","Firebase URL","Mailchimp API Key",
                "Stripe Public Key","Twilio Account SID","Twilio Auth Token","Algolia API Key",
                "Square Access Token","Square OAuth Secret","PayPal Client ID","Cloudinary URL",
                "Mapbox Token","S3 Bucket","Debug/Dev Endpoint","GraphQL Introspection",
                "Version Disclosure",
            },
            "LOW": {
                "Internal IP","Localhost Reference","JDBC Connection","Social Security Number",
            },
        }
        result = []
        for sev, names in SEVERITY.items():
            for name in names:
                result.append((name, sev))
        return result

    # ── Quick input helpers ───────────────────────────────────
    def _quick_js(self):
        dlg = QuickInputDialog(self, mode="js")
        self.wait_window(dlg)
        if dlg.result_path:
            self.config_panel.js_path_var.set(dlg.result_path)
            self.config_panel.mode_var.set("js")
            self.config_panel._mode_changed()
            self.log.append(f"[+] JS URL list saved to: {dlg.result_path}")

    def _quick_ep(self):
        dlg = QuickInputDialog(self, mode="ep")
        self.wait_window(dlg)
        if dlg.result_path:
            self.config_panel.ep_path_var.set(dlg.result_path)
            self.config_panel.mode_var.set("ep")
            self.config_panel._mode_changed()
            self.log.append(f"[+] Endpoint list saved to: {dlg.result_path}")

    # ── Scan management ───────────────────────────────────────
    def _start_scan(self):
        if not os.path.exists(SCANNER_PATH):
            messagebox.showerror("Missing", f"Scanner not found:\n{SCANNER_PATH}")
            return

        cfg = self.config_panel.get_config()

        # Validate file inputs
        if cfg["mode"] in ("js", "both"):
            if not os.path.exists(cfg["js"]):
                messagebox.showerror("File Not Found",
                                     f"JS file list not found:\n{cfg['js']}\n\n"
                                     "Use 'Paste JS URLs' to create one, or Browse to select.")
                return

        if cfg["mode"] in ("ep", "both"):
            if not os.path.exists(cfg["ep"]):
                messagebox.showerror("File Not Found",
                                     f"Endpoint list not found:\n{cfg['ep']}\n\n"
                                     "Use 'Paste Endpoints' to create one, or Browse to select.")
                return

        # Reset state
        self._results = []
        self._stop_flag.clear()
        self.results_table.load([])
        self.detail.clear()
        self.stats.reset()
        self.log.clear()
        self.config_panel.set_scanning(True)
        self.nb.select(1)  # switch to log tab

        # Build command
        cmd = [sys.executable, SCANNER_PATH]
        if cfg["mode"] in ("js", "both"):
            cmd += ["--js", cfg["js"]]
        if cfg["mode"] in ("ep", "both"):
            cmd += ["--endpoints", cfg["ep"]]
        cmd += ["-t", str(cfg["threads"])]
        cmd += ["-o", cfg["output"]]
        cmd += ["-j", cfg["json"]]
        if cfg["methods"]:
            cmd += ["--methods"] + cfg["methods"]

        self.log.append("Starting scan...")
        self.log.append("Command: " + " ".join(cmd))
        self.log.append("=" * 55)
        self._status_var.set(f"Scanning… threads={cfg['threads']}  output={cfg['output']}")

        # Run in background thread
        self._scan_thread = threading.Thread(
            target=self._run_scan, args=(cmd, cfg), daemon=True
        )
        self._scan_thread.start()

    def _run_scan(self, cmd, cfg):
        try:
            self._scan_proc = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                bufsize=1,
                universal_newlines=True,
            )

            for line in iter(self._scan_proc.stdout.readline, ""):
                if self._stop_flag.is_set():
                    self._scan_proc.terminate()
                    break
                line = line.rstrip()
                if line:
                    self.after(0, self.log.append, line)

            self._scan_proc.wait()

            if self._stop_flag.is_set():
                self.after(0, self._on_scan_stopped)
            else:
                self.after(0, self._on_scan_done, cfg)

        except Exception as e:
            self.after(0, self._on_scan_error, str(e))

    def _stop_scan(self):
        self._stop_flag.set()
        if self._scan_proc:
            try:
                self._scan_proc.terminate()
            except Exception:
                pass
        self.log.append("[!] Scan stopped by user")
        self.config_panel.set_scanning(False)
        self._status_var.set("Scan stopped")
        # Still try to load partial results
        cfg = self.config_panel.get_config()
        self._load_results(cfg)

    def _on_scan_done(self, cfg):
        self.log.append("=" * 55)
        self.log.append("[+] Scan complete — loading results...")
        self._load_results(cfg)
        self.config_panel.set_done()
        self._status_var.set(f"Done — {len(self._results)} URLs scanned  |  report: {cfg['output']}")
        self.nb.select(0)  # switch to results tab
        messagebox.showinfo("Scan Complete",
                            f"Scan finished!\n\n"
                            f"URLs scanned: {len(self._results)}\n"
                            f"Report: {cfg['output']}\n\n"
                            "Click 'Open Report' to view in browser.")

    def _on_scan_stopped(self):
        self.config_panel.set_scanning(False)
        self._status_var.set("Scan stopped")

    def _on_scan_error(self, msg):
        self.log.append(f"[ERROR] {msg}")
        self.config_panel.set_error(msg)
        self._status_var.set(f"Error: {msg[:60]}")
        messagebox.showerror("Scan Error", f"Scan failed:\n\n{msg}")

    def _load_results(self, cfg):
        json_path = cfg["json"]
        if not os.path.exists(json_path):
            # Try default name
            json_path = "scan_report.json"
        if os.path.exists(json_path):
            try:
                with open(json_path) as f:
                    data = json.load(f)
                if isinstance(data, dict):
                    js = data.get("js_results", [])
                    ep = data.get("endpoint_results", [])
                    self._results = js + ep
                elif isinstance(data, list):
                    self._results = data
                self.results_table.load(self._results)
                self.stats.update(self._results)
                self.log.append(f"[+] Loaded {len(self._results)} results from {json_path}")
            except Exception as e:
                self.log.append(f"[!] Could not load results JSON: {e}")
        else:
            self.log.append(f"[!] No JSON results file found at {json_path}")

    def _show_detail(self, result):
        self.detail.show(result)

# ══════════════════════════════════════════════════════════════
#  ENTRY POINT
# ══════════════════════════════════════════════════════════════
def main():
    # On Linux, try to use a better-looking font fallback
    try:
        import subprocess as sp
        result = sp.run(["fc-list", ":family=JetBrains Mono"],
                        capture_output=True, text=True, timeout=3)
        if not result.stdout.strip():
            # Fall back to Monospace or DejaVu
            global FONT_MONO, FONT_MONO_S, FONT_HEAD, FONT_TITLE, FONT_LABEL, FONT_BTN, FONT_SMALL
            FONT_MONO   = ("Monospace",   10)
            FONT_MONO_S = ("Monospace",    9)
            FONT_HEAD   = ("Monospace",   14, "bold")
            FONT_TITLE  = ("Monospace",   18, "bold")
            FONT_LABEL  = ("Monospace",   10)
            FONT_BTN    = ("Monospace",   10, "bold")
            FONT_SMALL  = ("Monospace",    8)
    except Exception:
        pass

    app = App()
    app.mainloop()

if __name__ == "__main__":
    main()