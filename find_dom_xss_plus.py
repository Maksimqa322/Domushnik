#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
find_dom_xss_plus.py
Улучшенный сканер JS на предмет DOM-синков / потенциальных XSS-источников.
Поддерживает:
 - единичный URL: -u/--url
 - файл с URL: -d/--dict
 - экспорт JSON/CSV
 - опциональный запуск внешних инструментов (waybackurls, katana) с ограничением результатов и таймаутами
 - фильтрацию минифицированных/стандартных библиотек (можно выключить)
 - генерацию простых PoC payloads (--poc)
"""
import argparse
import asyncio
import subprocess
import sys
import re
import json
import csv
from urllib.parse import urljoin, urlparse, quote_plus
from html.parser import HTMLParser
from pathlib import Path
from datetime import datetime

# optional nice output
try:
    from rich.console import Console
    from rich.table import Table
    from rich.panel import Panel
    console = Console()
    use_rich = True
except Exception:
    use_rich = False

# try to use aiohttp, else fallback to requests (sync)
try:
    import aiohttp
    use_aiohttp = True
except Exception:
    use_aiohttp = False
    import requests

# --------------------------
# Конфиг (пополняй тут)
# --------------------------
SINK_PATTERNS = [
    r"\bdocument\.write\s*\(",
    r"\bdocument\.writeln\s*\(",
    r"\bdocument\.domain\b",
    r"\binnerHTML\b\s*=",
    r"\bouterHTML\b\s*=",
    r"\btextContent\b\s*=",
    r"\binnerText\b\s*=",
    r"\bappendChild\s*\(",
    r"\bappend\s*\(",
    r"\bprepend\s*\(",
    r"\binsertAdjacentHTML\s*\(",
    r"\binsertAdjacentElement\s*\(",
    r"\binsertBefore\s*\(",
    r"\breplaceWith\s*\(",
    r"\breplaceAll\s*\(",
    r"\bsetAttribute\s*\(\s*['\"](?:innerHTML|src|href|on\w+)['\"]",
    r"\beval\s*\(",
    r"\bnew Function\s*\(",
    r"\bFunction\s*\(",
    r"\bexecScript\s*\(",
    r"\blocation\.hash\b",
    r"\blocation\s*=\s*",
    r"\blocation\.href\b",
    r"\bhistory\.pushState\s*\(",
    r"\bhistory\.replaceState\s*\(",
    # jQuery / helpers
    r"\.html\s*\(",
    r"\.append\s*\(",
    r"\.prepend\s*\(",
    r"\.after\s*\(",
    r"\.before\s*\(",
    r"\.replaceWith\s*\(",
    r"\.wrap\s*\(",
    r"\.wrapInner\s*\(",
    r"\.parseHTML\s*\(",
    r"\$\.parseHTML\s*\(",
    # modern frameworks
    r"\bdangerouslySetInnerHTML\b",
    r"\bDOMParser\b",
    r"\bparseFromString\s*\(",
    r"`[^`]*\$\{[^}]+\}[^`]*`",
]

COMPILED_PATTERNS = [re.compile(p, re.IGNORECASE) for p in SINK_PATTERNS]

# default filters to skip noisy/minified libs
DEFAULT_EXCLUDE_PATTERNS = [
    re.compile(r"\.min\.js$", re.IGNORECASE),
    re.compile(r"jquery", re.IGNORECASE),
    re.compile(r"node_modules", re.IGNORECASE),
    re.compile(r"/vendor/", re.IGNORECASE),
    re.compile(r"bootstrap", re.IGNORECASE),
    re.compile(r"react(-dom)?(\.min)?", re.IGNORECASE),
    re.compile(r"vue(\.min)?", re.IGNORECASE),
    re.compile(r"angular(\.min)?", re.IGNORECASE),
]

# --------------------------
# HTML parser to extract scripts & inline
# --------------------------
class ScriptExtractor(HTMLParser):
    def __init__(self, base_url):
        super().__init__()
        self.base = base_url
        self.scripts = []
        self.inline_scripts = []
        self._in_script = False
        self._current_script = []
        self._attrs = None

    def handle_starttag(self, tag, attrs):
        if tag.lower() == "script":
            self._in_script = True
            attrs = dict(attrs)
            if "src" in attrs:
                src = attrs["src"].strip()
                full = urljoin(self.base, src)
                self.scripts.append(full)

    def handle_endtag(self, tag):
        if tag.lower() == "script":
            if self._in_script and self._current_script:
                text = "".join(self._current_script).strip()
                if text:
                    self.inline_scripts.append(text)
            self._in_script = False
            self._current_script = []

    def handle_data(self, data):
        if self._in_script:
            self._current_script.append(data)

# --------------------------
# Utilities
# --------------------------
def should_exclude(url, no_filter=False, extra_patterns=None):
    if no_filter:
        return False
    pars = DEFAULT_EXCLUDE_PATTERNS[:]
    if extra_patterns:
        pars += extra_patterns
    for p in pars:
        try:
            if p.search(url):
                return True
        except Exception:
            continue
    return False

def snippet_with_context(text, start_idx, end_idx, context_lines=3):
    # return lines with line numbers for context
    lines = text.splitlines()
    # compute line numbers from char indices
    cumulative = []
    s = 0
    for i, ln in enumerate(lines):
        cumulative.append((s, s + len(ln) + 1))  # +1 for \n
        s += len(ln) + 1
    # find line index
    start_line = 0
    end_line = len(lines) - 1
    for i, (a,b) in enumerate(cumulative):
        if a <= start_idx < b:
            start_line = i
            break
    for j, (a,b) in enumerate(cumulative):
        if a <= end_idx < b:
            end_line = j
            break
    lo = max(0, start_line - context_lines)
    hi = min(len(lines)-1, end_line + context_lines)
    numbered = []
    for ln_no in range(lo, hi+1):
        numbered.append(f"{ln_no+1}: {lines[ln_no]}")
    return "\n".join(numbered), start_line+1

def find_patterns_with_positions(text):
    found = []
    for rx in COMPILED_PATTERNS:
        for m in rx.finditer(text):
            start, end = m.start(), m.end()
            snippet, lineno = snippet_with_context(text, start, end, context_lines=3)
            found.append({
                "pattern": rx.pattern,
                "match_text": text[start:end],
                "snippet": snippet,
                "line": lineno
            })
    return found

# --------------------------
# PoC generator (простые шаблоны)
# --------------------------
POC_TEMPLATES = [
    (re.compile(r"innerHTML", re.IGNORECASE),
     "<img src=x onerror=alert(1)>"),
    (re.compile(r"outerHTML", re.IGNORECASE),
     "<svg onload=alert(1)>"),
    (re.compile(r"insertAdjacentHTML", re.IGNORECASE),
     "<img src=x onerror=alert(1)>"),
    (re.compile(r"document\.write", re.IGNORECASE),
     "<script>alert(1)</script>"),
    (re.compile(r"eval|Function\(|new Function", re.IGNORECASE),
     "payload: alert(1) in eval context (manual)"),
    (re.compile(r"location\.hash|location\s*=", re.IGNORECASE),
     "#<img src=x onerror=alert(1)>"),
    (re.compile(r"setAttribute\(.+on\w+", re.IGNORECASE),
     "\"onerror=alert(1)\""),
    (re.compile(r"dangerouslySetInnerHTML", re.IGNORECASE),
     "{ __html: '<img src=x onerror=alert(1)>' }"),
]

def gen_poc_for_match(match_pattern, context_url):
    for rx, tpl in POC_TEMPLATES:
        try:
            if rx.search(match_pattern):
                # simple PoC: for URL-based injection return URL with fragment or param (best-effort)
                if "<img" in tpl or "<svg" in tpl:
                    # try to attach as fragment
                    return {"type": "fragment", "payload": tpl, "example": f"{context_url}#{quote_plus(tpl)}"}
                if tpl.startswith("<script"):
                    return {"type": "inline", "payload": tpl, "note": "Insert into response body or inline script testing"}
                if "payload" in tpl:
                    return {"type": "manual", "payload": tpl}
                return {"type": "generic", "payload": tpl}
        except Exception:
            continue
    return None

# --------------------------
# Fetching and external tools
# --------------------------
async def run_tool_with_input(cmd, input_text, timeout):
    try:
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdin=asyncio.subprocess.PIPE,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.DEVNULL
        )
        out, _ = await asyncio.wait_for(proc.communicate(input=input_text.encode()), timeout=timeout)
        return [line.strip() for line in out.decode(errors="ignore").splitlines() if line.strip()]
    except asyncio.TimeoutError:
        try:
            proc.kill()
        except Exception:
            pass
        return []
    except FileNotFoundError:
        return []
    except Exception:
        return []

async def run_tool_no_input(cmd, timeout):
    try:
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.DEVNULL
        )
        out, _ = await asyncio.wait_for(proc.communicate(), timeout=timeout)
        return [line.strip() for line in out.decode(errors="ignore").splitlines() if line.strip()]
    except asyncio.TimeoutError:
        try:
            proc.kill()
        except Exception:
            pass
        return []
    except FileNotFoundError:
        return []
    except Exception:
        return []

async def fetch_text(session, url, sem, timeout=15):
    try:
        async with sem:
            async with session.get(url, timeout=timeout) as resp:
                txt = await resp.text(errors="ignore")
                return txt
    except Exception:
        return ""

async def gather_js_urls_from_page(session, page_url, sem):
    text = await fetch_text(session, page_url, sem)
    extractor = ScriptExtractor(page_url)
    try:
        extractor.feed(text)
    except Exception:
        pass
    return list(dict.fromkeys(extractor.scripts)), extractor.inline_scripts, text

async def process_js_url(session, js_url, sem):
    txt = await fetch_text(session, js_url, sem)
    if not txt:
        return []
    return find_patterns_with_positions(txt), txt

# --------------------------
# Main per-URL flow
# --------------------------
async def process_single_url(url, sem, args):
    findings_map = {}  # js_url -> list of findings objects
    collected_candidates = set()

    # Run external tools if allowed
    wayback_results = []
    katana_results = []
    if not args.nowayback:
        wayback_results = await run_tool_with_input(["waybackurls"], url, timeout=args.tool_timeout)
        if args.max_wayback and len(wayback_results) > args.max_wayback:
            wayback_results = wayback_results[:args.max_wayback]
    if not args.nokatana:
        # katana -u <url> -silent outputs discovered urls
        katana_results = await run_tool_no_input(["katana", "-u", url, "-silent"], timeout=args.tool_timeout)
        if args.max_katana and len(katana_results) > args.max_katana:
            katana_results = katana_results[:args.max_katana]

    # filter and add
    for src in wayback_results + katana_results:
        collected_candidates.add(src)

    # fetch page & inline scripts
    async with aiohttp.ClientSession() as session:
        page_js_urls, inline_scripts, page_text = await gather_js_urls_from_page(session, url, sem)

        for j in page_js_urls:
            collected_candidates.add(j)

        # scan inline scripts
        for idx, script in enumerate(inline_scripts):
            matches = find_patterns_with_positions(script)
            if matches:
                key = f"{url} [inline #{idx+1}]"
                findings_map.setdefault(key, [])
                for m in matches:
                    entry = {
                        "pattern": m["pattern"],
                        "match_text": m["match_text"],
                        "snippet": m["snippet"],
                        "line": m["line"],
                        "source": key
                    }
                    if args.poc:
                        poc = gen_poc_for_match(m["pattern"], url)
                        if poc:
                            entry["poc"] = poc
                    findings_map[key].append(entry)

        # Now fetch each candidate (JS files or page snapshots) concurrently
        tasks = []
        for cand in collected_candidates:
            # only include likely js or html snapshots; allow user to override by --no-filter
            lower = cand.lower()
            ext_ok = lower.endswith((".js", ".mjs", ".jsx", ".ts", ".bundle")) or any(x in lower for x in [".js?", ".javascript"]) or lower.endswith((".html", "/"))
            if not ext_ok:
                # still include potential JS querystrings
                if "js" in lower or "?js" in lower or "javascript" in lower:
                    ext_ok = True
            if not ext_ok:
                continue
            if should_exclude(cand, no_filter=args.no_filter):
                continue
            tasks.append(fetch_and_scan_worker(session, cand, sem, findings_map, args))
        if tasks:
            await asyncio.gather(*tasks)

    return findings_map

async def fetch_and_scan_worker(session, url, sem, findings_map, args):
    txt = await fetch_text(session, url, sem, timeout=args.http_timeout)
    if not txt:
        return
    matches = find_patterns_with_positions(txt)
    if matches:
        findings_map.setdefault(url, [])
        unique = set()
        for m in matches:
            key = (m["pattern"], m["line"], m["match_text"][:80])
            if key in unique:
                continue
            unique.add(key)
            entry = {
                "pattern": m["pattern"],
                "match_text": m["match_text"],
                "snippet": m["snippet"],
                "line": m["line"],
                "source": url
            }
            if args.poc:
                poc = gen_poc_for_match(m["pattern"], url)
                if poc:
                    entry["poc"] = poc
            findings_map[url].append(entry)

# --------------------------
# IO helpers
# --------------------------
def load_urls_from_file(path):
    p = Path(path)
    if not p.exists():
        print(f"Файл {path} не найден.", file=sys.stderr)
        return []
    return [line.strip() for line in p.read_text(encoding="utf-8", errors="ignore").splitlines()
            if line.strip() and not line.strip().startswith("#")]

def save_json(path, obj):
    with open(path, "w", encoding="utf-8") as f:
        json.dump(obj, f, ensure_ascii=False, indent=2)

def save_csv(path, aggregated):
    # aggregated: dict source -> list entries
    with open(path, "w", newline="", encoding="utf-8") as csvfile:
        writer = csv.writer(csvfile)
        writer.writerow(["source","pattern","match_text","line","poc_type","poc_payload","poc_example"])
        for src, items in aggregated.items():
            for it in items:
                poc_type = it.get("poc", {}).get("type") if it.get("poc") else ""
                poc_payload = it.get("poc", {}).get("payload") if it.get("poc") else ""
                poc_example = it.get("poc", {}).get("example") if it.get("poc") else ""
                writer.writerow([src, it.get("pattern",""), it.get("match_text",""), it.get("line",""), poc_type, poc_payload, poc_example])

# --------------------------
# Main
# --------------------------
async def main(args):
    urls = []
    if args.url:
        urls.append(args.url)
    if args.dict:
        urls += load_urls_from_file(args.dict)
    if not urls:
        print("Нужно указать -u URL или -d файл.")
        return

    sem = asyncio.Semaphore(args.concurrency)
    overall = {}
    coros = []
    for u in urls:
        coros.append(process_single_url(u, sem, args))
    results = await asyncio.gather(*coros)

    # flatten
    for res in results:
        for k, v in res.items():
            overall.setdefault(k, []).extend(v)

    # output
    if not overall:
        if use_rich:
            console.print("[green]Ничего опасного не найдено по предоставленным URL.[/green]")
        else:
            print("Ничего опасного не найдено.")
        return

    # print nicely
    for src, items in overall.items():
        if use_rich:
            table = Table(show_header=True, header_style="bold magenta")
            table.add_column("Source", style="dim", overflow="fold")
            table.add_column("Pattern / Line", overflow="fold")
            table.add_column("Snippet (context)", overflow="fold")
            table.add_column("PoC", overflow="fold")
            for it in items:
                poc_str = ""
                if it.get("poc"):
                    poc = it["poc"]
                    poc_str = f"{poc.get('type')} {poc.get('payload')} {poc.get('example','')}"
                table.add_row(src, f"{it.get('pattern')} (line {it.get('line')})", it.get('snippet',''), poc_str)
            console.print(Panel(table, title=src))
        else:
            print(f"=== {src} ===")
            for it in items:
                print(f"- {it.get('pattern')} (line {it.get('line')})")
                print(it.get("snippet",""))
                if it.get("poc"):
                    poc = it["poc"]
                    print(f"  PoC: {poc.get('payload')} example: {poc.get('example','')}")
                print("")

    # save outputs
    if args.json_out:
        out_json = {
            "scanned_at": datetime.utcnow().isoformat() + "Z",
            "results": overall
        }
        save_json(args.json_out, out_json)
        print(f"[+] JSON saved to {args.json_out}")
    if args.csv_out:
        save_csv(args.csv_out, overall)
        print(f"[+] CSV saved to {args.csv_out}")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="find_dom_xss_plus.py — расширенный сканер DOM-синков")
    parser.add_argument("-u", "--url", help="Целевой URL")
    parser.add_argument("-d", "--dict", help="Файл со списком URL (по одному в строке)")
    parser.add_argument("-c", "--concurrency", type=int, default=30, help="Число одновременных скачиваний")
    parser.add_argument("--nowayback", action="store_true", help="Не запускать waybackurls")
    parser.add_argument("--nokatana", action="store_true", help="Не запускать katana")
    parser.add_argument("--max-wayback", type=int, default=200, help="Максимум результатов waybackurls")
    parser.add_argument("--max-katana", type=int, default=200, help="Максимум результатов katana")
    parser.add_argument("--tool-timeout", type=int, default=20, help="Таймаут (s) для внешних инструментов")
    parser.add_argument("--http-timeout", type=int, default=15, help="Таймаут (s) для HTTP запросов")
    parser.add_argument("--json-out", help="Сохранить результаты в JSON")
    parser.add_argument("--csv-out", help="Сохранить результаты в CSV")
    parser.add_argument("--no-filter", action="store_true", help="Отключить фильтрацию минифицированных/библиотечных файлов")
    parser.add_argument("--poc", action="store_true", help="Генерировать простые PoC для найденных sink'ов")
    parser.add_argument("--noaio", action="store_true", help="Не использовать aiohttp (если доступно) — падёт в синхронный режим")
    args = parser.parse_args()

    if not use_aiohttp and not args.noaio:
        print("aiohttp не установлен — перехожу в синхронный режим. Для лучшей скорости установи aiohttp.")
        args.noaio = True

    if args.noaio:
        # minimal sync fallback (keeps JSON/CSV export & PoC generation)
        def simple_scan_sync(urls_list):
            import requests as _req
            overall_sync = {}
            for u in urls_list:
                try:
                    r = _req.get(u, timeout=args.http_timeout)
                    page = r.text
                except Exception:
                    page = ""
                extractor = ScriptExtractor(u)
                try:
                    extractor.feed(page)
                except Exception:
                    pass
                candidates = set(extractor.scripts)
                for idx, s in enumerate(extractor.inline_scripts):
                    matches = find_patterns_with_positions(s)
                    if matches:
                        key = f"{u} [inline #{idx+1}]"
                        overall_sync.setdefault(key, [])
                        for m in matches:
                            entry = {"pattern": m["pattern"], "match_text": m["match_text"], "snippet": m["snippet"], "line": m["line"], "source": key}
                            if args.poc:
                                poc = gen_poc_for_match(m["pattern"], u)
                                if poc: entry["poc"] = poc
                            overall_sync[key].append(entry)
                # run tools sync
                if not args.nowayback:
                    try:
                        wb = subprocess.run(["waybackurls"], input=(u+"\n").encode(), stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, timeout=args.tool_timeout)
                        if wb.stdout:
                            for line in wb.stdout.decode(errors="ignore").splitlines():
                                candidates.add(line.strip())
                    except Exception:
                        pass
                if not args.nokatana:
                    try:
                        kt = subprocess.run(["katana", "-u", u, "-silent"], stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, timeout=args.tool_timeout)
                        if kt.stdout:
                            for line in kt.stdout.decode(errors="ignore").splitlines():
                                candidates.add(line.strip())
                    except Exception:
                        pass
                for c in candidates:
                    if should_exclude(c, no_filter=args.no_filter):
                        continue
                    try:
                        rr = _req.get(c, timeout=args.http_timeout)
                        mlist = find_patterns_with_positions(rr.text)
                        if mlist:
                            overall_sync.setdefault(c, [])
                            for m in mlist:
                                entry = {"pattern": m["pattern"], "match_text": m["match_text"], "snippet": m["snippet"], "line": m["line"], "source": c}
                                if args.poc:
                                    poc = gen_poc_for_match(m["pattern"], c)
                                    if poc: entry["poc"] = poc
                                overall_sync[c].append(entry)
                    except Exception:
                        pass
            return overall_sync

        scanned = simple_scan_sync(urls)
        if not scanned:
            print("Ничего не найдено (синхронный режим).")
            sys.exit(0)
        # print + save
        for k,v in scanned.items():
            print(f"=== {k} ===")
            for it in v:
                print(f"- {it['pattern']} line {it['line']}")
                print(it['snippet'])
                if it.get('poc'): print("  PoC:", it['poc'])
                print()
        if args.json_out:
            save_json(args.json_out, {"scanned_at": datetime.utcnow().isoformat()+"Z", "results": scanned})
            print("[+] JSON saved to", args.json_out)
        if args.csv_out:
            save_csv(args.csv_out, scanned)
            print("[+] CSV saved to", args.csv_out)
        sys.exit(0)

    try:
        asyncio.run(main(args))
    except KeyboardInterrupt:
        print("Прервано пользователем.")
