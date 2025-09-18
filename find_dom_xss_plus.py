#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import argparse
import asyncio
import subprocess
import sys
import re
import json
import csv
import time
import itertools
from urllib.parse import urljoin, quote_plus
from html.parser import HTMLParser
from pathlib import Path
from datetime import datetime, timezone

# Optional niceties
try:
    from rich.console import Console
    from rich.table import Table
    from rich.panel import Panel
    console = Console()
    use_rich = True
except Exception:
    console = None
    use_rich = False

# async HTTP
try:
    import aiohttp
    use_aiohttp = True
except Exception:
    use_aiohttp = False
    import requests

# banner library optional
try:
    import pyfiglet
    have_pyfiglet = True
except Exception:
    have_pyfiglet = False

# color fallback
try:
    from colorama import init as _colorama_init, Fore, Style
    _colorama_init(autoreset=True)
    HAVE_COLORAMA = True
except Exception:
    HAVE_COLORAMA = False
    class _Empty:
        def __getattr__(self, _): return ""
    Fore = _Empty()
    Style = _Empty()

# Global runtime flags (set in main)
VERBOSE = False

# --------------------------
# Banner and logging helpers
# --------------------------
def print_banner():
    title = "ДОМу ШНИК"
    subtitle = "DOM XSS Hunter"
    if have_pyfiglet:
        art = pyfiglet.figlet_format(title, font="slant")
        if use_rich:
            console.print(f"[bold cyan]{art}[/bold cyan]")
            console.print(f"[yellow]{subtitle} — сканер DOM sink'ов[/yellow]\n")
        else:
            print(Fore.CYAN + art + Style.RESET_ALL)
            print(Fore.YELLOW + subtitle + Style.RESET_ALL + "\n")
    else:
        line = "=" * 60
        if use_rich:
            console.print(f"[bold cyan]{line}\n  {title}\n{line}[/bold cyan]")
            console.print(f"[yellow]{subtitle} — сканер DOM sink'ов[/yellow]\n")
        else:
            print(Fore.CYAN + line + Style.RESET_ALL)
            print("  " + title)
            print(Fore.CYAN + line + Style.RESET_ALL)
            print(Fore.YELLOW + subtitle + Style.RESET_ALL + "\n")

def now_ts():
    # timezone-aware UTC timestamp
    return datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")

def log(msg, level="INFO"):
    # if DEBUG and not VERBOSE -> skip
    if level == "DEBUG" and not VERBOSE:
        return
    prefix = f"[{now_ts()}] [{level}]"
    if use_rich:
        console.log(f"{prefix} {msg}")
    else:
        print(f"{prefix} {msg}")

def step(msg):
    """Пошаговый вывод (видно процесс)."""
    if use_rich:
        console.print(f"[bold yellow][Шаг][/bold yellow] {msg}")
    else:
        print(Fore.GREEN + "[Шаг] " + Style.RESET_ALL + msg)

def spinner_task(message, duration=0.6):
    """Короткий спиннер (блокирующий) для визуального эффекта между шагами."""
    spinner = itertools.cycle("⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏")
    sys.stdout.write(Fore.GREEN + "[*] " + Style.RESET_ALL + message + " ")
    sys.stdout.flush()
    end = time.time() + duration
    while time.time() < end:
        sys.stdout.write(next(spinner))
        sys.stdout.flush()
        time.sleep(0.08)
        sys.stdout.write("\b")
    sys.stdout.write("✔\n")

# --------------------------
# Patterns config
# --------------------------
SINK_PATTERNS = [
    r"\bdocument\.write(?:ln)?\s*\(",
    r"\bdocument\.domain\b",
    r"\binnerHTML\b",
    r"\bouterHTML\b",
    r"\btextContent\b",
    r"\binnerText\b",
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
    # frameworks
    r"\bdangerouslySetInnerHTML\b",
    r"\bDOMParser\b",
    r"\bparseFromString\s*\(",
]
COMPILED_PATTERNS = [re.compile(p, re.IGNORECASE) for p in SINK_PATTERNS]

# improved exclude (catch many min variants)
DEFAULT_EXCLUDE_PATTERNS = [
    re.compile(r"\.min(?:[._A-Za-z0-9-]*)\.js$", re.IGNORECASE),
    re.compile(r"jquery", re.IGNORECASE),
    re.compile(r"node_modules", re.IGNORECASE),
    re.compile(r"/vendor/", re.IGNORECASE),
    re.compile(r"bootstrap", re.IGNORECASE),
    re.compile(r"react(-dom)?(\.min)?", re.IGNORECASE),
    re.compile(r"vue(\.min)?", re.IGNORECASE),
    re.compile(r"angular(\.min)?", re.IGNORECASE),
]

# --------------------------
# HTML parser
# --------------------------
class ScriptExtractor(HTMLParser):
    def __init__(self, base_url):
        super().__init__()
        self.base = base_url
        self.scripts = []
        self.inline_scripts = []
        self._in_script = False
        self._current_script = []

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

def snippet_with_context(text, start_idx, end_idx, context_lines=2):
    lines = text.splitlines()
    cumulative = []
    s = 0
    for i, ln in enumerate(lines):
        cumulative.append((s, s + len(ln) + 1))
        s += len(ln) + 1
    start_line = 0
    end_line = len(lines) - 1
    for i, (a, b) in enumerate(cumulative):
        if a <= start_idx < b:
            start_line = i
            break
    for j, (a, b) in enumerate(cumulative):
        if a <= end_idx < b:
            end_line = j
            break
    lo = max(0, start_line - context_lines)
    hi = min(len(lines) - 1, end_line + context_lines)
    numbered = []
    for ln_no in range(lo, hi + 1):
        numbered.append(f"{ln_no+1}: {lines[ln_no]}")
    return "\n".join(numbered), start_line + 1

def find_patterns_with_positions(text):
    found = []
    for rx in COMPILED_PATTERNS:
        for m in rx.finditer(text):
            start, end = m.start(), m.end()
            snippet, lineno = snippet_with_context(text, start, end, context_lines=1)
            found.append({
                "pattern": rx.pattern,
                "match_text": text[start:end],
                "snippet": snippet,
                "line": lineno
            })
    return found

# --------------------------
# POC templates (optional)
# --------------------------
POC_TEMPLATES = [
    (re.compile(r"innerHTML", re.IGNORECASE), "<img src=x onerror=alert(1)>"),
    (re.compile(r"outerHTML", re.IGNORECASE), "<svg onload=alert(1)>"),
    (re.compile(r"insertAdjacentHTML", re.IGNORECASE), "<img src=x onerror=alert(1)>"),
    (re.compile(r"document\.write", re.IGNORECASE), "<script>alert(1)</script>"),
    (re.compile(r"eval|Function\(|new Function", re.IGNORECASE), "payload: alert(1) in eval context (manual)"),
]

def gen_poc_for_match(match_pattern, context_url):
    for rx, tpl in POC_TEMPLATES:
        try:
            if rx.search(match_pattern):
                if "<img" in tpl or "<svg" in tpl:
                    return {"type": "fragment", "payload": tpl, "example": f"{context_url}#{quote_plus(tpl)}"}
                if tpl.startswith("<script"):
                    return {"type": "inline", "payload": tpl}
                return {"type": "generic", "payload": tpl}
        except Exception:
            continue
    return None

# --------------------------
# External tools (logging)
# --------------------------
async def run_tool_with_input(cmd, input_text, timeout):
    step(f"Запуск внешнего инструмента: {' '.join(cmd)}")
    try:
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdin=asyncio.subprocess.PIPE,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.DEVNULL
        )
        out, _ = await asyncio.wait_for(proc.communicate(input=input_text.encode()), timeout=timeout)
        results = [line.strip() for line in out.decode(errors="ignore").splitlines() if line.strip()]
        log(f"Инструмент {' '.join(cmd)} вернул {len(results)} строк.")
        return results
    except asyncio.TimeoutError:
        log(f"Инструмент {' '.join(cmd)}: таймаут ({timeout}s).", level="WARN")
        try:
            proc.kill()
        except Exception:
            pass
        return []
    except FileNotFoundError:
        log(f"Инструмент {' '.join(cmd)} не найден в PATH, пропускаем.", level="WARN")
        return []
    except Exception as e:
        log(f"Ошибка при запуске {' '.join(cmd)}: {e}", level="ERROR")
        return []

async def run_tool_no_input(cmd, timeout):
    step(f"Запуск внешнего инструмента: {' '.join(cmd)}")
    try:
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.DEVNULL
        )
        out, _ = await asyncio.wait_for(proc.communicate(), timeout=timeout)
        results = [line.strip() for line in out.decode(errors="ignore").splitlines() if line.strip()]
        log(f"Инструмент {' '.join(cmd)} вернул {len(results)} строк.")
        return results
    except asyncio.TimeoutError:
        log(f"Инструмент {' '.join(cmd)}: таймаут ({timeout}s).", level="WARN")
        try:
            proc.kill()
        except Exception:
            pass
        return []
    except FileNotFoundError:
        log(f"Инструмент {' '.join(cmd)} не найден в PATH, пропускаем.", level="WARN")
        return []
    except Exception as e:
        log(f"Ошибка при запуске {' '.join(cmd)}: {e}", level="ERROR")
        return []

# --------------------------
# HTTP helpers
# --------------------------
async def fetch_text(session, url, sem, timeout=15):
    try:
        async with sem:
            step(f"Загрузка: {url}")
            async with session.get(url, timeout=timeout) as resp:
                txt = await resp.text(errors="ignore")
                return txt
    except Exception as e:
        log(f"Не удалось загрузить {url}: {e}", level="WARN")
        return ""

async def gather_js_urls_from_page(session, page_url, sem):
    text = await fetch_text(session, page_url, sem)
    extractor = ScriptExtractor(page_url)
    try:
        extractor.feed(text)
    except Exception:
        pass
    return list(dict.fromkeys(extractor.scripts)), extractor.inline_scripts, text

# --------------------------
# Core per-URL processing
# --------------------------
async def process_single_url(url, sem, args):
    step(f"=== Начинаем обработку: {url} ===")
    findings_map = {}
    collected_candidates = set()

    # External tools
    wayback_results = []
    katana_results = []
    if not args.nowayback:
        wayback_results = await run_tool_with_input(["waybackurls"], url, timeout=args.tool_timeout)
        if args.max_wayback and len(wayback_results) > args.max_wayback:
            wayback_results = wayback_results[:args.max_wayback]
            log(f"Обрезали results wayback до {args.max_wayback}")
    if not args.nokatana:
        # Katana accepts -u or -list; using -u form may work as before
        katana_results = await run_tool_no_input(["katana", "-u", url, "-silent"], timeout=args.tool_timeout)
        if args.max_katana and len(katana_results) > args.max_katana:
            katana_results = katana_results[:args.max_katana]
            log(f"Обрезали results katana до {args.max_katana}")

    for src in wayback_results + katana_results:
        collected_candidates.add(src)

    async with aiohttp.ClientSession() as session:
        page_js_urls, inline_scripts, _ = await gather_js_urls_from_page(session, url, sem)
        log(f"Найдено {len(page_js_urls)} <script src=> на странице и {len(inline_scripts)} inline-скриптов.")
        for j in page_js_urls:
            collected_candidates.add(j)

        # scan inline scripts immediately, map to pseudo-source
        for idx, script in enumerate(inline_scripts):
            matches = find_patterns_with_positions(script)
            if matches:
                key = f"{url} [inline #{idx+1}]"
                findings_map.setdefault(key, [])
                for m in matches:
                    entry = {
                        "pattern": m["pattern"],
                        "match_text": m["match_text"],
                        "line": m["line"],
                        "snippet": m["snippet"],
                        "source": key
                    }
                    if args.poc:
                        poc = gen_poc_for_match(m["pattern"], url)
                        if poc:
                            entry["poc"] = poc
                    findings_map[key].append(entry)
                log(f"[inline #{idx+1}] найдено {len(matches)} потенциальных совпадений.", level="DEBUG")

        # prepare list and filter candidates
        cand_list = []
        for cand in collected_candidates:
            lower = cand.lower()
            ext_ok = lower.endswith((".js", ".mjs", ".jsx", ".ts", ".bundle")) or any(x in lower for x in [".js?", ".javascript"]) or lower.endswith((".html", "/"))
            if not ext_ok:
                if "js" in lower or "?js" in lower or "javascript" in lower:
                    ext_ok = True
            if not ext_ok:
                continue
            if should_exclude(cand, no_filter=args.no_filter):
                log(f"Пропускаем (фильтр): {cand}", level="DEBUG")
                continue
            cand_list.append(cand)

        log(f"Всего кандидатов для загрузки/сканирования: {len(cand_list)}")
        tasks = [fetch_and_scan_worker(session, cand, sem, findings_map, args) for cand in cand_list]
        if tasks:
            await asyncio.gather(*tasks)
        else:
            log("Нет задач для скачивания/сканирования.", level="DEBUG")

    step(f"=== Завершили обработку: {url} ===")
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
        log(f"[scan] {url} — найдено {len(matches)} совпадений (uniq {len(unique)}).", level="INFO")
    else:
        log(f"[scan] {url} — совпадений не найдено.", level="DEBUG")

# --------------------------
# IO helpers
# --------------------------
def load_urls_from_file(path):
    p = Path(path)
    if not p.exists():
        log(f"Файл {path} не найден.", level="ERROR")
        return []
    return [line.strip() for line in p.read_text(encoding="utf-8", errors="ignore").splitlines()
            if line.strip() and not line.strip().startswith("#")]

def save_json(path, obj):
    with open(path, "w", encoding="utf-8") as f:
        json.dump(obj, f, ensure_ascii=False, indent=2)

def save_csv(path, aggregated):
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
# Final printing helpers (clean and compact)
# --------------------------
def pretty_source_name(src):
    if len(src) > 100:
        return src[:90] + "..."
    return src

def humanize_pattern_from_entry(it):
    # Prefer using the actual matched text
    mt = (it.get("match_text") or "").strip()
    if mt:
        m2 = re.search(r"[A-Za-z_][A-Za-z0-9_]+", mt)
        if m2:
            return m2.group(0)
    # Fallback to cleaning pattern string (remove \b and escapes)
    pat = it.get("pattern","")
    cleaned = re.sub(r"\\b|\\", "", pat)
    m3 = re.search(r"[A-Za-z_][A-Za-z0-9_]+", cleaned)
    if m3:
        return m3.group(0)
    return cleaned[:40] or "match"

def print_compact_results(overall, max_per_source=100):
    total = sum(len(v) for v in overall.values())
    step(f"Найдено потенциально опасных мест: {total}")
    print()

    diagram_lines = []
    for src, items in overall.items():
        if not items:
            continue
        readable_src = pretty_source_name(src)
        # group by human-friendly name, collect line numbers and one snippet
        grouped = {}
        for it in items:
            name = humanize_pattern_from_entry(it)
            grouped.setdefault(name, {"lines": set(), "example": None})
            grouped[name]["lines"].add(it.get("line") or "")
            if grouped[name]["example"] is None:
                grouped[name]["example"] = it.get("snippet","").splitlines()[0] if it.get("snippet") else ""
        # produce list sorted by name
        entries = sorted(grouped.items(), key=lambda x: x[0])
        # limit
        omitted = 0
        if len(entries) > max_per_source:
            omitted = len(entries) - max_per_source
            entries = entries[:max_per_source]
        # print block
        print(Fore.CYAN + readable_src + Style.RESET_ALL)
        for name, data in entries:
            lines_str = ", ".join(str(x) for x in sorted(data["lines"]))
            print("  " + Fore.RED + "- " + Style.RESET_ALL + f"{name} (lines: {lines_str})")
        if omitted:
            print("  " + Fore.YELLOW + f"... and {omitted} more (use --max-per-source to increase)" + Style.RESET_ALL)
        print()
        diagram_lines.append((readable_src, entries))
    # ASCII diagram
    if diagram_lines:
        print(Fore.GREEN + Style.BRIGHT + "=== ASCII схема найденных уязвимостей ===" + Style.RESET_ALL)
        for src, entries in diagram_lines:
            print(Fore.CYAN + f"[{src}]" + Style.RESET_ALL)
            for i, (name, data) in enumerate(entries):
                branch = "├─" if i < len(entries)-1 else "└─"
                lines_str = ", ".join(str(x) for x in sorted(data["lines"]))
                print("  " + branch + f" {name} (lines: {lines_str})")
            print()
    else:
        print(Fore.YELLOW + "Уязвимых мест не найдено." + Style.RESET_ALL)

# --------------------------
# Main
# --------------------------
async def main(args):
    global VERBOSE
    VERBOSE = bool(args.verbose)
    print_banner()
    step("Запуск сканера")
    spinner_task("Подготовка... (короткая пауза)", duration=0.25)

    urls = []
    if args.url:
        urls.append(args.url)
    if args.dict:
        urls += load_urls_from_file(args.dict)
    if not urls:
        log("Нужно указать -u URL или -d файл.", level="ERROR")
        return

    step(f"Будут просканированы {len(urls)} URL(ов)")
    sem = asyncio.Semaphore(args.concurrency)
    coros = [process_single_url(u, sem, args) for u in urls]
    step("Запускаем обработку всех URL (параллельно)")
    results = await asyncio.gather(*coros)

    overall = {}
    for res in results:
        for k, v in res.items():
            overall.setdefault(k, []).extend(v)

    if not overall:
        log("Ничего опасного не найдено по предоставленным URL.", level="INFO")
        return

    print_compact_results(overall, max_per_source=args.max_per_source)

    if args.json_out:
        out_json = {"scanned_at": datetime.now(timezone.utc).isoformat(), "results": overall}
        save_json(args.json_out, out_json)
        log(f"[+] JSON saved to {args.json_out}")
    if args.csv_out:
        save_csv(args.csv_out, overall)
        log(f"[+] CSV saved to {args.csv_out}")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="find_dom_xss_plus.py — расширенный сканер DOM-синков (ДОМу ШНИК)")
    parser.add_argument("-u", "--url", help="Целевой URL")
    parser.add_argument("-d", "--dict", help="Файл со списком URL (по одному в строке)")
    parser.add_argument("-c", "--concurrency", type=int, default=20, help="Число одновременных скачиваний")
    parser.add_argument("--nowayback", action="store_true", help="Не запускать waybackurls")
    parser.add_argument("--nokatana", action="store_true", help="Не запускать katana")
    parser.add_argument("--max-wayback", type=int, default=200, help="Максимум результатов waybackurls")
    parser.add_argument("--max-katana", type=int, default=200, help="Максимум результатов katana")
    parser.add_argument("--tool-timeout", type=int, default=15, help="Таймаут (s) для внешних инструментов")
    parser.add_argument("--http-timeout", type=int, default=15, help="Таймаут (s) для HTTP запросов")
    parser.add_argument("--json-out", help="Сохранить результаты в JSON")
    parser.add_argument("--csv-out", help="Сохранить результаты в CSV")
    parser.add_argument("--no-filter", action="store_true", help="Отключить фильтрацию минифицированных/библиотечных файлов")
    parser.add_argument("--poc", action="store_true", help="Генерировать простые PoC для найденных sink'ов")
    parser.add_argument("--noaio", action="store_true", help="Не использовать aiohttp (если доступно) — падёт в синхронный режим")
    parser.add_argument("--verbose", action="store_true", help="Показывать DEBUG-логи")
    parser.add_argument("--max-per-source", type=int, default=100, help="Максимум уникальных паттернов для показа в одном source")
    args = parser.parse_args()

    if not use_aiohttp and not args.noaio:
        log("aiohttp не установлен — перехожу в синхронный режим.", level="WARN")
        args.noaio = True

    if args.noaio:
        # Sync fallback (keeps same compact output)
        print_banner()
        VERBOSE = bool(args.verbose)
        step("Запуск в синхронном режиме (noaio=True)")
        urls = []
        if args.url:
            urls.append(args.url)
        if args.dict:
            urls += load_urls_from_file(args.dict)
        if not urls:
            log("Нужно указать -u URL или -d файл.", level="ERROR")
            sys.exit(1)

        overall_sync = {}
        for u in urls:
            step(f"[sync] Загружаем страницу: {u}")
            try:
                import requests as _req
                r = _req.get(u, timeout=args.http_timeout)
                page = r.text
            except Exception as e:
                log(f"[sync] Ошибка загрузки страницы {u}: {e}", level="WARN")
                page = ""
            extractor = ScriptExtractor(u)
            try:
                extractor.feed(page)
            except Exception:
                pass
            candidates = set(extractor.scripts)
            # scan inline
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
            # external tools (sync)
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
            # scan candidates
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

        if not overall_sync:
            log("Ничего не найдено (синхронный режим).", level="INFO")
            sys.exit(0)
        print_compact_results(overall_sync, max_per_source=args.max_per_source)
        if args.json_out:
            save_json(args.json_out, {"scanned_at": datetime.now(timezone.utc).isoformat(), "results": overall_sync})
            log(f"[+] JSON saved to {args.json_out}")
        if args.csv_out:
            save_csv(args.csv_out, overall_sync)
            log(f"[+] CSV saved to {args.csv_out}")
        sys.exit(0)

    try:
        asyncio.run(main(args))
    except KeyboardInterrupt:
        log("Прервано пользователем.", level="ERROR")
