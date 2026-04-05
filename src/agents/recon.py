import json
from typing import Dict, List, Any
from src.agents.base import BaseAgent
from src.core.workspace import WorkspaceManager
from src.tools.browser import BrowserTool


class ReconAgent(BaseAgent):
    def __init__(self, engine):
        super().__init__(engine)
        self.system_prompt = (
            "You are a Reconnaissance AI Pentester. You have been provided raw HTML and "
            "a list of discovered links, forms, and input parameters from crawling the target URL. "
            "Your job is to analyze this data and summarize the attack surface. "
            "Focus on: endpoints, forms with input fields, query parameters, and visible technologies. "
            "Output a concise markdown summary of the attack surface."
        )

    async def execute(self, workspace: WorkspaceManager):
        print("[*] ReconAgent: Starting Playwright crawl of target...")
        browser = BrowserTool()

        try:
            target_url = workspace.target_url

            # Start browser with cookies for authenticated session
            await browser.start(
                headers=workspace.headers,
                cookies=workspace.cookies,
                target_url=target_url,
            )

            # ── Step 1: Navigate to root ──────────────────────────────────────────
            nav_result = await browser.navigate(target_url)

            # ── Step 1.5: Verify authenticated session ───────────────────────────
            auth_status = await self._check_authenticated(browser.page, target_url)
            workspace.add_recon_data("auth_status", auth_status)
            print(f"     [Browser] Auth status: {auth_status}")
            print(
                f"     [Browser] Navigated: {nav_result.get('url')} (status {nav_result.get('status')})"
            )

            # ── Step 2: Extract DOM ───────────────────────────────────────────────
            html = await browser.get_dom()

            # ── Step 3: Parse links & forms using lightweight Python (no LLM yet) ─
            from bs4 import BeautifulSoup
            from urllib.parse import urljoin, urlparse

            soup = BeautifulSoup(html[:100_000], "html.parser")

            base = target_url.rstrip("/")
            parsed_base = urlparse(base)

            # Collect same-origin links (scope-filtered)
            links = set()
            for tag in soup.find_all("a", href=True):
                href = tag["href"]
                full = urljoin(base, href)
                if urlparse(full).netloc == parsed_base.netloc and workspace.in_scope(full):
                    links.add(full)

            # Also collect file-serving URLs from media tags (path traversal candidates)
            import re as _re_pt
            _FILE_PARAM_RE = _re_pt.compile(
                r'[?&](filename|file|path|img|image|photo|pic|name|doc|page|resource|asset|media)=',
                _re_pt.IGNORECASE,
            )
            for tag in soup.find_all(["img", "source", "video", "audio", "embed", "track"]):
                for attr in ("src", "data-src", "data-lazy-src"):
                    val = tag.get(attr, "")
                    if val:
                        full = urljoin(base, val)
                        if (urlparse(full).netloc == parsed_base.netloc
                                and _FILE_PARAM_RE.search(full)
                                and workspace.in_scope(full)):
                            links.add(full)

            # Collect forms with their inputs
            forms = []
            for form in soup.find_all("form"):
                action = urljoin(base, form.get("action", ""))
                method = form.get("method", "get").upper()
                inputs = [
                    {"name": i.get("name", ""), "type": i.get("type", "text")}
                    for i in form.find_all(["input", "textarea", "select"])
                    if i.get("name")
                ]
                forms.append({"action": action, "method": method, "inputs": inputs})

            # Collect query parameters visible in page links
            params = set()
            for tag in soup.find_all("a", href=True):
                qp = urlparse(tag["href"]).query
                if qp:
                    params.update(k for k in qp.split("&") if "=" in k)

            # ── Step 3.5: Javascript Analysis (Endpoint + SPA Route Discovery) ─────
            import re

            js_endpoints = set()
            script_urls = set()

            # Find all script tags with src
            for script in soup.find_all("script", src=True):
                src = script["src"]
                full_src = urljoin(base, src)
                if urlparse(full_src).netloc == parsed_base.netloc:
                    script_urls.add(full_src)

            # Also look for inline scripts
            inline_scripts = []
            for script in soup.find_all("script"):
                if not script.get("src") and script.string:
                    inline_scripts.append(script.string)

            # General endpoint regex
            endpoint_regex = re.compile(
                r'["\']((?:/|(?:[a-zA-Z]{1,10}://)[^"\'\s]+)[^"\'\s]*)["\']',
                re.IGNORECASE,
            )
            # SPA route patterns: React Router, Angular, Vue Router, Next.js
            spa_route_patterns = [
                re.compile(r'path\s*:\s*["\']([/][^"\']{1,80})["\']'),        # React/Angular/Vue: path: "/..."
                re.compile(r'route\s*\(\s*["\']([/][^"\']{1,80})["\']'),      # Express-style route("/...")
                re.compile(r'to\s*=\s*["\']([/][^"\']{1,80})["\']'),          # React Router <Link to="/">
                re.compile(r'href\s*:\s*["\']([/][^"\']{1,80})["\']'),        # Object href
                re.compile(r'loadChildren\s*:\s*["\']([^"\']{1,80})["\']'),   # Angular lazy routes
                re.compile(r'component\s*:\s*.*?["\']([/][^"\']{1,60})["\']'),# Vue Router
                re.compile(r'["\']((?:/api/|/v\d/|/rest/)[^"\'?\s]{1,80})["\']'),  # API paths
            ]
            _SKIP_EXTS = {".js", ".css", ".png", ".jpg", ".jpeg", ".svg",
                          ".woff", ".woff2", ".ttf", ".ico", ".map", ".gz"}

            def _extract_from_js(content: str) -> None:
                # General paths
                for match in endpoint_regex.findall(content):
                    path = match[0] if isinstance(match, tuple) else match
                    if not any(path.endswith(e) for e in _SKIP_EXTS):
                        if len(path) > 3 and ("/" in path or "http" in path.lower()):
                            js_endpoints.add(path)
                # SPA routes
                for pat in spa_route_patterns:
                    for m in pat.findall(content):
                        route = m.strip()
                        if route and len(route) > 1:
                            js_endpoints.add(route)

            # Fetch same-origin JS files via Playwright (preserves auth cookies)
            for js_url in list(script_urls)[:10]:
                try:
                    print(f"     [Browser] Fetching JS: {js_url}")
                    await browser.page.goto(js_url, wait_until="domcontentloaded", timeout=10000)
                    js_content = await browser.page.content()
                    if js_content and len(js_content) > 10:
                        _extract_from_js(js_content)
                    await browser.page.goto(target_url, wait_until="domcontentloaded")
                except Exception as e:
                    print(f"     [!] Failed to fetch JS {js_url}: {e}")

            # Analyze inline scripts
            for inline_script in inline_scripts[:8]:
                try:
                    _extract_from_js(inline_script)
                except Exception:
                    pass

            if js_endpoints:
                print(f"     [Browser] Discovered {len(js_endpoints)} endpoint/route candidates from JS.")

            # ── Step 3.8: Passive HTTP header analysis ────────────────────────────
            import httpx as _httpx
            http_headers_raw = {}
            cookie_security = []
            try:
                _cookies = {k: v for k, v in workspace.cookies.items()}
                async with _httpx.AsyncClient(
                    verify=False,
                    timeout=10,
                    follow_redirects=True,
                ) as _hclient:
                    _resp = await _hclient.get(
                        target_url,
                        headers=workspace.headers,
                        cookies=_cookies,
                    )
                http_headers_raw = dict(_resp.headers)

                # Analyse security header presence
                _security_hdrs = [
                    "x-frame-options",
                    "x-content-type-options",
                    "x-xss-protection",
                    "content-security-policy",
                    "strict-transport-security",
                    "referrer-policy",
                    "permissions-policy",
                ]
                missing_hdrs = [
                    h for h in _security_hdrs if h not in {k.lower() for k in http_headers_raw}
                ]

                # Analyse Set-Cookie flags
                for hname, hval in http_headers_raw.items():
                    if hname.lower() == "set-cookie":
                        flags = {}
                        flags["raw"] = hval
                        flags["httponly"] = "httponly" in hval.lower()
                        flags["secure"] = "secure" in hval.lower()
                        flags["samesite"] = (
                            next((p.split("=")[1].strip() for p in hval.split(";")
                                  if "samesite" in p.lower()), "not set")
                        )
                        cookie_security.append(flags)

                workspace.add_recon_data("http_headers", http_headers_raw)
                workspace.add_recon_data("missing_security_headers", missing_hdrs)
                workspace.add_recon_data("cookie_security", cookie_security)
                workspace.add_recon_data(
                    "server_info",
                    http_headers_raw.get("server", http_headers_raw.get("Server", "Unknown")),
                )
            except Exception as _he:
                workspace.add_recon_data("http_headers", {})
                workspace.add_recon_data("missing_security_headers", [])
                workspace.add_recon_data("cookie_security", [])

            # ── Step 3.7: Navigation interaction — click menu/sidebar items ─────────
            # Many SPAs and dynamic apps don't render all links in static HTML.
            # Clicking navigation elements triggers JavaScript route changes, revealing
            # pages that are invisible to a static crawler.
            nav_discovered_links = set()
            try:
                await browser.page.goto(target_url, wait_until="networkidle", timeout=15000)
                # Find all clickable navigation items (nav, sidebar, header menus)
                nav_selectors = [
                    "nav a", "header a", ".nav a", ".navbar a", ".sidebar a",
                    ".menu a", ".menu-item a", "[role='navigation'] a",
                    ".drawer a", ".topbar a", ".left-menu a", ".main-menu a",
                ]
                for sel in nav_selectors:
                    try:
                        els = await browser.page.query_selector_all(sel)
                        for el in els[:20]:
                            try:
                                href = await el.get_attribute("href")
                                if href:
                                    full = urljoin(base, href)
                                    if (urlparse(full).netloc == parsed_base.netloc
                                            and workspace.in_scope(full)
                                            and full not in nav_discovered_links):
                                        nav_discovered_links.add(full)
                                        links.add(full)
                            except Exception:
                                pass
                    except Exception:
                        pass
                if nav_discovered_links:
                    print(f"     [Browser] Nav interaction: +{len(nav_discovered_links)} links from menus/sidebar.")
            except Exception as _ne:
                print(f"     [!] Nav interaction skipped: {_ne}")

            # ── Step 4: Multi-level crawl — 2 levels deep, up to 30 pages ───────────
            # Level 1: all discovered links from root page + nav interaction
            # Level 2: links discovered from Level-1 pages (expands to sub-menus, features)
            from urllib.parse import parse_qs

            visited = {target_url}
            all_forms = list(forms)
            crawl_queue = list(links)[:30]   # Level 1 — up to 30
            level2_queue = []                 # Filled during level-1 pass

            _HIGH_VALUE_KW = re.compile(
                r'admin|dashboard|manage|panel|upload|profile|account|order|cart|'
                r'payment|checkout|api|graphql|search|login|register|user|product|'
                r'report|setting|config|debug|test|backup|export|import',
                re.IGNORECASE,
            )

            async def _crawl_page(page_url: str, collect_level2: bool = False) -> None:
                """Visit a page, extract forms/params/links, store per-page context."""
                nonlocal all_forms
                if page_url in visited:
                    return
                visited.add(page_url)
                try:
                    await browser.navigate(page_url,
                                           headers=workspace.headers,
                                           cookies=workspace.cookies)
                    sub_html = await browser.get_dom()
                    sub_soup = BeautifulSoup(sub_html[:100_000], "html.parser")

                    # Forms
                    page_forms = []
                    for form in sub_soup.find_all("form"):
                        action = urljoin(page_url, form.get("action", ""))
                        method = form.get("method", "get").upper()
                        inputs = [
                            {"name": i.get("name", ""), "type": i.get("type", "text")}
                            for i in form.find_all(["input", "textarea", "select"])
                            if i.get("name")
                        ]
                        page_forms.append({"action": action, "method": method, "inputs": inputs})
                    all_forms.extend(page_forms)

                    # Query params
                    page_params = []
                    for a_tag in sub_soup.find_all("a", href=True):
                        qs = parse_qs(urlparse(a_tag["href"]).query)
                        page_params.extend(qs.keys())

                    # Same-origin links on this page
                    page_links = []
                    for a_tag in sub_soup.find_all("a", href=True):
                        href_full = urljoin(page_url, a_tag["href"])
                        if (urlparse(href_full).netloc == parsed_base.netloc
                                and workspace.in_scope(href_full)):
                            page_links.append(href_full)
                            if collect_level2 and href_full not in visited:
                                level2_queue.append(href_full)

                    # Also extract SPA routes and JS endpoints from inline scripts
                    for script in sub_soup.find_all("script"):
                        if not script.get("src") and script.string:
                            try:
                                _extract_from_js(script.string)
                            except Exception:
                                pass

                    # Store per-page context
                    workspace.add_page_context(page_url, {
                        "title": sub_soup.title.get_text(strip=True) if sub_soup.title else "",
                        "forms": page_forms,
                        "params": list(set(page_params)),
                        "links": page_links[:30],
                        "has_file_upload": any(
                            i.get("type") == "file"
                            for f in page_forms for i in f.get("inputs", [])
                        ),
                        "has_admin_path": any(
                            kw in page_url.lower()
                            for kw in ["/admin", "/dashboard", "/manage", "/panel", "/staff"]
                        ),
                        "auth_indicators": [
                            kw for kw in ["logout", "sign out", "my account", "profile"]
                            if kw in sub_html.lower()
                        ],
                        "is_high_value": bool(_HIGH_VALUE_KW.search(page_url)),
                    })

                except Exception:
                    pass

            # Level-1 crawl
            print(f"     [Crawl] Level 1: visiting up to {len(crawl_queue)} pages...")
            for lnk in crawl_queue:
                await _crawl_page(lnk, collect_level2=True)

            # Level-2 crawl — follow links discovered during level-1
            level2_unique = [u for u in dict.fromkeys(level2_queue)
                             if u not in visited][:20]
            if level2_unique:
                print(f"     [Crawl] Level 2: visiting {len(level2_unique)} additional pages...")
                for lnk in level2_unique:
                    await _crawl_page(lnk, collect_level2=False)

            print(f"     [Crawl] Total pages visited: {len(visited) - 1} "
                  f"({len(workspace.get_page_contexts())} with full context)")

            # ── Step 5: LLM surface analysis — full page context ─────────────────
            # Collect all params found across all crawled pages
            all_params = set(params)
            for ctx in workspace.get_page_contexts().values():
                all_params.update(ctx.get("params", []))

            # Resolve any SPA route stubs to absolute URLs
            resolved_spa = []
            for ep in list(js_endpoints)[:50]:
                if ep.startswith("/"):
                    resolved_spa.append(urljoin(base, ep))
                elif ep.startswith("http"):
                    if urlparse(ep).netloc == parsed_base.netloc:
                        resolved_spa.append(ep)
                else:
                    resolved_spa.append(ep)

            # Build per-page summary for high-value pages (admin, api, forms, uploads)
            high_value_pages = [
                {"url": url, "title": ctx.get("title", ""), "forms": ctx.get("forms", []),
                 "params": ctx.get("params", []), "has_upload": ctx.get("has_file_upload", False),
                 "is_admin": ctx.get("has_admin_path", False)}
                for url, ctx in workspace.get_page_contexts().items()
                if ctx.get("is_high_value") or ctx.get("has_file_upload") or ctx.get("has_admin_path")
            ][:20]

            recon_summary_input = {
                "target_url": target_url,
                "pages_crawled": len(visited) - 1,
                "links_found": sorted(list(links))[:50],
                "spa_routes_discovered": resolved_spa[:40],
                "forms": all_forms[:40],
                "query_params_seen": sorted(list(all_params))[:30],
                "high_value_pages": high_value_pages,
                "page_title": soup.title.get_text(strip=True) if soup.title else "",
                "technologies_hint": self._detect_tech(soup),
                "server_header": http_headers_raw.get("server", http_headers_raw.get("Server", "Unknown")),
                "x_powered_by": http_headers_raw.get("x-powered-by", http_headers_raw.get("X-Powered-By", "")),
                "missing_security_headers": workspace.get_recon_data("missing_security_headers") or [],
                "cookie_security_issues": [
                    c["raw"][:120] for c in cookie_security if not c["httponly"] or not c["secure"]
                ],
            }

            messages = [
                {
                    "role": "user",
                    "content": (
                        f"Target: {target_url}\n\n"
                        f"Full crawl results ({recon_summary_input['pages_crawled']} pages visited):\n"
                        f"{json.dumps(recon_summary_input, indent=2)}\n\n"
                        "Analyze the complete attack surface and produce a structured markdown report:\n"
                        "1. **Application Overview** — detected technology, auth mechanism, app type\n"
                        "2. **All Discovered Endpoints** — group by feature/module (auth, api, admin, user, etc.)\n"
                        "3. **Forms & Input Parameters** — list each form with its action, method, and input names\n"
                        "4. **SPA/JS Routes** — any routes discovered from JavaScript bundles\n"
                        "5. **High-Value Attack Surface** — endpoints most likely to yield vulnerabilities (admin, upload, API, payment, etc.)\n"
                        "6. **Security Header / Cookie Issues** — missing headers and cookie flag problems\n"
                        "7. **Recommended Test Priority** — ordered list of endpoints to focus exploit phase on"
                    ),
                }
            ]

            response = await self.engine.generate_response(
                messages=messages, system_prompt=self.system_prompt, max_tokens=3000
            )

            recon_text = self.engine.extract_text(response)

            workspace.add_recon_data("surface_map", recon_text)
            workspace.add_recon_data("structured", recon_summary_input)

            # ── Cross-scan memory: persist discovered endpoints & tech stack ──
            all_discovered_urls = list(links) + [
                str(urljoin(base, ep)) for ep in js_endpoints
                if ep.startswith("/")
            ]
            new_urls = workspace.memory.add_endpoints(all_discovered_urls)
            if new_urls:
                workspace.add_recon_data("new_endpoints_this_scan", new_urls)

            tech_hints = self._detect_tech(soup)
            if tech_hints:
                workspace.memory.update_tech_stack(tech_hints)

            # Persist security header audit to memory
            sec_hdr_presence = {
                h: (h not in (workspace.get_recon_data("missing_security_headers") or []))
                for h in [
                    "x-frame-options", "x-content-type-options", "content-security-policy",
                    "strict-transport-security", "referrer-policy",
                ]
            }
            workspace.memory.update_security_headers(sec_hdr_presence)

            # Annotate surface map with previously-known endpoint count
            known_count = len(workspace.memory.get_known_endpoints()) - len(new_urls)
            print(
                f"[+] Recon completed. {len(links)} links, {len(forms)} forms discovered "
                f"({len(new_urls)} new, {max(0, known_count)} previously known)."
            )

        except Exception as e:
            print(f"[!] ReconAgent error: {e}")
            workspace.add_recon_data("surface_map", f"Recon error: {e}")
            workspace.add_recon_data("structured", {})
        finally:
            await browser.stop()

    @staticmethod
    def _detect_tech(soup) -> List[str]:
        """Best-effort tech detection from HTML hints."""
        hints = []
        html_str = str(soup).lower()
        if "wp-content" in html_str or "wordpress" in html_str:
            hints.append("WordPress")
        if "laravel" in html_str or "csrf-token" in html_str:
            hints.append("Laravel/PHP")
        if "flask" in html_str or "werkzeug" in html_str:
            hints.append("Flask/Python")
        if "jquery" in html_str:
            hints.append("jQuery")
        if "react" in html_str:
            hints.append("React")
        if "php" in html_str or ".php" in html_str:
            hints.append("PHP")
        return hints

    async def _check_authenticated(self, page, target_url: str) -> dict:
        """Check if the session is authenticated by looking for common indicators."""
        from urllib.parse import urlparse

        result = {"authenticated": False, "user_info": None, "indicators": []}

        try:
            current_url = page.url
            html = (await page.content()).lower()

            # Check for common authenticated page indicators
            auth_indicators = [
                ("dashboard", ["dashboard", "admin panel", "control panel"]),
                (
                    "user_menu",
                    ["profile", "settings", "account", "logout", "sign out", "welcome"],
                ),
                ("user_data", ["username", "email", "user id", "member"]),
                ("privilege", ["admin", "moderator", "staff"]),
            ]

            for indicator_name, keywords in auth_indicators:
                for keyword in keywords:
                    if keyword in html:
                        result["indicators"].append(
                            f"{indicator_name}: found '{keyword}'"
                        )

            # Check URL for authenticated paths
            parsed = urlparse(current_url)
            auth_paths = [
                "/dashboard",
                "/admin",
                "/profile",
                "/settings",
                "/account",
                "/home",
                "/user",
            ]
            for path in auth_paths:
                if path in parsed.path:
                    result["indicators"].append(f"auth_path: {path}")

            # Check page title
            title = await page.title() if await page.title() else ""
            if title:
                result["indicators"].append(f"page_title: {title}")

            # Determine authenticated status
            result["authenticated"] = len(result["indicators"]) > 0

        except Exception as e:
            result["error"] = str(e)

        return result
