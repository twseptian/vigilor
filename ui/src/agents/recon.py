import json
from typing import Dict, List, Any
from src.agents.base import BaseAgent
from src.core.workspace import WorkspaceManager
from src.tools.browser import BrowserTool


class ReconAgent(BaseAgent):
    def __init__(self, engine):
        super().__init__(engine)
        self.system_prompt = (
            "You are an elite Offensive Security Recon Analyst. You receive the raw results of a "
            "browser-based crawl of a target web application. Your mission is to produce a precise, "
            "attack-oriented intelligence report — NOT a generic description. Every observation must "
            "be mapped to concrete attack opportunities.\n\n"

            "=== TECHNOLOGY FINGERPRINTING ===\n"
            "Identify with precision:\n"
            "  • Backend language: PHP (PHPSESSID, .php URLs, X-Powered-By), Java (JSESSIONID, .jsp, .do), "
            "    Python (Django/Flask cookies, Werkzeug in errors), Ruby (rack.session), .NET (__VIEWSTATE, ASPXAUTH, .aspx)\n"
            "  • Framework: Laravel (laravel_session), Spring (XSRF-TOKEN + JSESSIONID), Django (csrftoken + sessionid), "
            "    Express (connect.sid), Rails (authenticity_token)\n"
            "  • Server: Apache (Server: Apache/x.x), Nginx (Server: nginx/x.x), IIS (Server: Microsoft-IIS/x.x), "
            "    Caddy, Gunicorn, uWSGI\n"
            "  • JS frameworks: React (__NEXT_DATA__, _reactFiber), Angular (ng-version), Vue (__vue__), "
            "    Webpack bundles (main.[hash].js, chunk.[hash].js, runtime.[hash].js)\n"
            "  • WAF/CDN: Cloudflare (cf-ray header), AWS WAF (x-amzn-requestid), Akamai, Imperva, ModSecurity "
            "    (403 with 'ModSecurity' or 'Forbidden'), F5 BIG-IP\n"
            "  • Database hints: SQLite (.db download links), MySQL (MySQL error in stack), PostgreSQL (psycopg in error)\n\n"

            "=== AUTHENTICATION & SESSION ANALYSIS ===\n"
            "  • Login mechanisms: form-based (action URL, field names), HTTP Basic/Digest, OAuth2/OIDC "
            "    (look for /oauth/authorize, /auth/callback, client_id in URLs), SAML (/sso, SAMLResponse), API key (Authorization: Bearer)\n"
            "  • Session token analysis: JWT (eyJ prefix — 3 dot-separated b64 parts → alg:none candidate), "
            "    base64 encoded JSON (Flask session → forging candidate), numeric IDs (predictable), UUID v4 (strong)\n"
            "  • Cookie flags missing: Secure, HttpOnly, SameSite — each missing flag is an attack vector\n"
            "  • Multi-factor auth: /login/2fa, /verify, /otp endpoints → 2FA bypass candidate\n"
            "  • Password reset flow: /reset, /forgot, /password/reset → host header poisoning candidate\n\n"

            "=== API & ENDPOINT INTELLIGENCE ===\n"
            "  • REST API patterns: /api/v1/, /api/v2/ (version differential — older version may lack auth)\n"
            "  • GraphQL: /graphql, /api/graphql, /__graphql → introspection enabled?\n"
            "  • File/document serving: params named file=, filename=, path=, doc=, resource=, img=, page= "
            "    → path traversal / LFI candidates\n"
            "  • XML consumers: endpoints accepting Content-Type: application/xml, text/xml → XXE candidate\n"
            "  • File upload: multipart/form-data forms, enctype='multipart', input type=file → unrestricted upload candidate\n"
            "  • URL redirect params: redirect=, url=, next=, return=, goto=, dest= → open redirect / SSRF\n"
            "  • Server-side rendering params: ?page=, ?template=, ?view=, ?layout= → SSTI candidate\n"
            "  • Webhook / callback endpoints: /webhook, /callback, /notify → SSRF via URL parameter\n"
            "  • Export / report generation: /export, /report, /generate, /pdf, /download → "
            "    SSRF via Headless Chrome/wkhtmltopdf if HTML-to-PDF feature\n\n"

            "=== ATTACK SURFACE PRIORITISATION ===\n"
            "Rank endpoints by exploitation probability. Highest priority:\n"
            "  1. Admin panels (/admin, /dashboard, /management, /console) — auth bypass / forced browsing\n"
            "  2. File operations (upload, download, preview) — RCE / path traversal\n"
            "  3. User-specific resources with numeric IDs (/orders/123, /users/456) — IDOR\n"
            "  4. Authentication endpoints (login, register, reset, 2fa) — auth bypass / account takeover\n"
            "  5. Payment / cart / checkout — business logic tampering\n"
            "  6. Search / filter forms — injection entry points\n"
            "  7. API endpoints with version numbers — API versioning differential auth\n"
            "  8. Endpoints accepting XML or file content — XXE / deserialization\n\n"

            "=== SECURITY HEADER GAPS ===\n"
            "Each missing header is an attack vector. Flag:\n"
            "  • Missing Content-Security-Policy → XSS escalation possible\n"
            "  • Missing X-Frame-Options / CSP frame-ancestors → Clickjacking\n"
            "  • Missing HSTS → Protocol downgrade / MitM\n"
            "  • Missing X-Content-Type-Options → MIME sniffing\n"
            "  • CORS: Access-Control-Allow-Origin: * → cross-origin data theft\n\n"

            "=== OUTPUT FORMAT ===\n"
            "Structured markdown. Be concise but specific. Every finding must include: "
            "the exact URL/header/parameter AND the attack technique it enables."
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

            # ── Step 1.7: Active page interaction — trigger dynamic content ───────
            # Click tabs, accordions, dropdowns, scroll to bottom.
            # This fires JS-triggered API calls that would never be captured from static HTML.
            print("     [Browser] Triggering dynamic content (scroll, tabs, dropdowns)...")
            try:
                interaction_summary = await browser.trigger_dynamic_content()
                clicked_count = len(interaction_summary.get("clicked", []))
                if clicked_count:
                    print(f"     [Browser] Interacted with {clicked_count} dynamic elements.")
            except Exception as _ie:
                print(f"     [!] Dynamic interaction skipped: {_ie}")

            # ── Step 1.8: Extract JavaScript runtime context ───────────────────────
            # Pull window variables, framework state, localStorage, sessionStorage,
            # API base URLs, exposed config objects, and suspicious global variables.
            print("     [Browser] Extracting JS runtime context...")
            js_context = {}
            try:
                js_context = await browser.extract_js_context()
                if js_context:
                    print(f"     [Browser] JS context: {list(js_context.keys())}")
                    workspace.add_recon_data("js_context", js_context)
            except Exception as _jce:
                print(f"     [!] JS context extraction skipped: {_jce}")

            # ── Step 1.9: Detailed cookie analysis ────────────────────────────────
            try:
                cookies_detail = await browser.get_cookies_detail()
                workspace.add_recon_data("cookies_detail", cookies_detail)
            except Exception:
                pass

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

            # Collect file-serving URLs — path traversal candidates
            # Strategy: cast a wide net across ALL tags + link hrefs, using BOTH
            # parameter-name matching AND file-extension matching in path/value.
            import re as _re_pt

            # Matches query param NAMES that commonly serve files
            _FILE_PARAM_NAME_RE = _re_pt.compile(
                r'[?&](filename|file|path|filepath|img|image|photo|pic|name|doc|page|resource|asset|media|attachment|download|export|load|include|template|view|render|src|source|data)=',
                _re_pt.IGNORECASE,
            )
            # Matches query param VALUES that look like filenames (extension-based)
            _FILE_PARAM_VALUE_RE = _re_pt.compile(
                r'[?&][^=]+=([^&]*\.(?:jpg|jpeg|png|gif|bmp|pdf|doc|docx|xls|xlsx|csv|txt|xml|json|zip|tar|gz|log|cfg|conf|ini|php|html|htm|asp|aspx|jsp))',
                _re_pt.IGNORECASE,
            )
            # Matches URL paths that end with a file extension (path-based file serving)
            _FILE_EXT_PATH_RE = _re_pt.compile(
                r'\.(jpg|jpeg|png|gif|bmp|pdf|doc|docx|xls|xlsx|csv|txt|xml|zip|tar|gz|log|cfg|conf|ini|html|htm)$',
                _re_pt.IGNORECASE,
            )
            # Matches path segments that indicate file-serving endpoints
            _FILE_SERVE_PATH_RE = _re_pt.compile(
                r'/(image|images|img|files|file|download|downloads|export|media|uploads|upload|static|assets|serve|fetch|resource|resources|attachment|attachments|docs|documents|reports|backup|photo|photos|avatar|thumb|thumbnail)(/|$|\?)',
                _re_pt.IGNORECASE,
            )

            def _is_traversal_candidate(url: str) -> bool:
                parsed_u = urlparse(url)
                qs = parsed_u.query
                path_u = parsed_u.path
                return (
                    _FILE_PARAM_NAME_RE.search(url) or          # param name matches
                    _FILE_PARAM_VALUE_RE.search(url) or         # param value looks like filename
                    _FILE_EXT_PATH_RE.search(path_u) or         # path ends with file extension
                    _FILE_SERVE_PATH_RE.search(path_u)          # path contains file-serving segment
                )

            # Scan ALL tags with URL attributes — not just media tags
            for tag in soup.find_all(True):
                for attr in ("src", "href", "data-src", "data-url", "data-href",
                             "data-lazy-src", "action", "poster", "data-image"):
                    val = tag.get(attr, "")
                    if not val or val.startswith(("#", "javascript:", "mailto:", "tel:")):
                        continue
                    full = urljoin(base, val)
                    parsed_full = urlparse(full)
                    if (parsed_full.netloc == parsed_base.netloc
                            and workspace.in_scope(full)
                            and _is_traversal_candidate(full)):
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

            # ── Step 3.9: Root-domain discovery ──────────────────────────────────────
            # If the user supplied a deep path (e.g. /sqli/time?id=1), we also visit
            # the base origin so the full site structure is discovered before crawling.
            base_origin = f"{parsed_base.scheme}://{parsed_base.netloc}/"
            if target_url.rstrip("/") != base_origin.rstrip("/"):
                try:
                    print(f"     [Crawl] Target is a deep path — also visiting root: {base_origin}")
                    await browser.navigate(base_origin)
                    root_html = await browser.get_dom()
                    root_soup = BeautifulSoup(root_html[:100_000], "html.parser")
                    def _collect_from_soup(s, base_url):
                        found = []
                        for tag in s.find_all("a", href=True):
                            full = urljoin(base_url, tag["href"])
                            if urlparse(full).netloc == parsed_base.netloc and workspace.in_scope(full):
                                found.append(full)
                        for form in s.find_all("form"):
                            action = urljoin(base_url, form.get("action", ""))
                            method = form.get("method", "get").upper()
                            inputs = [
                                {"name": i.get("name", ""), "type": i.get("type", "text")}
                                for i in form.find_all(["input", "textarea", "select"])
                                if i.get("name")
                            ]
                            forms.append({"action": action, "method": method, "inputs": inputs})
                        return found

                    root_found = _collect_from_soup(root_soup, base_origin)

                    # Interact with root page UI (tabs/menus) to reveal dynamic links
                    try:
                        root_interaction = await browser.trigger_dynamic_content()
                        if root_interaction.get("clicked"):
                            dyn_root_html = await browser.get_dom()
                            dyn_root_soup = BeautifulSoup(dyn_root_html[:100_000], "html.parser")
                            root_found += _collect_from_soup(dyn_root_soup, base_origin)
                            print(f"     [Dynamic] Root page: {len(root_interaction['clicked'])} interactions performed.")
                    except Exception:
                        pass

                    root_links_found = 0
                    for full in root_found:
                        if full not in links:
                            links.add(full)
                            root_links_found += 1

                    # Navigate back to target so subsequent steps stay in context
                    await browser.navigate(target_url)
                    print(f"     [Crawl] Root discovery added {root_links_found} new links.")
                except Exception as _re:
                    print(f"     [!] Root discovery skipped: {_re}")

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

            def _extract_links_forms_from_soup(page_url: str, s_soup, collect_level2: bool) -> tuple:
                """Parse links, forms, params from a BeautifulSoup object."""
                p_forms = []
                for form in s_soup.find_all("form"):
                    action = urljoin(page_url, form.get("action", ""))
                    method = form.get("method", "get").upper()
                    inputs = [
                        {"name": i.get("name", ""), "type": i.get("type", "text")}
                        for i in form.find_all(["input", "textarea", "select"])
                        if i.get("name")
                    ]
                    p_forms.append({"action": action, "method": method, "inputs": inputs})

                p_params = []
                p_links = []
                for a_tag in s_soup.find_all("a", href=True):
                    qs = parse_qs(urlparse(a_tag["href"]).query)
                    p_params.extend(qs.keys())
                    href_full = urljoin(page_url, a_tag["href"])
                    if (urlparse(href_full).netloc == parsed_base.netloc
                            and workspace.in_scope(href_full)):
                        p_links.append(href_full)
                        links.add(href_full)
                        if collect_level2 and href_full not in visited:
                            level2_queue.append(href_full)

                for script in s_soup.find_all("script"):
                    if not script.get("src") and script.string:
                        try:
                            _extract_from_js(script.string)
                        except Exception:
                            pass

                return p_forms, p_params, p_links

            async def _crawl_page(page_url: str, collect_level2: bool = False) -> None:
                """Visit a page, interact with UI elements, extract forms/params/links."""
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

                    # Initial pass — collect links/forms from static DOM
                    page_forms, page_params, page_links = _extract_links_forms_from_soup(
                        page_url, sub_soup, collect_level2
                    )
                    all_forms.extend(page_forms)

                    # ── Dynamic interaction: click tabs/accordions/dropdowns ──────────
                    # Re-collect DOM after interaction to capture JS-revealed content.
                    try:
                        interaction = await browser.trigger_dynamic_content()
                        clicked = interaction.get("clicked", [])
                        if clicked:
                            # DOM may have changed — re-parse for new links/forms
                            dyn_html = await browser.get_dom()
                            dyn_soup = BeautifulSoup(dyn_html[:100_000], "html.parser")
                            dyn_forms, dyn_params, dyn_links = _extract_links_forms_from_soup(
                                page_url, dyn_soup, collect_level2
                            )
                            # Merge new items (avoid duplicates in all_forms)
                            existing_actions = {f["action"] for f in all_forms}
                            for f in dyn_forms:
                                if f["action"] not in existing_actions:
                                    all_forms.append(f)
                                    existing_actions.add(f["action"])
                            page_params = list(set(page_params + dyn_params))
                            page_links  = list(set(page_links + dyn_links))
                            # Re-assign soup to the post-interaction version for context
                            sub_soup = dyn_soup
                            if clicked:
                                print(f"     [Dynamic] {page_url[:60]} → {len(clicked)} interactions, "
                                      f"+{len(dyn_links)} new links revealed.")
                    except Exception as _de:
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

            # ── Step 4.5: Network traffic analysis — discover API endpoints ──────────
            # Playwright captured every XHR/fetch/image request made by the browser.
            # This is the ONLY reliable way to find API endpoints in SPAs and JS-heavy
            # apps — they never appear in static HTML.
            from urllib.parse import urlparse as _up, parse_qs as _pqs

            captured = browser.get_captured_requests()
            network_api_endpoints: list[dict] = []
            _SKIP_EXT = re.compile(
                r'\.(woff2?|ttf|eot|otf|ico|svg|css|js|map|png|jpg|jpeg|gif|webp|bmp|tiff|mp4|webm|ogg|mp3|wav)$',
                re.IGNORECASE,
            )

            for req in captured:
                req_url   = req.get("url", "")
                req_method = req.get("method", "GET")
                res_type  = req.get("resource_type", "")
                post_data = req.get("post_data")

                # Skip non-same-origin, static assets, and browser internals
                try:
                    _rp = _up(req_url)
                    if _rp.netloc != parsed_base.netloc:
                        continue
                    if _SKIP_EXT.search(_rp.path) and res_type not in ("xhr", "fetch"):
                        continue
                    if req_url.startswith("data:") or req_url.startswith("blob:"):
                        continue
                except Exception:
                    continue

                # Add to link set so vuln agent can generate hypotheses
                links.add(req_url)

                # Collect params from query string
                qs_raw = _rp.query
                if qs_raw:
                    for k in _pqs(qs_raw).keys():
                        all_params.add(k) if 'all_params' in dir() else params.add(k)  # noqa

                # Record interesting API calls for the LLM summary
                if res_type in ("xhr", "fetch") or req_method in ("POST", "PUT", "PATCH", "DELETE"):
                    entry: dict = {
                        "method": req_method,
                        "url": req_url,
                        "type": res_type,
                    }
                    if post_data:
                        entry["body_preview"] = post_data[:200]
                    network_api_endpoints.append(entry)

            # Also pick up response status codes — 403/401 = auth-protected, worth noting
            captured_responses = browser.captured_responses
            auth_protected: list[str] = []
            for resp in captured_responses:
                if resp.get("status") in (401, 403):
                    rp = _up(resp["url"])
                    if rp.netloc == parsed_base.netloc:
                        auth_protected.append(resp["url"])
                        links.add(resp["url"])   # auth-gated endpoints are prime targets

            if network_api_endpoints:
                print(f"     [Network] Captured {len(network_api_endpoints)} XHR/fetch API calls.")
            if auth_protected:
                print(f"     [Network] {len(auth_protected)} endpoints returned 401/403 (auth-protected).")

            workspace.add_recon_data("network_api_calls", network_api_endpoints[:80])
            workspace.add_recon_data("auth_protected_endpoints", auth_protected[:30])

            # ── Step 4.6: WebSocket analysis ─────────────────────────────────────
            ws_data = browser.get_websockets()
            ws_summary = []
            for ws in ws_data:
                ws_url = ws.get("url", "")
                frames_sent = ws.get("frames_sent", [])
                frames_recv = ws.get("frames_received", [])
                ws_summary.append({
                    "url": ws_url,
                    "frames_sent_count": len(frames_sent),
                    "frames_received_count": len(frames_recv),
                    "sample_sent": frames_sent[:3],
                    "sample_received": frames_recv[:3],
                })
                # Add WS URL to links for further analysis
                links.add(ws_url)
            if ws_summary:
                print(f"     [Network] Captured {len(ws_summary)} WebSocket connection(s).")
                workspace.add_recon_data("websockets", ws_summary)

            # ── Step 4.7: Console message analysis ───────────────────────────────
            # console.log/error output often leaks tokens, API keys, endpoints,
            # stack traces, and internal framework errors.
            console_msgs = browser.get_console_messages()
            security_console: list[dict] = []
            _SECRET_RE = re.compile(
                r'token|key|secret|auth|jwt|bearer|password|api[_\-]?key|'
                r'access[_\-]?token|credential|session|x-auth|x-token|'
                r'eyJ[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]*',   # JWT pattern
                re.IGNORECASE,
            )
            _ENDPOINT_RE = re.compile(r'https?://\S+|/api/\S+|/v\d+/\S+', re.IGNORECASE)

            for msg in console_msgs:
                text = msg.get("text", "")
                # Flag security-relevant console output
                if _SECRET_RE.search(text) or msg.get("type") == "error":
                    security_console.append(msg)
                # Extract any endpoints mentioned in console output
                for ep_match in _ENDPOINT_RE.findall(text):
                    ep_clean = ep_match.rstrip('",;)')
                    try:
                        ep_parsed = _up(ep_clean)
                        if ep_parsed.netloc == parsed_base.netloc and workspace.in_scope(ep_clean):
                            links.add(ep_clean)
                    except Exception:
                        pass

            if security_console:
                print(f"     [Console] {len(security_console)} security-relevant console messages.")
                workspace.add_recon_data("security_console_messages", security_console[:30])

            # ── Step 4.8: JS context security analysis ────────────────────────────
            # Extract API endpoints from JS runtime variables (window.API_URL, etc.)
            if js_context:
                for key, value in js_context.items():
                    if not isinstance(value, str):
                        continue
                    for ep_match in _ENDPOINT_RE.findall(value):
                        ep_clean = ep_match.rstrip('",;)')
                        try:
                            ep_parsed = _up(ep_clean)
                            if ep_parsed.netloc == parsed_base.netloc and workspace.in_scope(ep_clean):
                                links.add(ep_clean)
                        except Exception:
                            pass

            # Flag suspicious localStorage/sessionStorage entries
            _suspicious_storage: list[dict] = []
            for storage_key in ("localstorage", "sessionstorage"):
                raw = js_context.get(storage_key)
                if raw:
                    try:
                        import json as _j
                        storage_data = _j.loads(raw) if isinstance(raw, str) else raw
                        for k, v in (storage_data.items() if isinstance(storage_data, dict) else {}.items()):
                            if _SECRET_RE.search(k) or _SECRET_RE.search(str(v)[:200]):
                                _suspicious_storage.append({
                                    "storage": storage_key,
                                    "key": k,
                                    "value_preview": str(v)[:150],
                                })
                    except Exception:
                        pass
            if _suspicious_storage:
                print(f"     [Storage] {len(_suspicious_storage)} suspicious storage entries found.")
                workspace.add_recon_data("suspicious_storage", _suspicious_storage)

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
                "network_api_calls": network_api_endpoints[:40],
                "auth_protected_endpoints": auth_protected[:20],
                "websockets": ws_summary[:10],
                "security_console_messages": security_console[:15],
                "js_context_keys": list(js_context.keys()) if js_context else [],
                "suspicious_storage": _suspicious_storage[:10],
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
                        "7. **Live API Calls (XHR/Fetch)** — list each captured network request with method, URL, and body preview; identify which are most exploitable\n"
                        "8. **Auth-Protected Endpoints (401/403)** — endpoints that rejected the request; these are forced-browsing and IDOR candidates\n"
                        "9. **Recommended Test Priority** — ordered list of endpoints to focus exploit phase on, ranked by exploitation probability"
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
