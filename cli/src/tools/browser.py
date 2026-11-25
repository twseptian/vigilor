from playwright.async_api import async_playwright, Page, BrowserContext
from typing import Optional, List, Dict
import json as _json


class BrowserTool:
    def __init__(self):
        self.playwright = None
        self.browser = None
        self.context: Optional[BrowserContext] = None
        self.page: Optional[Page] = None
        # Dialog capture
        self.last_dialog: Optional[dict] = None
        # Network traffic capture (request + response)
        self.captured_requests: List[Dict] = []
        self.captured_responses: List[Dict] = []
        # WebSocket frame capture
        self.captured_websockets: List[Dict] = []
        # Browser console messages (console.log/error/warn)
        self.console_messages: List[Dict] = []

    # ── Getters ──────────────────────────────────────────────────────────────

    def get_captured_requests(self) -> List[Dict]:
        return list(self.captured_requests)

    def clear_captured_requests(self) -> None:
        self.captured_requests.clear()
        self.captured_responses.clear()

    def get_console_messages(self) -> List[Dict]:
        return list(self.console_messages)

    def get_websockets(self) -> List[Dict]:
        return list(self.captured_websockets)

    # ── Start ─────────────────────────────────────────────────────────────────

    async def start(self, headers: dict = None, cookies: dict = None, target_url: str = None):
        self.playwright = await async_playwright().start()
        self.browser = await self.playwright.chromium.launch(headless=True)

        context_options = {
            'viewport': {'width': 1280, 'height': 800},
            'ignore_https_errors': True,
        }
        if headers:
            context_options['extra_http_headers'] = headers

        self.context = await self.browser.new_context(**context_options)

        if cookies and target_url:
            from urllib.parse import urlparse
            domain = urlparse(target_url).hostname
            formatted_cookies = [
                {"name": k, "value": v, "domain": domain, "path": "/"}
                for k, v in cookies.items()
            ]
            await self.context.add_cookies(formatted_cookies)

        self.page = await self.context.new_page()

        # ── 1. Network request interception ──────────────────────────────────
        # Captures every XHR/fetch/document request: URL, method, body.
        async def _on_request(request):
            try:
                method = request.method
                post_data = None
                if method in ("POST", "PUT", "PATCH"):
                    try:
                        post_data = request.post_data
                        if post_data and len(post_data) > 600:
                            post_data = post_data[:600] + "…"
                    except Exception:
                        pass
                self.captured_requests.append({
                    "url": request.url,
                    "method": method,
                    "resource_type": request.resource_type,
                    "post_data": post_data,
                    "headers": dict(request.headers),
                })
            except Exception:
                pass

        async def _on_response(response):
            try:
                self.captured_responses.append({
                    "url": response.url,
                    "status": response.status,
                    "content_type": response.headers.get("content-type", ""),
                })
            except Exception:
                pass

        self.page.on("request", _on_request)
        self.page.on("response", _on_response)

        # ── 2. WebSocket interception ─────────────────────────────────────────
        # Captures WS connections and all sent/received frames.
        # Critical for real-time apps (chat, trading, live dashboards).
        def _on_websocket(ws):
            entry = {"url": ws.url, "frames_sent": [], "frames_received": []}
            self.captured_websockets.append(entry)

            def _on_frame_sent(payload):
                try:
                    entry["frames_sent"].append(
                        payload[:300] if isinstance(payload, str) else repr(payload[:100])
                    )
                except Exception:
                    pass

            def _on_frame_received(payload):
                try:
                    entry["frames_received"].append(
                        payload[:300] if isinstance(payload, str) else repr(payload[:100])
                    )
                except Exception:
                    pass

            ws.on("framesent", _on_frame_sent)
            ws.on("framereceived", _on_frame_received)

        self.page.on("websocket", _on_websocket)

        # ── 3. Console message capture ────────────────────────────────────────
        # Catches console.log/warn/error output — often contains:
        # leaked API tokens, debug endpoints, stack traces, JWT values,
        # internal URLs, framework errors with file paths.
        def _on_console(msg):
            try:
                text = msg.text
                if len(text) > 800:
                    text = text[:800] + "…"
                self.console_messages.append({
                    "type": msg.type,   # "log", "warning", "error", "info", "debug"
                    "text": text,
                })
            except Exception:
                pass

        self.page.on("console", _on_console)

        # ── 4. Dialog interception ────────────────────────────────────────────
        async def _on_dialog(dialog):
            self.last_dialog = {"type": dialog.type, "message": dialog.message}
            await dialog.accept()

        self.page.on("dialog", _on_dialog)

    # ── Stop ─────────────────────────────────────────────────────────────────

    async def stop(self):
        if self.context:
            await self.context.close()
        if self.browser:
            await self.browser.close()
        if self.playwright:
            await self.playwright.stop()

    # ── Navigation ───────────────────────────────────────────────────────────

    async def navigate(self, url: str, headers: dict = None, cookies: dict = None):
        if not self.page:
            await self.start(headers, cookies, url)
        try:
            from src.core.throttle import pace
            await pace()
        except Exception:
            pass
        response = await self.page.goto(url, wait_until="networkidle")
        return {
            "status": response.status if response else 0,
            "url": self.page.url,
        }

    async def get_dom(self):
        if not self.page:
            return ""
        return await self.page.content()

    # ── Active page interaction ───────────────────────────────────────────────

    async def trigger_dynamic_content(self) -> dict:
        """
        Actively interact with the page to trigger dynamically loaded content:
        - Scroll to bottom (lazy loading, infinite scroll)
        - Click tabs, accordions, dropdowns, buttons that are NOT navigation links
        - Hover over menus to reveal sub-items

        Returns a summary of interactions performed.
        """
        if not self.page:
            return {}

        summary = {"scrolled": False, "clicked": [], "errors": []}

        # ── Scroll to bottom in steps to trigger lazy-loading ────────────────
        try:
            await self.page.evaluate("""
                async () => {
                    const delay = ms => new Promise(r => setTimeout(r, ms));
                    let last = 0;
                    for (let i = 0; i < 5; i++) {
                        window.scrollBy(0, window.innerHeight);
                        await delay(400);
                        if (document.documentElement.scrollHeight === last) break;
                        last = document.documentElement.scrollHeight;
                    }
                    window.scrollTo(0, 0);
                }
            """)
            await self.page.wait_for_timeout(600)
            summary["scrolled"] = True
        except Exception as e:
            summary["errors"].append(f"scroll: {e}")

        # ── Click tabs, accordion headers, pill buttons, dropdown toggles ────
        # These trigger JS-loaded content and API calls that never appear in HTML.
        interactive_selectors = [
            # Bootstrap / generic tabs
            "[role='tab']:not([aria-selected='true'])",
            ".nav-link:not(.active)",
            ".tab:not(.active)",
            # Accordion
            "[data-toggle='collapse']",
            "[data-bs-toggle='collapse']",
            ".accordion-button.collapsed",
            # Dropdown toggles (reveal sub-menus with links)
            "[data-toggle='dropdown']",
            "[data-bs-toggle='dropdown']",
            ".dropdown-toggle",
            # Generic clickable elements labelled as expandable
            "[aria-expanded='false']",
            # "Load more" / pagination buttons
            "button[data-page]",
            "button.load-more",
            ".pagination a",
            # Filter / sort buttons that fire API calls
            "[data-filter]",
            "[data-sort]",
            "select[name='sort']",
            "select[name='filter']",
        ]
        for sel in interactive_selectors:
            try:
                elements = await self.page.query_selector_all(sel)
                for el in elements[:5]:      # max 5 per selector to avoid long loops
                    try:
                        is_visible = await el.is_visible()
                        if not is_visible:
                            continue
                        tag = await el.evaluate("e => e.tagName.toLowerCase()")
                        text = (await el.inner_text())[:40].strip().replace("\n", " ")
                        if tag == "select":
                            # Select the second option to fire a change/API event
                            await el.select_option(index=1)
                        else:
                            await el.click(timeout=2000)
                        await self.page.wait_for_timeout(500)
                        summary["clicked"].append(f"{sel} → '{text}'")
                    except Exception:
                        pass
            except Exception:
                pass

        # ── Hover over top-level menu items to reveal hidden sub-menus ────────
        hover_selectors = [
            "nav > ul > li", "nav > .nav-item", ".menu > li",
            ".topbar li", "header li",
        ]
        for sel in hover_selectors:
            try:
                items = await self.page.query_selector_all(sel)
                for item in items[:8]:
                    try:
                        await item.hover(timeout=1000)
                        await self.page.wait_for_timeout(300)
                    except Exception:
                        pass
            except Exception:
                pass

        return summary

    # ── JS context extraction ─────────────────────────────────────────────────

    async def extract_js_context(self) -> dict:
        """
        Extract security-relevant data from the JavaScript runtime context:
        - Framework state (Next.js, Nuxt, Angular, React)
        - Global config objects (API base URLs, feature flags, environment)
        - Exposed secrets or tokens in window variables
        - GraphQL schema hints
        - Service worker registration URLs
        """
        if not self.page:
            return {}

        result = {}

        js_probes = {
            # Next.js
            "next_data":       "window.__NEXT_DATA__ ? JSON.stringify(window.__NEXT_DATA__).substring(0, 2000) : null",
            # Nuxt.js
            "nuxt_state":      "window.__NUXT__ ? JSON.stringify(window.__NUXT__).substring(0, 2000) : null",
            # Angular
            "ng_version":      "window.ng ? (window.ng.VERSION || window.ng.version || {}).full || 'present' : null",
            # React (look for DevTools hook)
            "react_present":   "!!(window.__REACT_DEVTOOLS_GLOBAL_HOOK__ || window._reactFiberHostRoot)",
            # Common config objects
            "window_config":   """(function(){
                var keys = ['API_URL','API_BASE','API_BASE_URL','BASE_URL','BACKEND_URL',
                            'CONFIG','config','APP_CONFIG','appConfig','__config__',
                            'apiBase','apiUrl','baseURL','endpoints','ENDPOINTS'];
                var found = {};
                keys.forEach(function(k){
                    if (window[k] !== undefined) {
                        try { found[k] = JSON.stringify(window[k]).substring(0, 400); }
                        catch(e) { found[k] = String(window[k]).substring(0, 200); }
                    }
                });
                return Object.keys(found).length ? JSON.stringify(found) : null;
            })()""",
            # Environment variables exposed to frontend
            "process_env":     """(function(){
                if (typeof process !== 'undefined' && process.env) {
                    try {
                        var e = {};
                        Object.keys(process.env).forEach(function(k){
                            if (!/secret|password|private/i.test(k))
                                e[k] = String(process.env[k]).substring(0, 100);
                        });
                        return JSON.stringify(e).substring(0, 1000);
                    } catch(e) { return null; }
                }
                return null;
            })()""",
            # GraphQL introspection hint
            "graphql_client":  """(function(){
                var keys = Object.keys(window);
                var gql = keys.filter(function(k){
                    return /apollo|graphql|relay/i.test(k);
                });
                return gql.length ? gql.join(',') : null;
            })()""",
            # Service Worker registrations
            "service_workers": """(function(){
                if (!navigator.serviceWorker) return null;
                return navigator.serviceWorker.getRegistrations().then(function(regs){
                    return regs.map(function(r){ return r.scope; }).join(',');
                });
            })()""",
            # LocalStorage keys and values (security-relevant ones)
            "localstorage":    """(function(){
                try {
                    var out = {};
                    for (var i = 0; i < localStorage.length; i++) {
                        var k = localStorage.key(i);
                        var v = localStorage.getItem(k) || '';
                        out[k] = v.substring(0, 200);
                    }
                    return JSON.stringify(out).substring(0, 1500);
                } catch(e) { return null; }
            })()""",
            # SessionStorage keys and values
            "sessionstorage":  """(function(){
                try {
                    var out = {};
                    for (var i = 0; i < sessionStorage.length; i++) {
                        var k = sessionStorage.key(i);
                        var v = sessionStorage.getItem(k) || '';
                        out[k] = v.substring(0, 200);
                    }
                    return JSON.stringify(out).substring(0, 1500);
                } catch(e) { return null; }
            })()""",
            # All window keys that look like API/config/token
            "suspicious_globals": """(function(){
                var suspicious = [];
                Object.keys(window).forEach(function(k){
                    if (/token|key|secret|auth|jwt|api|endpoint|url|config|pass|cred/i.test(k)) {
                        try {
                            var v = window[k];
                            if (typeof v === 'string' || typeof v === 'number')
                                suspicious.push(k + '=' + String(v).substring(0, 100));
                            else if (typeof v === 'object' && v !== null)
                                suspicious.push(k + '={object}');
                        } catch(e) {}
                    }
                });
                return suspicious.length ? suspicious.join(' | ') : null;
            })()""",
        }

        for key, js_code in js_probes.items():
            try:
                value = await self.page.evaluate(js_code)
                if value:
                    result[key] = value
            except Exception:
                pass

        return result

    # ── Storage inspection ────────────────────────────────────────────────────

    async def get_cookies_detail(self) -> List[Dict]:
        """Return all cookies with security flag analysis."""
        if not self.context:
            return []
        try:
            cookies = await self.context.cookies()
            result = []
            for c in cookies:
                result.append({
                    "name": c.get("name", ""),
                    "value": c.get("value", "")[:100],
                    "domain": c.get("domain", ""),
                    "path": c.get("path", "/"),
                    "http_only": c.get("httpOnly", False),
                    "secure": c.get("secure", False),
                    "same_site": c.get("sameSite", "None"),
                    "expires": c.get("expires", -1),
                })
            return result
        except Exception:
            return []

    # ── Existing methods ──────────────────────────────────────────────────────

    async def inject_evidence_banner(self, message: str, color: str = "#d32f2f"):
        if not self.page:
            return
        safe_msg = message.replace("'", "\\'").replace("\n", " ")
        try:
            await self.page.evaluate(f"""
                (function() {{
                    var b = document.getElementById('__pentest_banner__');
                    if (b) b.remove();
                    var div = document.createElement('div');
                    div.id = '__pentest_banner__';
                    div.style.cssText = (
                        'position:fixed;top:0;left:0;width:100%;z-index:2147483647;'
                        'background:{color};color:#fff;font-size:18px;font-weight:bold;'
                        'padding:14px 20px;font-family:monospace;box-shadow:0 2px 8px rgba(0,0,0,0.5);'
                        'white-space:pre-wrap;word-break:break-all;'
                    );
                    div.textContent = '{safe_msg}';
                    document.body.prepend(div);
                }})();
            """)
        except Exception:
            pass

    async def scroll_to_error(self):
        if not self.page:
            return
        try:
            await self.page.evaluate("""
                (function() {
                    var errorKeywords = [
                        'error', 'warning', 'exception', 'sql', 'mysql', 'syntax',
                        'fatal', 'notice', 'traceback', 'stack trace', 'undefined',
                    ];
                    var walker = document.createTreeWalker(
                        document.body, NodeFilter.SHOW_TEXT, null, false
                    );
                    var node;
                    while ((node = walker.nextNode())) {
                        var txt = node.textContent.toLowerCase();
                        if (errorKeywords.some(function(k){ return txt.includes(k); })) {
                            var el = node.parentElement;
                            if (el && el.offsetHeight > 0) {
                                el.scrollIntoView({behavior:'instant', block:'center'});
                                return;
                            }
                        }
                    }
                })();
            """)
            await self.page.wait_for_timeout(300)
        except Exception:
            pass

    async def screenshot(self, path: str):
        if not self.page:
            return False
        try:
            await self.page.screenshot(path=path, full_page=True)
            return True
        except Exception as e:
            print(f"Screenshot failed: {e}")
            return False

    async def click(self, selector: str):
        if not self.page:
            return False
        try:
            await self.page.click(selector)
            return True
        except Exception as e:
            print(f"Click failed: {e}")
            return False

    async def fill(self, selector: str, text: str):
        if not self.page:
            return False
        try:
            await self.page.fill(selector, text)
            return True
        except Exception as e:
            print(f"Fill failed: {e}")
            return False
