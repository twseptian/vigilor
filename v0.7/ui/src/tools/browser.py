from playwright.async_api import async_playwright, Page, BrowserContext
from typing import Optional


class BrowserTool:
    def __init__(self):
        self.playwright = None
        self.browser = None
        self.context: Optional[BrowserContext] = None
        self.page: Optional[Page] = None
        # Stores the last dialog (alert/confirm/prompt) that was auto-accepted.
        # Format: {"type": "alert", "message": "XSS"} or None
        self.last_dialog: Optional[dict] = None

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
            formatted_cookies = []
            for name, value in cookies.items():
                formatted_cookies.append({
                    "name": name,
                    "value": value,
                    "domain": domain,
                    "path": "/",
                })
            await self.context.add_cookies(formatted_cookies)

        self.page = await self.context.new_page()

        # Intercept and capture browser dialogs (alert / confirm / prompt).
        # Without a handler Playwright auto-dismisses them silently; with this
        # handler we capture the message so it can be shown in the screenshot.
        async def _on_dialog(dialog):
            self.last_dialog = {
                "type": dialog.type,
                "message": dialog.message,
            }
            await dialog.accept()

        self.page.on("dialog", _on_dialog)

    async def stop(self):
        if self.context:
            await self.context.close()
        if self.browser:
            await self.browser.close()
        if self.playwright:
            await self.playwright.stop()

    async def navigate(self, url: str, headers: dict = None, cookies: dict = None):
        if not self.page:
            await self.start(headers, cookies, url)
        response = await self.page.goto(url, wait_until="networkidle")
        return {
            "status": response.status if response else 0,
            "url": self.page.url,
        }

    async def get_dom(self):
        if not self.page:
            return ""
        return await self.page.content()

    async def inject_evidence_banner(self, message: str, color: str = "#d32f2f"):
        """Inject a fixed-position banner into the live page so the screenshot
        clearly shows what was triggered (e.g. 'XSS: alert(1) fired').
        The banner is removed from the DOM after the screenshot is taken."""
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
        """Scroll the page to the first visible element that looks like an
        error message, so error-based SQLi / verbose errors appear in the
        screenshot viewport."""
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
