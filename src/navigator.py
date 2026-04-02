"""
MiniProgramNavigator - inject JS navigator and control mini program pages.
"""
import asyncio
import json
from pathlib import Path

_NAV_JS = (Path(__file__).parent / "nav_inject.js").read_text(encoding="utf-8")


class MiniProgramNavigator:
    """Inject universal navigator JS, then use window.nav for all operations."""

    def __init__(self, engine):
        self.engine = engine
        self.pages = []
        self.tab_bar_pages = []
        self.app_info = {}
        self._injected = False

    async def _ensure(self, force=False):
        if force or not self._injected:
            await self.engine.evaluate_js(_NAV_JS, timeout=10.0)
            self._injected = True

    async def fetch_config(self):
        """Inject navigator and read pages/tabBar/appid from window.nav."""
        # 强制重新注入，以支持切换小程序后获取新配置
        await self._ensure(force=True)
        result = await self.engine.evaluate_js(
            "JSON.stringify({pages:window.nav?window.nav.allPages:[],"
            "tabBar:window.nav?window.nav.tabBarPages:[],"
            "appid:window.nav&&window.nav.config?(window.nav.config.appid||''):'',"
            "entry:window.nav&&window.nav.config?(window.nav.config.entryPagePath||''):'',"
            "name:(function(){try{var a=window.__wxConfig||window.wx&&window.wx.__wxConfig||{};"
            "var b=a.accountInfo&&a.accountInfo.appAccount;"
            "return b&&b.nickname||a.appname||''}catch(e){return ''}})()"
            "})",
            timeout=5.0,
        )
        value = self._extract_value(result)
        if not value:
            return
        try:
            config = json.loads(value)
        except (json.JSONDecodeError, TypeError):
            return
        self.pages = config.get("pages", [])
        self.tab_bar_pages = config.get("tabBar", [])
        self.app_info = {
            "appid": config.get("appid", ""),
            "entry": config.get("entry", ""),
            "name": config.get("name", ""),
        }

    async def navigate_to(self, route):
        """Smart navigate via window.nav.goTo (switchTab for tabbar, navigateTo for others)."""
        await self._ensure()
        safe = route.replace("'", "\\'")
        await self.engine.evaluate_js(f"window.nav.goTo('{safe}')", timeout=5.0)

    async def redirect_to(self, route):
        """wx.redirectTo via the detected wxFrame."""
        await self._ensure()
        safe = route.replace("'", "\\'")
        await self.engine.evaluate_js(
            f"window.nav.wxFrame.wx.redirectTo({{url:'/{safe}'}})", timeout=5.0
        )

    async def relaunch_to(self, route):
        """Safe navigate: reLaunch → switchTab → redirectTo fallback chain."""
        await self._ensure()
        safe = route.replace("'", "\\'")
        await self.engine.evaluate_js(
            f"window.nav._safeNavigate('{safe}')", timeout=5.0
        )

    async def navigate_back(self, delta=1):
        """wx.navigateBack via window.nav.back."""
        await self._ensure()
        await self.engine.evaluate_js(f"window.nav.back({delta})", timeout=5.0)

    async def get_current_route(self):
        """Get current page route via the detected wxFrame."""
        await self._ensure()
        result = await self.engine.evaluate_js(
            "(function(){try{if(window.nav&&window.nav.wxFrame){"
            "var p=window.nav.wxFrame.getCurrentPages();"
            "return p.length?p[p.length-1].route||p[p.length-1].__route__||'':''"
            "}return ''}catch(e){return ''}})()",
            timeout=3.0,
        )
        return self._extract_value(result) or ""

    async def auto_visit(self, pages, delay=2.0, on_progress=None, cancel_event=None):
        """Visit pages sequentially using safe navigation."""
        total = len(pages)
        for i, route in enumerate(pages):
            if cancel_event and cancel_event.is_set():
                break
            if on_progress:
                on_progress(i, total, route)
            try:
                await self.relaunch_to(route)
            except Exception:
                pass
            await asyncio.sleep(delay)
        if on_progress:
            on_progress(total, total, "done")

    async def enable_redirect_guard(self):
        """开启防强制跳转"""
        await self._ensure()
        result = await self.engine.evaluate_js(
            "JSON.stringify(window.nav.enableRedirectGuard())", timeout=5.0)
        value = self._extract_value(result)
        if value:
            try:
                return json.loads(value)
            except (json.JSONDecodeError, TypeError):
                pass
        return {"ok": False}

    async def disable_redirect_guard(self):
        """关闭防强制跳转"""
        await self._ensure()
        await self.engine.evaluate_js(
            "window.nav.disableRedirectGuard()", timeout=5.0)

    async def get_blocked_redirects(self):
        """获取被拦截的跳转记录"""
        await self._ensure()
        result = await self.engine.evaluate_js(
            "JSON.stringify(window.nav.getBlockedRedirects())", timeout=5.0)
        value = self._extract_value(result)
        if value:
            try:
                return json.loads(value)
            except (json.JSONDecodeError, TypeError):
                pass
        return []

    @staticmethod
    def _extract_value(result):
        if not result:
            return None
        r = result.get("result", {})
        inner = r.get("result", {})
        return inner.get("value")
