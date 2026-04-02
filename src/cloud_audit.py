"""
CloudAuditor — 全局云函数捕获（只显示实际触发过的）+ 手动调用
"""
import asyncio
import json
from pathlib import Path

_CLOUD_JS = (Path(__file__).parent / "cloud_audit_inject.js").read_text(encoding="utf-8")


class CloudAuditor:
    """全局云函数 Hook 捕获"""

    def __init__(self, engine):
        self.engine = engine
        self._injected = False
        self._enabled = False
        self._seen_count = 0  # 上次拉取到的 hookedCalls 长度

    async def inject(self):
        await self.engine.evaluate_js(_CLOUD_JS, timeout=10.0)
        self._injected = True

    async def start(self):
        """启动全局 Hook：注入 JS，安装 hook，启动自动扫描新 frame"""
        if self._enabled:
            return {"ok": True, "already": True}
        await self.inject()
        result = await self.engine.evaluate_js(
            "JSON.stringify(window.cloudAudit.installHook())", timeout=5.0)
        value = self._extract_value(result)
        if value:
            try:
                info = json.loads(value)
                if info.get("ok"):
                    self._enabled = True
                return info
            except (json.JSONDecodeError, TypeError):
                pass
        return {"ok": False}

    async def stop(self):
        """停止 Hook"""
        if not self._enabled:
            return
        self._enabled = False
        try:
            await self.inject()
            await self.engine.evaluate_js(
                "window.cloudAudit.uninstallHook()", timeout=5.0)
        except Exception:
            pass

    async def poll(self):
        """拉取新捕获的云函数调用，只返回增量"""
        if not self._enabled:
            return []
        try:
            await self.inject()
            result = await self.engine.evaluate_js(
                "JSON.stringify(window.cloudAudit.getHookedCalls())", timeout=5.0)
            value = self._extract_value(result)
            if not value:
                return []
            calls = json.loads(value)
            if len(calls) <= self._seen_count:
                return []
            new_calls = calls[self._seen_count:]
            self._seen_count = len(calls)
            return new_calls
        except Exception:
            return []

    async def clear(self):
        """清空捕获记录"""
        self._seen_count = 0
        try:
            await self.inject()
            await self.engine.evaluate_js(
                "window.cloudAudit.clearHookedCalls()", timeout=3.0)
        except Exception:
            pass

    async def static_scan(self, on_progress=None):
        """静态扫描：通过 CDP Debugger 获取 JS 源码，提取云函数引用"""
        import re
        _RE_NAME = re.compile(r'name\s*:\s*["\']([^"\']+)["\']')
        _RE_DATA = re.compile(r'data\s*:\s*\{([^}]{1,500})\}')
        _RE_FIELD = re.compile(r'(\w+)\s*:')
        _RE_COLL = re.compile(r'\.collection\s*\(\s*["\']([^"\']+)["\']\s*\)')
        _SKIP = {"name", "success", "fail", "complete", "config", "env", "data"}
        _FILE_M = {"uploadFile", "downloadFile", "deleteFile", "getTempFileURL"}
        _DB_OPS = {"add", "get", "update", "remove", "count", "aggregate", "doc", "where"}

        # 获取当前 appId
        await self.inject()
        try:
            r = await self.engine.evaluate_js(
                "JSON.stringify(window.cloudAudit.detectEnv())", timeout=5.0)
            v = self._extract_value(r)
            if v:
                info = json.loads(v)
                if info.get("ok"):
                    self._current_appid = info.get("appId", "")
        except Exception:
            pass
        appid = getattr(self, '_current_appid', '')

        # 收集脚本
        script_ids = []
        def _on_parsed(data):
            p = data.get("params", {})
            sid = p.get("scriptId")
            if sid:
                script_ids.append((sid, p.get("url", "")))

        self.engine.on_cdp_event("Debugger.scriptParsed", _on_parsed)
        try:
            try:
                await self.engine.send_cdp_command("Debugger.disable", timeout=3.0)
            except Exception:
                pass
            await asyncio.sleep(0.2)
            await self.engine.send_cdp_command("Debugger.enable", timeout=5.0)
            await asyncio.sleep(1.5)
            prev = 0
            for _ in range(5):
                if len(script_ids) == prev and prev > 0:
                    break
                prev = len(script_ids)
                await asyncio.sleep(0.4)
        except Exception:
            pass
        finally:
            self.engine.off_cdp_event("Debugger.scriptParsed", _on_parsed)

        if on_progress:
            on_progress(f"发现 {len(script_ids)} 个脚本，开始扫描...")

        found = {}
        for i, (sid, url) in enumerate(script_ids):
            if on_progress and i % 10 == 0:
                on_progress(f"扫描中... ({i}/{len(script_ids)}) 已发现 {len(found)} 个")
            try:
                resp = await self.engine.send_cdp_command(
                    "Debugger.getScriptSource", {"scriptId": sid}, timeout=8.0)
                source = resp.get("result", {}).get("scriptSource", "")
                if not source:
                    continue
                # callFunction
                pos = 0
                while True:
                    pos = source.find("callFunction", pos)
                    if pos == -1:
                        break
                    w = source[pos:pos+1000]
                    nm = _RE_NAME.search(w)
                    if nm:
                        name = nm.group(1)
                        key = f"fn:{name}"
                        if key not in found:
                            found[key] = {"type": "function", "name": name, "params": [], "count": 0}
                        found[key]["count"] += 1
                        dm = _RE_DATA.search(w)
                        if dm:
                            for fm in _RE_FIELD.finditer(dm.group(1)):
                                f = fm.group(1)
                                if f not in _SKIP and f not in found[key]["params"]:
                                    found[key]["params"].append(f)
                    pos += 12
                # collection
                for m in _RE_COLL.finditer(source):
                    coll = m.group(1)
                    key = f"db:{coll}"
                    if key not in found:
                        found[key] = {"type": "database", "name": coll, "params": [], "count": 0}
                    found[key]["count"] += 1
                    after = source[m.end():m.end()+300]
                    for op in _DB_OPS:
                        if f".{op}(" in after and op not in found[key]["params"]:
                            found[key]["params"].append(op)
                # storage
                for fm in _FILE_M:
                    if fm in source:
                        key = f"storage:{fm}"
                        if key not in found:
                            found[key] = {"type": "storage", "name": fm, "params": [], "count": 0}
                        found[key]["count"] += 1
            except Exception:
                continue

        try:
            await self.engine.send_cdp_command("Debugger.disable", timeout=3.0)
        except Exception:
            pass

        results = []
        for key, info in found.items():
            results.append({
                "name": info["name"],
                "type": info["type"],
                "appId": appid,
                "params": info["params"],
                "count": info["count"],
            })
        if on_progress:
            on_progress(f"扫描完成，发现 {len(results)} 个云函数引用")
        return results

    async def call_function(self, name, data=None):
        await self.inject()
        safe_name = name.replace("'", "\\'")
        safe_data = json.dumps(data or {}, ensure_ascii=False)
        await self.engine.evaluate_js(
            "window._cloudAuditLastResult=null", timeout=3.0)
        js = (f"window.cloudAudit.callFunction('{safe_name}', {safe_data})"
              f".then(function(r){{window._cloudAuditLastResult=JSON.stringify(r)}})"
              f"['catch'](function(e){{window._cloudAuditLastResult="
              f"JSON.stringify({{ok:false,status:'fail',error:e.message||String(e)}})}})")
        await self.engine.evaluate_js(js, timeout=15.0)
        for _ in range(24):
            await asyncio.sleep(0.5)
            result = await self.engine.evaluate_js(
                "window._cloudAuditLastResult", timeout=5.0)
            value = self._extract_value(result)
            if value:
                try:
                    return json.loads(value)
                except (json.JSONDecodeError, TypeError):
                    return {"ok": False, "status": "fail", "reason": "parse error"}
        return {"ok": False, "status": "fail", "reason": "调用超时，无响应"}

    def export_report(self, all_items, call_history):
        return {
            "captured_calls": all_items,
            "call_history": {k: v for k, v in call_history.items() if v},
        }

    @staticmethod
    def _extract_value(result):
        if not result:
            return None
        r = result.get("result", {})
        inner = r.get("result", {})
        return inner.get("value")
