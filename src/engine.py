"""
DebugEngine - wraps debug_server, proxy_server, frida_server into a reusable class.
"""
import asyncio
import json
import random
import re
import sys
from collections import Counter
from pathlib import Path

import frida
import websockets
import websockets.server
import websockets.exceptions

from .codex import wrap_debug_message_data, unwrap_debug_message_data
from .third_party import wmpf_debug_pb2 as proto
from .userscript import (
    build_cdp_enable_page_command,
    build_cdp_add_script_command,
    build_injection_wrapper,
)


class DebugMessageBus:
    """Central event bus bridging debug server and CDP proxy server."""

    def __init__(self):
        self._cdp_callbacks = []
        self._proxy_callbacks = []

    def on_cdp_message(self, callback):
        self._cdp_callbacks.append(callback)

    def on_proxy_message(self, callback):
        self._proxy_callbacks.append(callback)

    def emit_cdp_message(self, message: str):
        for cb in self._cdp_callbacks:
            cb(message)

    def emit_proxy_message(self, message: str):
        for cb in self._proxy_callbacks:
            cb(message)


def buffer_to_hex_string(data: bytes) -> str:
    return data.hex()


def _build_protobuf_cdp_message(cdp_json: str, seq: int) -> bytes:
    """Wrap a CDP JSON command into protobuf binary for sending to the miniapp runtime."""
    raw_payload = {
        "jscontext_id": "",
        "op_id": round(100 * random.random()),
        "payload": cdp_json,
    }
    wrapped = wrap_debug_message_data(raw_payload, "chromeDevtools", 0)
    out_msg = proto.WARemoteDebug_DebugMessage()
    out_msg.seq = seq
    out_msg.category = "chromeDevtools"
    out_msg.data = wrapped["buffer"]
    out_msg.compressAlgo = 0
    out_msg.originalSize = wrapped["originalSize"]
    return out_msg.SerializeToString()


class DebugEngine:
    """Wraps all three subsystems: debug server, proxy server, frida injection."""

    def __init__(self, options, logger, userscripts=None):
        self.options = options
        self.logger = logger
        self.bus = DebugMessageBus()
        self.userscripts = userscripts or []
        self.debug_srv = None
        self.proxy_srv = None
        self.frida_session = None
        self.frida_script = None
        self.miniapp_clients = set()
        self.devtools_clients = set()
        self.message_counter = 0
        self._pending_responses = {}
        self._cmd_counter = 80000
        self._status_callbacks = []
        self._event_listeners = {}   # method -> [callback, ...]
        self.status = {"frida": False, "miniapp": False, "devtools": False}

    def on_status_change(self, callback):
        self._status_callbacks.append(callback)

    def _notify_status(self, key, value):
        self.status[key] = value
        for cb in self._status_callbacks:
            try:
                cb(dict(self.status))
            except Exception:
                pass

    def _next_cmd_id(self):
        self._cmd_counter += 1
        return self._cmd_counter

    async def start(self):
        """Start all three subsystems."""
        self.debug_srv = await self._start_debug_server()
        self.proxy_srv = await self._start_proxy_server()
        try:
            self.frida_session, self.frida_script = await self._start_frida()
            self._notify_status("frida", True)
        except Exception as e:
            self.logger.error(str(e))
            raise

    async def stop(self):
        """Graceful shutdown."""
        if self.debug_srv:
            self.debug_srv.close()
            await self.debug_srv.wait_closed()
            self.debug_srv = None
        if self.proxy_srv:
            self.proxy_srv.close()
            await self.proxy_srv.wait_closed()
            self.proxy_srv = None
        if self.frida_script:
            try:
                self.frida_script.unload()
            except Exception:
                pass
            self.frida_script = None
        if self.frida_session:
            try:
                self.frida_session.detach()
            except Exception:
                pass
            self.frida_session = None
        self._notify_status("frida", False)
        self._notify_status("miniapp", False)
        self._notify_status("devtools", False)
        self.miniapp_clients.clear()
        self.devtools_clients.clear()
        self.message_counter = 0
        self._pending_responses.clear()
        self.logger.info("[server] engine stopped")

    async def evaluate_js(self, expression, timeout=5.0):
        """Send Runtime.evaluate via CDP to the miniapp, return result dict."""
        if not self.miniapp_clients:
            raise RuntimeError("No miniapp client connected")
        cmd_id = self._next_cmd_id()
        cdp_cmd = json.dumps({
            "id": cmd_id,
            "method": "Runtime.evaluate",
            "params": {"expression": expression, "returnByValue": True}
        })
        loop = asyncio.get_event_loop()
        future = loop.create_future()
        self._pending_responses[cmd_id] = future
        self.bus.emit_proxy_message(cdp_cmd)
        try:
            return await asyncio.wait_for(future, timeout=timeout)
        except asyncio.TimeoutError:
            self._pending_responses.pop(cmd_id, None)
            raise

    async def send_cdp_command(self, method, params=None, timeout=5.0):
        """Send an arbitrary CDP command and return the response."""
        if not self.miniapp_clients:
            raise RuntimeError("No miniapp client connected")
        cmd_id = self._next_cmd_id()
        cdp_cmd = json.dumps({"id": cmd_id, "method": method, "params": params or {}})
        loop = asyncio.get_event_loop()
        future = loop.create_future()
        self._pending_responses[cmd_id] = future
        self.bus.emit_proxy_message(cdp_cmd)
        try:
            return await asyncio.wait_for(future, timeout=timeout)
        except asyncio.TimeoutError:
            self._pending_responses.pop(cmd_id, None)
            raise

    async def set_extra_headers(self, headers: dict):
        """Enable Network domain and set extra HTTP headers via CDP."""
        await self.send_cdp_command("Network.enable")
        await self.send_cdp_command("Network.setExtraHTTPHeaders",
                                    {"headers": headers})

    def on_cdp_event(self, method, callback):
        """Subscribe to a CDP event by method name (e.g. 'Debugger.scriptParsed')."""
        self._event_listeners.setdefault(method, []).append(callback)

    def off_cdp_event(self, method, callback):
        """Unsubscribe from a CDP event."""
        cbs = self._event_listeners.get(method, [])
        if callback in cbs:
            cbs.remove(callback)

    def _handle_cdp_response(self, message_str):
        """Check if a CDP response matches a pending evaluate_js call, or dispatch events."""
        try:
            data = json.loads(message_str)
        except (json.JSONDecodeError, TypeError):
            return
        msg_id = data.get("id")
        if msg_id is not None and msg_id in self._pending_responses:
            future = self._pending_responses.pop(msg_id)
            if not future.done():
                future.set_result(data)
        # Dispatch CDP events (messages with "method" but no "id")
        method = data.get("method")
        if method and method in self._event_listeners:
            for cb in self._event_listeners[method]:
                try:
                    cb(data)
                except Exception:
                    pass

    # ── Debug Server ──

    async def _start_debug_server(self):
        engine = self
        logger = self.logger
        bus = self.bus
        userscripts = self.userscripts

        scripts_injected = False

        def on_proxy_message(message: str):
            engine.message_counter += 1
            raw_payload = {
                "jscontext_id": "",
                "op_id": round(100 * random.random()),
                "payload": str(message),
            }
            logger.main_debug(raw_payload)
            wrapped = wrap_debug_message_data(raw_payload, "chromeDevtools", 0)
            out_msg = proto.WARemoteDebug_DebugMessage()
            out_msg.seq = engine.message_counter
            out_msg.category = "chromeDevtools"
            out_msg.data = wrapped["buffer"]
            out_msg.compressAlgo = 0
            out_msg.originalSize = wrapped["originalSize"]
            encoded = out_msg.SerializeToString()
            clients_snapshot = list(engine.miniapp_clients)
            for ws in clients_snapshot:
                try:
                    task = asyncio.ensure_future(ws.send(encoded))
                    task.add_done_callback(lambda t: t.exception() if t.done() and not t.cancelled() and t.exception() else None)
                except Exception:
                    pass

        bus.on_proxy_message(on_proxy_message)

        async def handler(websocket):
            nonlocal scripts_injected
            engine.miniapp_clients.add(websocket)
            engine._notify_status("miniapp", True)
            logger.info("[miniapp] miniapp client connected")

            if userscripts and not scripts_injected:
                scripts_injected = True
                logger.info("[userscript] registering scripts immediately on connection...")
                try:
                    seq = engine.message_counter
                    cmd_id = 90000
                    seq += 1
                    await websocket.send(_build_protobuf_cdp_message(
                        build_cdp_enable_page_command(cmd_id), seq
                    ))
                    cmd_id += 1
                    seq += 1
                    await websocket.send(_build_protobuf_cdp_message(
                        json.dumps({"id": cmd_id, "method": "Debugger.enable", "params": {}}), seq
                    ))
                    cmd_id += 1
                    logger.info("[anti-debug] Debugger.enable sent")
                    seq += 1
                    await websocket.send(_build_protobuf_cdp_message(
                        json.dumps({"id": cmd_id, "method": "Debugger.setSkipAllPauses", "params": {"skip": True}}), seq
                    ))
                    cmd_id += 1
                    logger.info("[anti-debug] Debugger.setSkipAllPauses(true) sent")
                    for script in userscripts:
                        seq += 1
                        await websocket.send(_build_protobuf_cdp_message(
                            build_cdp_add_script_command(script, cmd_id), seq
                        ))
                        cmd_id += 1
                        logger.info(f"[userscript] registered (persistent): {script.name}")
                    engine.message_counter = seq
                    logger.info("[userscript] registration done, scripts will run on page load")
                except Exception as e:
                    logger.error(f"[userscript] registration error: {e}")

            immediate_done = False
            try:
                async for message in websocket:
                    if isinstance(message, str):
                        message = message.encode("utf-8")
                    msg_category = ""
                    try:
                        decoded_msg = proto.WARemoteDebug_DebugMessage()
                        decoded_msg.ParseFromString(message)
                        msg_category = decoded_msg.category
                    except Exception:
                        pass
                    self._process_miniapp_message(message)
                    if msg_category == "setupContext" and userscripts and not immediate_done:
                        immediate_done = True
                        await asyncio.sleep(0.5)
                        try:
                            seq = engine.message_counter
                            cmd_id = 91000
                            seq += 1
                            await websocket.send(_build_protobuf_cdp_message(
                                json.dumps({"id": cmd_id, "method": "Debugger.enable", "params": {}}), seq
                            ))
                            cmd_id += 1
                            seq += 1
                            await websocket.send(_build_protobuf_cdp_message(
                                json.dumps({"id": cmd_id, "method": "Debugger.setSkipAllPauses", "params": {"skip": True}}), seq
                            ))
                            cmd_id += 1
                            logger.info("[anti-debug] Debugger.setSkipAllPauses re-sent after setupContext")
                            for script in userscripts:
                                wrapped = build_injection_wrapper(script)
                                seq += 1
                                cdp_cmd = json.dumps({
                                    "id": cmd_id,
                                    "method": "Runtime.evaluate",
                                    "params": {
                                        "expression": wrapped,
                                        "includeCommandLineAPI": True,
                                        "silent": False,
                                    },
                                })
                                await websocket.send(_build_protobuf_cdp_message(cdp_cmd, seq))
                                cmd_id += 1
                                logger.info(f"[userscript] immediate inject (Runtime.evaluate): {script.name}")
                            engine.message_counter = seq
                        except Exception as e:
                            logger.error(f"[userscript] immediate inject error: {e}")
            except websockets.exceptions.ConnectionClosed:
                pass
            except Exception as e:
                logger.error(f"[miniapp] miniapp client err: {e}")
            finally:
                engine.miniapp_clients.discard(websocket)
                if not engine.miniapp_clients:
                    engine._notify_status("miniapp", False)
                logger.info("[miniapp] miniapp client disconnected")

        server = await websockets.server.serve(
            handler, "0.0.0.0", self.options.debug_port,
            max_size=None,
        )
        logger.info(f"[server] debug server running on ws://localhost:{self.options.debug_port}")
        logger.info("[server] debug server waiting for miniapp to connect...")
        return server

    def _process_miniapp_message(self, message: bytes):
        self.logger.main_debug(
            f"[miniapp] client received raw message (hex): {buffer_to_hex_string(message)}"
        )
        unwrapped_data = None
        try:
            decoded = proto.WARemoteDebug_DebugMessage()
            decoded.ParseFromString(message)
            unwrapped_data = unwrap_debug_message_data(decoded)
            self.logger.main_debug("[miniapp] [DEBUG] decoded data:")
            self.logger.main_debug(unwrapped_data)
        except Exception as e:
            self.logger.error(f"[miniapp] miniapp client err: {e}")

        if unwrapped_data is None:
            return

        if unwrapped_data.get("category") == "chromeDevtoolsResult":
            payload = unwrapped_data["data"].get("payload", "")
            self.bus.emit_cdp_message(payload)
            # Also check for pending evaluate_js responses
            self._handle_cdp_response(payload)

    # ── Proxy Server ──

    async def _start_proxy_server(self):
        engine = self
        logger = self.logger
        bus = self.bus

        def on_cdp_message(message: str):
            clients_snapshot = list(engine.devtools_clients)
            for ws in clients_snapshot:
                try:
                    task = asyncio.ensure_future(ws.send(message))
                    task.add_done_callback(lambda t: t.exception() if t.done() and not t.cancelled() and t.exception() else None)
                except Exception:
                    pass

        bus.on_cdp_message(on_cdp_message)

        async def handler(websocket):
            engine.devtools_clients.add(websocket)
            engine._notify_status("devtools", True)
            logger.info("[cdp] CDP client connected")
            try:
                async for message in websocket:
                    if isinstance(message, bytes):
                        message = message.decode("utf-8")
                    bus.emit_proxy_message(message)
            except websockets.exceptions.ConnectionClosed:
                pass
            except Exception as e:
                logger.error(f"[cdp] CDP client err: {e}")
            finally:
                engine.devtools_clients.discard(websocket)
                if not engine.devtools_clients:
                    engine._notify_status("devtools", False)
                logger.info("[cdp] CDP client disconnected")

        server = await websockets.server.serve(
            handler, "0.0.0.0", self.options.cdp_port,
            max_size=None,
        )
        logger.info(f"[server] proxy server running on ws://localhost:{self.options.cdp_port}")
        logger.info(f"[server] link: devtools://devtools/bundled/inspector.html?ws=127.0.0.1:{self.options.cdp_port}")
        return server

    # ── Frida ──

    async def _start_frida(self):
        logger = self.logger
        device = frida.get_local_device()
        processes = device.enumerate_processes(scope="metadata")
        wmpf_processes = [p for p in processes if p.name == "WeChatAppEx.exe"]
        if not wmpf_processes:
            raise RuntimeError("[frida] WeChatAppEx.exe process not found")

        wmpf_ppids = []
        for p in wmpf_processes:
            ppid = p.parameters.get("ppid", 0)
            wmpf_ppids.append(ppid if ppid else 0)

        if not wmpf_ppids:
            raise RuntimeError("[frida] WeChatAppEx.exe process not found")

        pid_counts = Counter(wmpf_ppids)
        wmpf_pid = pid_counts.most_common(1)[0][0]

        if wmpf_pid == 0:
            raise RuntimeError("[frida] WeChatAppEx.exe process not found")

        wmpf_process = None
        for p in processes:
            if p.pid == wmpf_pid:
                wmpf_process = p
                break

        if wmpf_process is None:
            raise RuntimeError("[frida] Could not find main WMPF process")

        wmpf_process_path = wmpf_process.parameters.get("path", "")
        version_matches = re.findall(r"\d+", wmpf_process_path)
        if not version_matches:
            raise RuntimeError("[frida] error in find wmpf version")
        wmpf_version = int(version_matches[-1])
        if wmpf_version == 0:
            raise RuntimeError("[frida] error in find wmpf version")

        session = device.attach(wmpf_pid)

        if getattr(sys, 'frozen', False):
            # PyInstaller onefile: resources in _MEIPASS; onedir: next to exe
            project_root = Path(getattr(sys, '_MEIPASS', Path(sys.executable).parent)).resolve()
        else:
            project_root = Path(__file__).parent.parent.resolve()

        hook_path = project_root / "frida" / "hook.js"
        if not hook_path.exists():
            raise RuntimeError("[frida] hook script not found")
        script_content = hook_path.read_text(encoding="utf-8")

        config_path = project_root / "frida" / "config" / f"addresses.{wmpf_version}.json"
        if not config_path.exists():
            raise RuntimeError(f"[frida] version config not found: {wmpf_version}")
        config_content = config_path.read_text(encoding="utf-8")
        config_content = json.dumps(json.loads(config_content))

        final_script = script_content.replace("@@CONFIG@@", config_content)
        script = session.create_script(final_script)

        def on_message(message, data):
            if message.get("type") == "error":
                logger.error("[frida client]", message)
                return
            logger.frida_debug("[frida client]", message.get("payload", ""))

        script.on("message", on_message)
        script.load()

        logger.info(f"[frida] script loaded, WMPF version: {wmpf_version}, pid: {wmpf_pid}")
        logger.info("[frida] you can now open any miniapps")

        return session, script
