import argparse
import os
import sys

DEBUG_PORT = 9421
CDP_PORT = 62000


class CliOptions:
    def __init__(self, cdp_port: int, debug_main: bool, debug_frida: bool,
                 scripts_dir: str = "", script_files: list = None):
        self.debug_port = DEBUG_PORT  # 小程序硬编码 9421，不可修改
        self.cdp_port = cdp_port
        self.debug_main = debug_main
        self.debug_frida = debug_frida
        self.scripts_dir = scripts_dir
        self.script_files = script_files or []


def parse_port(name: str, value, default_value: int) -> int:
    if value is None:
        return default_value
    try:
        port = int(value)
    except (ValueError, TypeError):
        raise ValueError(f"[main] invalid {name}: {value}")
    if port < 1 or port > 65535:
        raise ValueError(f"[main] invalid {name}: {value}")
    return port


def parse_cli_options() -> CliOptions:
    parser = argparse.ArgumentParser(
        description="First - WeChat Miniapp Debugger",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=f"""Examples:
  python main.py
  python main.py --cdp-port 62000
  python main.py --debug-main --debug-frida

Default ports:
  Debug server: {DEBUG_PORT} (fixed)
  CDP proxy:    {CDP_PORT}

Usage:
  Connect Chrome DevTools to: devtools://devtools/bundled/inspector.html?ws=127.0.0.1:<cdp-port>"""
    )
    parser.add_argument("--cdp-port", type=str, default=None,
                        help=f"CDP proxy server port (default: {CDP_PORT})")
    parser.add_argument("--debug-main", action="store_true", default=False,
                        help="Output main process debug messages")
    parser.add_argument("--debug-frida", action="store_true", default=False,
                        help="Output Frida client messages")
    parser.add_argument("--scripts-dir", type=str, default=None,
                        help="UserScripts directory path (default: ./userscripts)")
    parser.add_argument("--script", type=str, action="append", default=None,
                        help="Specific .js file(s) to inject (can be used multiple times). "
                             "When set, --scripts-dir is ignored.")

    args = parser.parse_args()

    if args.scripts_dir:
        scripts_dir = os.path.abspath(args.scripts_dir)
    else:
        scripts_dir = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "userscripts")

    script_files = []
    if args.script:
        for f in args.script:
            script_files.append(os.path.abspath(f))

    return CliOptions(
        cdp_port=parse_port("--cdp-port", args.cdp_port, CDP_PORT),
        debug_main=args.debug_main,
        debug_frida=args.debug_frida,
        scripts_dir=scripts_dir,
        script_files=script_files,
    )
