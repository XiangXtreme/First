"""
First
Author: vs-olitus | https://github.com/vs-olitus/First
"""
import asyncio
import sys

from src.cli import parse_cli_options
from src.logger import create_logger
from src.engine import DebugEngine
from src.userscript import load_userscripts, load_userscripts_by_files


async def main():
    options = parse_cli_options()
    logger = create_logger(options)

    # Load userscripts
    if options.script_files:
        userscripts = load_userscripts_by_files(options.script_files)
    else:
        userscripts = load_userscripts(options.scripts_dir)
    if userscripts:
        logger.info(f"[userscript] loaded {len(userscripts)} userscript(s) from {options.scripts_dir}:")
        for s in userscripts:
            logger.info(f"[userscript]   - {s.name} (run-at: {s.run_at}, match: {s.match})")
    else:
        logger.info(f"[userscript] no userscripts found in {options.scripts_dir}")

    engine = DebugEngine(options, logger, userscripts)
    try:
        await engine.start()
    except Exception:
        sys.exit(1)

    # Keep running until interrupted
    try:
        await asyncio.Future()
    except (KeyboardInterrupt, asyncio.CancelledError):
        logger.info("[server] shutting down...")
    finally:
        await engine.stop()


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        pass
