import sys
from .cli import CliOptions


class Logger:
    def __init__(self, options: CliOptions):
        self._debug_main = options.debug_main
        self._debug_frida = options.debug_frida
        self._output_callback = None

    def set_output_callback(self, callback):
        """Set callback(level, text) for GUI log capture."""
        self._output_callback = callback

    def _emit(self, level, *messages):
        text = " ".join(str(m) for m in messages)
        print(text, flush=True, file=sys.stderr if level == "error" else sys.stdout)
        if self._output_callback:
            try:
                self._output_callback(level, text)
            except Exception:
                pass

    def info(self, *messages):
        self._emit("info", *messages)

    def error(self, *messages):
        self._emit("error", *messages)

    def main_debug(self, *messages):
        if self._debug_main:
            self._emit("debug", *messages)

    def frida_debug(self, *messages):
        if self._debug_frida:
            self._emit("frida", *messages)


def create_logger(options: CliOptions) -> Logger:
    return Logger(options)
