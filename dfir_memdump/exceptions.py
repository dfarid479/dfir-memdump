"""Custom exception hierarchy for dfir-memdump."""


class MemdumpError(Exception):
    """Base exception for all dfir-memdump errors."""


class Vol3NotFoundError(MemdumpError):
    """Volatility3 binary not found at the configured path."""


class PluginError(MemdumpError):
    """A Volatility3 plugin invocation failed or returned unparseable output."""
    def __init__(self, plugin_name: str, message: str):
        self.plugin_name = plugin_name
        super().__init__(f"[{plugin_name}] {message}")


class IntelError(MemdumpError):
    """An intelligence module encountered a non-fatal error."""
    def __init__(self, module_name: str, message: str):
        self.module_name = module_name
        super().__init__(f"[{module_name}] {message}")


class ReportError(MemdumpError):
    """Report generation failed."""


class FeedError(MemdumpError):
    """Threat intel feed fetch or parse failed."""


class ImageNotFoundError(MemdumpError):
    """Memory image file does not exist or is not readable."""
