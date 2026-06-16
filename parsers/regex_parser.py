"""
Regex, Grok, and pattern-based custom parsers.

Provides flexible parsing for custom log formats using regular expressions,
Grok patterns, and named capture groups.
"""

import re
import logging
from .base import BaseParser, ParseError, ParserResult

logger = logging.getLogger(__name__)


class RegexParser(BaseParser):
    """Parser using a user-supplied regular expression.

    The regex should use named groups (?P<name>...) to capture fields.
    """

    def __init__(self, name="regex", pattern=None, field_map=None, description=""):
        super().__init__(name=name, description=description or "Regex parser", priority=20)
        self._pattern_str = pattern
        self._pattern = None
        if pattern:
            self._pattern = re.compile(pattern, re.MULTILINE | re.DOTALL)

    def _compile_patterns(self):
        if self._pattern_str and not self._pattern:
            self._pattern = re.compile(self._pattern_str, re.MULTILINE | re.DOTALL)

    def set_pattern(self, pattern):
        """Set the regex pattern."""
        self._pattern_str = pattern
        self._pattern = re.compile(pattern, re.MULTILINE | re.DOTALL)

    def parse(self, raw_data):
        if not self._pattern:
            raise ParseError("No pattern configured")

        data = self._decode(raw_data)

        match = self._pattern.search(data)
        if not match:
            raise ParseError("Pattern did not match")

        fields = {"raw_data": data}

        for group_name, group_value in match.groupdict().items():
            if group_value is not None:
                # Map field name
                mapped = self.field_map.get(group_name, group_name)
                fields[mapped] = group_value

        fields.setdefault("event_type", "system")
        fields.setdefault("vendor", "regex")
        fields.setdefault("collection_method", "regex")

        fields = self._clean_fields(fields)
        return ParserResult(fields=fields, parser_name=self.name, confidence=0.7)

    def can_parse(self, raw_data):
        if not self._pattern:
            return False
        return bool(self._pattern.search(self._decode(raw_data)))


class GrokParser(BaseParser):
    """Parser using Grok-style patterns.

    Grok patterns are named regex patterns: %{PATTERN_NAME:field_name:type}

    This is a simplified Grok implementation that supports common patterns.
    """

    # Predefined Grok patterns
    GROK_PATTERNS = {
        "IP": r"(?:\d{1,3}\.){3}\d{1,3}",
        "IPV6": r"(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}",
        "HOSTNAME": r"\b(?:[0-9A-Za-z][0-9A-Za-z\-]{0,62])(?:\.(?:[0-9A-Za-z][0-9A-Za-z\-]{0,62}))*\.?",
        "WORD": r"\b\w+\b",
        "NUMBER": r"-?\d+(?:\.\d+)?",
        "INT": r"-?\d+",
        "POSINT": r"\d+",
        "DATA": r".*?",
        "GREEDYDATA": r".*",
        "NOTSPACE": r"\S+",
        "SPACE": r"\s+",
        "QUOTEDSTRING": r'"(?:[^"\\]|\\.)*"',
        "UUID": r"[0-9a-fA-F]{8}-(?:[0-9a-fA-F]{4}-){3}[0-9a-fA-F]{12}",
        "MAC": r"(?:[0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}",
        "EMAILADDRESS": r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}",
        "TIMESTAMP_ISO8601": r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?",
        "DATE": r"\d{4}-\d{2}-\d{2}|\d{2}/\d{2}/\d{4}|\d{2}/\d{2}/\d{2}",
        "TIME": r"\d{2}:\d{2}:\d{2}",
        "HTTPDATE": r"\d{2}/\d{3}/\d{4}:\d{2}:\d{2}:\d{2}\s+[+-]\d{4}",
        "MONTH": r"(?:Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)",
        "MONTHDAY": r"(?:0[1-9]|[12][0-9]|3[01])",
        "TIME": r"(?:[0-2][0-9]):(?:[0-5][0-9])(?::(?:[0-5][0-9]))?",
        "HOUR": r"(?:[0-1][0-9]|2[0-3])",
        "MINUTE": r"(?:[0-5][0-9])",
        "SECOND": r"(?:(?:[0-5][0-9]|60)(?:[:.,][0-9]+)?)",
        "HTTPMETHOD": r"(?:GET|POST|PUT|DELETE|HEAD|OPTIONS|PATCH|TRACE|CONNECT)",
        "URIPATH": r"(?:/[^\s?#]*)+",
        "URL": r"https?://[^\s]+",
        "PATH": r"(?:[\w./-]+/)*[\w.-]+",
        "USERNAME": r"[a-zA-Z0-9._-]+",
        "USER": r"%{USERNAME}",
        "EMAILADDRESS": r"[\w.+-]+@[\w.-]+\.\w+",
        "SYSLOGTIMESTAMP": r"(?:Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}",
        "SYSLOGHOST": r"%{HOSTNAME}",
        "SYSLOGPROG": r"[\w./-]+(?:\[\d+\])?",
        "SYSLOGFACILITY": r"<\d+>",
    }

    GROK_PATTERN_RE = re.compile(r'%\{(\w+)(?::(\w+))?(?::(\w+))?\}')

    def __init__(self, name="grok", grok_pattern=None, description="", field_map=None):
        super().__init__(name=name, description=description or "Grok parser", priority=15)
        self._grok_pattern = grok_pattern
        self._compiled_pattern = None
        self._field_types = {}
        if grok_pattern:
            self._compile_grok(grok_pattern)
        self.field_map = field_map or {}

    def _compile_grok(self, grok_pattern):
        """Compile a Grok pattern into a regex."""
        self._grok_pattern = grok_pattern

        def replace_grok(match):
            pattern_name = match.group(1)
            field_name = match.group(2)
            field_type = match.group(3)

            if pattern_name not in self.GROK_PATTERNS:
                logger.warning("Unknown Grok pattern: %s", pattern_name)
                return match.group(0)

            regex = self.GROK_PATTERNS[pattern_name]

            if field_name:
                # Recursively expand nested patterns
                if "%{" in regex:
                    regex = self.GROK_PATTERN_RE.sub(replace_grok, regex)
                self._field_types[field_name] = field_type or "str"
                return f"(?P<{field_name}>{regex})"
            else:
                if "%{" in regex:
                    regex = self.GROK_PATTERN_RE.sub(replace_grok, regex)
                return f"(?:{regex})"

        expanded = self.GROK_PATTERN_RE.sub(replace_grok, grok_pattern)
        try:
            self._compiled_pattern = re.compile(expanded)
        except re.error as exc:
            raise ParseError(f"Invalid compiled regex from Grok: {exc}")

    def set_pattern(self, grok_pattern):
        """Set the Grok pattern."""
        self._compile_grok(grok_pattern)

    def parse(self, raw_data):
        if not self._compiled_pattern:
            raise ParseError("No Grok pattern configured")

        data = self._decode(raw_data)
        match = self._compiled_pattern.search(data)
        if not match:
            raise ParseError("Grok pattern did not match")

        fields = {"raw_data": data}

        for group_name, group_value in match.groupdict().items():
            if group_value is not None:
                field_type = self._field_types.get(group_name, "str")
                value = self._cast_value(group_value, field_type)
                mapped = self.field_map.get(group_name, group_name)
                fields[mapped] = value

        fields.setdefault("event_type", "system")
        fields.setdefault("vendor", "grok")
        fields.setdefault("collection_method", "grok")

        fields = self._clean_fields(fields)
        return ParserResult(fields=fields, parser_name=self.name, confidence=0.8)

    def _cast_value(self, value, field_type):
        """Cast a value to the specified type."""
        if value is None:
            return None
        try:
            if field_type == "int":
                return int(value)
            elif field_type == "float":
                return float(value)
            elif field_type == "bool":
                return value.lower() in ("true", "1", "yes")
            else:
                return str(value)
        except (ValueError, TypeError):
            return value

    def can_parse(self, raw_data):
        if not self._compiled_pattern:
            return False
        return bool(self._compiled_pattern.search(self._decode(raw_data)))


class PatternParser(BaseParser):
    """Pattern-based parser with multiple named patterns.

    Allows defining multiple regex patterns and trying them in order.
    """

    def __init__(self, name="pattern", patterns=None, description=""):
        super().__init__(name=name, description=description or "Pattern parser", priority=18)
        self._patterns = []  # List of (name, compiled_regex, field_map)
        if patterns:
            for p in patterns:
                self.add_pattern(p.get("name"), p["regex"], p.get("field_map", {}))

    def add_pattern(self, name, regex, field_map=None):
        """Add a named regex pattern."""
        compiled = re.compile(regex, re.MULTILINE)
        self._patterns.append((name, compiled, field_map or {}))

    def parse(self, raw_data):
        data = self._decode(raw_data)

        for name, pattern, fmap in self._patterns:
            match = pattern.search(data)
            if match:
                fields = {"raw_data": data, "_matched_pattern": name}
                for group_name, group_value in match.groupdict().items():
                    if group_value is not None:
                        mapped = fmap.get(group_name, group_name)
                        fields[mapped] = group_value

                fields.setdefault("event_type", "system")
                fields.setdefault("vendor", "pattern")
                fields.setdefault("collection_method", "pattern")
                fields = self._clean_fields(fields)
                return ParserResult(fields=fields, parser_name=self.name, confidence=0.7)

        raise ParseError("No patterns matched")

    def can_parse(self, raw_data):
        data = self._decode(raw_data)
        return any(p.search(data) for _, p, _ in self._patterns)


# Pre-configured pattern sets for common log formats
COMMON_PATTERNS = {
    "ssh_failed_login": {
        "regex": r'^(?P<timestamp>\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+'
                  r'(?P<source_host>\S+)\s+sshd\[(?P<pid>\d+)\]:\s+'
                  r'Failed password for (?:invalid user )?(?P<user>\S+)\s+'
                  r'from (?P<source_ip>\d+\.\d+\.\d+\.\d+)\s+port\s+(?P<source_port>\d+)',
        "field_map": {"timestamp": "timestamp", "source_host": "source_host",
                       "user": "source_user", "source_ip": "source_ip",
                       "source_port": "source_port"},
    },
    "ssh_accepted_login": {
        "regex": r'^(?P<timestamp>\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+'
                  r'(?P<source_host>\S+)\s+sshd\[(?P<pid>\d+)\]:\s+'
                  r'Accepted password for (?P<user>\S+)\s+'
                  r'from (?P<source_ip>\d+\.\d+\.\d+\.\d+)\s+port\s+(?P<source_port>\d+)',
        "field_map": {},
    },
    "sudo_command": {
        "regex": r'^(?P<timestamp>\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+'
                  r'(?P<source_host>\S+)\s+sudo:\s+(?P<user>\S+)\s+:'
                  r'\s+TTY=(?P<tty>\S+)\s+;\s+PWD=(?P<pwd>\S+)\s+;\s+'
                  r'USER=(?P<target_user>\S+)\s+;\s+COMMAND=(?P<command>.+)',
        "field_map": {"user": "source_user", "command": "command_line"},
    },
    "iptables_log": {
        "regex": r'(?P<timestamp>\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+'
                  r'(?P<source_host>\S+)\s+kernel:\s+\[.*?\]\s+'
                  r'(?P<action>\w+).*?IN=(?P<iface_in>\S*).*?OUT=(?P<iface_out>\S*)'
                  r'.*?SRC=(?P<source_ip>\d+\.\d+\.\d+\.\d+)'
                  r'.*?DST=(?P<dest_ip>\d+\.\d+\.\d+\.\d+)'
                  r'.*?PROTO=(?P<protocol>\w+)'
                  r'(?:.*?SPT=(?P<source_port>\d+))?'
                  r'(?:.*?DPT=(?P<dest_port>\d+))?',
        "field_map": {},
    },
}
