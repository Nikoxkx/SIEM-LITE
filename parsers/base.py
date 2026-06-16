"""
Base parser classes and parser registry.

All parsers inherit from BaseParser and implement the parse() method to
convert a raw log line into a dictionary of fields.
"""

import re
import logging
from abc import ABC, abstractmethod
from collections import OrderedDict

logger = logging.getLogger(__name__)


class ParseError(Exception):
    """Raised when a parser fails to parse input."""
    pass


class ParserResult:
    """Result of a parse operation."""

    __slots__ = ("fields", "parser_name", "confidence", "warnings", "metadata")

    def __init__(self, fields, parser_name="", confidence=1.0, warnings=None, metadata=None):
        self.fields = fields or {}
        self.parser_name = parser_name
        self.confidence = confidence
        self.warnings = warnings or []
        self.metadata = metadata or {}

    @property
    def is_valid(self):
        return bool(self.fields) and self.confidence > 0

    def to_dict(self):
        return {
            "fields": self.fields,
            "parser": self.parser_name,
            "confidence": self.confidence,
            "warnings": self.warnings,
            "metadata": self.metadata,
        }

    def __repr__(self):
        return f"ParserResult(parser={self.parser_name}, fields={len(self.fields)}, conf={self.confidence:.2f})"


class BaseParser(ABC):
    """Abstract base class for all log parsers.

    Subclasses must implement the parse() method.

    Attributes:
        name: Parser name (used for identification).
        description: Human-readable description.
        priority: Parser priority (higher = checked first in auto-detection).
        patterns: Pre-compiled regex patterns (if applicable).
        field_map: Mapping of parsed field names to canonical field names.
    """

    def __init__(self, name=None, description="", priority=0, field_map=None):
        self.name = name or self.__class__.__name__
        self.description = description
        self.priority = priority
        self.field_map = field_map or {}
        self.patterns = {}
        self._compiled = False
        self._parse_count = 0
        self._error_count = 0
        self._compile_patterns()

    def _compile_patterns(self):
        """Compile regex patterns. Override in subclasses."""
        self._compiled = True

    @abstractmethod
    def parse(self, raw_data):
        """Parse raw log data into fields.

        Args:
            raw_data: Raw log string or bytes.

        Returns:
            ParserResult with parsed fields.

        Raises:
            ParseError: If parsing fails.
        """
        pass

    def can_parse(self, raw_data):
        """Check if this parser can handle the given data.

        Override in subclasses for format detection.
        """
        try:
            result = self.parse(raw_data)
            return result.is_valid
        except (ParseError, Exception):
            return False

    def _map_fields(self, fields):
        """Map parsed fields to canonical names using field_map."""
        if not self.field_map:
            return fields
        mapped = {}
        for key, value in fields.items():
            canonical = self.field_map.get(key, key)
            if canonical in mapped:
                # Merge into existing
                if isinstance(mapped[canonical], list):
                    mapped[canonical].append(value)
                else:
                    mapped[canonical] = [mapped[canonical], value]
            else:
                mapped[canonical] = value
        return mapped

    def _clean_value(self, value):
        """Clean a parsed field value."""
        if value is None:
            return None
        if isinstance(value, str):
            value = value.strip()
            # Remove surrounding quotes
            if len(value) >= 2 and value[0] in '"\'' and value[-1] == value[0]:
                value = value[1:-1]
            # Convert common null representations
            if value in ("-", "null", "NULL", "nil", "N/A", ""):
                return None
            if value.lower() == "true":
                return True
            if value.lower() == "false":
                return False
        return value

    def _clean_fields(self, fields):
        """Clean all field values."""
        return {k: self._clean_value(v) for k, v in fields.items() if v is not None and v != ""}

    def safe_parse(self, raw_data):
        """Parse without raising exceptions.

        Returns ParserResult or None on failure.
        """
        try:
            self._parse_count += 1
            result = self.parse(raw_data)
            return result
        except ParseError as exc:
            self._error_count += 1
            logger.debug("Parse error in %s: %s", self.name, exc)
            return None
        except Exception as exc:
            self._error_count += 1
            logger.warning("Unexpected error in parser %s: %s", self.name, exc, exc_info=True)
            return None

    def stats(self):
        """Return parser statistics."""
        success_rate = 0.0
        total = self._parse_count
        if total > 0:
            success_rate = (total - self._error_count) / total
        return {
            "name": self.name,
            "parse_count": self._parse_count,
            "error_count": self._error_count,
            "success_rate": success_rate,
        }

    def reset_stats(self):
        """Reset parser statistics."""
        self._parse_count = 0
        self._error_count = 0

    @staticmethod
    def _decode(raw_data):
        """Decode bytes to string if needed."""
        if isinstance(raw_data, bytes):
            for encoding in ("utf-8", "latin-1", "ascii"):
                try:
                    return raw_data.decode(encoding)
                except (UnicodeDecodeError, AttributeError):
                    continue
            return raw_data.decode("utf-8", errors="replace")
        return str(raw_data) if raw_data else ""


class ParserRegistry:
    """Registry of available parsers with auto-detection capability."""

    def __init__(self):
        self._parsers = OrderedDict()
        self._auto_detect_order = []
        self._default_parser = None
        self._field_mappings = {}

    def register(self, parser, auto_detect=True, priority=None):
        """Register a parser.

        Args:
            parser: BaseParser instance or class.
            auto_detect: Include in auto-detection chain.
            priority: Detection priority (overrides parser.priority).
        """
        if isinstance(parser, type):
            parser = parser()
        if not isinstance(parser, BaseParser):
            raise TypeError("Must be a BaseParser instance")

        self._parsers[parser.name] = parser
        if priority is not None:
            parser.priority = priority

        if auto_detect:
            self._rebuild_auto_detect_order()

        logger.debug("Registered parser: %s (priority=%d)", parser.name, parser.priority)
        return parser

    def unregister(self, name):
        """Unregister a parser by name."""
        if name in self._parsers:
            del self._parsers[name]
            self._rebuild_auto_detect_order()
            return True
        return False

    def _rebuild_auto_detect_order(self):
        """Rebuild the auto-detection order based on priority."""
        parsers = [p for p in self._parsers.values()]
        self._auto_detect_order = sorted(parsers, key=lambda p: p.priority, reverse=True)

    def get_parser(self, name):
        """Get a parser by name."""
        return self._parsers.get(name)

    def parse_with(self, parser_name, raw_data):
        """Parse with a specific parser."""
        parser = self._parsers.get(parser_name)
        if not parser:
            raise ParseError(f"Unknown parser: {parser_name}")
        return parser.parse(raw_data)

    def auto_parse(self, raw_data):
        """Automatically detect the format and parse.

        Tries parsers in priority order until one succeeds.

        Returns:
            ParserResult or None.
        """
        # Quick format detection
        data_str = BaseParser._decode(raw_data)
        parser_name = self._detect_format(data_str)

        if parser_name:
            result = self.parse_with(parser_name, raw_data)
            if result and result.is_valid:
                return result

        # Fall back to trying all parsers in priority order
        for parser in self._auto_detect_order:
            if parser.can_parse(raw_data):
                result = parser.safe_parse(raw_data)
                if result and result.is_valid:
                    return result

        # Last resort: default parser
        if self._default_parser:
            return self._default_parser.safe_parse(raw_data)

        return None

    def _detect_format(self, data):
        """Quick format detection based on heuristics."""
        if not data:
            return None
        data = data.strip()

        # JSON
        if data.startswith("{") and data.rstrip().endswith("}"):
            return "json"
        if data.startswith("[") and data.rstrip().endswith("]"):
            return "json"

        # CEF
        if data.startswith("CEF:"):
            return "cef"

        # LEEF
        if data.startswith("LEEF:"):
            return "leef"

        # Key-value
        if "=" in data and " " in data and not data.startswith("<"):
            return "keyvalue"

        # RFC 5424 syslog
        if data.startswith("<") and ">" in data[:5]:
            # Could be RFC 3164 or 5424
            if re.match(r'^<\d+>\d+\s', data):
                return "rfc5424"
            return "rfc3164"

        # Apache/Nginx access log
        if re.match(r'^\d+\.\d+\.\d+\.\d+\s', data) and '"' in data:
            return "apache"

        # Windows XML event
        if data.startswith("<Event"):
            return "windows_xml"

        return None

    def set_default(self, parser_name):
        """Set the default fallback parser."""
        self._default_parser = self._parsers.get(parser_name)

    def list_parsers(self):
        """List all registered parsers."""
        return [p.stats() for p in self._parsers.values()]

    def all_stats(self):
        """Get statistics for all parsers."""
        return {name: p.stats() for name, p in self._parsers.items()}

    def reset_all_stats(self):
        """Reset statistics for all parsers."""
        for parser in self._parsers.values():
            parser.reset_stats()
