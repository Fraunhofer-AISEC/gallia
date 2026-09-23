# SPDX-FileCopyrightText: AISEC Pentesting Team
#
# SPDX-License-Identifier: Apache-2.0

import argparse
import json
import re
import shlex
from collections.abc import Callable

from gallia.log import PenlogRecord

FILTER_FIELDS = ("module", "host", "data", "tag", "line")

FILTER_SYNTAX = """\
Terms are separated by spaces; a record matches if all terms match.
  word            data contains word (case insensitive)
  !word           data does not contain word
  field=a,b       field is a or b
  field!=a,b      field is neither a nor b
  field~regex     field matches the regular expression
  field!~regex    field does not match the regular expression
Fields: {fields}; tag matches any of the record's tags.
Use quotes for spaces, e.g. data~"no response".
Example: module=scanner tag=result !timeout""".format(fields=", ".join(FILTER_FIELDS))

_TERM = re.compile(r"(?P<field>\w+)(?P<op>!=|!~|=|~)(?P<value>.*)", re.DOTALL)

Predicate = Callable[[PenlogRecord], bool]


class FilterError(ValueError):
    pass


def _values(record: PenlogRecord, field: str) -> list[str]:
    match field:
        case "tag":
            return record.tags or []
        case "line":
            return [record.line or ""]
        case _:
            return [getattr(record, field)]


def _json_escaped(value: str) -> bytes | None:
    """Returns how ``value`` appears in a JSON record, if unambiguous."""
    if not value.isascii():
        # Might be escaped or not, depending on the producer.
        return None
    return json.dumps(value).encode()


def _parse_term(term: str) -> tuple[Predicate, re.Pattern[bytes] | None]:
    """Returns the predicate for a term and a regex for the raw record,
    which must match if the predicate matches. Searching the raw record
    is much faster than parsing it; this speeds up searching rare records."""
    if (m := _TERM.fullmatch(term)) is None:
        # A plain word searches the data.
        negate = term.startswith("!") and len(term) > 1
        word = (term[1:] if negate else term).casefold()
        raw = None
        if not negate and (escaped := _json_escaped(word)) is not None:
            raw = re.compile(re.escape(escaped[1:-1]), re.IGNORECASE)
        return (lambda record: (word in record.data.casefold()) != negate), raw

    field, op, value = m.group("field", "op", "value")
    if field not in FILTER_FIELDS:
        raise FilterError(f"unknown field '{field}', use one of: {', '.join(FILTER_FIELDS)}")

    raw = None
    if op in ("=", "!="):
        choices = set(value.split(","))
        needles = [e for choice in choices if (e := _json_escaped(choice)) is not None]
        # An empty value also matches missing fields, which do not appear in the raw record.
        if op == "=" and len(needles) == len(choices) and "" not in choices:
            raw = re.compile(b"|".join(re.escape(e) for e in needles))

        def matches(record: PenlogRecord) -> bool:
            return any(v in choices for v in _values(record, field))
    else:
        try:
            pattern = re.compile(value)
        except re.error as e:
            raise FilterError(f"invalid regex '{value}': {e}") from e

        def matches(record: PenlogRecord) -> bool:
            return any(pattern.search(v) is not None for v in _values(record, field))

    if op.startswith("!"):
        return (lambda record: not matches(record)), None
    return matches, raw


class RecordFilter:
    """Filters records with a simple query language, see ``FILTER_SYNTAX``."""

    def __init__(self, text: str = "") -> None:
        self.text = text.strip()
        try:
            terms = shlex.split(self.text)
        except ValueError as e:
            raise FilterError(str(e)) from e
        parsed = [_parse_term(term) for term in terms]
        self._predicates = [predicate for predicate, _ in parsed]
        # Regexes which all match the raw JSON of each matching record.
        # They can be used to quickly skip records, see PenlogReader.search().
        self.raw_patterns = [raw for _, raw in parsed if raw is not None]

    def __bool__(self) -> bool:
        return len(self._predicates) > 0

    def __call__(self, record: PenlogRecord) -> bool:
        return all(predicate(record) for predicate in self._predicates)

    def may_match(self, raw: bytes) -> bool:
        """A fast check on the raw JSON record; if False, the record does
        not match. Otherwise, it has to be parsed and checked."""
        return all(pattern.search(raw) is not None for pattern in self.raw_patterns)

    @classmethod
    def parse(cls, text: str) -> "RecordFilter":
        """Wrapper for argparse which reports invalid filters properly."""
        try:
            return cls(text)
        except FilterError as e:
            raise argparse.ArgumentTypeError(f"invalid filter: {e}") from e
