#!/usr/bin/env python3
"""Validate a sanitized audit snapshot and build a self-contained report.

The module intentionally depends only on the Python 3.11 standard library so it
can be copied into an agent skill without bringing a runtime package manager.
"""

from __future__ import annotations

import argparse
import copy
import hashlib
import html
import json
import os
import re
import shutil
import sys
import tempfile
from dataclasses import dataclass
from datetime import date, datetime, timedelta
from decimal import Decimal, InvalidOperation
from pathlib import Path
from typing import Any, Iterable, Mapping, Sequence
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError


OUTPUT_FILES = (
    "audit-snapshot.json",
    "artifact.json",
    "report.html",
    "qa.json",
)

UUID_RE = re.compile(
    r"(?i)(?<![0-9a-f])"
    r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}"
    r"(?![0-9a-f])"
)
WINDOWS_ABSOLUTE_RE = re.compile(r"(?i)(?:^|[\s'\"(])(?:[a-z]:[\\/]|\\\\[^\\/]+[\\/])")
POSIX_ABSOLUTE_RE = re.compile(
    r"(?:^|[\s'\"(=:])/(?!/)(?:[A-Za-z0-9._~-]+/)+[A-Za-z0-9._~-]*"
)
FILE_URL_RE = re.compile(r"(?i)file://")
FORBIDDEN_BRAND_RE = re.compile(r"(?i)code\s*[-_ ]?bar|codex\s*[-_ ]?bar")
EMAIL_VALUE_RE = re.compile(r"(?i)\b[a-z0-9.!#$%&'*+/=?^_`{|}~-]+@[a-z0-9.-]+\.[a-z]{2,}\b")
FORBIDDEN_KEY_PARTS = (
    "prompt",
    "payload",
    "account",
    "customer",
    "apikey",
    "secret",
    "credential",
    "authorization",
    "sessionid",
    "userid",
    "email",
    "phone",
)
SECRET_VALUE_RE = re.compile(
    r"(?i)(?:\bsk-[a-z0-9_-]{12,}|\bgh[oprsu]_[a-z0-9]{12,}|\bAKIA[0-9A-Z]{16}\b)"
)
SHA256_RE = re.compile(r"^[0-9a-fA-F]{64}$")
ANONYMOUS_ALIAS_RE = re.compile(
    r"^(?:root-main|root-worker-[a-z]|agent-[0-9]{1,4}|unattributed|audit-self)$"
)
SUPPORTED_SCHEMA_VERSIONS = {1, "agent-cost-audit/v1"}
CONTEXT_BUCKET_ORDER = ("≤32K", "32K–128K", "128K–272K", ">272K")
SAFE_INT_FIELDS = ("input_tokens", "cached_tokens", "output_tokens", "total_tokens", "requests")
COST_TOLERANCE = Decimal("0.0000001")

ROOT_FIELDS = {
    "schema_version",
    "project",
    "status",
    "source_snapshot_sha256",
    "provenance",
    "generated_at",
    "window",
    "sanitization",
    "totals",
    "models",
    "daily",
    "transaction_categories",
    "ui_attribution",
    "tool_calls",
    "context_buckets",
    "quality_output",
    "efficiency_signals",
    "methodology",
    "reconciliation",
}
TOKEN_ROW_FIELDS = set(SAFE_INT_FIELDS)


class ValidationError(ValueError):
    """Raised when a snapshot fails one or more contract checks."""

    def __init__(self, errors: Sequence[str]):
        self.errors = list(errors)
        super().__init__("; ".join(self.errors))


@dataclass(frozen=True)
class ValidationResult:
    checks: tuple[dict[str, str], ...]

    def as_qa(self, generated_at: str) -> dict[str, Any]:
        return {
            "status": "passed",
            "generated_at": generated_at,
            "input": "audit-snapshot.json",
            "summary": {"passed": len(self.checks), "failed": 0},
            "checks": [dict(item) for item in self.checks],
            "errors": [],
            "warnings": [],
        }


def _snapshot_warnings(snapshot: Mapping[str, Any]) -> list[str]:
    warnings: list[str] = []
    if snapshot.get("status") == "fixture":
        warnings.append("Synthetic fixture: do not treat this output as a real audit.")
    unknown_models = [
        str(row.get("model"))
        for row in snapshot.get("models", [])
        if isinstance(row, dict) and row.get("api_equivalent_base_usd") is None
    ]
    if unknown_models:
        warnings.append("Unknown model prices remain null: " + ", ".join(sorted(unknown_models)))
    if isinstance(snapshot.get("window"), dict) and snapshot["window"].get("partial_end_day") is True:
        warnings.append("The final calendar day is partial and should not be compared as a full day.")
    return warnings


def _iso_datetime(value: Any, path: str, errors: list[str]) -> datetime | None:
    if not isinstance(value, str):
        errors.append(f"{path} must be an ISO-8601 string")
        return None
    try:
        normalized = value[:-1] + "+00:00" if value.endswith("Z") else value
        parsed = datetime.fromisoformat(normalized)
    except ValueError:
        errors.append(f"{path} must be a valid ISO-8601 timestamp")
        return None
    if parsed.tzinfo is None:
        errors.append(f"{path} must include a UTC offset")
        return None
    return parsed


def _date(value: Any, path: str, errors: list[str]) -> date | None:
    if not isinstance(value, str):
        errors.append(f"{path} must be a YYYY-MM-DD string")
        return None
    try:
        return date.fromisoformat(value)
    except ValueError:
        errors.append(f"{path} must be a valid YYYY-MM-DD date")
        return None


def _is_int(value: Any) -> bool:
    return isinstance(value, int) and not isinstance(value, bool)


def _nonnegative_int(value: Any, path: str, errors: list[str]) -> int | None:
    if not _is_int(value) or value < 0:
        errors.append(f"{path} must be a non-negative integer")
        return None
    return value


def _decimal(value: Any, path: str, errors: list[str], *, nullable: bool = False) -> Decimal | None:
    if value is None and nullable:
        return None
    if isinstance(value, bool) or not isinstance(value, (int, float, Decimal)):
        errors.append(f"{path} must be a non-negative number" + (" or null" if nullable else ""))
        return None
    try:
        result = Decimal(str(value))
    except (InvalidOperation, ValueError):
        errors.append(f"{path} must be a finite non-negative number")
        return None
    if not result.is_finite() or result < 0:
        errors.append(f"{path} must be a finite non-negative number")
        return None
    return result


def _mapping(value: Any, path: str, errors: list[str]) -> Mapping[str, Any] | None:
    if not isinstance(value, dict):
        errors.append(f"{path} must be an object")
        return None
    return value


def _rows(value: Any, path: str, errors: list[str], *, nonempty: bool = True) -> list[Mapping[str, Any]]:
    if not isinstance(value, list) or (nonempty and not value):
        qualifier = "a non-empty" if nonempty else "an"
        errors.append(f"{path} must be {qualifier} array")
        return []
    output: list[Mapping[str, Any]] = []
    for index, row in enumerate(value):
        if not isinstance(row, dict):
            errors.append(f"{path}[{index}] must be an object")
        else:
            output.append(row)
    return output


def _validate_privacy(value: Any, errors: list[str], path: str = "$") -> None:
    if isinstance(value, dict):
        for key, child in value.items():
            key_text = str(key)
            normalized_key = re.sub(r"[^a-z0-9]", "", key_text.lower())
            if any(part in normalized_key for part in FORBIDDEN_KEY_PARTS):
                errors.append(f"{path}.{key_text} uses a forbidden sensitive-data key")
            _validate_privacy(child, errors, f"{path}.{key_text}")
        return
    if isinstance(value, list):
        for index, child in enumerate(value):
            _validate_privacy(child, errors, f"{path}[{index}]")
        return
    if not isinstance(value, str):
        return
    if UUID_RE.search(value):
        errors.append(f"{path} contains a UUID")
    if FILE_URL_RE.search(value):
        errors.append(f"{path} contains a file URL")
    if POSIX_ABSOLUTE_RE.search(value) or WINDOWS_ABSOLUTE_RE.search(value):
        errors.append(f"{path} contains an absolute filesystem path")
    if FORBIDDEN_BRAND_RE.search(value):
        errors.append(f"{path} contains forbidden legacy branding")
    if SECRET_VALUE_RE.search(value):
        errors.append(f"{path} contains a secret-like value")
    if EMAIL_VALUE_RE.search(value):
        errors.append(f"{path} contains an email address")


def _reject_unknown_keys(
    value: Mapping[str, Any], allowed: set[str], path: str, errors: list[str]
) -> None:
    for key in value:
        if key not in allowed:
            errors.append(f"{path}.{key} is not allowed by the v1 public snapshot schema")


def _validate_project_name(value: str, path: str, errors: list[str]) -> None:
    if not value.strip():
        errors.append(f"{path} must be a non-empty string")
        return
    if len(value) > 160:
        errors.append(f"{path} must not exceed 160 characters")
    if any(ord(character) < 32 or ord(character) == 127 for character in value):
        errors.append(f"{path} must not contain control characters or line breaks")
    if (
        re.search(r"(?i)(?:https?|data|javascript):", value)
        or "![" in value
        or "](" in value
        or "<" in value
        or ">" in value
    ):
        errors.append(f"{path} must not contain URLs, HTML, or Markdown links")


def _validate_object_schema(root: Mapping[str, Any], errors: list[str]) -> None:
    """Reject fields that the public v1 renderer does not understand."""

    _reject_unknown_keys(root, ROOT_FIELDS, "$", errors)

    project = root.get("project")
    if isinstance(project, dict):
        _reject_unknown_keys(project, {"name", "title"}, "$.project", errors)

    provenance = root.get("provenance")
    if isinstance(provenance, dict):
        _reject_unknown_keys(provenance, {"kind"}, "$.provenance", errors)

    window = root.get("window")
    if isinstance(window, dict):
        _reject_unknown_keys(window, {"start", "end", "timezone", "partial_end_day"}, "$.window", errors)

    sanitization = root.get("sanitization")
    if isinstance(sanitization, dict):
        _reject_unknown_keys(sanitization, {"level", "removed", "note"}, "$.sanitization", errors)

    totals = root.get("totals")
    if isinstance(totals, dict):
        _reject_unknown_keys(
            totals,
            TOKEN_ROW_FIELDS | {"identifiable_cost_usd", "proxy_ceiling_usd"},
            "$.totals",
            errors,
        )

    collection_fields = {
        "models": TOKEN_ROW_FIELDS | {"model", "api_equivalent_base_usd"},
        "daily": TOKEN_ROW_FIELDS | {"day", "identifiable_cost_usd"},
        "transaction_categories": TOKEN_ROW_FIELDS | {"category", "active_hours", "sessions"},
        "ui_attribution": TOKEN_ROW_FIELDS | {"id", "active_hours", "sessions"},
        "tool_calls": {"tool_group", "calls"},
        "context_buckets": {"bucket", "requests", "raw_tokens"},
    }
    for collection, allowed in collection_fields.items():
        rows = root.get(collection)
        if isinstance(rows, list):
            for index, row in enumerate(rows):
                if isinstance(row, dict):
                    _reject_unknown_keys(row, allowed, f"$.{collection}[{index}]", errors)

    quality = root.get("quality_output")
    if isinstance(quality, dict):
        _reject_unknown_keys(
            quality, {"commits", "insertions", "deletions", "commit_types"}, "$.quality_output", errors
        )
        commit_types = quality.get("commit_types")
        if isinstance(commit_types, list):
            for index, row in enumerate(commit_types):
                if isinstance(row, dict):
                    _reject_unknown_keys(row, {"type", "count"}, f"$.quality_output.commit_types[{index}]", errors)

    efficiency = root.get("efficiency_signals")
    if isinstance(efficiency, dict):
        _reject_unknown_keys(
            efficiency,
            {
                "canonical_thread_records_with_usage",
                "project_thread_records_total",
                "ui_thread_count",
                "auto_review_thread_count",
                "subagent_thread_count",
                "agent_active_hours_capped_5m",
                "top_10_thread_token_share",
                "average_tokens_per_request",
                "cache_share_of_input",
                "output_share_of_total",
                "auto_review_share",
            },
            "$.efficiency_signals",
            errors,
        )

    methodology = root.get("methodology")
    if isinstance(methodology, dict):
        _reject_unknown_keys(
            methodology,
            {"actual_total", "transaction_attribution", "time", "distribution", "estimation", "cost"},
            "$.methodology",
            errors,
        )

    reconciliation = root.get("reconciliation")
    if isinstance(reconciliation, dict):
        reconciliation_fields = {
            "models": {"total_tokens", "requests", "identifiable_cost_usd"},
            "daily": TOKEN_ROW_FIELDS | {"identifiable_cost_usd"},
            "transaction_categories": {
                "total_tokens",
                "requests",
                "component_split_status",
                "row_sum_minus_totals",
            },
            "ui_attribution": TOKEN_ROW_FIELDS,
            "context_buckets": {"requests", "raw_tokens_status"},
            "quality_output": {"commit_type_counts"},
            "agent_hours": {
                "precise_total",
                "transaction_category_rows",
                "ui_attribution_rows",
                "status",
            },
        }
        _reject_unknown_keys(reconciliation, set(reconciliation_fields), "$.reconciliation", errors)
        for key, allowed in reconciliation_fields.items():
            section = reconciliation.get(key)
            if isinstance(section, dict):
                _reject_unknown_keys(section, allowed, f"$.reconciliation.{key}", errors)
        transaction = reconciliation.get("transaction_categories")
        if isinstance(transaction, dict):
            residual = transaction.get("row_sum_minus_totals")
            if isinstance(residual, dict):
                _reject_unknown_keys(
                    residual,
                    {"input_tokens", "cached_tokens", "output_tokens"},
                    "$.reconciliation.transaction_categories.row_sum_minus_totals",
                    errors,
                )


def _validate_token_row(row: Mapping[str, Any], path: str, errors: list[str]) -> dict[str, int] | None:
    values: dict[str, int] = {}
    for field in SAFE_INT_FIELDS:
        parsed = _nonnegative_int(row.get(field), f"{path}.{field}", errors)
        if parsed is None:
            return None
        values[field] = parsed
    if values["total_tokens"] != values["input_tokens"] + values["output_tokens"]:
        errors.append(f"{path}.total_tokens must equal input_tokens + output_tokens")
    if values["cached_tokens"] > values["input_tokens"]:
        errors.append(f"{path}.cached_tokens must not exceed input_tokens")
    return values


def _sum_rows(rows: Iterable[Mapping[str, Any]], fields: Sequence[str]) -> dict[str, int]:
    return {field: sum(int(row[field]) for row in rows) for field in fields}


def _compare_totals(
    label: str,
    observed: Mapping[str, int],
    expected: Mapping[str, int],
    fields: Sequence[str],
    errors: list[str],
) -> None:
    for field in fields:
        if observed[field] != expected[field]:
            errors.append(
                f"{label}.{field} reconciliation failed: {observed[field]} != {expected[field]}"
            )


def validate_snapshot(snapshot: Any, source_sha256: str | None = None) -> ValidationResult:
    """Validate the public, sanitized aggregate snapshot contract."""

    errors: list[str] = []
    checks: list[dict[str, str]] = []
    root = _mapping(snapshot, "$", errors)
    if root is None:
        raise ValidationError(errors)

    _validate_object_schema(root, errors)
    _validate_privacy(root, errors)
    checks.append({"id": "privacy", "status": "passed", "detail": "sanitized aggregate fields only"})

    status = root.get("status")
    if status not in {"frozen_real_aggregate", "fixture"}:
        errors.append("$.status must be frozen_real_aggregate or fixture")
    schema_version = root.get("schema_version")
    if schema_version not in SUPPORTED_SCHEMA_VERSIONS:
        errors.append("$.schema_version is not supported")

    source_hash = root.get("source_snapshot_sha256")
    provenance = root.get("provenance")
    if status == "frozen_real_aggregate":
        if not isinstance(source_hash, str) or not SHA256_RE.fullmatch(source_hash):
            errors.append("real aggregate snapshots require a 64-hex source_snapshot_sha256")
        elif source_sha256 is None:
            errors.append("real aggregate snapshots require a verified source file")
        elif source_hash.lower() != source_sha256.lower():
            errors.append("source file SHA-256 does not match source_snapshot_sha256")
        if provenance is not None:
            errors.append("real aggregate snapshots use source_snapshot_sha256, not fixture provenance")
    elif status == "fixture":
        if not isinstance(provenance, dict) or provenance.get("kind") != "synthetic_test_fixture":
            errors.append("fixture snapshots require provenance.kind=synthetic_test_fixture")
        if source_hash is not None:
            errors.append("fixture snapshots must not claim a real source_snapshot_sha256")
        if source_sha256 is not None:
            errors.append("fixture snapshots must not use a real source file")

    sanitization = _mapping(root.get("sanitization"), "$.sanitization", errors)
    if sanitization is not None:
        if sanitization.get("level") != "sanitized_aggregate":
            errors.append("$.sanitization.level must be sanitized_aggregate")
        removed = sanitization.get("removed")
        if not isinstance(removed, list) or not removed or not all(
            isinstance(item, str) and item.strip() for item in removed
        ):
            errors.append("$.sanitization.removed must be a non-empty string array")
    checks.append(
        {
            "id": "provenance",
            "status": "passed",
            "detail": "real source file hash matched or explicit synthetic fixture provenance is present",
        }
    )

    if "project" in root and not isinstance(root["project"], (str, dict)):
        errors.append("$.project must be a string or object when present")
    project = root.get("project")
    if isinstance(project, str):
        _validate_project_name(project, "$.project", errors)
    elif isinstance(project, dict):
        for key in ("name", "title"):
            candidate = project.get(key)
            if candidate is not None:
                if not isinstance(candidate, str):
                    errors.append(f"$.project.{key} must be a string")
                else:
                    _validate_project_name(candidate, f"$.project.{key}", errors)

    generated_at = _iso_datetime(root.get("generated_at"), "$.generated_at", errors)
    window = _mapping(root.get("window"), "$.window", errors)
    start_dt = end_dt = None
    start_local = end_local = None
    declared_zone: ZoneInfo | None = None
    partial = None
    if window is not None:
        start_dt = _iso_datetime(window.get("start"), "$.window.start", errors)
        end_dt = _iso_datetime(window.get("end"), "$.window.end", errors)
        timezone = window.get("timezone")
        if not isinstance(timezone, str) or not timezone.strip():
            errors.append("$.window.timezone must be a non-empty string")
        else:
            try:
                declared_zone = ZoneInfo(timezone)
            except (ZoneInfoNotFoundError, ValueError):
                errors.append("$.window.timezone must be a valid IANA timezone")
        partial = window.get("partial_end_day")
        if not isinstance(partial, bool):
            errors.append("$.window.partial_end_day must be a boolean")
        if start_dt is not None and end_dt is not None and start_dt >= end_dt:
            errors.append("$.window.start must precede $.window.end")
        if declared_zone is not None and start_dt is not None:
            start_local = start_dt.astimezone(declared_zone)
            if start_dt.utcoffset() != start_local.utcoffset():
                errors.append("$.window.start offset must match $.window.timezone")
            if start_local.time().replace(tzinfo=None).isoformat() != "00:00:00":
                errors.append("$.window.start must begin at local midnight")
        if declared_zone is not None and end_dt is not None:
            end_local = end_dt.astimezone(declared_zone)
            if end_dt.utcoffset() != end_local.utcoffset():
                errors.append("$.window.end offset must match $.window.timezone")
            ends_at_midnight = end_local.time().replace(tzinfo=None).isoformat() == "00:00:00"
            if partial is True and ends_at_midnight:
                errors.append("partial_end_day=true requires a non-midnight local end")
            if partial is False and not ends_at_midnight:
                errors.append("partial_end_day=false requires a midnight local end")
        if generated_at is not None and end_dt is not None:
            if generated_at < end_dt.astimezone(generated_at.tzinfo):
                errors.append("$.generated_at must not precede the frozen window end")
    checks.append({"id": "window", "status": "passed", "detail": "ISO dates and partial-day state are explicit"})

    totals = _mapping(root.get("totals"), "$.totals", errors)
    total_values: dict[str, int] | None = None
    identifiable_cost: Decimal | None = None
    if totals is not None:
        total_values = _validate_token_row(totals, "$.totals", errors)
        identifiable_cost = _decimal(
            totals.get("identifiable_cost_usd"), "$.totals.identifiable_cost_usd", errors
        )
        if "proxy_ceiling_usd" in totals:
            proxy = _decimal(totals.get("proxy_ceiling_usd"), "$.totals.proxy_ceiling_usd", errors, nullable=True)
            if proxy is not None and identifiable_cost is not None and proxy < identifiable_cost:
                errors.append("$.totals.proxy_ceiling_usd must not be below identifiable_cost_usd")
    checks.append({"id": "totals", "status": "passed", "detail": "token identity and cache boundary reconcile"})

    models = _rows(root.get("models"), "$.models", errors)
    valid_models: list[Mapping[str, Any]] = []
    known_costs: list[Decimal] = []
    seen_models: set[str] = set()
    for index, row in enumerate(models):
        path = f"$.models[{index}]"
        name = row.get("model")
        if not isinstance(name, str) or not name.strip():
            errors.append(f"{path}.model must be a non-empty string")
        elif name in seen_models:
            errors.append(f"{path}.model must be unique")
        else:
            seen_models.add(name)
            _validate_project_name(name, f"{path}.model", errors)
        if _validate_token_row(row, path, errors) is not None:
            valid_models.append(row)
        cost = _decimal(row.get("api_equivalent_base_usd"), f"{path}.api_equivalent_base_usd", errors, nullable=True)
        if cost is not None:
            known_costs.append(cost)
    if total_values is not None and len(valid_models) == len(models) and models:
        model_sums = _sum_rows(valid_models, SAFE_INT_FIELDS)
        _compare_totals("models", model_sums, total_values, SAFE_INT_FIELDS, errors)
    if identifiable_cost is not None and abs(sum(known_costs, Decimal(0)) - identifiable_cost) > COST_TOLERANCE:
        errors.append("models known-price cost does not reconcile to totals.identifiable_cost_usd")
    checks.append({"id": "models", "status": "passed", "detail": "usage and known-price cost reconcile; null remains unknown"})

    daily = _rows(root.get("daily"), "$.daily", errors)
    valid_daily: list[Mapping[str, Any]] = []
    day_values: list[date] = []
    daily_costs: list[Decimal] = []
    for index, row in enumerate(daily):
        path = f"$.daily[{index}]"
        parsed_day = _date(row.get("day"), f"{path}.day", errors)
        if parsed_day is not None:
            day_values.append(parsed_day)
        if _validate_token_row(row, path, errors) is not None:
            valid_daily.append(row)
        cost = _decimal(row.get("identifiable_cost_usd"), f"{path}.identifiable_cost_usd", errors)
        if cost is not None:
            daily_costs.append(cost)
    if day_values:
        if day_values != sorted(day_values) or len(day_values) != len(set(day_values)):
            errors.append("$.daily days must be unique and sorted ascending")
        if start_local is not None and day_values[0] != start_local.date():
            errors.append("$.daily must begin on window.start's local date")
        expected_end_day = None
        if end_local is not None and isinstance(partial, bool):
            expected_end_day = end_local.date() if partial else end_local.date() - timedelta(days=1)
        if expected_end_day is not None and day_values[-1] != expected_end_day:
            errors.append("$.daily must end on window.end's local date")
        for before, after in zip(day_values, day_values[1:]):
            if after != before + timedelta(days=1):
                errors.append("$.daily must contain each calendar day in the window exactly once")
                break
    if total_values is not None and len(valid_daily) == len(daily) and daily:
        daily_sums = _sum_rows(valid_daily, SAFE_INT_FIELDS)
        _compare_totals("daily", daily_sums, total_values, SAFE_INT_FIELDS, errors)
    if identifiable_cost is not None and daily_costs:
        if abs(sum(daily_costs, Decimal(0)) - identifiable_cost) > COST_TOLERANCE:
            errors.append("daily identifiable cost does not reconcile to totals.identifiable_cost_usd")
    checks.append({"id": "daily", "status": "passed", "detail": "calendar coverage, usage, and cost reconcile"})

    ui_rows = _rows(root.get("ui_attribution"), "$.ui_attribution", errors)
    valid_ui: list[Mapping[str, Any]] = []
    seen_ui: set[str] = set()
    for index, row in enumerate(ui_rows):
        path = f"$.ui_attribution[{index}]"
        row_id = row.get("id")
        if not isinstance(row_id, str) or not ANONYMOUS_ALIAS_RE.fullmatch(row_id):
            errors.append(f"{path}.id must be a lowercase anonymous alias")
        elif row_id in seen_ui:
            errors.append(f"{path}.id must be unique")
        else:
            seen_ui.add(row_id)
        if _validate_token_row(row, path, errors) is not None:
            valid_ui.append(row)
        _decimal(row.get("active_hours"), f"{path}.active_hours", errors)
        _nonnegative_int(row.get("sessions"), f"{path}.sessions", errors)
    if total_values is not None and len(valid_ui) == len(ui_rows) and ui_rows:
        ui_sums = _sum_rows(valid_ui, SAFE_INT_FIELDS)
        _compare_totals("ui_attribution", ui_sums, total_values, SAFE_INT_FIELDS, errors)
    missing_reserved_aliases = {"unattributed", "audit-self"} - seen_ui
    if missing_reserved_aliases:
        errors.append(
            "$.ui_attribution must include explicit reserved rows: "
            + ", ".join(sorted(missing_reserved_aliases))
        )
    checks.append({"id": "ui_attribution", "status": "passed", "detail": "anonymous session allocation reconciles"})

    transaction_rows = _rows(root.get("transaction_categories"), "$.transaction_categories", errors)
    transaction_sums = {"total_tokens": 0, "requests": 0}
    seen_categories: set[str] = set()
    for index, row in enumerate(transaction_rows):
        path = f"$.transaction_categories[{index}]"
        category = row.get("category")
        if not isinstance(category, str) or not category.strip():
            errors.append(f"{path}.category must be a non-empty string")
        elif category in seen_categories:
            errors.append(f"{path}.category must be unique")
        else:
            seen_categories.add(category)
            _validate_project_name(category, f"{path}.category", errors)
        token_total = _nonnegative_int(row.get("total_tokens"), f"{path}.total_tokens", errors)
        requests = _nonnegative_int(row.get("requests"), f"{path}.requests", errors)
        component_values: dict[str, int] = {}
        for field in ("input_tokens", "cached_tokens", "output_tokens"):
            parsed = _nonnegative_int(row.get(field), f"{path}.{field}", errors)
            if parsed is not None:
                component_values[field] = parsed
        if (
            "cached_tokens" in component_values
            and "input_tokens" in component_values
            and component_values["cached_tokens"] > component_values["input_tokens"]
        ):
            errors.append(f"{path}.cached_tokens must not exceed input_tokens")
        _decimal(row.get("active_hours"), f"{path}.active_hours", errors)
        _nonnegative_int(row.get("sessions"), f"{path}.sessions", errors)
        if token_total is not None:
            transaction_sums["total_tokens"] += token_total
        if requests is not None:
            transaction_sums["requests"] += requests
    if total_values is not None:
        _compare_totals(
            "transaction_categories",
            transaction_sums,
            total_values,
            ("total_tokens", "requests"),
            errors,
        )
    checks.append({"id": "transaction_categories", "status": "passed", "detail": "category token and request totals reconcile"})

    tool_rows = root.get("tool_calls")
    if tool_rows is not None:
        seen_tools: set[str] = set()
        for index, row in enumerate(_rows(tool_rows, "$.tool_calls", errors, nonempty=False)):
            path = f"$.tool_calls[{index}]"
            tool_group = row.get("tool_group")
            if not isinstance(tool_group, str) or not tool_group.strip():
                errors.append(f"{path}.tool_group must be a non-empty string")
            elif tool_group in seen_tools:
                errors.append(f"{path}.tool_group must be unique")
            else:
                seen_tools.add(tool_group)
                _validate_project_name(tool_group, f"{path}.tool_group", errors)
            _nonnegative_int(row.get("calls"), f"{path}.calls", errors)
    checks.append({"id": "tool_calls", "status": "passed", "detail": "optional tool counts are non-negative"})

    context_rows = _rows(root.get("context_buckets"), "$.context_buckets", errors)
    context_requests = 0
    seen_buckets: set[str] = set()
    for index, row in enumerate(context_rows):
        path = f"$.context_buckets[{index}]"
        bucket = row.get("bucket")
        if bucket not in CONTEXT_BUCKET_ORDER:
            errors.append(f"{path}.bucket must use a supported mutually exclusive boundary")
        elif bucket in seen_buckets:
            errors.append(f"{path}.bucket must be unique")
        else:
            seen_buckets.add(bucket)
        requests = _nonnegative_int(row.get("requests"), f"{path}.requests", errors)
        if requests is not None:
            context_requests += requests
        if "raw_tokens" in row:
            _nonnegative_int(row.get("raw_tokens"), f"{path}.raw_tokens", errors)
    if total_values is not None and context_requests != total_values["requests"]:
        errors.append(
            f"context_buckets.requests reconciliation failed: {context_requests} != {total_values['requests']}"
        )
    if seen_buckets != set(CONTEXT_BUCKET_ORDER):
        errors.append("v1 context_buckets must include all four supported buckets, including zero rows")
    checks.append({"id": "context_buckets", "status": "passed", "detail": "request buckets reconcile"})

    quality = _mapping(root.get("quality_output"), "$.quality_output", errors)
    if quality is not None:
        commits = _nonnegative_int(quality.get("commits"), "$.quality_output.commits", errors)
        for field in ("insertions", "deletions"):
            _nonnegative_int(quality.get(field), f"$.quality_output.{field}", errors)
        commit_rows = _rows(quality.get("commit_types"), "$.quality_output.commit_types", errors, nonempty=False)
        commit_sum = 0
        seen_types: set[str] = set()
        for index, row in enumerate(commit_rows):
            path = f"$.quality_output.commit_types[{index}]"
            commit_type = row.get("type")
            if not isinstance(commit_type, str) or not commit_type.strip():
                errors.append(f"{path}.type must be a non-empty string")
            elif commit_type in seen_types:
                errors.append(f"{path}.type must be unique")
            else:
                seen_types.add(commit_type)
                _validate_project_name(commit_type, f"{path}.type", errors)
            count = _nonnegative_int(row.get("count"), f"{path}.count", errors)
            if count is not None:
                commit_sum += count
        if commits is not None and commit_sum != commits:
            errors.append(
                f"quality_output.commit_types reconciliation failed: {commit_sum} != {commits}"
            )
    checks.append({"id": "quality_output", "status": "passed", "detail": "commit types reconcile to commit total"})

    efficiency = root.get("efficiency_signals")
    if efficiency is not None:
        if not isinstance(efficiency, dict):
            errors.append("$.efficiency_signals must be an object")
        else:
            count_fields = (
                "canonical_thread_records_with_usage",
                "project_thread_records_total",
                "ui_thread_count",
                "auto_review_thread_count",
                "subagent_thread_count",
            )
            for field in count_fields:
                if field in efficiency:
                    _nonnegative_int(efficiency.get(field), f"$.efficiency_signals.{field}", errors)
            numeric_fields = ("agent_active_hours_capped_5m", "average_tokens_per_request")
            for field in numeric_fields:
                if field in efficiency:
                    _decimal(efficiency.get(field), f"$.efficiency_signals.{field}", errors)
            ratio_fields = (
                "top_10_thread_token_share",
                "cache_share_of_input",
                "output_share_of_total",
                "auto_review_share",
            )
            for field in ratio_fields:
                if field in efficiency:
                    ratio = _decimal(efficiency.get(field), f"$.efficiency_signals.{field}", errors)
                    if ratio is not None and ratio > 1:
                        errors.append(f"$.efficiency_signals.{field} must be between 0 and 1")
            if total_values is not None:
                expected_values = {
                    "average_tokens_per_request": (
                        Decimal(total_values["total_tokens"]) / Decimal(total_values["requests"])
                        if total_values["requests"]
                        else Decimal(0)
                    ),
                    "cache_share_of_input": (
                        Decimal(total_values["cached_tokens"]) / Decimal(total_values["input_tokens"])
                        if total_values["input_tokens"]
                        else Decimal(0)
                    ),
                    "output_share_of_total": (
                        Decimal(total_values["output_tokens"]) / Decimal(total_values["total_tokens"])
                        if total_values["total_tokens"]
                        else Decimal(0)
                    ),
                }
                for field, expected in expected_values.items():
                    if field in efficiency:
                        actual = _decimal(
                            efficiency.get(field), f"$.efficiency_signals.{field}", errors
                        )
                        if actual is not None and abs(actual - expected) > COST_TOLERANCE:
                            errors.append(f"$.efficiency_signals.{field} does not reconcile")
    checks.append({"id": "efficiency_signals", "status": "passed", "detail": "optional counts, hours, and ratios are bounded"})

    methodology = root.get("methodology")
    if methodology is not None:
        if not isinstance(methodology, dict):
            errors.append("$.methodology must be an object")
        else:
            for key, value in methodology.items():
                if not isinstance(value, str) or not value.strip():
                    errors.append(f"$.methodology.{key} must be a non-empty string")
    reconciliation = root.get("reconciliation")
    if reconciliation is not None:
        if not isinstance(reconciliation, dict):
            errors.append("$.reconciliation must be an object")
        else:
            for section_name in (
                "models",
                "daily",
                "ui_attribution",
                "context_buckets",
                "quality_output",
            ):
                section = reconciliation.get(section_name)
                if section is not None:
                    if not isinstance(section, dict):
                        errors.append(f"$.reconciliation.{section_name} must be an object")
                    else:
                        for key, value in section.items():
                            if not isinstance(value, str) or not value.strip():
                                errors.append(
                                    f"$.reconciliation.{section_name}.{key} must be a non-empty status string"
                                )
            transaction_reconciliation = reconciliation.get("transaction_categories")
            if transaction_reconciliation is not None:
                if not isinstance(transaction_reconciliation, dict):
                    errors.append("$.reconciliation.transaction_categories must be an object")
                else:
                    for key in ("total_tokens", "requests", "component_split_status"):
                        value = transaction_reconciliation.get(key)
                        if not isinstance(value, str) or not value.strip():
                            errors.append(
                                f"$.reconciliation.transaction_categories.{key} must be a non-empty status string"
                            )
                    residual = transaction_reconciliation.get("row_sum_minus_totals")
                    if not isinstance(residual, dict):
                        errors.append(
                            "$.reconciliation.transaction_categories.row_sum_minus_totals must be an object"
                        )
                    else:
                        for key, value in residual.items():
                            if not _is_int(value):
                                errors.append(
                                    "$.reconciliation.transaction_categories."
                                    f"row_sum_minus_totals.{key} must be an integer"
                                )
            hours_reconciliation = reconciliation.get("agent_hours")
            if hours_reconciliation is not None:
                if not isinstance(hours_reconciliation, dict):
                    errors.append("$.reconciliation.agent_hours must be an object")
                else:
                    for key in ("precise_total", "transaction_category_rows", "ui_attribution_rows"):
                        _decimal(
                            hours_reconciliation.get(key),
                            f"$.reconciliation.agent_hours.{key}",
                            errors,
                        )
                    value = hours_reconciliation.get("status")
                    if not isinstance(value, str) or not value.strip():
                        errors.append("$.reconciliation.agent_hours.status must be a non-empty string")

    if errors:
        raise ValidationError(errors)
    return ValidationResult(tuple(checks))


def load_snapshot(path: Path) -> dict[str, Any]:
    def reject_nonfinite(constant: str) -> None:
        raise ValueError(f"non-finite JSON number {constant} is not allowed")

    try:
        with path.open("r", encoding="utf-8") as handle:
            value = json.load(handle, parse_constant=reject_nonfinite)
    except OSError as exc:
        raise ValidationError(["cannot read input snapshot"]) from exc
    except json.JSONDecodeError as exc:
        raise ValidationError([f"malformed JSON at line {exc.lineno}, column {exc.colno}"]) from exc
    except ValueError as exc:
        raise ValidationError([f"malformed JSON: {exc}"]) from exc
    if not isinstance(value, dict):
        raise ValidationError(["snapshot root must be an object"])
    return value


def hash_source_file(path: Path | None) -> str | None:
    if path is None:
        return None
    digest = hashlib.sha256()
    try:
        with path.open("rb") as handle:
            for chunk in iter(lambda: handle.read(1024 * 1024), b""):
                digest.update(chunk)
    except OSError as exc:
        raise ValidationError(["cannot read frozen source evidence"]) from exc
    return digest.hexdigest()


def _project_name(snapshot: Mapping[str, Any], override: str | None) -> str:
    if override and override.strip():
        return override.strip()
    project = snapshot.get("project")
    if isinstance(project, str) and project.strip():
        return project.strip()
    if isinstance(project, dict):
        for key in ("name", "title"):
            value = project.get(key)
            if isinstance(value, str) and value.strip():
                return value.strip()
    return "Agent Project"


def _ratio(numerator: int | float, denominator: int | float) -> float:
    return float(numerator) / float(denominator) if denominator else 0.0


def _compact(value: int | float) -> str:
    absolute = abs(value)
    for unit, divisor in (("T", 1_000_000_000_000), ("B", 1_000_000_000), ("M", 1_000_000), ("K", 1_000)):
        if absolute >= divisor:
            rendered = f"{value / divisor:.2f}".rstrip("0").rstrip(".")
            return rendered + unit
    return f"{value:,}"


def _percent(value: float) -> str:
    return f"{value * 100:.2f}%"


def _money(value: Any) -> str:
    if value is None:
        return "—"
    return f"${float(value):,.2f}"


def _inline_markdown(text: str) -> str:
    escaped = html.escape(text, quote=False)
    escaped = re.sub(r"`([^`]+)`", lambda match: f"<code>{match.group(1)}</code>", escaped)
    escaped = re.sub(r"\*\*([^*]+)\*\*", lambda match: f"<strong>{match.group(1)}</strong>", escaped)
    return escaped


def render_markdown(markdown: str) -> str:
    """Render the small Markdown subset used by generated narrative blocks."""

    output: list[str] = []
    paragraph: list[str] = []
    list_kind: str | None = None

    def close_paragraph() -> None:
        if paragraph:
            output.append(f"<p>{_inline_markdown(' '.join(paragraph))}</p>")
            paragraph.clear()

    def close_list() -> None:
        nonlocal list_kind
        if list_kind:
            output.append(f"</{list_kind}>")
            list_kind = None

    for raw in markdown.splitlines():
        line = raw.strip()
        if not line:
            close_paragraph()
            close_list()
            continue
        heading = re.match(r"^(#{1,3})\s+(.+)$", line)
        if heading:
            close_paragraph()
            close_list()
            level = len(heading.group(1))
            output.append(f"<h{level}>{_inline_markdown(heading.group(2))}</h{level}>")
            continue
        unordered = re.match(r"^-\s+(.+)$", line)
        ordered = re.match(r"^\d+[.)]\s+(.+)$", line)
        if unordered or ordered:
            close_paragraph()
            desired = "ul" if unordered else "ol"
            if list_kind != desired:
                close_list()
                output.append(f"<{desired}>")
                list_kind = desired
            item = (unordered or ordered).group(1)
            output.append(f"<li>{_inline_markdown(item)}</li>")
            continue
        close_list()
        paragraph.append(line)
    close_paragraph()
    close_list()
    return "\n".join(output)


def _summary(snapshot: Mapping[str, Any]) -> dict[str, Any]:
    totals = snapshot["totals"]
    requests = totals["requests"]
    total_tokens = totals["total_tokens"]
    context_over_32k = sum(
        row["requests"] for row in snapshot["context_buckets"] if row["bucket"] != "≤32K"
    )
    priced_tokens = sum(
        row["total_tokens"]
        for row in snapshot["models"]
        if row["api_equivalent_base_usd"] is not None
    )
    priced_requests = sum(
        row["requests"]
        for row in snapshot["models"]
        if row["api_equivalent_base_usd"] is not None
    )
    unattributed = next(
        (row["total_tokens"] for row in snapshot["ui_attribution"] if row.get("id") == "unattributed"),
        0,
    )
    audit_self = next(
        (row["total_tokens"] for row in snapshot["ui_attribution"] if row.get("id") == "audit-self"),
        0,
    )
    efficiency = snapshot.get("efficiency_signals")
    efficiency = efficiency if isinstance(efficiency, dict) else {}
    agent_hours = efficiency.get("agent_active_hours_capped_5m")
    if not isinstance(agent_hours, (int, float)):
        agent_hours = sum(
            float(row.get("active_hours", 0)) for row in snapshot["transaction_categories"]
        )
    start = datetime.fromisoformat(snapshot["window"]["start"].replace("Z", "+00:00"))
    end = datetime.fromisoformat(snapshot["window"]["end"].replace("Z", "+00:00"))
    wall_clock_hours = (end - start).total_seconds() / 3600
    return {
        "total_tokens": total_tokens,
        "requests": requests,
        "identifiable_cost_usd": totals["identifiable_cost_usd"],
        "proxy_ceiling_usd": totals.get("proxy_ceiling_usd"),
        "cache_share": _ratio(totals["cached_tokens"], totals["input_tokens"]),
        "average_tokens_per_request": _ratio(total_tokens, requests),
        "agent_hours": float(agent_hours),
        "wall_clock_hours": wall_clock_hours,
        "average_concurrency": _ratio(float(agent_hours), wall_clock_hours),
        "priced_token_share": _ratio(priced_tokens, total_tokens),
        "priced_request_share": _ratio(priced_requests, requests),
        "requests_over_32k_share": _ratio(context_over_32k, requests),
        "unattributed_share": _ratio(unattributed, total_tokens),
        "audit_self_share": _ratio(audit_self, total_tokens),
    }


def _evidence_label(snapshot: Mapping[str, Any]) -> str:
    return "来源哈希已核验的聚合快照" if snapshot.get("status") == "frozen_real_aggregate" else "合成测试夹具"


def _anonymous_label(row_id: str) -> str:
    labels = {
        "root-main": "主执行会话",
        "unattributed": "未归属池",
        "audit-self": "审计自身会话",
    }
    if row_id in labels:
        return labels[row_id]
    if row_id.startswith("root-worker-"):
        return f"执行会话 {row_id.removeprefix('root-worker-').upper()}"
    return f"匿名 Agent {row_id.removeprefix('agent-')}"


def _markdown_blocks(project_name: str, snapshot: Mapping[str, Any], summary: Mapping[str, Any]) -> list[dict[str, str]]:
    totals = snapshot["totals"]
    top_activity = max(snapshot["transaction_categories"], key=lambda row: row["total_tokens"])
    window = snapshot["window"]
    partial_note = "，末日为部分日" if window["partial_end_day"] else ""
    unknown_models = [row["model"] for row in snapshot["models"] if row["api_equivalent_base_usd"] is None]
    unknown_text = "、".join(unknown_models) if unknown_models else "无"
    proxy = totals.get("proxy_ceiling_usd")
    proxy_text = f"；另列代理上限 **{_money(proxy)}**" if proxy is not None else ""
    blocks = [
        {
            "id": "executive-summary",
            "markdown": (
                "## Executive Summary\n\n"
                f"- 审计窗口内共消耗 **{_compact(totals['total_tokens'])} Token**，发生 **{totals['requests']:,} 次请求**。\n"
                f"- 最大活动类别是 **{top_activity['category']}**，占总 Token 的 **{_percent(_ratio(top_activity['total_tokens'], totals['total_tokens']))}**。\n"
                f"- **{_percent(summary['requests_over_32k_share'])}** 的请求超过 32K；缓存输入占比为 **{_percent(summary['cache_share'])}**。\n"
                f"- 可识别 API 等价成本为 **{_money(totals['identifiable_cost_usd'])}**{proxy_text}；"
                "未知价格模型保持为空，不补推费用。"
            ),
        },
        {
            "id": "activity-analysis",
            "markdown": (
                "## 活动开销分析\n\n"
                f"**{top_activity['category']}** 是首要优化对象。应先检查该类别中的重复上下文、重试和可合并步骤，"
                "再评估低占比类别。"
            ),
        },
        {
            "id": "pricing-analysis",
            "markdown": (
                "## 模型与定价\n\n"
                f"可识别成本仅汇总有冻结价格的模型。未知价格模型：**{unknown_text}**。"
                "报告成本是 API 等价估算，不是账单或发票。"
            ),
        },
        {
            "id": "quality-analysis",
            "markdown": (
                "## 工程与质量证据\n\n"
                f"窗口内记录 **{snapshot['quality_output']['commits']:,} 次提交**、"
                f"**{snapshot['quality_output'].get('insertions', 0):,} 行新增**和"
                f"**{snapshot['quality_output'].get('deletions', 0):,} 行删除**。"
                "这些数据只表示工程活动量，不能单独证明质量、验收结果或 ROI。"
            ),
        },
        {
            "id": "recommendations",
            "markdown": (
                "## 建议\n\n"
                "1. 为高占比活动设置每请求 Token 与长上下文占比预算。\n"
                "2. 在会话创建时写入稳定的父链标识，持续降低未归属池。\n"
                "3. 为未知价格模型保留 Token 预算与 `null` 成本状态，补齐价格后再复算。"
            ),
        },
        {
            "id": "methodology",
            "markdown": (
                "## 统计口径\n\n"
                f"观察窗为 `{window['start']}` 至 `{window['end']}`，时区 `{window['timezone']}`{partial_note}。"
                "Token、请求与冻结成本来自脱敏聚合快照；活动归类、会话归属与 Agent-hours 为规则估算。"
            ),
        },
        {
            "id": "limitations",
            "markdown": (
                "## 限制与假设\n\n"
                "- 当前交付是脱敏聚合结果，不包含逐事件账本、原始提示词或本地路径。\n"
                "- 活动分类、归属和 Agent-hours 是规则估算。\n"
                f"- 日期比较必须考虑部分日状态：**{'是' if window['partial_end_day'] else '否'}**。\n"
                "- 未知价格保持为空；所有成本均不是实际账单。"
            ),
        },
    ]
    detail_blocks: list[dict[str, str]] = []
    tool_rows = snapshot.get("tool_calls")
    if isinstance(tool_rows, list) and tool_rows:
        top_tool = max(tool_rows, key=lambda row: row["calls"])
        detail_blocks.append(
            {
                "id": "tool-analysis",
                "markdown": (
                    "## 工具调用\n\n"
                    f"共记录 **{sum(row['calls'] for row in tool_rows):,} 次工具调用**；"
                    f"最高频分组是 **{top_tool['tool_group']}**（{top_tool['calls']:,} 次）。"
                ),
            }
        )
    detail_blocks.extend(
        [
            {
                "id": "time-analysis",
                "markdown": (
                    "## 时间与并发\n\n"
                    f"墙钟时间为 **{summary['wall_clock_hours']:.2f} 小时**；规则估算 Agent-hours 为 "
                    f"**{summary['agent_hours']:.2f}**，平均并发约 **{summary['average_concurrency']:.2f}**。"
                    "并行 Agent 可使 Agent-hours 高于墙钟时间。"
                ),
            },
            {
                "id": "lineage-analysis",
                "markdown": (
                    "## 归属与审计自身开销\n\n"
                    f"未归属 Token 占 **{_percent(summary['unattributed_share'])}**；"
                    f"审计自身会话占 **{_percent(summary['audit_self_share'])}**。"
                    "二者均保留为独立归属，不并入主要执行会话。"
                ),
            },
        ]
    )
    blocks[2:2] = detail_blocks
    source_hash = snapshot.get("source_snapshot_sha256")
    source_note = (
        f"源账本 SHA-256 已记录（前缀 `{source_hash[:12]}`）"
        if isinstance(source_hash, str)
        else "当前输入为显式合成测试夹具"
    )
    blocks[-1:-1] = [
        {
            "id": "reconciliation-analysis",
            "markdown": (
                "## 对账状态\n\n"
                "模型、日期、活动、归属、上下文和提交类型均通过阻断式校验。"
                "输出文件哈希与 HTML 自包含检查记录在 `qa.json`。"
            ),
        },
        {
            "id": "sources-analysis",
            "markdown": (
                "## 来源\n\n"
                f"{source_note}。公开报告仅引用 `audit-snapshot.json`，不包含逐事件账本。"
            ),
        },
    ]
    return blocks


def build_artifact(snapshot: Mapping[str, Any], project_name: str) -> dict[str, Any]:
    summary = _summary(snapshot)
    narrative = _markdown_blocks(project_name, snapshot, summary)
    source = {
        "id": "sanitized-audit-snapshot",
        "label": "脱敏聚合审计快照",
        "path": "audit-snapshot.json",
        "generatedAt": snapshot["generated_at"],
        "evidenceStatus": snapshot["status"],
    }
    if isinstance(snapshot.get("source_snapshot_sha256"), str):
        source["sourceSha256"] = snapshot["source_snapshot_sha256"]
    datasets = [
        {"id": "summary", "rows": [summary]},
        {"id": "activity", "rows": copy.deepcopy(snapshot["transaction_categories"])},
        {
            "id": "context",
            "rows": sorted(
                copy.deepcopy(snapshot["context_buckets"]),
                key=lambda row: CONTEXT_BUCKET_ORDER.index(row["bucket"]),
            ),
        },
        {"id": "daily", "rows": copy.deepcopy(snapshot["daily"])},
        {"id": "models", "rows": copy.deepcopy(snapshot["models"])},
        {"id": "ui-attribution", "rows": copy.deepcopy(snapshot["ui_attribution"])},
        {"id": "commit-types", "rows": copy.deepcopy(snapshot["quality_output"]["commit_types"])},
    ]
    if isinstance(snapshot.get("tool_calls"), list):
        datasets.append({"id": "tool-calls", "rows": copy.deepcopy(snapshot["tool_calls"])})
    metric_ids = [
        "total_tokens",
        "requests",
        "identifiable_cost_usd",
        "proxy_ceiling_usd",
        "cache_share",
        "requests_over_32k_share",
        "agent_hours",
        "wall_clock_hours",
        "unattributed_share",
    ]
    blocks: list[dict[str, Any]] = [
        {
            "id": "title",
            "type": "markdown",
            "body": f"# {project_name} 运行成本审计报告",
            "evidenceClass": "presentation",
        },
        {
            "id": "headline-metrics",
            "type": "metric-strip",
            "dataset": "summary",
            "metrics": metric_ids,
            "evidenceClass": "deterministic_derivation",
        },
        {
            "id": "activity-chart",
            "type": "chart",
            "dataset": "activity",
            "chart": "horizontal-bar",
            "evidenceClass": "rule_estimate",
        },
        {
            "id": "context-chart",
            "type": "chart",
            "dataset": "context",
            "chart": "horizontal-bar",
            "evidenceClass": "deterministic_derivation",
        },
        {
            "id": "daily-chart",
            "type": "chart",
            "dataset": "daily",
            "chart": "horizontal-bar",
            "evidenceClass": "observed_fact",
        },
    ]
    detail_tables: dict[str, list[dict[str, Any]]] = {
        "activity-analysis": [
            {
                "id": "lineage-chart",
                "type": "chart",
                "dataset": "ui-attribution",
                "chart": "horizontal-bar",
                "labelRule": "derive generic label from anonymous id",
                "evidenceClass": "rule_estimate",
            },
            {
                "id": "ui-table",
                "type": "table",
                "dataset": "ui-attribution",
                "evidenceClass": "rule_estimate",
            },
        ],
        "pricing-analysis": [
            {
                "id": "models-table",
                "type": "table",
                "dataset": "models",
                "evidenceClass": "cost_proxy",
            }
        ],
        "quality-analysis": [
            {
                "id": "commit-table",
                "type": "table",
                "dataset": "commit-types",
                "evidenceClass": "observed_fact",
            }
        ],
    }
    if isinstance(snapshot.get("tool_calls"), list):
        detail_tables["tool-analysis"] = [
            {
                "id": "tool-table",
                "type": "table",
                "dataset": "tool-calls",
                "evidenceClass": "observed_fact",
            }
        ]
    for item in narrative:
        evidence_class = {
            "activity-analysis": "rule_estimate",
            "pricing-analysis": "cost_proxy",
            "recommendations": "rule_estimate",
        }.get(item["id"], "observed_and_derived")
        blocks.append(
            {
                "id": item["id"],
                "type": "markdown",
                "body": item["markdown"],
                "sourceId": source["id"],
                "evidenceClass": evidence_class,
            }
        )
        if item["id"] in detail_tables:
            blocks.extend(detail_tables[item["id"]])
    return {
        "surface": "report",
        "manifest": {
            "version": 1,
            "surface": "report",
            "title": f"{project_name} 运行成本审计报告",
            "description": "由脱敏聚合快照生成的数据优先审计报告。",
            "generatedAt": snapshot["generated_at"],
            "auditWindow": copy.deepcopy(snapshot["window"]),
            "evidenceStatus": snapshot["status"],
            "blocks": blocks,
        },
        "snapshot": {
            "version": snapshot.get("schema_version", 1),
            "status": snapshot.get("status", "validated"),
            "generatedAt": snapshot["generated_at"],
            "window": copy.deepcopy(snapshot["window"]),
            "datasets": datasets,
            "derivations": {
                "cache_share": {
                    "numerator": "totals.cached_tokens",
                    "denominator": "totals.input_tokens",
                    "unit": "ratio",
                    "rule": "divide with zero denominator mapped to 0",
                },
                "average_tokens_per_request": {
                    "numerator": "totals.total_tokens",
                    "denominator": "totals.requests",
                    "unit": "tokens/request",
                    "rule": "divide with zero denominator mapped to 0",
                },
                "priced_token_share": {
                    "numerator": "known-price model total_tokens",
                    "denominator": "totals.total_tokens",
                    "unit": "ratio",
                    "rule": "unknown-price model costs remain null",
                },
                "priced_request_share": {
                    "numerator": "known-price model requests",
                    "denominator": "totals.requests",
                    "unit": "ratio",
                    "rule": "unknown-price model costs remain null",
                },
                "requests_over_32k_share": {
                    "numerator": "non-≤32K bucket requests",
                    "denominator": "totals.requests",
                    "unit": "ratio",
                    "rule": "four mutually exclusive context buckets",
                },
                "unattributed_share": {
                    "numerator": "unattributed total_tokens",
                    "denominator": "totals.total_tokens",
                    "unit": "ratio",
                    "rule": "unmatched lineage remains explicit",
                },
                "wall_clock_hours": {
                    "numerator": "window.end - window.start",
                    "denominator": "3600 seconds/hour",
                    "unit": "hours",
                    "rule": "elapsed duration between frozen boundaries",
                },
                "average_concurrency": {
                    "numerator": "summary.agent_hours",
                    "denominator": "summary.wall_clock_hours",
                    "unit": "ratio",
                    "rule": "parallel agent streams are additive",
                },
                "audit_self_share": {
                    "numerator": "audit-self total_tokens",
                    "denominator": "totals.total_tokens",
                    "unit": "ratio",
                    "rule": "audit-self remains a separate anonymous lineage row",
                },
            },
        },
        "sources": [source],
    }


def _bar_figure(
    figure_id: str,
    title: str,
    description: str,
    rows: Sequence[Mapping[str, Any]],
    label_field: str,
    value_field: str,
    value_formatter,
) -> str:
    maximum = max((float(row[value_field]) for row in rows), default=0.0)
    bar_rows: list[str] = []
    table_rows: list[str] = []
    for row in rows:
        raw_value = float(row[value_field])
        width = 0.0 if maximum == 0 else raw_value / maximum * 100
        label = html.escape(str(row[label_field]))
        formatted = html.escape(value_formatter(row[value_field]))
        bar_rows.append(
            f'<div class="bar-row"><div class="bar-label">{label}</div>'
            f'<div class="bar-track" aria-hidden="true"><span style="width:{width:.4f}%"></span></div>'
            f'<div class="bar-value">{formatted}</div></div>'
        )
        table_rows.append(f"<tr><th scope=\"row\">{label}</th><td>{formatted}</td></tr>")
    return (
        f'<section class="report-section chart-section" id="{figure_id}">'
        f"<h2>{html.escape(title)}</h2><p>{html.escape(description)}</p>"
        f'<figure><div class="bars" role="img" aria-label="{html.escape(title)}。{html.escape(description)}">'
        f'{"".join(bar_rows)}</div>'
        f'<div class="table-scroll"><table><caption>{html.escape(title)}数据表</caption>'
        f'<thead><tr><th scope="col">项目</th><th scope="col">数值</th></tr></thead>'
        f'<tbody>{"".join(table_rows)}</tbody></table></div></figure></section>'
    )


def _data_table(
    section_id: str,
    title: str,
    headers: Sequence[str],
    rows: Sequence[Sequence[str]],
) -> str:
    head = "".join(f'<th scope="col">{html.escape(column)}</th>' for column in headers)
    body_rows = []
    for row in rows:
        cells = "".join(
            (f'<th scope="row">{html.escape(value)}</th>' if index == 0 else f"<td>{html.escape(value)}</td>")
            for index, value in enumerate(row)
        )
        body_rows.append(f"<tr>{cells}</tr>")
    return (
        f'<section class="report-section" id="{html.escape(section_id)}"><h2>{html.escape(title)}</h2>'
        f'<div class="table-scroll"><table><caption>{html.escape(title)}</caption>'
        f"<thead><tr>{head}</tr></thead><tbody>{''.join(body_rows)}</tbody></table></div></section>"
    )


def build_html(snapshot: Mapping[str, Any], project_name: str) -> str:
    totals = snapshot["totals"]
    summary = _summary(snapshot)
    window = snapshot["window"]
    narrative = _markdown_blocks(project_name, snapshot, summary)
    partial_label = "部分日" if window["partial_end_day"] else "完整日"
    metrics = [
        ("总 Token", _compact(totals["total_tokens"]), f"输入 {_compact(totals['input_tokens'])} · 输出 {_compact(totals['output_tokens'])}"),
        ("请求数", f"{totals['requests']:,}", f"平均 {_compact(summary['average_tokens_per_request'])} Token/请求"),
        (
            "可识别成本",
            _money(totals["identifiable_cost_usd"]),
            (
                f"Token {_percent(summary['priced_token_share'])} · 请求 "
                f"{_percent(summary['priced_request_share'])} · 非账单"
            ),
        ),
        ("代理上限", _money(totals.get("proxy_ceiling_usd")), "预算代理值，不是支出或账单"),
        ("输入缓存占比", _percent(summary["cache_share"]), f"缓存 {_compact(totals['cached_tokens'])} Token"),
        ("超过 32K 请求", _percent(summary["requests_over_32k_share"]), "按请求上下文区间统计"),
        ("Agent-hours", f"{summary['agent_hours']:.2f}", "规则估算，平行 Agent 累加"),
        ("墙钟时间", f"{summary['wall_clock_hours']:.2f}h", "按冻结窗口起止计算"),
        ("未归属 Token", _percent(summary["unattributed_share"]), "显式保留，不强制归类"),
    ]
    metric_html = "".join(
        f'<article class="metric"><div class="metric-label">{html.escape(label)}</div>'
        f'<div class="metric-value">{html.escape(value)}</div><div class="metric-note">{html.escape(note)}</div></article>'
        for label, value, note in metrics
    )

    activity_chart = _bar_figure(
        "activity-chart",
        "活动与开销分布",
        "按总 Token 降序；类别来自规则归属。",
        sorted(snapshot["transaction_categories"], key=lambda row: row["total_tokens"], reverse=True),
        "category",
        "total_tokens",
        lambda value: f"{_compact(value)} · {_percent(_ratio(value, totals['total_tokens']))}",
    )
    context_chart = _bar_figure(
        "context-chart",
        "请求上下文分布",
        "各区间互斥，请求数合计等于总体请求数。",
        sorted(snapshot["context_buckets"], key=lambda row: CONTEXT_BUCKET_ORDER.index(row["bucket"])),
        "bucket",
        "requests",
        lambda value: f"{int(value):,} · {_percent(_ratio(value, totals['requests']))}",
    )
    daily_chart = _bar_figure(
        "daily-chart",
        "每日 Token 用量",
        f"按 {window['timezone']} 自然日统计；末日状态：{partial_label}。",
        snapshot["daily"],
        "day",
        "total_tokens",
        lambda value: _compact(value),
    )

    model_rows = [
        [
            str(row["model"]),
            f"{row['total_tokens']:,}",
            f"{row['requests']:,}",
            _percent(_ratio(row["total_tokens"], totals["total_tokens"])),
            _money(row["api_equivalent_base_usd"]),
            "价格未知" if row["api_equivalent_base_usd"] is None else "冻结价格已知",
        ]
        for row in sorted(snapshot["models"], key=lambda item: item["total_tokens"], reverse=True)
    ]
    model_table = _data_table(
        "models-table",
        "模型用量与定价覆盖",
        ("模型", "Token", "请求", "Token 占比", "可识别成本", "定价状态"),
        model_rows,
    )
    commit_rows = [
        [str(row["type"]), f"{row['count']:,}"]
        for row in sorted(snapshot["quality_output"]["commit_types"], key=lambda item: item["count"], reverse=True)
    ]
    commit_table = _data_table("commit-table", "提交类型", ("类型", "提交数"), commit_rows)
    lineage_rows = [
        {**row, "display_label": _anonymous_label(str(row["id"]))}
        for row in sorted(snapshot["ui_attribution"], key=lambda item: item["total_tokens"], reverse=True)
    ]
    lineage_chart = _bar_figure(
        "lineage-chart",
        "匿名会话归属",
        "按总 Token 降序；未归属与审计自身会话保持独立。",
        lineage_rows,
        "display_label",
        "total_tokens",
        lambda value: f"{_compact(value)} · {_percent(_ratio(value, totals['total_tokens']))}",
    )
    ui_rows = [
        [
            _anonymous_label(str(row["id"])),
            f"{row['total_tokens']:,}",
            f"{row['requests']:,}",
            _percent(_ratio(row["total_tokens"], totals["total_tokens"])),
            f"{float(row['active_hours']):.2f}",
        ]
        for row in sorted(snapshot["ui_attribution"], key=lambda item: item["total_tokens"], reverse=True)
    ]
    ui_table = _data_table(
        "ui-table",
        "会话归属明细",
        ("匿名会话", "Token", "请求", "Token 占比", "Agent-hours"),
        ui_rows,
    )
    tool_table = ""
    if isinstance(snapshot.get("tool_calls"), list):
        tool_rows = [
            [str(row["tool_group"]), f"{row['calls']:,}"]
            for row in sorted(snapshot["tool_calls"], key=lambda item: item["calls"], reverse=True)
        ]
        tool_table = _data_table("tool-table", "工具调用明细", ("工具分组", "调用数"), tool_rows)
    detail_tables = {
        "activity-analysis": lineage_chart + ui_table,
        "tool-analysis": tool_table,
        "pricing-analysis": model_table,
        "quality-analysis": commit_table,
    }
    narrative_parts: list[str] = []
    for item in narrative:
        narrative_parts.append(
            f'<section class="report-section narrative" id="{item["id"]}">'
            f'{render_markdown(item["markdown"])}</section>'
        )
        if item["id"] in detail_tables:
            narrative_parts.append(detail_tables[item["id"]])
    rendered_narrative = "".join(narrative_parts)

    css = """
    :root { color-scheme: light; --ink:#172033; --muted:#5d677a; --line:#d9dee8; --soft:#f5f7fa; --accent:#2563eb; }
    * { box-sizing:border-box; }
    html { background:#fff; }
    body { margin:0; color:var(--ink); background:#fff; font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif; line-height:1.65; overflow-x:hidden; }
    main { width:min(1080px,calc(100% - 32px)); margin:0 auto; padding:48px 0 80px; }
    h1,h2 { line-height:1.25; letter-spacing:-.02em; }
    h1 { margin:0 0 8px; font-size:clamp(1.8rem,4vw,2.7rem); }
    h2 { margin:0 0 12px; font-size:1.35rem; }
    p { margin:0 0 14px; }
    .lede { color:var(--muted); margin-bottom:28px; overflow-wrap:anywhere; }
    .metrics { display:grid; grid-template-columns:repeat(3,minmax(0,1fr)); gap:12px; margin:24px 0 42px; }
    .metric { border:1px solid var(--line); border-radius:8px; padding:16px; min-width:0; }
    .metric-label,.metric-note { color:var(--muted); font-size:.86rem; }
    .metric-value { margin:4px 0; font-size:clamp(1.35rem,3vw,2rem); font-weight:700; overflow-wrap:anywhere; }
    .report-section { border-top:1px solid var(--line); padding:34px 0; }
    .chart-section > p { color:var(--muted); }
    figure { margin:22px 0 0; }
    .bars { display:grid; gap:12px; }
    .bar-row { display:grid; grid-template-columns:minmax(130px,2fr) minmax(140px,5fr) minmax(100px,1.4fr); align-items:center; gap:12px; }
    .bar-label { overflow-wrap:anywhere; }
    .bar-track { height:12px; background:#e8edf5; border-radius:2px; overflow:hidden; }
    .bar-track span { display:block; height:100%; min-width:2px; background:var(--accent); }
    .bar-value { text-align:right; font-variant-numeric:tabular-nums; color:var(--muted); }
    .table-scroll { max-width:100%; overflow-x:auto; margin-top:18px; }
    table { width:100%; border-collapse:collapse; font-size:.92rem; }
    caption { text-align:left; font-weight:600; margin-bottom:8px; }
    th,td { border-bottom:1px solid var(--line); padding:10px 12px; text-align:left; vertical-align:top; }
    td:not(:first-child),thead th:not(:first-child) { text-align:right; font-variant-numeric:tabular-nums; }
    code { padding:1px 4px; border-radius:3px; background:var(--soft); overflow-wrap:anywhere; }
    ul,ol { padding-left:1.3rem; }
    .footer { color:var(--muted); font-size:.84rem; }
    @media (max-width:720px) {
      main { width:min(100% - 24px,1080px); padding-top:28px; }
      .metrics { grid-template-columns:repeat(2,minmax(0,1fr)); }
      .bar-row { grid-template-columns:minmax(0,1fr) 82px; gap:7px 10px; }
      .bar-track { grid-column:1 / -1; grid-row:2; }
      .bar-value { grid-column:2; grid-row:1; font-size:.82rem; }
      th,td { white-space:nowrap; }
    }
    @media (max-width:390px) { .metrics { grid-template-columns:1fr; } }
    @media print { main { width:100%; padding:0; } .metric,.report-section { break-inside:avoid; } }
    """
    title = f"{project_name} 运行成本审计报告"
    return (
        "<!doctype html>\n<html lang=\"zh-CN\"><head><meta charset=\"utf-8\">"
        '<meta name="viewport" content="width=device-width,initial-scale=1">'
        f"<title>{html.escape(title)}</title><style>{css}</style></head><body><main>"
        f'<header id="report-title"><h1>{html.escape(title)}</h1>'
        f'<p class="lede">{html.escape(window["start"])} 至 {html.escape(window["end"])} · '
        f'{html.escape(window["timezone"])} · {partial_label} · {html.escape(_evidence_label(snapshot))}</p></header>'
        f'<section class="metrics" id="headline-metrics" aria-label="项目总体指标">{metric_html}</section>'
        f"{activity_chart}{context_chart}{daily_chart}{rendered_narrative}"
        f'<footer class="report-section footer">生成时间：{html.escape(snapshot["generated_at"])} · 来源：audit-snapshot.json</footer>'
        "</main></body></html>\n"
    )


def _json_bytes(value: Any) -> bytes:
    return (
        json.dumps(value, ensure_ascii=False, indent=2, allow_nan=False, sort_keys=True) + "\n"
    ).encode("utf-8")


def _sha256(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


def _validate_report_html(report: str) -> dict[str, Any]:
    lowered = report.lower()
    errors: list[str] = []
    external_patterns = {
        "URL scheme": r"(?:https?:|data:|javascript:|file:|src\s*=\s*['\"]?//)",
        "CSS resource": r"(?:@import|url\s*\()",
        "active or embedded element": r"<(?:script|link|iframe|object|embed|img|video|audio|source)\b",
    }
    for label, pattern in external_patterns.items():
        if re.search(pattern, lowered):
            errors.append(f"report HTML contains a forbidden {label}")

    ordered_ids = (
        'id="report-title"',
        'id="headline-metrics"',
        'id="activity-chart"',
        'id="context-chart"',
        'id="daily-chart"',
        'id="executive-summary"',
    )
    positions: list[int] = []
    for marker in ordered_ids:
        position = lowered.find(marker)
        if position < 0:
            errors.append(f"report HTML is missing {marker}")
        positions.append(position)
    if all(position >= 0 for position in positions) and positions != sorted(positions):
        errors.append("report HTML does not follow the data-first block order")
    metric_count = lowered.count('class="metric"')
    if metric_count != 9:
        errors.append(f"report HTML must contain 9 headline metrics, found {metric_count}")
    if 'name="viewport"' not in lowered or "overflow-x:hidden" not in lowered.replace(" ", ""):
        errors.append("report HTML is missing the responsive viewport contract")
    if errors:
        raise ValidationError(errors)
    return {
        "data_first": True,
        "self_contained": True,
        "external_resources": 0,
        "headline_metrics": metric_count,
        "charts": ["activity", "context", "daily"],
    }


def _validate_artifact_report_alignment(
    artifact: Mapping[str, Any], report: str
) -> dict[str, Any]:
    manifest = artifact.get("manifest")
    snapshot = artifact.get("snapshot")
    if not isinstance(manifest, dict) or not isinstance(snapshot, dict):
        raise ValidationError(["Artifact is missing manifest or snapshot"])
    blocks = manifest.get("blocks")
    datasets = snapshot.get("datasets")
    if not isinstance(blocks, list) or not isinstance(datasets, list):
        raise ValidationError(["Artifact blocks or datasets are malformed"])
    dataset_ids = {
        row.get("id") for row in datasets if isinstance(row, dict) and isinstance(row.get("id"), str)
    }
    positions: list[int] = []
    errors: list[str] = []
    for index, block in enumerate(blocks):
        if not isinstance(block, dict) or not isinstance(block.get("id"), str):
            errors.append(f"Artifact block {index} has no id")
            continue
        block_id = block["id"]
        html_id = "report-title" if block_id == "title" else block_id
        marker = f'id="{html_id}"'
        position = report.find(marker)
        if position < 0:
            errors.append(f"Artifact block {block_id} has no matching HTML section")
        else:
            positions.append(position)
        dataset = block.get("dataset")
        if dataset is not None and dataset not in dataset_ids:
            errors.append(f"Artifact block {block_id} references unknown dataset {dataset}")
    if len(positions) == len(blocks) and positions != sorted(positions):
        errors.append("Artifact block order does not match HTML section order")
    if errors:
        raise ValidationError(errors)
    return {"artifact_aligned": True, "artifact_blocks": len(blocks)}


def _validate_public_text(text: str, label: str) -> None:
    errors: list[str] = []
    for pattern, detail in (
        (UUID_RE, "UUID"),
        (FILE_URL_RE, "file URL"),
        (POSIX_ABSOLUTE_RE, "absolute POSIX path"),
        (WINDOWS_ABSOLUTE_RE, "absolute Windows path"),
        (FORBIDDEN_BRAND_RE, "forbidden legacy branding"),
        (SECRET_VALUE_RE, "secret-like value"),
        (EMAIL_VALUE_RE, "email address"),
    ):
        if pattern.search(text):
            errors.append(f"{label} contains a {detail}")
    if errors:
        raise ValidationError(errors)


def _atomic_write(path: Path, payload: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary_name = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    try:
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary_name, path)
    except BaseException:
        try:
            os.unlink(temporary_name)
        except FileNotFoundError:
            pass
        raise


def _validate_output_target(output_dir: Path) -> None:
    if output_dir.is_symlink():
        raise ValidationError(["output directory must not be a symlink"])
    if not output_dir.exists():
        return
    if not output_dir.is_dir():
        raise ValidationError(["output path must be a directory"])
    entries = list(output_dir.iterdir())
    entry_names = {entry.name for entry in entries}
    unexpected = sorted(entry.name for entry in entries if entry.name not in OUTPUT_FILES)
    unsafe = sorted(
        entry.name
        for entry in entries
        if entry.name in OUTPUT_FILES and (entry.is_symlink() or not entry.is_file())
    )
    if unexpected:
        raise ValidationError(
            ["output directory contains files not owned by this build: " + ", ".join(unexpected)]
        )
    if unsafe:
        raise ValidationError(["output directory contains unsafe output entries: " + ", ".join(unsafe)])
    if entry_names and entry_names != set(OUTPUT_FILES):
        raise ValidationError(["existing output directory must be empty or contain the exact four-file set"])


def _publish_output_set(output_dir: Path, payloads: Mapping[str, bytes]) -> None:
    """Publish an exact four-file generation with directory-level rollback."""

    _validate_output_target(output_dir)
    parent = output_dir.parent
    parent.mkdir(parents=True, exist_ok=True)
    staging = Path(tempfile.mkdtemp(prefix=f".{output_dir.name}.stage-", dir=parent))
    backup: Path | None = None
    try:
        for filename in OUTPUT_FILES:
            _atomic_write(staging / filename, payloads[filename])
        if {entry.name for entry in staging.iterdir()} != set(OUTPUT_FILES):
            raise ValidationError(["staged output set is incomplete"])

        _validate_output_target(output_dir)
        if output_dir.exists():
            backup = Path(tempfile.mkdtemp(prefix=f".{output_dir.name}.backup-", dir=parent))
            backup.rmdir()
            os.replace(output_dir, backup)
            try:
                _validate_output_target(backup)
                os.replace(staging, output_dir)
            except BaseException:
                if not output_dir.exists() and backup.exists():
                    os.replace(backup, output_dir)
                    backup = None
                raise
        else:
            os.replace(staging, output_dir)

        if backup is not None:
            shutil.rmtree(backup)
            backup = None
    finally:
        if staging.exists():
            shutil.rmtree(staging)
        if backup is not None and backup.exists() and not output_dir.exists():
            os.replace(backup, output_dir)


def build_report(
    input_path: Path,
    output_dir: Path,
    project_name: str | None = None,
    source_path: Path | None = None,
) -> dict[str, Any]:
    snapshot = load_snapshot(input_path)
    validation = validate_snapshot(snapshot, hash_source_file(source_path))
    name = _project_name(snapshot, project_name)
    name_errors: list[str] = []
    _validate_privacy(name, name_errors, "$.project_name")
    _validate_project_name(name, "$.project_name", name_errors)
    if name_errors:
        raise ValidationError(name_errors)

    snapshot_payload = _json_bytes(snapshot)
    artifact = build_artifact(snapshot, name)
    artifact["manifest"]["rendererVersion"] = "agent-cost-audit/v1"
    artifact["sources"][0]["publicSnapshotSha256"] = _sha256(snapshot_payload)
    artifact_errors: list[str] = []
    _validate_privacy(artifact, artifact_errors, "$.artifact")
    if artifact_errors:
        raise ValidationError(artifact_errors)
    artifact_payload = _json_bytes(artifact)
    report = build_html(snapshot, name)
    report_payload = report.encode("utf-8")
    report_contract = _validate_report_html(report)
    report_contract.update(_validate_artifact_report_alignment(artifact, report))
    for label, payload in (
        ("audit-snapshot.json", snapshot_payload),
        ("artifact.json", artifact_payload),
        ("report.html", report_payload),
    ):
        _validate_public_text(payload.decode("utf-8"), label)

    qa = validation.as_qa(snapshot["generated_at"])
    qa["warnings"] = _snapshot_warnings(snapshot)
    qa["outputs"] = {
        "snapshot": "audit-snapshot.json",
        "artifact": "artifact.json",
        "report": "report.html",
        "qa": "qa.json",
    }
    qa["hashes"] = {
        "audit-snapshot.json": _sha256(snapshot_payload),
        "artifact.json": _sha256(artifact_payload),
        "report.html": _sha256(report_payload),
    }
    qa["report_contract"] = report_contract
    qa["checks"].extend(
        [
            {
                "id": "output_privacy",
                "status": "passed",
                "detail": "all four public outputs passed structured and byte-level scans",
            },
            {
                "id": "report_html",
                "status": "passed",
                "detail": "data-first order and zero external resources verified from rendered HTML",
            },
            {
                "id": "artifact_html_alignment",
                "status": "passed",
                "detail": "Artifact datasets, blocks, and order match rendered HTML",
            },
        ]
    )
    qa["summary"]["passed"] = len(qa["checks"])
    qa_errors: list[str] = []
    _validate_privacy(qa, qa_errors, "$.qa")
    if qa_errors:
        raise ValidationError(qa_errors)
    qa_payload = _json_bytes(qa)
    _validate_public_text(qa_payload.decode("utf-8"), "qa.json")

    payloads = {
        "audit-snapshot.json": snapshot_payload,
        "artifact.json": artifact_payload,
        "report.html": report_payload,
        "qa.json": qa_payload,
    }
    _publish_output_set(output_dir, payloads)
    return qa


def _failed_payload(exc: ValidationError) -> dict[str, Any]:
    return {
        "status": "failed",
        "summary": {"passed": 0, "failed": len(exc.errors)},
        "errors": exc.errors,
    }


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Build a sanitized agent-cost audit report")
    subparsers = parser.add_subparsers(dest="command", required=True)
    validate = subparsers.add_parser("validate", help="validate a sanitized aggregate snapshot")
    validate.add_argument("--input", required=True, type=Path, help="input snapshot JSON")
    validate.add_argument(
        "--source-file", type=Path, help="frozen source evidence whose SHA-256 must match a real snapshot"
    )
    build = subparsers.add_parser("build", help="validate and build report artifacts")
    build.add_argument("--input", required=True, type=Path, help="input snapshot JSON")
    build.add_argument("--output-dir", required=True, type=Path, help="directory for generated files")
    build.add_argument("--project-name", help="report project name override")
    build.add_argument(
        "--source-file", type=Path, help="frozen source evidence whose SHA-256 must match a real snapshot"
    )
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    try:
        if args.command == "validate":
            snapshot = load_snapshot(args.input)
            validation = validate_snapshot(snapshot, hash_source_file(args.source_file))
            qa = validation.as_qa(snapshot["generated_at"])
            qa["warnings"] = _snapshot_warnings(snapshot)
        else:
            qa = build_report(
                args.input,
                args.output_dir,
                args.project_name,
                source_path=args.source_file,
            )
    except ValidationError as exc:
        print(json.dumps(_failed_payload(exc), ensure_ascii=False, indent=2), file=sys.stderr)
        return 1
    except OSError:
        payload = {"status": "failed", "errors": ["build failed due to an operating-system error"]}
        print(json.dumps(payload, ensure_ascii=False, indent=2), file=sys.stderr)
        return 2
    except (ValueError, TypeError) as exc:
        payload = {"status": "failed", "errors": [f"build failed: {exc}"]}
        print(json.dumps(payload, ensure_ascii=False, indent=2), file=sys.stderr)
        return 2
    print(json.dumps(qa, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
