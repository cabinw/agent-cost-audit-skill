from __future__ import annotations

import copy
import importlib.util
import json
import re
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


REPOSITORY = Path(__file__).resolve().parents[1]
SCRIPT = REPOSITORY / "scripts" / "audit_report.py"
FIXTURE = REPOSITORY / "tests" / "fixtures" / "minimal-audit-snapshot.json"

SPEC = importlib.util.spec_from_file_location("audit_report", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
audit_report = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = audit_report
SPEC.loader.exec_module(audit_report)


def fixture() -> dict:
    return json.loads(FIXTURE.read_text(encoding="utf-8"))


class ValidationTests(unittest.TestCase):
    def test_normal_snapshot_passes(self) -> None:
        result = audit_report.validate_snapshot(fixture())
        self.assertGreaterEqual(len(result.checks), 8)

    def test_schema_provenance_and_sanitization_are_enforced(self) -> None:
        mutations = []

        unsupported_status = fixture()
        unsupported_status["status"] = "design_only"
        mutations.append(unsupported_status)

        unsupported_schema = fixture()
        unsupported_schema["schema_version"] = 999
        mutations.append(unsupported_schema)

        missing_schema = fixture()
        del missing_schema["schema_version"]
        mutations.append(missing_schema)

        missing_fixture_provenance = fixture()
        del missing_fixture_provenance["provenance"]
        mutations.append(missing_fixture_provenance)

        fake_real = fixture()
        fake_real["status"] = "frozen_real_aggregate"
        del fake_real["provenance"]
        mutations.append(fake_real)

        unsanitized = fixture()
        unsanitized["sanitization"]["level"] = "raw"
        mutations.append(unsanitized)

        for value in mutations:
            with self.subTest(status=value.get("status"), schema=value.get("schema_version")):
                with self.assertRaises(audit_report.ValidationError):
                    audit_report.validate_snapshot(value)

    def test_real_snapshot_requires_matching_frozen_source(self) -> None:
        source_payload = b"canonical frozen source evidence\n"
        source_hash = audit_report._sha256(source_payload)
        value = fixture()
        value["status"] = "frozen_real_aggregate"
        value["source_snapshot_sha256"] = source_hash
        del value["provenance"]

        with self.assertRaises(audit_report.ValidationError):
            audit_report.validate_snapshot(value)
        with self.assertRaises(audit_report.ValidationError):
            audit_report.validate_snapshot(value, "0" * 64)
        result = audit_report.validate_snapshot(value, source_hash)
        self.assertTrue(result.checks)

    def test_unknown_and_secret_fields_are_rejected(self) -> None:
        cases = [
            ("api_key", "sk-live-supersecret-value"),
            ("password", "hunter2"),
            ("session_id", "alice-private-session"),
        ]
        for key, secret in cases:
            with self.subTest(key=key):
                value = fixture()
                value[key] = secret
                with self.assertRaises(audit_report.ValidationError):
                    audit_report.validate_snapshot(value)

        nested = fixture()
        nested["models"][0]["private_note"] = "not public"
        with self.assertRaises(audit_report.ValidationError):
            audit_report.validate_snapshot(nested)

        direct_label = fixture()
        direct_label["ui_attribution"][0]["ui_session"] = "Alice private session"
        with self.assertRaises(audit_report.ValidationError):
            audit_report.validate_snapshot(direct_label)

        direct_alias = fixture()
        direct_alias["ui_attribution"][0]["id"] = "alice-private-session"
        with self.assertRaises(audit_report.ValidationError):
            audit_report.validate_snapshot(direct_alias)

        missing_audit_self = fixture()
        missing_audit_self["ui_attribution"] = [
            row for row in missing_audit_self["ui_attribution"] if row["id"] != "audit-self"
        ]
        with self.assertRaises(audit_report.ValidationError):
            audit_report.validate_snapshot(missing_audit_self)

        account_like_project_id = fixture()
        account_like_project_id["project"]["id"] = "acct-prod-12345"
        with self.assertRaises(audit_report.ValidationError):
            audit_report.validate_snapshot(account_like_project_id)

    def test_declared_timezone_partial_day_and_context_boundaries_are_enforced(self) -> None:
        invalid_timezone = fixture()
        invalid_timezone["window"]["timezone"] = "Mars/Olympus"
        with self.assertRaises(audit_report.ValidationError):
            audit_report.validate_snapshot(invalid_timezone)

        traversal_timezone = fixture()
        traversal_timezone["window"]["timezone"] = "../UTC"
        with self.assertRaises(audit_report.ValidationError):
            audit_report.validate_snapshot(traversal_timezone)

        wrong_offset = fixture()
        wrong_offset["window"]["timezone"] = "Asia/Shanghai"
        with self.assertRaises(audit_report.ValidationError):
            audit_report.validate_snapshot(wrong_offset)

        full_day_with_partial_end = fixture()
        full_day_with_partial_end["window"]["partial_end_day"] = False
        with self.assertRaises(audit_report.ValidationError):
            audit_report.validate_snapshot(full_day_with_partial_end)

        arbitrary_bucket = fixture()
        arbitrary_bucket["context_buckets"][0]["bucket"] = "0–100K"
        with self.assertRaises(audit_report.ValidationError):
            audit_report.validate_snapshot(arbitrary_bucket)

        missing_bucket = fixture()
        missing_bucket["context_buckets"].pop()
        with self.assertRaises(audit_report.ValidationError):
            audit_report.validate_snapshot(missing_bucket)

        complete_window = fixture()
        complete_window["window"]["end"] = "2026-01-03T00:00:00+00:00"
        complete_window["window"]["partial_end_day"] = False
        complete_window["generated_at"] = "2026-01-03T00:00:00Z"
        audit_report.validate_snapshot(complete_window)

    def test_optional_numeric_fields_are_bounded(self) -> None:
        mutations = [
            lambda value: value["transaction_categories"][0].__setitem__("active_hours", -1),
            lambda value: value["ui_attribution"][0].__setitem__("sessions", -1),
            lambda value: value["tool_calls"][0].__setitem__("calls", -1),
            lambda value: value["quality_output"].__setitem__("insertions", -1),
            lambda value: value["efficiency_signals"].__setitem__("cache_share_of_input", 1.1),
        ]
        for mutate in mutations:
            value = fixture()
            mutate(value)
            with self.assertRaises(audit_report.ValidationError):
                audit_report.validate_snapshot(value)

        missing_displayed_value = fixture()
        del missing_displayed_value["quality_output"]["deletions"]
        with self.assertRaises(audit_report.ValidationError):
            audit_report.validate_snapshot(missing_displayed_value)

        missing_hours = fixture()
        del missing_hours["ui_attribution"][0]["active_hours"]
        with self.assertRaises(audit_report.ValidationError):
            audit_report.validate_snapshot(missing_hours)

    def test_reconciliation_metadata_is_typed(self) -> None:
        value = fixture()
        value["reconciliation"] = {
            "agent_hours": {
                "precise_total": -1,
                "transaction_category_rows": 4.0,
                "ui_attribution_rows": 4.0,
                "status": "rounded"
            }
        }
        with self.assertRaises(audit_report.ValidationError):
            audit_report.validate_snapshot(value)

    def test_malformed_total_is_rejected(self) -> None:
        value = fixture()
        value["totals"]["total_tokens"] += 1
        with self.assertRaises(audit_report.ValidationError) as raised:
            audit_report.validate_snapshot(value)
        self.assertIn("input_tokens + output_tokens", str(raised.exception))

    def test_unknown_price_stays_null_and_known_cost_reconciles(self) -> None:
        value = fixture()
        audit_report.validate_snapshot(value)
        artifact = audit_report.build_artifact(value, "Pricing Boundary")
        models = next(
            dataset["rows"]
            for dataset in artifact["snapshot"]["datasets"]
            if dataset["id"] == "models"
        )
        unknown = next(model for model in models if model["model"] == "unknown-model")
        self.assertIsNone(unknown["api_equivalent_base_usd"])
        rendered = audit_report.build_html(value, "Pricing Boundary")
        self.assertIn("价格未知", rendered)
        self.assertNotIn("None", rendered)

    def test_zero_is_a_valid_known_price_boundary(self) -> None:
        value = fixture()
        value["models"][0]["api_equivalent_base_usd"] = 0
        value["totals"]["identifiable_cost_usd"] = 0
        value["daily"][0]["identifiable_cost_usd"] = 0
        value["daily"][1]["identifiable_cost_usd"] = 0
        audit_report.validate_snapshot(value)
        html = audit_report.build_html(value, "Zero Price")
        self.assertIn("$0.00", html)

    def test_negative_and_mismatched_price_are_rejected(self) -> None:
        negative = fixture()
        negative["models"][0]["api_equivalent_base_usd"] = -0.01
        with self.assertRaises(audit_report.ValidationError):
            audit_report.validate_snapshot(negative)

        mismatch = fixture()
        mismatch["totals"]["identifiable_cost_usd"] = 1.24
        mismatch["daily"][1]["identifiable_cost_usd"] = 0.24
        with self.assertRaises(audit_report.ValidationError) as raised:
            audit_report.validate_snapshot(mismatch)
        self.assertIn("known-price cost", str(raised.exception))

    def test_partial_day_must_match_window_and_is_visible(self) -> None:
        value = fixture()
        html = audit_report.build_html(value, "Partial Window")
        self.assertIn("部分日", html)
        self.assertIn("2026-01-02T04:00:00+00:00", html)

        invalid = fixture()
        invalid["window"]["end"] = "2026-01-03T04:00:00+00:00"
        invalid["generated_at"] = "2026-01-03T04:00:00Z"
        with self.assertRaises(audit_report.ValidationError) as raised:
            audit_report.validate_snapshot(invalid)
        self.assertIn("window.end", str(raised.exception))

    def test_privacy_guards(self) -> None:
        cases = [
            ("uuid", "018f767e-4c63-7f14-9a6b-4d8ea3ea1941"),
            ("absolute_path", "/Users/person/private/report.json"),
            ("file_url", "file:///private/report.json"),
            ("legacy_brand", "Codex" + "Bar collector"),
        ]
        for label, unsafe in cases:
            with self.subTest(label=label):
                value = fixture()
                value["notes"] = unsafe
                with self.assertRaises(audit_report.ValidationError):
                    audit_report.validate_snapshot(value)

        for key in ("raw_prompt", "event_payload", "account_id", "customer_name"):
            with self.subTest(key=key):
                value = fixture()
                value[key] = "redacted"
                with self.assertRaises(audit_report.ValidationError):
                    audit_report.validate_snapshot(value)

    def test_exact_reconciliations_are_enforced(self) -> None:
        mutations = [
            ("models", lambda value: value["models"][0].__setitem__("requests", 5)),
            ("daily", lambda value: value["daily"][0].__setitem__("cached_tokens", 499)),
            ("ui", lambda value: value["ui_attribution"][0].__setitem__("output_tokens", 79)),
            (
                "transaction",
                lambda value: value["transaction_categories"][0].__setitem__("requests", 5),
            ),
            ("context", lambda value: value["context_buckets"][0].__setitem__("requests", 3)),
            (
                "commit_types",
                lambda value: value["quality_output"]["commit_types"][0].__setitem__("count", 1),
            ),
        ]
        for label, mutate in mutations:
            with self.subTest(label=label):
                value = fixture()
                mutate(value)
                with self.assertRaises(audit_report.ValidationError):
                    audit_report.validate_snapshot(value)


class BuildTests(unittest.TestCase):
    def test_build_writes_contract_files_and_machine_readable_qa(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "report"
            qa = audit_report.build_report(FIXTURE, output, "Override Project")
            self.assertEqual(set(audit_report.OUTPUT_FILES), {path.name for path in output.iterdir()})
            self.assertEqual("passed", qa["status"])
            written_qa = json.loads((output / "qa.json").read_text(encoding="utf-8"))
            self.assertEqual(9, written_qa["report_contract"]["headline_metrics"])
            self.assertEqual("audit-snapshot.json", written_qa["input"])
            self.assertEqual([], written_qa["errors"])
            self.assertTrue(any("Synthetic fixture" in item for item in written_qa["warnings"]))
            self.assertEqual(
                {"audit-snapshot.json", "artifact.json", "report.html"},
                set(written_qa["hashes"]),
            )
            copied = json.loads((output / "audit-snapshot.json").read_text(encoding="utf-8"))
            self.assertEqual(fixture(), copied)

            artifact = json.loads((output / "artifact.json").read_text(encoding="utf-8"))
            self.assertEqual("report", artifact["surface"])
            self.assertEqual("report", artifact["manifest"]["surface"])
            self.assertIn("snapshot", artifact)
            self.assertEqual("sanitized-audit-snapshot", artifact["sources"][0]["id"])

    def test_report_is_self_contained_and_data_first(self) -> None:
        report = audit_report.build_html(fixture(), "Order Test")
        lowered = report.lower()
        self.assertIsNone(re.search(r"https?://", lowered))
        self.assertNotIn("<link", lowered)
        self.assertNotIn("<script", lowered)
        self.assertIn('name="viewport"', lowered)
        self.assertIn("overflow-x:hidden", lowered.replace(" ", ""))

        order = [
            report.index('id="report-title"'),
            report.index('id="headline-metrics"'),
            report.index('id="activity-chart"'),
            report.index('id="context-chart"'),
            report.index('id="daily-chart"'),
            report.index('id="executive-summary"'),
        ]
        self.assertEqual(sorted(order), order)
        self.assertEqual(9, report.count('class="metric"'))
        self.assertGreaterEqual(report.count('role="img"'), 4)
        self.assertGreaterEqual(report.count("<table>"), 7)
        self.assertIn("合成测试夹具", report)
        self.assertIn("代理上限", report)
        self.assertIn("工具调用明细", report)

    def test_project_name_injection_is_rejected_before_output(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "report"
            with self.assertRaises(audit_report.ValidationError):
                audit_report.build_report(
                    FIXTURE,
                    output,
                    "Safe\n\n![external](https://tracker.invalid/pixel)",
                )
            self.assertFalse(output.exists())

    def test_build_is_byte_deterministic_and_hashes_match(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            first = Path(directory) / "first"
            second = Path(directory) / "second"
            renamed_input = Path(directory) / "customer-acme-prod-billing.json"
            renamed_input.write_bytes(FIXTURE.read_bytes())
            audit_report.build_report(FIXTURE, first)
            audit_report.build_report(renamed_input, second)
            for filename in audit_report.OUTPUT_FILES:
                self.assertEqual((first / filename).read_bytes(), (second / filename).read_bytes())

            qa = json.loads((first / "qa.json").read_text(encoding="utf-8"))
            for filename, expected in qa["hashes"].items():
                self.assertEqual(expected, audit_report._sha256((first / filename).read_bytes()))

    def test_atomic_publish_rejects_unowned_files_without_changes(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "report"
            output.mkdir()
            unrelated = output / "unrelated.txt"
            unrelated.write_text("keep", encoding="utf-8")
            with self.assertRaises(audit_report.ValidationError):
                audit_report.build_report(FIXTURE, output)
            self.assertEqual("keep", unrelated.read_text(encoding="utf-8"))
            self.assertEqual({"unrelated.txt"}, {path.name for path in output.iterdir()})

    def test_atomic_publish_rejects_partial_prior_generation(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "report"
            output.mkdir()
            prior_qa = output / "qa.json"
            prior_qa.write_text('{"status":"passed"}', encoding="utf-8")
            with self.assertRaises(audit_report.ValidationError):
                audit_report.build_report(FIXTURE, output)
            self.assertEqual('{"status":"passed"}', prior_qa.read_text(encoding="utf-8"))

    def test_staging_failure_preserves_previous_generation(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "report"
            audit_report.build_report(FIXTURE, output)
            before = {path.name: path.read_bytes() for path in output.iterdir()}
            original = audit_report._atomic_write
            calls = 0

            def fail_third(path: Path, payload: bytes) -> None:
                nonlocal calls
                calls += 1
                if calls == 3:
                    raise OSError("injected staging failure")
                original(path, payload)

            audit_report._atomic_write = fail_third
            try:
                with self.assertRaises(OSError):
                    audit_report.build_report(FIXTURE, output, "Second Generation")
            finally:
                audit_report._atomic_write = original

            after = {path.name: path.read_bytes() for path in output.iterdir()}
            self.assertEqual(before, after)
            self.assertFalse(any(path.name.startswith(".report.stage-") for path in Path(directory).iterdir()))

    def test_html_contract_is_computed_not_hard_coded(self) -> None:
        original = audit_report.build_html
        audit_report.build_html = lambda snapshot, name: '<html><img src="//tracker.invalid/pixel"></html>'
        try:
            with tempfile.TemporaryDirectory() as directory:
                output = Path(directory) / "report"
                with self.assertRaises(audit_report.ValidationError):
                    audit_report.build_report(FIXTURE, output)
                self.assertFalse(output.exists())
        finally:
            audit_report.build_html = original

    def test_artifact_and_html_block_order_must_align(self) -> None:
        value = fixture()
        artifact = audit_report.build_artifact(value, "Alignment Test")
        report = audit_report.build_html(value, "Alignment Test")
        result = audit_report._validate_artifact_report_alignment(artifact, report)
        self.assertTrue(result["artifact_aligned"])
        with self.assertRaises(audit_report.ValidationError):
            audit_report._validate_artifact_report_alignment(
                artifact,
                report.replace('id="lineage-chart"', 'id="missing-lineage-chart"', 1),
            )

    def test_markdown_subset_escapes_html(self) -> None:
        rendered = audit_report.render_markdown(
            "## Finding\n\n- **Strong** and `code`\n- <script>alert(1)</script>"
        )
        self.assertIn("<h2>Finding</h2>", rendered)
        self.assertIn("<strong>Strong</strong>", rendered)
        self.assertIn("<code>code</code>", rendered)
        self.assertNotIn("<script>", rendered)
        self.assertIn("&lt;script&gt;", rendered)

    def test_invalid_build_does_not_create_output_directory(self) -> None:
        value = fixture()
        value["totals"]["cached_tokens"] = 1001
        with tempfile.TemporaryDirectory() as directory:
            bad_input = Path(directory) / "bad.json"
            bad_input.write_text(json.dumps(value), encoding="utf-8")
            output = Path(directory) / "not-created"
            with self.assertRaises(audit_report.ValidationError):
                audit_report.build_report(bad_input, output)
            self.assertFalse(output.exists())

    def test_cli_validate_build_and_malformed_json(self) -> None:
        validate = subprocess.run(
            [sys.executable, str(SCRIPT), "validate", "--input", str(FIXTURE)],
            cwd=REPOSITORY,
            text=True,
            capture_output=True,
            check=False,
        )
        self.assertEqual(0, validate.returncode, validate.stderr)
        self.assertEqual("passed", json.loads(validate.stdout)["status"])

        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "build"
            build = subprocess.run(
                [
                    sys.executable,
                    str(SCRIPT),
                    "build",
                    "--input",
                    str(FIXTURE),
                    "--output-dir",
                    str(output),
                    "--project-name",
                    "CLI Project",
                ],
                cwd=REPOSITORY,
                text=True,
                capture_output=True,
                check=False,
            )
            self.assertEqual(0, build.returncode, build.stderr)
            self.assertIn("CLI Project", (output / "report.html").read_text(encoding="utf-8"))

            malformed = Path(directory) / "malformed.json"
            malformed.write_text("{oops", encoding="utf-8")
            failed = subprocess.run(
                [sys.executable, str(SCRIPT), "validate", "--input", str(malformed)],
                cwd=REPOSITORY,
                text=True,
                capture_output=True,
                check=False,
            )
            self.assertEqual(1, failed.returncode)
            error = json.loads(failed.stderr)
            self.assertEqual("failed", error["status"])
            self.assertIn("malformed JSON", error["errors"][0])

            source = Path(directory) / "frozen-evidence.json"
            source.write_bytes(b"frozen source evidence\n")
            real = fixture()
            real["status"] = "frozen_real_aggregate"
            real["source_snapshot_sha256"] = audit_report._sha256(source.read_bytes())
            del real["provenance"]
            real_input = Path(directory) / "real.json"
            real_input.write_text(json.dumps(real), encoding="utf-8")

            missing_source = subprocess.run(
                [sys.executable, str(SCRIPT), "validate", "--input", str(real_input)],
                cwd=REPOSITORY,
                text=True,
                capture_output=True,
                check=False,
            )
            self.assertEqual(1, missing_source.returncode)

            verified = subprocess.run(
                [
                    sys.executable,
                    str(SCRIPT),
                    "validate",
                    "--input",
                    str(real_input),
                    "--source-file",
                    str(source),
                ],
                cwd=REPOSITORY,
                text=True,
                capture_output=True,
                check=False,
            )
            self.assertEqual(0, verified.returncode, verified.stderr)


if __name__ == "__main__":
    unittest.main()
