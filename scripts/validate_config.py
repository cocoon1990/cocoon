#!/usr/bin/env python3
"""
validate_config.py — SCP-GHOST Routing Config Business Logic Validator

این اسکریپت توسط GitHub Actions فراخوانی می‌شود.
JSON Schema validation توسط ajv-cli انجام می‌شود (قبل از این اسکریپت).
این اسکریپت قوانین تجاری را که JSON Schema نمی‌تواند بررسی کند، validate می‌کند.

خروجی:
  exit code 0  → validation کامل موفق
  exit code 1  → حداقل یک خطای FATAL یا ERROR وجود دارد
"""

import json
import sys
import os
from typing import Any

# ──────────────────────────────────────────────────────────────
#  رنگ‌بندی خروجی برای GitHub Actions Logs
# ──────────────────────────────────────────────────────────────
IS_CI = os.environ.get("CI", "false").lower() == "true"

def color(text: str, code: str) -> str:
    if IS_CI:
        return text  # GitHub Actions رنگ ANSI را نمایش می‌دهد اما برخی runners نه
    return f"\033[{code}m{text}\033[0m"

def ok(msg: str) -> None:
    print(f"  ✅ {color(msg, '32')}")

def warn(msg: str) -> None:
    print(f"  ⚠️  {color(msg, '33')}")

def fail(msg: str) -> None:
    print(f"  ❌ {color(msg, '31')}")


# ──────────────────────────────────────────────────────────────
#  Validator Functions
# ──────────────────────────────────────────────────────────────

def check_deny_rule_exists(rules: list[dict]) -> list[str]:
    """بررسی وجود حداقل یک deny rule — معادل Nginx 'deny all'"""
    errors = []
    deny_rules = [r for r in rules if r.get("action", {}).get("backend") == "deny"]
    if not deny_rules:
        errors.append("FATAL: No 'deny' backend rule found. 'default_deny' is required.")
    else:
        ok(f"Found {len(deny_rules)} deny rule(s)")
    return errors


def check_unique_priorities(rules: list[dict]) -> list[str]:
    """بررسی یکتایی priority ها — دو rule نمی‌توانند یک priority داشته باشند"""
    errors = []
    priorities = [r.get("priority") for r in rules]
    seen = set()
    duplicates = set()
    for p in priorities:
        if p in seen:
            duplicates.add(p)
        seen.add(p)

    if duplicates:
        errors.append(f"ERROR: Duplicate priorities found: {sorted(duplicates)}. Each rule must have a unique priority.")
    else:
        ok(f"All {len(priorities)} priorities are unique")
    return errors


def check_deny_rule_priority(rules: list[dict]) -> list[str]:
    """بررسی اینکه deny rule باید بالاترین priority عددی (۹۹) را داشته باشد"""
    errors = []
    for rule in rules:
        if rule.get("action", {}).get("backend") == "deny":
            p = rule.get("priority", 0)
            if p != 99:
                errors.append(
                    f"ERROR: deny rule '{rule['name']}' has priority={p}. "
                    f"It must be 99 to act as a catch-all default."
                )
            else:
                ok(f"deny rule '{rule['name']}' correctly has priority=99")
    return errors


def check_apps_script_endpoints(rules: list[dict]) -> list[str]:
    """بررسی Apps Script Pool — باید حداقل یک endpoint داشته باشد"""
    errors = []
    for rule in rules:
        action = rule.get("action", {})
        if action.get("backend") == "google_apps_script_pool":
            eps = action.get("endpoints", [])
            rule_name = rule["name"]
            if not eps:
                errors.append(
                    f"ERROR: Rule '{rule_name}' uses 'google_apps_script_pool' "
                    f"but has no endpoints defined."
                )
            elif len(eps) > 10:
                errors.append(
                    f"WARNING: Rule '{rule_name}' has {len(eps)} endpoints. "
                    f"Maximum recommended is 4 (daily quota management)."
                )
            else:
                ok(f"Rule '{rule_name}' has {len(eps)} Apps Script endpoint(s)")
    return errors


def check_rate_limits(rate: dict[str, Any]) -> list[str]:
    """بررسی منطقی بودن rate limits"""
    errors = []
    streaming_rpm = rate.get("streaming_rpm", 0)
    buffered_rpm = rate.get("buffered_rpm", 0)

    # Cloudflare free tier: 100,000 req/day ≈ 69.4 req/min average
    CF_FREE_DAILY_LIMIT = 100_000
    cf_rpm_equivalent = CF_FREE_DAILY_LIMIT / 1440

    if streaming_rpm > 1000:
        errors.append(
            f"WARNING: streaming_rpm={streaming_rpm} is very high. "
            f"Cloudflare free tier averages ~{cf_rpm_equivalent:.0f} req/min over 24h."
        )
    else:
        ok(f"streaming_rpm={streaming_rpm} is within safe bounds")

    if buffered_rpm > 5000:
        errors.append(
            f"WARNING: buffered_rpm={buffered_rpm} may exhaust "
            f"Google Apps Script quota (20K req/day per account)."
        )
    else:
        ok(f"buffered_rpm={buffered_rpm} is within safe bounds")

    if streaming_rpm <= 0 or buffered_rpm <= 0:
        errors.append("ERROR: rate limit values must be positive integers.")

    return errors


def check_health_check_config(hc: dict[str, Any]) -> list[str]:
    """بررسی پیکربندی health check"""
    errors = []
    interval = hc.get("interval_seconds", 0)
    if interval < 10:
        errors.append(
            f"WARNING: health_check.interval_seconds={interval} is very low. "
            f"Recommended minimum is 30s to avoid quota exhaustion."
        )
    elif interval > 300:
        errors.append(
            f"WARNING: health_check.interval_seconds={interval} is very high. "
            f"Failing endpoints will remain in rotation too long."
        )
    else:
        ok(f"health_check.interval_seconds={interval} is reasonable")

    failure_threshold = hc.get("failure_threshold", 0)
    if failure_threshold < 1:
        errors.append("ERROR: health_check.failure_threshold must be >= 1.")
    else:
        ok(f"failure_threshold={failure_threshold}")

    return errors


def check_streaming_rule_has_hmac(rules: list[dict]) -> list[str]:
    """بررسی اینکه streaming rule باید hmac_required=true داشته باشد"""
    errors = []
    for rule in rules:
        action = rule.get("action", {})
        if action.get("backend") == "cloudflare_stream_worker":
            if not action.get("hmac_required", False):
                errors.append(
                    f"ERROR: Rule '{rule['name']}' uses 'cloudflare_stream_worker' "
                    f"but 'hmac_required' is false. This is a security risk."
                )
            else:
                ok(f"Rule '{rule['name']}' correctly requires HMAC")
    return errors


# ──────────────────────────────────────────────────────────────
#  Main Entry Point
# ──────────────────────────────────────────────────────────────

def main() -> int:
    if len(sys.argv) < 2:
        print("Usage: python3 validate_config.py <path-to-config.json>")
        return 1

    config_path = sys.argv[1]

    print(f"\n{'═' * 60}")
    print(f"  SCP-GHOST Config Business Logic Validator")
    print(f"  File: {config_path}")
    print(f"{'═' * 60}\n")

    # ── خواندن فایل Config ────────────────────────────────────
    try:
        with open(config_path, "r", encoding="utf-8") as f:
            config = json.load(f)
    except FileNotFoundError:
        print(f"❌ FATAL: Config file not found: {config_path}")
        return 1
    except json.JSONDecodeError as e:
        print(f"❌ FATAL: Invalid JSON in config file: {e}")
        return 1

    print(f"📄 Config version : {config.get('version', 'unknown')}")
    print(f"📅 Updated at     : {config.get('updated_at', 'unknown')}")
    print(f"📋 Total rules    : {len(config.get('routing_rules', []))}")
    print()

    rules = config.get("routing_rules", [])
    rate = config.get("rate_limits", {})
    hc = config.get("health_check", {})

    all_errors: list[str] = []

    # اجرای تمام checks
    print("── Routing Rules ──────────────────────────────────────")
    all_errors += check_deny_rule_exists(rules)
    all_errors += check_unique_priorities(rules)
    all_errors += check_deny_rule_priority(rules)
    all_errors += check_apps_script_endpoints(rules)
    all_errors += check_streaming_rule_has_hmac(rules)

    print("\n── Rate Limits ────────────────────────────────────────")
    all_errors += check_rate_limits(rate)

    print("\n── Health Check ───────────────────────────────────────")
    all_errors += check_health_check_config(hc)

    # ── نمایش نتیجه نهایی ─────────────────────────────────────
    print(f"\n{'═' * 60}")
    fatal_or_error = [e for e in all_errors if e.startswith("FATAL") or e.startswith("ERROR")]
    warnings = [e for e in all_errors if e.startswith("WARNING")]

    if warnings:
        print(f"\n⚠️  Warnings ({len(warnings)}):")
        for w in warnings:
            warn(w)

    if fatal_or_error:
        print(f"\n❌ Validation FAILED — {len(fatal_or_error)} critical error(s):")
        for e in fatal_or_error:
            fail(e)
        print()
        return 1

    print(f"✅ All business logic checks passed.")
    print(f"   Rules validated : {len(rules)}")
    print(f"   Warnings        : {len(warnings)}")
    print(f"   Fatal errors    : 0")
    print()
    return 0


if __name__ == "__main__":
    sys.exit(main())
