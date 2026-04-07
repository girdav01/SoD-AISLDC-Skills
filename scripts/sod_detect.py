#!/usr/bin/env python3
"""
SoD Detection Engine for AI-Generated Code
Implements Phases 1-4 of the Separation of Duties framework.

Usage:
    python sod_detect.py --gen-model <model_id> --review-model <model_id> [options]
    python sod_detect.py --scan-git-log [--repo-path <path>]
    python sod_detect.py --audit-report <output_path>

© 2026 David Girard
"""

import argparse
import hashlib
import json
import os
import re
import subprocess
import sys
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Optional


# ============================================================
# PHASE 1: Model Registry & Lineage Mapping
# ============================================================

class ModelFamily(Enum):
    """Known model families grouped by training lineage."""
    ANTHROPIC_CLAUDE = "anthropic-claude"
    OPENAI_GPT = "openai-gpt"
    GOOGLE_GEMINI = "google-gemini"
    META_LLAMA = "meta-llama"
    MISTRAL = "mistral"
    DEEPSEEK = "deepseek"
    COHERE = "cohere-command"
    ALIBABA_QWEN = "alibaba-qwen"
    UNKNOWN = "unknown"


# Map model identifiers to families. Extend as needed.
MODEL_FAMILY_MAP: dict[str, ModelFamily] = {
    # Anthropic
    "claude-opus-4-6": ModelFamily.ANTHROPIC_CLAUDE,
    "claude-sonnet-4-6": ModelFamily.ANTHROPIC_CLAUDE,
    "claude-sonnet-4-5": ModelFamily.ANTHROPIC_CLAUDE,
    "claude-haiku-4-5": ModelFamily.ANTHROPIC_CLAUDE,
    "claude-opus-4": ModelFamily.ANTHROPIC_CLAUDE,
    "claude-sonnet-4": ModelFamily.ANTHROPIC_CLAUDE,
    "claude-3-5-sonnet": ModelFamily.ANTHROPIC_CLAUDE,
    "claude-3-opus": ModelFamily.ANTHROPIC_CLAUDE,
    "claude-3-haiku": ModelFamily.ANTHROPIC_CLAUDE,
    "claude-code": ModelFamily.ANTHROPIC_CLAUDE,
    "claude-4": ModelFamily.ANTHROPIC_CLAUDE,
    # OpenAI
    "gpt-4o": ModelFamily.OPENAI_GPT,
    "gpt-4-turbo": ModelFamily.OPENAI_GPT,
    "gpt-4": ModelFamily.OPENAI_GPT,
    "gpt-4.1": ModelFamily.OPENAI_GPT,
    "gpt-4.5": ModelFamily.OPENAI_GPT,
    "o1": ModelFamily.OPENAI_GPT,
    "o1-mini": ModelFamily.OPENAI_GPT,
    "o1-pro": ModelFamily.OPENAI_GPT,
    "o3": ModelFamily.OPENAI_GPT,
    "o3-mini": ModelFamily.OPENAI_GPT,
    "o4-mini": ModelFamily.OPENAI_GPT,
    "codex": ModelFamily.OPENAI_GPT,
    "copilot": ModelFamily.OPENAI_GPT,
    # Google
    "gemini-2.5-pro": ModelFamily.GOOGLE_GEMINI,
    "gemini-2.5-flash": ModelFamily.GOOGLE_GEMINI,
    "gemini-2.0-pro": ModelFamily.GOOGLE_GEMINI,
    "gemini-2.0-flash": ModelFamily.GOOGLE_GEMINI,
    "gemini-1.5-pro": ModelFamily.GOOGLE_GEMINI,
    "gemini-1.5-flash": ModelFamily.GOOGLE_GEMINI,
    "gemma-2": ModelFamily.GOOGLE_GEMINI,
    # Meta
    "llama-4-maverick": ModelFamily.META_LLAMA,
    "llama-4-scout": ModelFamily.META_LLAMA,
    "llama-3.3": ModelFamily.META_LLAMA,
    "llama-3.1": ModelFamily.META_LLAMA,
    "llama-3": ModelFamily.META_LLAMA,
    "codellama": ModelFamily.META_LLAMA,
    # Mistral
    "mistral-large": ModelFamily.MISTRAL,
    "mistral-medium": ModelFamily.MISTRAL,
    "mistral-small": ModelFamily.MISTRAL,
    "mistral-nemo": ModelFamily.MISTRAL,
    "mixtral": ModelFamily.MISTRAL,
    "codestral": ModelFamily.MISTRAL,
    # DeepSeek
    "deepseek-r1": ModelFamily.DEEPSEEK,
    "deepseek-r1-lite": ModelFamily.DEEPSEEK,
    "deepseek-v3": ModelFamily.DEEPSEEK,
    "deepseek-coder": ModelFamily.DEEPSEEK,
    # Cohere
    "command-r-plus": ModelFamily.COHERE,
    "command-r": ModelFamily.COHERE,
    # Alibaba
    "qwen-2.5": ModelFamily.ALIBABA_QWEN,
    "qwen-2.5-coder": ModelFamily.ALIBABA_QWEN,
    "qwen-coder": ModelFamily.ALIBABA_QWEN,
}

# Map IDE/tool names to their underlying model families
TOOL_MODEL_MAP: dict[str, ModelFamily] = {
    "claude-code": ModelFamily.ANTHROPIC_CLAUDE,
    "github-copilot": ModelFamily.OPENAI_GPT,
    "cursor-default": ModelFamily.OPENAI_GPT,  # Cursor defaults to GPT-4/Claude depending on config
    "cursor-claude": ModelFamily.ANTHROPIC_CLAUDE,
    "codex-cli": ModelFamily.OPENAI_GPT,
    "amazon-q": ModelFamily.ANTHROPIC_CLAUDE,  # Amazon Q uses Claude under the hood
    "codewhisperer": ModelFamily.ANTHROPIC_CLAUDE,
    "windsurf": ModelFamily.ANTHROPIC_CLAUDE,
    "gemini-code-assist": ModelFamily.GOOGLE_GEMINI,
    "tabnine": ModelFamily.UNKNOWN,  # Uses multiple backends (OpenAI, custom models)
    "supermaven": ModelFamily.UNKNOWN,  # Configurable backend
    "cody": ModelFamily.ANTHROPIC_CLAUDE,  # Sourcegraph Cody uses Claude
    "continue": ModelFamily.UNKNOWN,  # Configurable backend
    "aider": ModelFamily.UNKNOWN,  # Configurable backend
}


def resolve_model_family(model_id: str) -> ModelFamily:
    """
    Resolve a model identifier to its family.
    Handles partial matches and case variations (e.g., "Claude-Opus-4-6").
    """
    model_id_lower = model_id.lower().strip()

    # Sanitize: limit length to prevent ReDoS or memory issues
    if len(model_id_lower) > 256:
        return ModelFamily.UNKNOWN

    # Direct match
    if model_id_lower in MODEL_FAMILY_MAP:
        return MODEL_FAMILY_MAP[model_id_lower]

    # Tool name match
    if model_id_lower in TOOL_MODEL_MAP:
        return TOOL_MODEL_MAP[model_id_lower]

    # Normalize: replace underscores and hyphens for better matching
    model_normalized = model_id_lower.replace("_", "-")

    # Partial / prefix match with normalization
    for key, family in MODEL_FAMILY_MAP.items():
        key_normalized = key.replace("_", "-")
        if key_normalized in model_normalized or model_normalized in key_normalized:
            return family

    # Fine-tune detection: "ft:gpt-4o:org:custom" → still OpenAI
    if model_id_lower.startswith("ft:"):
        base = model_id_lower.split(":")[1] if ":" in model_id_lower else ""
        return resolve_model_family(base)

    return ModelFamily.UNKNOWN


# ============================================================
# PHASE 2: SoD Detection Engine
# ============================================================

class SoDVerdict(Enum):
    ENFORCED = "ENFORCED"
    VIOLATED = "VIOLATED"
    WARNING = "WARNING"  # Same family but different provider config
    UNKNOWN = "UNKNOWN"  # Could not determine one or both models


@dataclass
class SoDCheck:
    """Result of a Separation of Duties check."""
    generation_model: str
    generation_family: ModelFamily
    generation_provider: str
    review_model: str
    review_family: ModelFamily
    review_provider: str
    verdict: SoDVerdict
    method: str  # "multi-provider", "multi-family", "same-entity", etc.
    reasons: list[str] = field(default_factory=list)
    timestamp: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

    def to_dict(self) -> dict:
        d = asdict(self)
        d["generation_family"] = self.generation_family.value
        d["review_family"] = self.review_family.value
        d["verdict"] = self.verdict.value
        return d


def get_provider(family: ModelFamily) -> str:
    """Map family to provider name."""
    mapping = {
        ModelFamily.ANTHROPIC_CLAUDE: "anthropic",
        ModelFamily.OPENAI_GPT: "openai",
        ModelFamily.GOOGLE_GEMINI: "google-deepmind",
        ModelFamily.META_LLAMA: "meta",
        ModelFamily.MISTRAL: "mistral-ai",
        ModelFamily.DEEPSEEK: "deepseek",
        ModelFamily.COHERE: "cohere",
        ModelFamily.ALIBABA_QWEN: "alibaba-cloud",
        ModelFamily.UNKNOWN: "unknown",
    }
    return mapping.get(family, "unknown")


def check_sod(gen_model: str, review_model: str) -> SoDCheck:
    """
    Phase 2: Compare generation and review entities.
    Returns a full SoD assessment.
    """
    gen_family = resolve_model_family(gen_model)
    rev_family = resolve_model_family(review_model)
    gen_provider = get_provider(gen_family)
    rev_provider = get_provider(rev_family)
    reasons = []

    # Check 1: Unknown models
    if gen_family == ModelFamily.UNKNOWN or rev_family == ModelFamily.UNKNOWN:
        reasons.append("Could not resolve one or both model families")
        return SoDCheck(
            generation_model=gen_model,
            generation_family=gen_family,
            generation_provider=gen_provider,
            review_model=review_model,
            review_family=rev_family,
            review_provider=rev_provider,
            verdict=SoDVerdict.UNKNOWN,
            method="unresolved",
            reasons=reasons,
        )

    # Check 2: Exact same model
    if gen_model.lower().strip() == review_model.lower().strip():
        reasons.append(f"Identical model used for generation and review: {gen_model}")
        reasons.append("This is a direct SoD violation — self-review detected")
        return SoDCheck(
            generation_model=gen_model,
            generation_family=gen_family,
            generation_provider=gen_provider,
            review_model=review_model,
            review_family=rev_family,
            review_provider=rev_provider,
            verdict=SoDVerdict.VIOLATED,
            method="same-model",
            reasons=reasons,
        )

    # Check 3: Same family (e.g., Claude Opus generates, Claude Sonnet reviews)
    if gen_family == rev_family:
        reasons.append(f"Same model family: {gen_family.value}")
        reasons.append("Models share training lineage, architecture, and potential blind spots")
        reasons.append("Different prompt or version does NOT constitute separation")
        return SoDCheck(
            generation_model=gen_model,
            generation_family=gen_family,
            generation_provider=gen_provider,
            review_model=review_model,
            review_family=rev_family,
            review_provider=rev_provider,
            verdict=SoDVerdict.VIOLATED,
            method="same-family",
            reasons=reasons,
        )

    # Check 4: Same provider, different family (edge case — currently unlikely)
    if gen_provider == rev_provider:
        reasons.append(f"Different families but same provider: {gen_provider}")
        reasons.append("Independence is partial — provider-level biases may overlap")
        return SoDCheck(
            generation_model=gen_model,
            generation_family=gen_family,
            generation_provider=gen_provider,
            review_model=review_model,
            review_family=rev_family,
            review_provider=rev_provider,
            verdict=SoDVerdict.WARNING,
            method="same-provider",
            reasons=reasons,
        )

    # Check 5: Different provider, different family — SoD enforced
    reasons.append(f"Generation: {gen_family.value} ({gen_provider})")
    reasons.append(f"Review: {rev_family.value} ({rev_provider})")
    reasons.append("Independent training lineage confirmed")
    reasons.append("Different architectural biases and failure modes")
    return SoDCheck(
        generation_model=gen_model,
        generation_family=gen_family,
        generation_provider=gen_provider,
        review_model=review_model,
        review_family=rev_family,
        review_provider=rev_provider,
        verdict=SoDVerdict.ENFORCED,
        method="multi-provider",
        reasons=reasons,
    )


# ============================================================
# PHASE 3: Git Integration — Scan for SoD in commit history
# ============================================================

# Pattern to detect AI-generation markers in commit messages or code comments
AI_GEN_PATTERNS = [
    r"generated by (claude|gpt|gemini|copilot|cursor|codex|llama|deepseek|mistral)",
    r"ai-generated",
    r"llm-generated",
    r"model:\s*(claude|gpt|gemini|copilot|codex)",
    r"Co-authored-by:.*\b(claude|copilot|cursor)\b",
    r"# Generated by AI",
    r"// AI-assisted",
]


def scan_git_log(repo_path: str = ".", max_commits: int = 50) -> list[dict]:
    """Scan recent git commits for AI-generation markers."""
    results = []
    try:
        log_output = subprocess.check_output(
            ["git", "log", f"--max-count={max_commits}", "--format=%H|||%s|||%b|||%an|||%ai"],
            cwd=repo_path,
            text=True,
            stderr=subprocess.DEVNULL,
        )
    except (subprocess.CalledProcessError, FileNotFoundError):
        return results

    for line in log_output.strip().split("\n"):
        if not line.strip():
            continue
        parts = line.split("|||")
        if len(parts) < 5:
            continue
        commit_hash, subject, body, author, date = parts[0], parts[1], parts[2], parts[3], parts[4]
        full_msg = f"{subject} {body}".lower()

        for pattern in AI_GEN_PATTERNS:
            match = re.search(pattern, full_msg, re.IGNORECASE)
            if match:
                results.append({
                    "commit": commit_hash[:8],
                    "date": date,
                    "author": author,
                    "subject": subject.strip(),
                    "ai_indicator": match.group(0),
                    "needs_sod_review": True,
                })
                break

    return results


# ============================================================
# PHASE 4: Audit Record Generation
# ============================================================

COMPLIANCE_MAPPINGS = {
    "NIST SP 800-53 AC-5": "Separation of Duties",
    "ISO 27001 A.5.3": "Segregation of Duties",
    "SOX Section 404": "Internal Controls — Segregation",
    "PCI-DSS 6.3": "Secure Development — Code Review",
    "NIST SSDF PW.7": "Review and/or Analyze Code for Vulnerabilities",
    "OWASP LLM Top 10": "LLM08 — Excessive Agency",
    "SOC 2 CC6.1": "Logical Access — Segregation of Duties",
}


@dataclass
class AuditRecord:
    """Complete audit record for an SoD assessment."""
    sod_check: SoDCheck
    code_hash: Optional[str] = None
    file_path: Optional[str] = None
    commit_hash: Optional[str] = None
    compliance_mappings: dict = field(default_factory=lambda: COMPLIANCE_MAPPINGS)
    deterministic_tools: list[str] = field(default_factory=list)
    review_timestamp: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

    def to_dict(self) -> dict:
        return {
            "audit_version": "1.0",
            "sod_assessment": self.sod_check.to_dict(),
            "artifact": {
                "code_hash": self.code_hash,
                "file_path": self.file_path,
                "commit_hash": self.commit_hash,
            },
            "deterministic_validation": self.deterministic_tools,
            "compliance_framework_coverage": self.compliance_mappings,
            "review_timestamp": self.review_timestamp,
        }

    def to_json(self, indent: int = 2) -> str:
        return json.dumps(self.to_dict(), indent=indent)


def compute_code_hash(file_path: str) -> str:
    """SHA-256 hash of a source file."""
    with open(file_path, "rb") as f:
        return hashlib.sha256(f.read()).hexdigest()


# ============================================================
# CLI Interface
# ============================================================

def print_verdict(check: SoDCheck, as_json: bool = False):
    """Pretty-print an SoD verdict to terminal, or output as JSON if as_json=True."""
    if as_json:
        print(json.dumps(check.to_dict(), indent=2))
        return

    icons = {
        SoDVerdict.ENFORCED: "✅",
        SoDVerdict.VIOLATED: "❌",
        SoDVerdict.WARNING: "⚠️",
        SoDVerdict.UNKNOWN: "❓",
    }
    colors = {
        SoDVerdict.ENFORCED: "\033[92m",
        SoDVerdict.VIOLATED: "\033[91m",
        SoDVerdict.WARNING: "\033[93m",
        SoDVerdict.UNKNOWN: "\033[90m",
    }
    reset = "\033[0m"
    c = colors[check.verdict]

    print(f"\n{'='*60}")
    print(f"  SoD Assessment — {icons[check.verdict]} {c}{check.verdict.value}{reset}")
    print(f"{'='*60}")
    print(f"  Generation : {check.generation_model} ({check.generation_family.value})")
    print(f"  Review     : {check.review_model} ({check.review_family.value})")
    print(f"  Method     : {check.method}")
    print(f"  Timestamp  : {check.timestamp}")
    print(f"{'─'*60}")
    for reason in check.reasons:
        print(f"  → {reason}")
    print(f"{'='*60}\n")


def scan_file_for_metadata(file_path: str) -> dict:
    """
    Scan a source file for AI generation metadata comments.
    Returns a dict with detected model family and metadata.

    WARNING: Metadata tags are assertions, not cryptographic proof. They can be
    forged by malicious actors. Always cross-reference with external audit records
    (CI/CD logs, signed commits) before making compliance decisions.
    """
    try:
        content = Path(file_path).read_text()
    except Exception as e:
        return {
            "file": file_path,
            "detected": False,
            "error": str(e),
        }

    # Search for generation metadata patterns
    result = {
        "file": file_path,
        "detected": False,
        "model_family": None,
        "metadata": [],
    }

    metadata_patterns = [
        (r"@trendCodeSecurity\s+generatedBy\s*[:=]\s*(\S+)", "provenance_tag"),
        (r"generated\s+by\s+(\w+[\w\-]*)", "comment"),
        (r"ai-generated-by:\s*(\S+)", "marker"),
        (r"model:\s*(\S+)", "marker"),
        (r"@generatedBy\s+(\S+)", "tag"),
    ]

    for pattern, pattern_type in metadata_patterns:
        matches = re.finditer(pattern, content, re.IGNORECASE)
        for match in matches:
            model_str = match.group(1)
            family = resolve_model_family(model_str)
            result["metadata"].append({
                "pattern_type": pattern_type,
                "matched_model": model_str,
                "resolved_family": family.value,
            })
            if family != ModelFamily.UNKNOWN and not result["detected"]:
                result["detected"] = True
                result["model_family"] = family.value

    return result


def main():
    parser = argparse.ArgumentParser(
        description="SoD Detection Engine for AI-Generated Code",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Check SoD between two models
  python sod_detect.py check --gen-model claude-opus-4-6 --review-model gpt-4o

  # Check with file hash and output JSON
  python sod_detect.py check --gen-model claude-sonnet-4-5 --review-model mistral-large \\
    --file main.py --output audit.json

  # Scan git log for AI-generated code markers
  python sod_detect.py scan --repo-path . --max-commits 100

  # Validate if a file contains AI metadata
  python sod_detect.py validate --file generated_code.py

  # List all known models grouped by family
  python sod_detect.py registry

  # Check SoD with JSON output for CI/CD piping
  python sod_detect.py check --gen-model claude-4 --review-model gpt-4.5 --json

  # Strict mode: treat WARNINGs as violations
  python sod_detect.py check --gen-model claude-3-opus --review-model gpt-4 --strict
        """,
    )
    sub = parser.add_subparsers(dest="command")

    # Check command
    chk = sub.add_parser("check", help="Check SoD between generation and review models")
    chk.add_argument("--gen-model", required=True, help="Model used for code generation")
    chk.add_argument("--review-model", required=True, help="Model used for code review")
    chk.add_argument("--file", help="Source file to include in audit (computes hash)")
    chk.add_argument("--commit", help="Git commit hash to include in audit")
    chk.add_argument("--tools", nargs="*", default=[], help="Deterministic tools used (e.g., semgrep sonarqube)")
    chk.add_argument("--output", help="Write JSON audit record to file")
    chk.add_argument("--json", action="store_true", help="Output JSON only (no pretty-print), useful for CI/CD")
    chk.add_argument("--strict", action="store_true", help="Treat WARNING as VIOLATED (exit code 1)")

    # Scan command
    scn = sub.add_parser("scan", help="Scan git log for AI-generated code markers")
    scn.add_argument("--repo-path", default=".", help="Path to git repository")
    scn.add_argument("--max-commits", type=int, default=50, help="Number of commits to scan")

    # Validate command
    val = sub.add_parser("validate", help="Check if a file contains AI generation metadata")
    val.add_argument("--file", required=True, help="Source file to scan for metadata")
    val.add_argument("--json", action="store_true", help="Output JSON only")

    # Registry command
    reg = sub.add_parser("registry", help="List known model families and their members")

    args = parser.parse_args()

    if args.command == "check":
        result = check_sod(args.gen_model, args.review_model)
        print_verdict(result, as_json=args.json)

        # Build audit record
        code_hash = compute_code_hash(args.file) if args.file else None
        audit = AuditRecord(
            sod_check=result,
            code_hash=code_hash,
            file_path=args.file,
            commit_hash=args.commit,
            deterministic_tools=args.tools,
        )

        if args.output and not args.json:
            Path(args.output).write_text(audit.to_json())
            print(f"  Audit record written to: {args.output}")
        elif not args.json:
            print("  Audit Record (JSON):")
            print(audit.to_json())

        # Exit code: 0 = enforced, 1 = violated, 2 = warning, 3 = unknown
        exit_codes = {
            SoDVerdict.ENFORCED: 0,
            SoDVerdict.VIOLATED: 1,
            SoDVerdict.WARNING: 2 if not args.strict else 1,
            SoDVerdict.UNKNOWN: 3,
        }
        sys.exit(exit_codes[result.verdict])

    elif args.command == "scan":
        findings = scan_git_log(args.repo_path, args.max_commits)
        if not findings:
            print("No AI-generation markers found in recent commits.")
            return
        print(f"\nFound {len(findings)} commits with AI-generation markers:\n")
        for f in findings:
            print(f"  {f['commit']}  {f['date'][:10]}  {f['ai_indicator']}")
            print(f"           └─ {f['subject'][:70]}")
        print(f"\n  These commits require SoD verification against the reviewing model.\n")

    elif args.command == "validate":
        result = scan_file_for_metadata(args.file)
        if args.json:
            print(json.dumps(result, indent=2))
        else:
            print(f"\nValidating: {args.file}\n")
            if result.get("error"):
                print(f"  Error: {result['error']}")
            elif result["detected"]:
                print(f"  ✓ AI generation metadata detected")
                print(f"  Detected model family: {result['model_family']}")
                if result["metadata"]:
                    print(f"  Metadata found:")
                    for meta in result["metadata"]:
                        print(f"    - Type: {meta['pattern_type']}")
                        print(f"      Model: {meta['matched_model']}")
                        print(f"      Family: {meta['resolved_family']}")
            else:
                print(f"  No AI generation metadata detected in this file.")
            print()

    elif args.command == "registry":
        print("\nKnown Model Families:\n")
        by_family: dict[str, list[str]] = {}
        for model, family in sorted(MODEL_FAMILY_MAP.items()):
            by_family.setdefault(family.value, []).append(model)
        for family, models in sorted(by_family.items()):
            print(f"  {family}")
            for m in models:
                print(f"    └─ {m}")
        print()

    else:
        parser.print_help()


if __name__ == "__main__":
    main()
