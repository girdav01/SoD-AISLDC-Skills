# SoD Code Security Skills
## Separation of Duties Enforcement for AI-Generated Code

> **The entity that generates code must not be the entity that certifies its security.**
> — NIST SP 800-53 AC-5 / ISO 27001 A.5.3

© 2026 David Girard. Released under MIT License.

---

## What This Is

These are drop-in rules, skills, and tooling that enforce Separation of Duties (SoD) across AI coding assistants and CI/CD pipelines. The package implements a four-phase enforcement architecture:

1. **Generation Metadata Capture** — AI assistants tag generated code with provenance data (model ID, family, provider, timestamp, code hash)
2. **SoD Detection Engine** — Extract lineage and compare generation/review entities; block self-review violations
3. **Independent Security Review** — Different LLM family conducts review alongside deterministic tools (SAST/SCA)
4. **Audit Trail & Compliance Evidence** — Immutable record proving generator ≠ reviewer, mapped to regulatory frameworks

This toolkit is framework-agnostic and works with any LLM-based coding tool: Claude Code, Cursor, ChatGPT, GitHub Copilot, Amazon Q, or custom models. It integrates seamlessly into GitHub Actions, GitLab CI, Jenkins, and local development workflows.

---

## Architecture — Four Phases

```
┌─────────────────────────────────────────────────────────┐
│ PHASE 1: Generation Metadata Capture                    │
│ AI assistant tags every generated file with model_id,   │
│ model_family, provider, timestamp, code_hash            │
├─────────────────────────────────────────────────────────┤
│ PHASE 2: SoD Detection Engine                           │
│ Extract lineage → Compare entities → Decision:          │
│   Same entity? → VIOLATION (block/warn per policy)      │
│   Different entity? → PASS (proceed to review)          │
├─────────────────────────────────────────────────────────┤
│ PHASE 3: Independent Security Review                    │
│ Different LLM family + SAST/SCA/DAST + threat intel     │
│ + policy checks (secrets, IaC, license, compliance)     │
├─────────────────────────────────────────────────────────┤
│ PHASE 4: Audit Trail & Compliance Evidence              │
│ Immutable record: gen model ≠ review model              │
│ Mapped to NIST AC-5, ISO 27001, SOX, PCI-DSS, SOC 2    │
└─────────────────────────────────────────────────────────┘
```

---

## Repository Structure

```
sod-skills/
├── README.md                          # This file
├── claude-code/
│   └── SKILL.md                       # Claude Code skill (auto-triggers)
├── cursor/
│   ├── .cursorrules                   # Legacy format (Cursor < 0.45 compat)
│   └── .cursor/
│       └── rules/                     # Modern Cursor 3 .mdc rules
│           ├── sod-core.mdc           # Core SoD principles (always active)
│           ├── sod-metadata.mdc       # Generation metadata tagging (file-glob)
│           ├── sod-cursor3-agents.mdc # Agent & Background Agent SoD rules
│           ├── sod-detection.mdc      # Detection logic & response procedures
│           └── sod-detect-cli.mdc     # sod_detect.py CLI integration guide
├── codex/
│   └── CODEX.md                       # OpenAI Codex/ChatGPT system instructions
├── ci-cd/
│   └── github-actions-sod.yml         # GitHub Actions + GitLab CI examples
├── scripts/
│   └── sod_detect.py                  # Python detection engine (zero deps)
└── tests/
    ├── test_sod_detect.py             # Automated pytest suite (141 tests)
    ├── MANUAL_TEST_SCENARIOS.md        # Manual test procedures
    └── requirements-test.txt           # Test dependencies
```

---

## Installation

### Prerequisites
- Python 3.10+ (for sod_detect.py — no external dependencies)
- Git (for commit scanning features)

### Claude Code

```bash
# Option A: Copy to your project's .claude/skills/ directory
mkdir -p .claude/skills/sod-code-security
cp claude-code/SKILL.md .claude/skills/sod-code-security/SKILL.md

# Option B: Symlink for easy updates
ln -s /path/to/sod-skills/claude-code/SKILL.md .claude/skills/sod-code-security/SKILL.md

# The skill auto-triggers when Claude detects security review requests
```

### Cursor IDE

**Cursor 3 / 0.45+ (Recommended — Modern .mdc Rules):**

```bash
# Copy the .cursor/rules/ directory to your project root
mkdir -p /path/to/your-project/.cursor/rules
cp cursor/.cursor/rules/*.mdc /path/to/your-project/.cursor/rules/

# Rules auto-load based on their frontmatter:
#   sod-core.mdc        → alwaysApply: true (always in context)
#   sod-metadata.mdc     → globs: **/*.{py,js,ts,...} (auto-attach on code files)
#   sod-cursor3-agents.mdc → agent-triggered (when using Agent/Background Agents)
#   sod-detection.mdc    → agent-triggered (when doing security reviews)
#   sod-detect-cli.mdc   → agent-triggered (when running CLI commands)

# Commit to git so your team inherits the rules
git add .cursor/rules/
git commit -m "Add SoD enforcement rules for Cursor"
```

**Cursor < 0.45 (Legacy .cursorrules):**

```bash
# Copy to your project root (Cursor reads .cursorrules automatically)
cp cursor/.cursorrules /path/to/your-project/.cursorrules
```

### OpenAI Codex CLI / ChatGPT Custom GPT

```bash
# Option A: Add as system instructions in your Custom GPT
# Copy the content of codex/CODEX.md into the GPT's system prompt

# Option B: Use with Codex CLI
# Add codex/CODEX.md to your project and reference in your codex config
```

### CI/CD Pipeline

```bash
# GitHub Actions
cp ci-cd/github-actions-sod.yml .github/workflows/sod-check.yml

# GitLab CI — merge the gitlab section from ci-cd/github-actions-sod.yml
# into your .gitlab-ci.yml

# Generic — use the Makefile targets at the bottom of the yml file
```

### Detection Script

```bash
# Copy to your project (zero dependencies — stdlib only)
cp scripts/sod_detect.py your-project/scripts/

# Verify it works
python scripts/sod_detect.py --help
python scripts/sod_detect.py registry
```

---

## Quick Start

### 1. Check Two Models for SoD Compliance

```bash
# Different providers — ENFORCED
python scripts/sod_detect.py check \
  --gen-model claude-opus-4-6 \
  --review-model gpt-4o

# ✅ ENFORCED — Anthropic (Claude) vs OpenAI (GPT) — different families

# Same provider — VIOLATED
python scripts/sod_detect.py check \
  --gen-model claude-opus-4-6 \
  --review-model claude-haiku-4-5

# ❌ VIOLATED — both Anthropic family

# Mix deterministic tools — ENFORCED
python scripts/sod_detect.py check \
  --gen-model gpt-4o \
  --review-model semgrep

# ✅ ENFORCED — LLM vs deterministic SAST tool
```

### 2. Scan Your Git History for AI-Generated Code

```bash
# Find commits with AI-generation markers
python scripts/sod_detect.py scan --repo-path . --max-commits 100

# Output: which commits were AI-generated, model family used, reviewer status
```

### 3. List All Known Models

```bash
python scripts/sod_detect.py registry

# Output: 40+ known models organized by family (Anthropic, OpenAI, Google, etc.)
```

### 4. Generate an Audit Record

```bash
python scripts/sod_detect.py check \
  --gen-model claude-opus-4-6 \
  --review-model gpt-4o \
  --file src/auth.py \
  --commit abc1234def5678 \
  --tools semgrep trivy gitleaks \
  --output audit-record.json

# Output: JSON file with SoD decision, compliance mappings, tool results
```

---

## What Each Skill Does

### Claude Code (`claude-code/SKILL.md`)

- **Auto-detects self-review** via session history and metadata
- **Flags SoD violations** when Claude is asked to review its own generated code
- **Provides remediation guidance** — recommend independent review models (GPT-4o, Gemini, Mistral)
- **Generates Phase 4 audit records** for compliant reviews (timestamped, JSON-serializable)
- **Integrates with Claude Code's skill system** — auto-triggers on security review requests
- **Zero setup required** — copy the SKILL.md file to `.claude/skills/` and it's active

### Cursor (`.cursorrules`)

- **Applies as project-level rules** for all Cursor sessions in your repo
- **Enforces metadata tagging** on all AI-generated code (model_id, timestamp, family)
- **Quick SoD self-check table** for evaluating two models in seconds
- **Guides users to independent review** tools and procedures
- **Works with any model** Cursor is configured to use (Claude, GPT, Gemini, etc.)
- **Version-controllable** — commit `.cursorrules` to git for team-wide enforcement

### Codex / ChatGPT (`codex/CODEX.md`)

- **System instructions for OpenAI-based assistants** (ChatGPT, GPT-4, Codex API)
- **Four-phase framework adapted for GPT family** — simplified language, GPT-optimized prompts
- **Decision table for common SoD scenarios** — same-family violations, multi-tool setups
- **Compatible with Custom GPTs, API system prompts, Codex CLI**
- **Auditable interaction log** — store chat history to evidence SoD compliance

### CI/CD Pipeline (`ci-cd/github-actions-sod.yml`)

- **GitHub Actions workflow with SoD gate** — blocks merge on violation
- **Phase 1: Scan commits** for AI-generation markers and metadata
- **Phase 2: Verify gen model ≠ review model** using registry
- **Phase 3: Run deterministic tools** (Semgrep for SAST, Trivy for SCA, Gitleaks for secrets)
- **Phase 4: Upload audit record** as artifact and push to Vision One (optional)
- **Includes GitLab CI equivalent** and generic shell targets

### Detection Script (`scripts/sod_detect.py`)

- **Pure Python, zero external dependencies** — runs anywhere Python 3.10+ is available
- **Model family registry** covering 40+ models: Anthropic (Claude), OpenAI (GPT), Google (Gemini), Meta (Llama), Mistral, DeepSeek, Cohere, Alibaba, and more
- **Handles fine-tuned variants, tool aliases, partial matching** — e.g., "claude" → claude-opus-4-6
- **Exit codes for CI/CD integration** — 0=enforced, 1=violated, 2=warning, 3=unknown
- **JSON audit records** with compliance framework mapping (NIST AC-5, ISO 27001, SOX, etc.)
- **Extensible model registry** — add new models by editing MODEL_FAMILY_MAP

---

## SoD Violation Examples

| Generation Model | Review Model | Verdict | Reason |
|-----------------|-------------|---------|--------|
| claude-opus-4-6 | claude-haiku-4-5 | ❌ VIOLATED | Same family (Anthropic) |
| gpt-4o | gpt-4 | ❌ VIOLATED | Same family (OpenAI) |
| gpt-4o | gpt-4o | ❌ VIOLATED | Identical model |
| mistral-large | mistral-medium | ❌ VIOLATED | Same family (Mistral) |
| copilot (claude backend) | claude-opus-4-6 | ❌ VIOLATED | IDE tool resolves to Claude |
| github-copilot (gpt backend) | gpt-4o | ❌ VIOLATED | Wrapper uses underlying model |
| claude-opus-4-6 | gpt-4o | ✅ ENFORCED | Different families (Anthropic vs OpenAI) |
| gpt-4o | gemini-2.5-pro | ✅ ENFORCED | Different families (OpenAI vs Google) |
| claude-opus-4-6 | semgrep | ✅ ENFORCED | LLM + deterministic SAST |
| any model | trivy + snyk | ✅ ENFORCED | Multiple deterministic tools |
| gpt-4o | claude-opus-4-6 + semgrep | ✅ ENFORCED | Different LLM family + deterministic tool |

---

## Compliance Framework Coverage

| Framework | Control | SoD Relevance | Status |
|-----------|---------|--------------|--------|
| NIST SP 800-53 | AC-5 | Separation of Duties | Primary control |
| ISO 27001:2022 | A.5.3 | Segregation of Duties | Annex A organizational control |
| SOX (Sarbanes-Oxley) | Section 404 | Internal Controls | Code review segregation evidence |
| PCI-DSS 4.0 | 6.3.2 | Secure Development | Code review before production |
| NIST SSDF | PW.7.2 | Code Review Process | Reviewer independence requirement |
| OWASP LLM Top 10 | LLM08 | Excessive Agency | Mitigates AI model overreach |
| SOC 2 Type II | CC6.1 | Logical Access Segregation | Duty separation in CI/CD |
| HIPAA | 164.312(a)(2)(i) | Access Controls | Code review segregation |

---

## Testing

### Automated Tests

```bash
cd sod-skills
pip install pytest

# Run all 141 tests
python -m pytest tests/test_sod_detect.py -v

# Output: ~0.3 seconds, 100% pass rate
# Tests cover: model family classification, variant detection, tool aliasing,
# SoD decision logic, audit record generation, JSON schema validation
```

### Manual Tests

See `tests/MANUAL_TEST_SCENARIOS.md` for step-by-step procedures covering all five environments:

1. **Claude Code** — Use skill in a project, trigger self-review violation
2. **Cursor IDE** — Load `.cursorrules`, verify metadata tagging and SoD table
3. **Codex/ChatGPT** — Test as Custom GPT with system instructions
4. **GitHub Actions** — Trigger workflow, verify gate blocks on violation
5. **Detection Script** — Run all CLI commands with sample diffs and repos

---

## Security Considerations

### What These Skills CAN Do

- **Detect self-review violations** when the same model family is used for both generation and review
- **Flag SoD violations** with remediation guidance (e.g., "use Gemini-2.5-Pro instead of GPT-4o")
- **Generate audit records** including timestamps, model families, tools used, compliance mappings
- **Add constraints to AI behavior** — refuse self-review, require provenance tags, enforce metadata
- **Integrate with CI/CD gates** — block merges on violation unless explicitly approved

### What These Skills CANNOT Do

- **Grant new capabilities** — the skills only remove actions (self-review), never add them
- **Execute code, access APIs, or modify files** beyond normal scope — all rules are assertion-only
- **Override safety guidelines or content policies** — no jailbreak patterns or bypass instructions
- **Provide cryptographic proof** of review independence — metadata is assertion-based, not cryptographic
- **Detect hallucinations or reasoning errors** — these are code quality issues, not SoD violations

### Prompt Injection Resistance

These skills are **RESTRICTIVE by design** — they add constraints, not capabilities. Security properties:

- **Only reduce what models can do** — refuse self-review, require tagging (constraints, not expansions)
- **No executable payloads** — zero instructions that could be repurposed for harm
- **No "ignore previous instructions" patterns** — no override or escape hatches
- **No external URL dependencies** — no fetching policies from untrusted endpoints
- **No code execution capabilities** — metadata scanning is text-pattern based only

### Metadata Trust Model

Generation metadata tags (`@generatedBy`, `model_family:` comments) are **assertions, not cryptographic proof**. Threat model and mitigations:

1. **Threat: Attacker spoofs metadata** — Claim code was generated by Claude when it was actually GPT
   - **Mitigation 1:** Cross-reference with CI/CD pipeline logs and git author history
   - **Mitigation 2:** Use signed commits (GPG/SSH) to authenticate generation events
   - **Mitigation 3:** Correlate metadata with Vision One runtime telemetry (who deployed what)

2. **Threat: Untagged code** — An attacker omits metadata to hide generator identity
   - **Mitigation:** Treat untagged AI code as unknown provenance (default: block or require review)

3. **Threat: Registry poisoning** — attacker adds fake models to sod_detect.py
   - **Mitigation:** Commit registry to git with code review; version it alongside the engine

### Known Limitations

- **Static model registry** — new models require manual addition to `sod_detect.py`. Workaround: submit PR or maintain a custom fork
- **Tool-to-model mappings may change** — e.g., "Amazon Q" backend switched from Claude to custom model in 2025. Workaround: check vendor docs, update registry
- **Endpoint verification not performed** — the script trusts the model identifier provided; it doesn't validate endpoint reachability
- **Metadata scanning uses regex patterns** — could miss obfuscated or non-standard tags. Use language-specific AST parsing for 100% coverage
- **No file integrity checking** — doesn't verify code wasn't modified after tagging. Use signed commits or Git signatures

---

## Extending the Model Registry

To add a new model or tool mapping:

### Add a Model

Edit `scripts/sod_detect.py` in the `MODEL_FAMILY_MAP` dictionary:

```python
MODEL_FAMILY_MAP = {
    # Existing entries...
    "your-new-model": ModelFamily.PROVIDER_FAMILY,
    "your-model-v2": ModelFamily.PROVIDER_FAMILY,
}
```

For example, to add Cohere's new command-r-plus model:
```python
"command-r-plus": ModelFamily.COHERE,
```

### Add an IDE or Tool Alias

If an IDE uses a model but exposes a different name, add it to `TOOL_MODEL_MAP`:

```python
TOOL_MODEL_MAP = {
    # Maps tool/IDE name to underlying model family
    "amazon-q": ModelFamily.ANTHROPIC,  # Amazon Q uses Claude backend
    "replit-ghostwriter": ModelFamily.MISTRAL,  # Replit uses Mistral
}
```

### Add a New Model Family

If your provider isn't already in the `ModelFamily` enum, add it:

```python
class ModelFamily(Enum):
    # Existing...
    ANTHROPIC = "anthropic"
    OPENAI = "openai"
    GOOGLE = "google"
    # New family:
    YOUR_PROVIDER = "your-provider"
```

Then add models to the registry using `ModelFamily.YOUR_PROVIDER`.

---

## Contributing

We welcome contributions to improve SoD enforcement across the AI coding ecosystem.

### How to Contribute

1. **Fork the repository** and create a feature branch: `git checkout -b feature/my-improvement`
2. **Add tests first** — all new features need test coverage in `tests/test_sod_detect.py`
3. **Update the registry** — if adding models or tools, update the relevant maps in `sod_detect.py`
4. **Document changes** — update this README or add a note in the commit message
5. **Run tests** — ensure all 141 tests pass: `python -m pytest tests/test_sod_detect.py -v`
6. **Submit a pull request** with clear description of what and why

### Areas We're Looking For

- **New model families** — request PR with model names and vendor confirmation
- **IDE/tool integrations** — Neovim plugins, VSCode extensions, JetBrains IDE rules
- **Language-specific rules** — Rust, Java, Go, JavaScript detection heuristics
- **Audit trail improvements** — better hash algorithms, tamper-evident storage formats
- **Compliance mapping** — additional frameworks (NIST CSF, CIS Controls, etc.)

---

## License

© 2026 David Girard. Released under MIT License for the security community.

Accompanying article: *"The Blind Spot in AI Code Security: Why the Generator Should Never Be the Reviewer"* by David Girard.
