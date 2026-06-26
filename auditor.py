"""
auditor.py - Core Smart Contract Audit Engine
Handles all Gemini API interaction and audit logic.
"""

import os
import json
import re
import time
from dataclasses import dataclass, field, asdict
from typing import Optional
from dotenv import load_dotenv
import google.generativeai as genai

load_dotenv()

# ---------------------------------------------------------------------------
# Data Models
# ---------------------------------------------------------------------------

SEVERITY_ORDER = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]
SEVERITY_WEIGHTS = {"CRITICAL": 10, "HIGH": 7, "MEDIUM": 4, "LOW": 2, "INFO": 0}


@dataclass
class Finding:
    vulnerability_name: str
    severity: str           # CRITICAL / HIGH / MEDIUM / LOW / INFO
    line_reference: str     # e.g. "Line 34" or "Lines 34-40" or "withdraw()"
    explanation: str
    recommendation: str

    def severity_weight(self) -> int:
        return SEVERITY_WEIGHTS.get(self.severity.upper(), 0)


@dataclass
class AuditReport:
    contract_name: str
    findings: list[Finding] = field(default_factory=list)
    overall_risk_score: float = 0.0      # 0–100
    overall_risk_label: str = "SAFE"
    summary: str = ""
    audit_timestamp: str = ""
    raw_response: str = ""               # stored for debugging
    error: Optional[str] = None

    def to_dict(self) -> dict:
        d = asdict(self)
        d.pop("raw_response", None)      # exclude raw dump from export
        return d

    def severity_counts(self) -> dict:
        counts = {s: 0 for s in SEVERITY_ORDER}
        for f in self.findings:
            sev = f.severity.upper()
            if sev in counts:
                counts[sev] += 1
        return counts


# ---------------------------------------------------------------------------
# Prompt Engineering
# ---------------------------------------------------------------------------

AUDIT_SYSTEM_PROMPT = """You are a senior smart contract security auditor with 10+ years of experience
auditing Solidity contracts for DeFi protocols, NFT platforms, and DAOs.

You specialize in identifying:
- Reentrancy vulnerabilities (single and cross-function)
- Integer overflow/underflow (especially in older Solidity versions)
- Access control flaws (missing modifiers, tx.origin misuse)
- Unprotected selfdestruct and delegatecall
- Flash loan attack vectors
- Front-running opportunities
- Denial of service vulnerabilities
- Improper event emission
- Gas griefing and unbounded loops
- Oracle manipulation risks

Your job is to produce structured, accurate, and actionable audit reports."""


def build_audit_prompt(contract_code: str) -> str:
    return f"""Audit the following Solidity smart contract for security vulnerabilities.

STRICT OUTPUT FORMAT:
- Respond ONLY with valid JSON
- Do NOT include markdown code fences, backticks, or any text outside the JSON
- Every field in the schema is required

JSON Schema:
{{
  "contract_name": "string (infer from code or use 'UnnamedContract')",
  "summary": "string (2-3 sentence executive summary of the contract's purpose and overall risk)",
  "findings": [
    {{
      "vulnerability_name": "string (specific name, e.g. 'Reentrancy in withdraw()')",
      "severity": "string (exactly one of: CRITICAL, HIGH, MEDIUM, LOW, INFO)",
      "line_reference": "string (e.g. 'Line 34', 'Lines 34-40', or 'withdraw() function')",
      "explanation": "string (clear explanation of the vulnerability and how it can be exploited)",
      "recommendation": "string (specific, actionable fix with code guidance where possible)"
    }}
  ]
}}

Severity guidelines:
- CRITICAL: Can lead to complete loss of funds or contract control
- HIGH: Significant risk, likely exploitable with moderate effort
- MEDIUM: Risk exists but requires specific conditions or partial trust
- LOW: Minor issue, best practice violation, unlikely to be exploited
- INFO: Informational note, gas optimization, or code quality issue

If the contract has NO vulnerabilities, return an empty findings array and explain that in the summary.
Do not invent vulnerabilities. Only report what you can clearly identify in the code.

CONTRACT TO AUDIT:
```solidity
{contract_code}
```"""


# ---------------------------------------------------------------------------
# JSON Parsing with Fallback
# ---------------------------------------------------------------------------

def _strip_fences(text: str) -> str:
    """Remove markdown code fences that Gemini sometimes adds."""
    text = text.strip()
    # Remove ```json ... ``` or ``` ... ```
    text = re.sub(r"^```(?:json)?\s*", "", text)
    text = re.sub(r"\s*```$", "", text)
    return text.strip()


def _parse_findings_from_text(raw: str) -> list[Finding]:
    """
    Emergency fallback: if JSON parsing completely fails, try to extract
    findings from plain text using pattern matching.
    """
    findings = []
    severity_pattern = re.compile(
        r"(CRITICAL|HIGH|MEDIUM|LOW|INFO)", re.IGNORECASE
    )

    # Split on numbered items or bullet points
    chunks = re.split(r"\n(?:\d+[\.\)]\s+|\-\s+|\*\s+)", raw)

    for chunk in chunks[1:]:  # skip first chunk (likely preamble)
        sev_match = severity_pattern.search(chunk)
        severity = sev_match.group(1).upper() if sev_match else "INFO"

        # Extract first line as vulnerability name
        lines = [l.strip() for l in chunk.split("\n") if l.strip()]
        name = lines[0][:80] if lines else "Unidentified Issue"
        explanation = " ".join(lines[1:3]) if len(lines) > 1 else chunk[:200]

        findings.append(Finding(
            vulnerability_name=name,
            severity=severity,
            line_reference="See contract",
            explanation=explanation,
            recommendation="Review the flagged section and consult Solidity security best practices."
        ))

    return findings[:10]  # cap at 10 to avoid noise


def parse_gemini_response(raw_text: str) -> tuple[list[Finding], str, str]:
    """
    Parse Gemini's response into (findings, summary, contract_name).
    Attempts JSON parse first, falls back to text extraction.
    Returns (findings, summary, contract_name).
    """
    # Attempt 1: Direct JSON parse
    try:
        data = json.loads(raw_text)
        return _extract_from_json(data)
    except json.JSONDecodeError:
        pass

    # Attempt 2: Strip markdown fences and retry
    try:
        cleaned = _strip_fences(raw_text)
        data = json.loads(cleaned)
        return _extract_from_json(data)
    except json.JSONDecodeError:
        pass

    # Attempt 3: Find JSON object within the text
    try:
        json_match = re.search(r"\{.*\}", raw_text, re.DOTALL)
        if json_match:
            data = json.loads(json_match.group())
            return _extract_from_json(data)
    except (json.JSONDecodeError, AttributeError):
        pass

    # Fallback: Extract from plain text
    findings = _parse_findings_from_text(raw_text)
    return (
        findings,
        "Note: Response could not be fully parsed as JSON. Findings extracted from text.",
        "UnnamedContract"
    )


def _extract_from_json(data: dict) -> tuple[list[Finding], str, str]:
    """Extract findings from a parsed JSON dict."""
    findings = []
    raw_findings = data.get("findings", [])

    for item in raw_findings:
        # Validate and normalise severity
        sev = str(item.get("severity", "INFO")).upper().strip()
        if sev not in SEVERITY_ORDER:
            sev = "INFO"

        findings.append(Finding(
            vulnerability_name=str(item.get("vulnerability_name", "Unnamed Issue")),
            severity=sev,
            line_reference=str(item.get("line_reference", "Unknown")),
            explanation=str(item.get("explanation", "No explanation provided.")),
            recommendation=str(item.get("recommendation", "No recommendation provided."))
        ))

    summary = str(data.get("summary", "No summary provided."))
    contract_name = str(data.get("contract_name", "UnnamedContract"))
    return findings, summary, contract_name


# ---------------------------------------------------------------------------
# Risk Scoring
# ---------------------------------------------------------------------------

def compute_risk_score(findings: list[Finding]) -> tuple[float, str]:
    """
    Returns (score 0–100, label).
    Score is weighted by severity counts with diminishing returns per category.
    """
    if not findings:
        return 0.0, "SAFE"

    total = 0.0
    counts = {s: 0 for s in SEVERITY_ORDER}
    for f in findings:
        counts[f.severity.upper()] += 1

    # Diminishing returns: first finding counts fully, each additional = 50%
    for sev, weight in SEVERITY_WEIGHTS.items():
        count = counts[sev]
        if count == 0:
            continue
        total += weight * (1 + 0.5 * (count - 1))

    # Normalise to 0–100 (max theoretical: 4 CRITICAL + many HIGH)
    score = min(100.0, (total / 60.0) * 100)

    if score >= 70:
        label = "CRITICAL RISK"
    elif score >= 45:
        label = "HIGH RISK"
    elif score >= 25:
        label = "MEDIUM RISK"
    elif score >= 10:
        label = "LOW RISK"
    else:
        label = "SAFE"

    return round(score, 1), label


# ---------------------------------------------------------------------------
# Main Audit Function
# ---------------------------------------------------------------------------

def audit_contract(contract_code: str, retries: int = 2) -> AuditReport:
    """
    Submit a Solidity contract for AI audit.
    Returns an AuditReport dataclass.
    Handles API errors, rate limits, and malformed responses.
    """
    from datetime import datetime

    api_key = os.getenv("GEMINI_API_KEY", "").strip()
    if not api_key or api_key == "your_gemini_api_key_here":
        report = AuditReport(contract_name="Error")
        report.error = (
            "GEMINI_API_KEY not set. Please add your API key to the .env file.\n"
            "Get a free key at: https://aistudio.google.com/app/apikey"
        )
        return report

    genai.configure(api_key=api_key)
    model = genai.GenerativeModel(
        model_name="gemini-2.0-flash",
        system_instruction=AUDIT_SYSTEM_PROMPT
    )

    prompt = build_audit_prompt(contract_code)
    raw_text = ""
    last_error = ""

    for attempt in range(retries + 1):
        try:
            response = model.generate_content(
                prompt,
                generation_config=genai.GenerationConfig(
                    temperature=0.1,       # low temp for deterministic analysis
                    max_output_tokens=4096,
                )
            )
            raw_text = response.text
            break

        except Exception as e:
            last_error = str(e)
            if "429" in last_error or "quota" in last_error.lower():
                if attempt < retries:
                    time.sleep(5 * (attempt + 1))
                    continue
                report = AuditReport(contract_name="Error")
                report.error = (
                    "Rate limit reached. You have exceeded the free tier quota.\n"
                    "Wait a minute and try again. Free tier: 1,500 requests/day."
                )
                return report
            elif "API_KEY_INVALID" in last_error or "api key" in last_error.lower():
                report = AuditReport(contract_name="Error")
                report.error = (
                    "Invalid API key. Please check your GEMINI_API_KEY in the .env file.\n"
                    "Get a free key at: https://aistudio.google.com/app/apikey"
                )
                return report
            else:
                if attempt < retries:
                    time.sleep(3)
                    continue
                report = AuditReport(contract_name="Error")
                report.error = f"Gemini API error: {last_error}"
                return report

    if not raw_text:
        report = AuditReport(contract_name="Error")
        report.error = f"No response from Gemini after {retries + 1} attempts. Last error: {last_error}"
        return report

    # Parse response
    findings, summary, contract_name = parse_gemini_response(raw_text)
    score, label = compute_risk_score(findings)

    # Sort findings by severity
    findings.sort(key=lambda f: SEVERITY_ORDER.index(f.severity.upper())
                  if f.severity.upper() in SEVERITY_ORDER else 99)

    report = AuditReport(
        contract_name=contract_name,
        findings=findings,
        overall_risk_score=score,
        overall_risk_label=label,
        summary=summary,
        audit_timestamp=datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        raw_response=raw_text
    )
    return report
