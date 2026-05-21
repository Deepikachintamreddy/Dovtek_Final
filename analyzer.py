from dotenv import load_dotenv
load_dotenv()

import json
import os
import re
from typing import Any

import google.generativeai as genai

from fraud_rules import (
    apply_rule_validation,
    heuristic_result,
    normalize_ai_result,
    scan_message_rules,
)
from models import ScanResult
from prompts import PASS1_SYSTEM, PASS2_SYSTEM

try:
    import fitz  # PyMuPDF
except ImportError:
    fitz = None


api_key = os.environ.get("GEMINI_API_KEY") or os.environ.get("GOOGLE_API_KEY")
if api_key:
    genai.configure(api_key=api_key)

GEMINI_MODEL = os.environ.get("GEMINI_MODEL", "gemini-2.5-flash")
GEMINI_FALLBACK_MODELS = [
    GEMINI_MODEL,
    "gemini-2.0-flash",
    "gemini-1.5-flash",
]

SAFETY_SETTINGS = {
    "HARM_CATEGORY_HARASSMENT": "BLOCK_NONE",
    "HARM_CATEGORY_HATE_SPEECH": "BLOCK_NONE",
    "HARM_CATEGORY_SEXUALLY_EXPLICIT": "BLOCK_NONE",
    "HARM_CATEGORY_DANGEROUS_CONTENT": "BLOCK_NONE",
}


async def extract_text_from_pdf(pdf_bytes: bytes) -> str:
    """Extract text content from a PDF file using PyMuPDF."""
    if not fitz:
        return "[PDF text extraction is unavailable because PyMuPDF is not installed]"

    try:
        text_parts = []
        doc = fitz.open(stream=pdf_bytes, filetype="pdf")
        for page in doc:
            text_parts.append(page.get_text())
        return "\n".join(text_parts).strip()
    except Exception as exc:
        return f"[Error extracting PDF text: {exc}]"


async def analyze_message(
    message: str = None,
    image_bytes: bytes = None,
    image_media_type: str = None,
) -> ScanResult:
    """
    Fraud analysis pipeline.

    1. Deterministic fraud rules create a safety baseline.
    2. Gemini performs language and context-aware analysis when an API key exists.
    3. The rule layer validates the AI output to catch false positives/negatives.
    """
    content, text_for_rules = await _build_content(message, image_bytes, image_media_type)

    if not content:
        raise ValueError("No content provided for analysis")

    if text_for_rules and not image_bytes:
        rule_verdict = scan_message_rules(text_for_rules)
        if (rule_verdict.force_high and rule_verdict.score >= 85) or rule_verdict.force_low:
            return heuristic_result(text_for_rules)

    if not api_key:
        if text_for_rules:
            return heuristic_result(text_for_rules)
        raise ValueError("GEMINI_API_KEY is required to analyze images or PDFs without extractable text.")

    try:
        verdict = await _run_injection_guard(content)
        if verdict == "BLOCK":
            return ScanResult(
                risk_score=100,
                risk_level="HIGH",
                summary="This message contains hidden instructions designed to manipulate AI systems.",
                reasons=[
                    "The message tries to override or control the fraud scanner",
                    "Hidden AI instructions are a known advanced abuse technique",
                    "Normal messages do not ask security tools to ignore their rules",
                ],
                action="BLOCK",
                what_to_do="Do not follow the message; block or report the sender if it came from an unknown source.",
                pass1_blocked=True,
            )

        ai_result = await _run_deep_analysis(content)
        if text_for_rules:
            return apply_rule_validation(ai_result, text_for_rules)
        return ai_result

    except Exception as exc:
        if text_for_rules:
            return heuristic_result(text_for_rules)
        raise ValueError(f"AI Analysis Failed: {exc}") from exc


async def _build_content(
    message: str | None,
    image_bytes: bytes | None,
    image_media_type: str | None,
) -> tuple[list[Any], str]:
    content: list[Any] = []
    text_for_rules = (message or "").strip()

    if image_media_type == "application/pdf" and image_bytes:
        pdf_text = await extract_text_from_pdf(image_bytes)
        content.append(f"Document Content (PDF):\n\n{pdf_text}")
        text_for_rules = "\n\n".join(filter(None, [text_for_rules, pdf_text]))
    elif image_bytes:
        content.append({
            "mime_type": image_media_type or "image/jpeg",
            "data": image_bytes,
        })
        content.append(
            "Read all visible text in this image or screenshot, then analyze it for fraud signals."
        )

    if message:
        content.append(f"Message to check:\n\n{message.strip()[:5000]}")

    return content, text_for_rules[:7000]


async def _run_injection_guard(content: list[Any]) -> str:
    response = await _generate_with_fallback(
        [PASS1_SYSTEM] + content,
        generation_config=genai.GenerationConfig(max_output_tokens=10, temperature=0),
    )
    verdict = _safe_text(response).strip().upper()
    return "BLOCK" if "BLOCK" in verdict and "SAFE" not in verdict else "SAFE"


async def _run_deep_analysis(content: list[Any]) -> ScanResult:
    response = await _generate_with_fallback(
        [PASS2_SYSTEM] + content,
        generation_config=genai.GenerationConfig(
            max_output_tokens=1200,
            temperature=0.1,
            response_mime_type="application/json",
        ),
    )
    raw = _safe_text(response).strip()
    data = _extract_json(raw)
    return normalize_ai_result(data)


async def _generate_with_fallback(content: list[Any], generation_config: genai.GenerationConfig):
    last_error = None
    tried = []

    for model_name in dict.fromkeys(GEMINI_FALLBACK_MODELS):
        if not model_name or model_name in tried:
            continue
        tried.append(model_name)
        try:
            model = genai.GenerativeModel(model_name)
            return await model.generate_content_async(
                content,
                generation_config=generation_config,
                safety_settings=SAFETY_SETTINGS,
            )
        except Exception as exc:
            last_error = exc

    raise ValueError(f"Gemini request failed for configured models: {last_error}")


def _safe_text(response) -> str:
    try:
        return response.text or ""
    except ValueError as exc:
        raise ValueError("The AI safety filters blocked the content completely.") from exc


def _extract_json(raw: str) -> dict:
    cleaned = raw.strip()
    if cleaned.startswith("```"):
        cleaned = re.sub(r"^```(?:json)?", "", cleaned, flags=re.IGNORECASE).strip()
        cleaned = re.sub(r"```$", "", cleaned).strip()

    try:
        return json.loads(cleaned)
    except json.JSONDecodeError:
        match = re.search(r"\{.*\}", cleaned, re.DOTALL)
        if not match:
            raise ValueError(f"AI did not return JSON: {raw[:200]}")
        return json.loads(match.group(0))
