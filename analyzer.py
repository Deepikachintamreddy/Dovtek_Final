from dotenv import load_dotenv
load_dotenv()

import json
import os
import re
import asyncio
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


async def extract_text_from_pdf_basic(pdf_bytes: bytes) -> str:
    """Extract only the first page text content from a PDF file for basic plans."""
    if not fitz:
        return "[PDF text extraction is unavailable because PyMuPDF is not installed]"

    try:
        doc = fitz.open(stream=pdf_bytes, filetype="pdf")
        if doc.page_count > 0:
            return doc[0].get_text().strip()
        return ""
    except Exception as exc:
        return f"[Error extracting PDF text: {exc}]"


async def extract_text_from_pdf_advanced(pdf_bytes: bytes) -> tuple[str, dict, list[str]]:
    """Extract full text content, metadata, and embedded hyperlinks from a PDF file for advanced plans."""
    if not fitz:
        return "[PDF text extraction is unavailable because PyMuPDF is not installed]", {}, []

    try:
        text_parts = []
        links = []
        doc = fitz.open(stream=pdf_bytes, filetype="pdf")
        for page in doc:
            text_parts.append(page.get_text())
            for link in page.get_links():
                if "uri" in link:
                    links.append(link["uri"])
        return "\n".join(text_parts).strip(), doc.metadata or {}, links
    except Exception as exc:
        return f"[Error extracting PDF text: {exc}]", {}, []


async def analyze_message(
    message: str = None,
    image_bytes: bytes = None,
    image_media_type: str = None,
    user_plan: str = "free",
) -> ScanResult:
    """
    Fraud analysis pipeline.

    1. Deterministic fraud rules create a safety baseline.
    2. Gemini performs language and context-aware analysis when an API key exists.
    3. The rule layer validates the AI output to catch false positives/negatives.
    """
    if user_plan == "free":
        # Simulate queue/non-priority processing delay
        await asyncio.sleep(1.5)

    content, text_for_rules = await _build_content(message, image_bytes, image_media_type, user_plan=user_plan)

    if not content:
        raise ValueError("No content provided for analysis")

    if text_for_rules and not image_bytes:
        rule_verdict = scan_message_rules(text_for_rules)
        if (rule_verdict.force_high and rule_verdict.score >= 85) or rule_verdict.force_low:
            res = heuristic_result(text_for_rules)
            res.priority_used = (user_plan != "free")
            return res

    if not api_key:
        if text_for_rules:
            res = heuristic_result(text_for_rules)
            res.priority_used = (user_plan != "free")
            return res
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
                priority_used=(user_plan != "free"),
            )

        ai_result = await _run_deep_analysis(content)
        result = ai_result
        if text_for_rules:
            result = apply_rule_validation(ai_result, text_for_rules)
        result.priority_used = (user_plan != "free")
        return result

    except Exception as exc:
        if "safety filters blocked" in str(exc):
            return ScanResult(
                risk_score=100,
                risk_level="HIGH",
                summary="AI Security Alert: This document was flagged and blocked by AI safety filters.",
                reasons=[
                    "The document contains content that triggered safety policies",
                    "Safety blocks indicate potentially hazardous or manipulative text",
                    "Security tools block requests that contain malicious payloads",
                ],
                action="BLOCK",
                what_to_do="Do not open or trust this document; delete it immediately.",
                pass1_blocked=True,
                priority_used=(user_plan != "free"),
            )
        if text_for_rules:
            res = heuristic_result(text_for_rules)
            res.priority_used = (user_plan != "free")
            return res
        raise ValueError(f"AI Analysis Failed: {exc}") from exc


async def _build_content(
    message: str | None,
    image_bytes: bytes | None,
    image_media_type: str | None,
    user_plan: str = "free",
) -> tuple[list[Any], str]:
    content: list[Any] = []
    text_for_rules = (message or "").strip()

    if image_media_type == "application/pdf" and image_bytes:
        if user_plan == "free":
            if len(image_bytes) > 100 * 1024:
                raise ValueError("PDF size limit exceeded (100KB max for free tier). Upgrade to Pro for unlimited document size and advanced link scanning.")
            pdf_text = await extract_text_from_pdf_basic(image_bytes)
            content.append(f"Document Content (PDF - Basic Scan):\n\n{pdf_text}")
            text_for_rules = "\n\n".join(filter(None, [text_for_rules, pdf_text]))
        else:
            pdf_text, metadata, links = await extract_text_from_pdf_advanced(image_bytes)
            content.append({
                "mime_type": "application/pdf",
                "data": image_bytes
            })
            analysis_text = "Read all text and analyze this PDF document for fraud signals."
            if metadata:
                analysis_text += f"\n\nDocument Metadata:\n{json.dumps(metadata)}"
            if links:
                analysis_text += f"\n\nEmbedded Hyperlinks:\n" + "\n".join(links)
            content.append(analysis_text)
            text_for_rules = "\n\n".join(filter(None, [text_for_rules, pdf_text] + links))
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
        generation_config=genai.GenerationConfig(max_output_tokens=50, temperature=0),
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


def _get_gemini_api_keys() -> list[str]:
    raw_keys = os.environ.get("GEMINI_API_KEY") or os.environ.get("GOOGLE_API_KEY") or ""
    keys = [k.strip() for k in raw_keys.split(",") if k.strip()]
    for i in range(2, 6):
        k = os.environ.get(f"GEMINI_API_KEY_{i}")
        if k:
            keys.append(k.strip())
    return keys


async def _generate_with_fallback(content: list[Any], generation_config: genai.GenerationConfig):
    keys = _get_gemini_api_keys()
    if not keys:
        raise ValueError("No Gemini API key configured.")

    last_error = None
    for key in keys:
        try:
            genai.configure(api_key=key)
        except Exception as e:
            last_error = e
            continue

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
                err_str = str(exc).lower()
                if "quota" in err_str or "exhausted" in err_str or "api key" in err_str or "invalid" in err_str or "429" in err_str:
                    break

    raise ValueError(f"Gemini request failed for configured models: {last_error}")


def _safe_text(response) -> str:
    try:
        if hasattr(response, "candidates") and response.candidates:
            candidate = response.candidates[0]
            finish_reason = getattr(candidate, "finish_reason", None)
            # FinishReason 3 corresponds to SAFETY
            if finish_reason == 3 or (hasattr(finish_reason, "name") and finish_reason.name == "SAFETY"):
                raise ValueError("The AI safety filters blocked the content completely.")
            
            content_obj = getattr(candidate, "content", None)
            if content_obj and hasattr(content_obj, "parts"):
                parts = getattr(content_obj, "parts", [])
                text_parts = [part.text for part in parts if hasattr(part, "text") and part.text]
                if text_parts:
                    return "".join(text_parts)
        return response.text or ""
    except ValueError as exc:
        if "safety" in str(exc).lower():
            raise ValueError("The AI safety filters blocked the content completely.") from exc
        return ""


def _repair_json_string(raw: str) -> str:
    cleaned = raw.strip()
    if not cleaned:
        return "{}"
        
    in_quote = False
    escaped = False
    reconstructed = []
    
    for char in cleaned:
        if char == '"' and not escaped:
            in_quote = not in_quote
        if char == '\\' and not escaped:
            escaped = True
        else:
            escaped = False
        reconstructed.append(char)
        
    if in_quote:
        reconstructed.append('"')
        
    repaired = "".join(reconstructed)
    
    # Try to close open braces
    open_braces = repaired.count("{")
    close_braces = repaired.count("}")
    if open_braces > close_braces:
        temp = repaired.rstrip()
        # Remove trailing trailing comma or colon if present
        if temp.endswith(",") or temp.endswith(":"):
            temp = temp[:-1].rstrip()
            if in_quote and not temp.endswith('"'):
                temp += '"'
        repaired = temp + "}" * (open_braces - close_braces)
        
    return repaired


def _extract_json(raw: str) -> dict:
    cleaned = raw.strip()
    if cleaned.startswith("```"):
        cleaned = re.sub(r"^```(?:json)?", "", cleaned, flags=re.IGNORECASE).strip()
        cleaned = re.sub(r"```$", "", cleaned).strip()

    try:
        return json.loads(cleaned)
    except json.JSONDecodeError:
        pass

    match = re.search(r"\{.*\}", cleaned, re.DOTALL)
    if match:
        try:
            return json.loads(match.group(0))
        except json.JSONDecodeError:
            cleaned = match.group(0)

    # Attempt to auto-repair truncated JSON
    repaired = _repair_json_string(cleaned)
    try:
        return json.loads(repaired)
    except json.JSONDecodeError as e:
        raise ValueError(f"AI did not return JSON: {raw[:200]}") from e
