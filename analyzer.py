from dotenv import load_dotenv
load_dotenv()

import json
import os
import google.generativeai as genai
from prompts import PASS1_SYSTEM, PASS2_SYSTEM
from models import ScanResult

# Optional PDF support
try:
    import fitz  # PyMuPDF
except ImportError:
    fitz = None

# Configure Gemini
api_key = os.environ.get("GEMINI_API_KEY")
if api_key:
    genai.configure(api_key=api_key)

# Use the latest 2.5 Flash model available on your API key
model = genai.GenerativeModel('gemini-2.5-flash')

async def extract_text_from_pdf(pdf_bytes: bytes) -> str:
    """Extract text content from a PDF file using PyMuPDF."""
    if not fitz:
        return "[Error: PDF processing library (PyMuPDF) not installed on server]"

    text = ""
    try:
        doc = fitz.open(stream=pdf_bytes, filetype="pdf")
        for page in doc:
            text += page.get_text()
        return text
    except Exception as e:
        return f"[Error extracting PDF text: {str(e)}]"


async def analyze_message(
    message: str = None,
    image_bytes: bytes = None,
    image_media_type: str = None,
) -> ScanResult:
    """
    Two-pass fraud analysis using Gemini AI.
    Pass 1: Prompt injection guard
    Pass 2: Deep fraud analysis

    Supports: text messages, images/screenshots, and PDF documents.
    """
    if not api_key:
        raise ValueError("GEMINI_API_KEY environment variable is not set. Please add it to your .env file.")

    try:
        content = []

        # Handle PDF
        if image_media_type == "application/pdf" and image_bytes:
            pdf_text = await extract_text_from_pdf(image_bytes)
            content.append(f"Document Content (PDF):\n\n{pdf_text}")

        # Handle Images
        elif image_bytes:
            # Gemini expects image bytes wrapped in a dict with mime_type
            content.append({
                "mime_type": image_media_type or "image/jpeg",
                "data": image_bytes
            })
            if not message:
                content.append("Analyse the text in this image for fraud signals.")

        # Handle Text Message
        if message:
            content.append(f"Message to check:\n\n{message}")

        if not content:
            raise ValueError("No content provided for analysis")

        safety_settings = {
            "HARM_CATEGORY_HARASSMENT": "BLOCK_NONE",
            "HARM_CATEGORY_HATE_SPEECH": "BLOCK_NONE",
            "HARM_CATEGORY_SEXUALLY_EXPLICIT": "BLOCK_NONE",
            "HARM_CATEGORY_DANGEROUS_CONTENT": "BLOCK_NONE",
        }

        # ── Pass 1: Prompt Injection Guard ──────────────────────────────
        pass1_prompt = [
            {"role": "user", "parts": [{"text": PASS1_SYSTEM}] + content}
        ]
        
        # We simulate the system prompt by prepending it to user content for Gemini
        pass1_response = await model.generate_content_async(
            [PASS1_SYSTEM] + content,
            generation_config=genai.GenerationConfig(max_output_tokens=10),
            safety_settings=safety_settings
        )
        
        try:
            verdict = pass1_response.text.strip().upper()
        except ValueError:
            # If Gemini completely blocked the text due to safety, we treat it as highly dangerous
            verdict = "BLOCK"

        if verdict == "BLOCK":
            return ScanResult(
                risk_score=100,
                risk_level="HIGH",
                summary="This message contains hidden instructions designed to manipulate AI systems.",
                reasons=[
                    "The message contains text trying to override AI safety rules",
                    "This is a prompt injection attack — used by advanced fraudsters to fool AI tools",
                    "No legitimate message would contain instructions telling an AI to ignore its rules",
                ],
                action="BLOCK",
                what_to_do="Do not interact with this message or whoever sent it. Block the sender immediately.",
                pass1_blocked=True,
            )

        # ── Pass 2: Deep Fraud Analysis ──────────────────────────────────
        pass2_response = await model.generate_content_async(
            [PASS2_SYSTEM] + content,
            generation_config=genai.GenerationConfig(
                max_output_tokens=1000,
                temperature=0.2,
                response_mime_type="application/json"
            ),
            safety_settings=safety_settings
        )
        
        try:
            raw = pass2_response.text.strip()
        except ValueError:
            raise ValueError("The AI safety filters completely blocked the content. It contains highly dangerous, graphic, or restricted material.")

        if "```json" in raw:
            raw = raw.split("```json")[1].split("```")[0]
        elif raw.startswith("```"):
            raw = raw.split("```")[1]
            if raw.startswith("json"):
                raw = raw[4:]

        data = json.loads(raw.strip())
        data["pass1_blocked"] = False
        return ScanResult(**data)

    except Exception as e:
        raise ValueError(f"AI Analysis Failed: {str(e)}")