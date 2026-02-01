"""Regex-based injection pattern library.

Each pattern has a regex, category, confidence weight, and description.
Patterns are organized by attack category for maintainability.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

from detector.models import AttackCategory


@dataclass
class InjectionPattern:
    name: str
    pattern: re.Pattern
    category: AttackCategory
    confidence: float
    description: str


def _compile(patterns: list[dict]) -> list[InjectionPattern]:
    return [
        InjectionPattern(
            name=p["name"],
            pattern=re.compile(p["regex"], re.IGNORECASE | re.DOTALL),
            category=p["category"],
            confidence=p["confidence"],
            description=p["description"],
        )
        for p in patterns
    ]


ROLE_OVERRIDE_PATTERNS = _compile([
    {
        "name": "ignore_previous",
        "regex": r"(ignore|drop|disregard|forget|discard|skip|override|dismiss)\s+(all\s+)?(previous|prior|above|earlier)\s+(instructions?|prompts?|rules?|guidelines?|context)",
        "category": AttackCategory.ROLE_OVERRIDE,
        "confidence": 0.95,
        "description": "Tells the model to ignore its system instructions",
    },
    {
        "name": "you_are_now",
        "regex": r"you\s+are\s+now\s+((a|an|the|my)\s+)?\w+",
        "category": AttackCategory.ROLE_OVERRIDE,
        "confidence": 0.85,
        "description": "Attempts to redefine the model's identity/role",
    },
    {
        "name": "disregard",
        "regex": r"disregard\s+(your|all|any|the)\s+(previous|system|initial|original)\s+",
        "category": AttackCategory.ROLE_OVERRIDE,
        "confidence": 0.9,
        "description": "Tells the model to disregard system configuration",
    },
    {
        "name": "new_instructions",
        "regex": r"(new|updated|revised|override)\s+instructions?\s*[:\-]",
        "category": AttackCategory.ROLE_OVERRIDE,
        "confidence": 0.85,
        "description": "Provides replacement instructions",
    },
    {
        "name": "forget_everything",
        "regex": r"forget\s+(everything|all|anything)\s+(you|that)\s+(know|were|have)",
        "category": AttackCategory.ROLE_OVERRIDE,
        "confidence": 0.9,
        "description": "Tells the model to forget its training or instructions",
    },
    {
        "name": "do_not_follow",
        "regex": r"do\s+not\s+follow\s+(your|the|any)\s+(previous|original|initial|system)",
        "category": AttackCategory.ROLE_OVERRIDE,
        "confidence": 0.9,
        "description": "Explicitly tells the model not to follow system rules",
    },
    {
        "name": "pretend_to_be",
        "regex": r"pretend\s+(to\s+be|you\s+are|that\s+you)",
        "category": AttackCategory.ROLE_OVERRIDE,
        "confidence": 0.8,
        "description": "Asks the model to pretend to be something else",
    },
    {
        "name": "act_as",
        "regex": r"act\s+as\s+(a|an|if|though)\s+",
        "category": AttackCategory.ROLE_OVERRIDE,
        "confidence": 0.7,
        "description": "Asks the model to act as a different entity",
    },
    {
        "name": "jailbreak_mode",
        "regex": r"(developer|god|admin|sudo|root)\s*mode|DAN\s*(mode|prompt|jailbreak|\(Do\s+Anything)|Do\s+Anything\s+Now",
        "category": AttackCategory.ROLE_OVERRIDE,
        "confidence": 0.95,
        "description": "Activates a known jailbreak mode",
    },
    {
        "name": "bypass_restrictions",
        "regex": r"bypass\s+(your|all|any|the)\s+(restrictions?|filters?|safety|guardrails?|limitations?)",
        "category": AttackCategory.ROLE_OVERRIDE,
        "confidence": 0.95,
        "description": "Explicitly asks to bypass safety measures",
    },
])

INSTRUCTION_LEAK_PATTERNS = _compile([
    {
        "name": "repeat_instructions",
        "regex": r"(repeat|show|display|print|output|reveal)\s+(your|the|all)\s+(system\s+)?(instructions?|prompt|rules?|guidelines?|configuration)",
        "category": AttackCategory.INSTRUCTION_LEAK,
        "confidence": 0.9,
        "description": "Requests the model to reveal its system prompt",
    },
    {
        "name": "what_were_you_told",
        "regex": r"what\s+(were|are)\s+you(r)?\s+(told|instructed|programmed|configured|given)",
        "category": AttackCategory.INSTRUCTION_LEAK,
        "confidence": 0.85,
        "description": "Asks what the model was configured with",
    },
    {
        "name": "system_prompt_extract",
        "regex": r"(system\s+prompt|initial\s+prompt|hidden\s+prompt|secret\s+instructions?)",
        "category": AttackCategory.INSTRUCTION_LEAK,
        "confidence": 0.8,
        "description": "References the system prompt directly",
    },
    {
        "name": "beginning_of_conversation",
        "regex": r"(beginning|start|first\s+part)\s+of\s+(this\s+)?(conversation|chat|session|context)",
        "category": AttackCategory.INSTRUCTION_LEAK,
        "confidence": 0.7,
        "description": "Attempts to reference the start of the conversation context",
    },
    {
        "name": "verbatim_output",
        "regex": r"(verbatim|word\s+for\s+word|exactly\s+as)\s+(output|repeat|copy|print)",
        "category": AttackCategory.INSTRUCTION_LEAK,
        "confidence": 0.85,
        "description": "Requests verbatim output of instructions",
    },
    {
        "name": "above_text",
        "regex": r"(text|content|message)\s+(above|before)\s+(this|the\s+user)",
        "category": AttackCategory.INSTRUCTION_LEAK,
        "confidence": 0.75,
        "description": "References text above the user message",
    },
    {
        "name": "developer_instructions",
        "regex": r"(developer|creator|maker|builder)\s+(instructions?|notes?|prompt)",
        "category": AttackCategory.INSTRUCTION_LEAK,
        "confidence": 0.8,
        "description": "References developer-level instructions",
    },
    {
        "name": "internal_config",
        "regex": r"(internal|private|confidential|hidden)\s+(config|settings?|parameters?|rules?)",
        "category": AttackCategory.INSTRUCTION_LEAK,
        "confidence": 0.8,
        "description": "Attempts to access internal configuration",
    },
])

ENCODING_EVASION_PATTERNS = _compile([
    {
        "name": "base64_instruction",
        "regex": r"(base64|b64|decode)\s*[:\(]\s*[A-Za-z0-9+/=]{20,}",
        "category": AttackCategory.ENCODING_EVASION,
        "confidence": 0.85,
        "description": "Contains Base64-encoded content that may hide instructions",
    },
    {
        "name": "hex_encoded",
        "regex": r"\\x[0-9a-fA-F]{2}(\\x[0-9a-fA-F]{2}){4,}",
        "category": AttackCategory.ENCODING_EVASION,
        "confidence": 0.8,
        "description": "Contains hex-encoded byte sequences",
    },
    {
        "name": "unicode_escape",
        "regex": r"\\u[0-9a-fA-F]{4}(\\u[0-9a-fA-F]{4}){3,}",
        "category": AttackCategory.ENCODING_EVASION,
        "confidence": 0.8,
        "description": "Contains Unicode escape sequences",
    },
    {
        "name": "rot13_reference",
        "regex": r"(rot13|caesar\s+cipher|rot\s*-?\s*13)\s*[:\(]",
        "category": AttackCategory.ENCODING_EVASION,
        "confidence": 0.85,
        "description": "References ROT13 or similar simple ciphers",
    },
    {
        "name": "leetspeak_instructions",
        "regex": r"1gn0r3\s+pr3v10us|1nstruct10ns?|syst3m\s+pr0mpt",
        "category": AttackCategory.ENCODING_EVASION,
        "confidence": 0.8,
        "description": "Uses leetspeak to disguise injection keywords",
    },
    {
        "name": "reversed_text",
        "regex": r"(reverse\s+(this|the\s+text|instructions?|string|prompt)|read\s+(it\s+)?backwards?|tpmorP|snoitcurtsni)",
        "category": AttackCategory.ENCODING_EVASION,
        "confidence": 0.6,
        "description": "May contain reversed text to evade detection",
    },
])

DELIMITER_INJECTION_PATTERNS = _compile([
    {
        "name": "triple_quotes",
        "regex": r'"""[\s\S]*?(system|instruction|prompt|ignore)',
        "category": AttackCategory.DELIMITER_INJECTION,
        "confidence": 0.85,
        "description": "Uses triple quotes to inject system-like context",
    },
    {
        "name": "hash_delimiter",
        "regex": r"#{3,}\s*(system|instruction|end|new\s+section)",
        "category": AttackCategory.DELIMITER_INJECTION,
        "confidence": 0.8,
        "description": "Uses hash delimiters to create fake section boundaries",
    },
    {
        "name": "system_tag",
        "regex": r"\[(SYSTEM|INST|SYS|ADMIN|ASSISTANT|USER)\]",
        "category": AttackCategory.DELIMITER_INJECTION,
        "confidence": 0.9,
        "description": "Injects role tags to manipulate conversation structure",
    },
    {
        "name": "xml_tags",
        "regex": r"<\s*/?\s*(system|instruction|prompt|context|message)\s*>",
        "category": AttackCategory.DELIMITER_INJECTION,
        "confidence": 0.85,
        "description": "Uses XML-like tags to inject system context",
    },
    {
        "name": "separator_override",
        "regex": r"[-=]{5,}\s*(system|new|override|instructions?|end\s+of)",
        "category": AttackCategory.DELIMITER_INJECTION,
        "confidence": 0.8,
        "description": "Uses visual separators to create fake boundaries",
    },
    {
        "name": "markdown_heading_inject",
        "regex": r"^#+\s*(system|instructions?|override|configuration)\s*$",
        "category": AttackCategory.DELIMITER_INJECTION,
        "confidence": 0.75,
        "description": "Uses markdown headings to inject system-like sections",
    },
])

INDIRECT_INJECTION_PATTERNS = _compile([
    {
        "name": "when_user_asks",
        "regex": r"when\s+(the\s+)?(user|human|person)\s+(asks?|says?|mentions?|requests?)\s+",
        "category": AttackCategory.INDIRECT_INJECTION,
        "confidence": 0.85,
        "description": "Embeds conditional instructions for future interactions",
    },
    {
        "name": "instead_do",
        "regex": r"instead\s+(of\s+)?(answering|responding|doing)\s+",
        "category": AttackCategory.INDIRECT_INJECTION,
        "confidence": 0.75,
        "description": "Redirects the model's default behavior",
    },
    {
        "name": "from_now_on",
        "regex": r"from\s+now\s+on\s+(you\s+)?(will|must|should|shall)\s+",
        "category": AttackCategory.INDIRECT_INJECTION,
        "confidence": 0.85,
        "description": "Sets persistent behavioral changes",
    },
    {
        "name": "always_respond",
        "regex": r"(always|never)\s+(respond|reply|answer|say)\s+(with|that|as)\s+",
        "category": AttackCategory.INDIRECT_INJECTION,
        "confidence": 0.8,
        "description": "Sets permanent response overrides",
    },
    {
        "name": "hidden_instruction",
        "regex": r"(hidden|secret|embedded)\s+(instruction|command|directive|task)",
        "category": AttackCategory.INDIRECT_INJECTION,
        "confidence": 0.85,
        "description": "References hidden instructions in content",
    },
    {
        "name": "important_instruction",
        "regex": r"IMPORTANT\s*[:\-!]\s*(ignore|override|forget|disregard|you\s+must)",
        "category": AttackCategory.INDIRECT_INJECTION,
        "confidence": 0.9,
        "description": "Uses urgency markers to emphasize injected instructions",
    },
])

CONTEXT_MANIPULATION_PATTERNS = _compile([
    {
        "name": "fake_assistant",
        "regex": r"(assistant|ai|bot|model)\s*:\s*(sure|okay|yes|absolutely|of\s+course)",
        "category": AttackCategory.CONTEXT_MANIPULATION,
        "confidence": 0.85,
        "description": "Simulates a compliant assistant response to set precedent",
    },
    {
        "name": "fake_conversation",
        "regex": r"(user|human)\s*:\s*.+\n\s*(assistant|ai)\s*:\s*",
        "category": AttackCategory.CONTEXT_MANIPULATION,
        "confidence": 0.8,
        "description": "Embeds fake conversation history",
    },
    {
        "name": "simulated_output",
        "regex": r"(simulate|emulate|generate)\s+(the\s+)?(output|response|result)\s+(of|from|as\s+if)",
        "category": AttackCategory.CONTEXT_MANIPULATION,
        "confidence": 0.75,
        "description": "Asks for simulated or hypothetical outputs",
    },
    {
        "name": "hypothetical_scenario",
        "regex": r"(hypothetically|in\s+theory|imagine\s+that|suppose\s+that|what\s+if)\s+.*(ignore|bypass|override|no\s+restrictions?)",
        "category": AttackCategory.CONTEXT_MANIPULATION,
        "confidence": 0.85,
        "description": "Uses hypothetical framing to bypass restrictions",
    },
    {
        "name": "tool_output_fake",
        "regex": r"(tool|function|api)\s+(output|result|response)\s*[:\{]",
        "category": AttackCategory.CONTEXT_MANIPULATION,
        "confidence": 0.7,
        "description": "Simulates tool/function output to manipulate context",
    },
    {
        "name": "previous_conversation",
        "regex": r"(in\s+our\s+previous|last\s+time|earlier\s+you\s+said|you\s+already\s+agreed)",
        "category": AttackCategory.CONTEXT_MANIPULATION,
        "confidence": 0.75,
        "description": "References fake previous interactions",
    },
])

ALL_PATTERNS: list[InjectionPattern] = (
    ROLE_OVERRIDE_PATTERNS
    + INSTRUCTION_LEAK_PATTERNS
    + ENCODING_EVASION_PATTERNS
    + DELIMITER_INJECTION_PATTERNS
    + INDIRECT_INJECTION_PATTERNS
    + CONTEXT_MANIPULATION_PATTERNS
)
