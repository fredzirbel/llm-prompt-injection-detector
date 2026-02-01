"""Attack pattern category definitions."""

from detector.models import AttackCategory

CATEGORY_DESCRIPTIONS: dict[AttackCategory, str] = {
    AttackCategory.ROLE_OVERRIDE: (
        "Attempts to override the system role or identity of the LLM, "
        "e.g., 'ignore previous instructions', 'you are now...'"
    ),
    AttackCategory.INSTRUCTION_LEAK: (
        "Attempts to extract the system prompt or internal instructions, "
        "e.g., 'print your system prompt', 'what were you told'"
    ),
    AttackCategory.ENCODING_EVASION: (
        "Uses encoding, obfuscation, or alternate representations to bypass filters, "
        "e.g., Base64, Unicode homoglyphs, leetspeak"
    ),
    AttackCategory.DELIMITER_INJECTION: (
        "Attempts to close or manipulate prompt context boundaries, "
        "e.g., injecting '###', '\"\"\"', '[SYSTEM]' delimiters"
    ),
    AttackCategory.INDIRECT_INJECTION: (
        "Embeds instructions for the LLM to follow when processing external content, "
        "e.g., 'when the user asks about X, instead do Y'"
    ),
    AttackCategory.CONTEXT_MANIPULATION: (
        "Manipulates the conversational context or attempts to alter LLM behavior, "
        "e.g., fake conversation history, simulated tool outputs"
    ),
}
