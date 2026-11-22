import idna
from typing import Dict, Any, List

# Common Cyrillic & Greek homoglyphs used in IDN homograph phishing attacks
HOMOGLYPH_LOOKALIKES = {
    '\u0430': 'a',  # Cyrillic small letter a
    '\u0441': 'c',  # Cyrillic small letter es (looks like c)
    '\u0435': 'e',  # Cyrillic small letter ie (looks like e)
    '\u0456': 'i',  # Cyrillic small letter byelorussian-ukrainian i
    '\u0458': 'j',  # Cyrillic small letter je
    '\u043e': 'o',  # Cyrillic small letter o
    '\u0440': 'p',  # Cyrillic small letter er (looks like p)
    '\u0455': 's',  # Cyrillic small letter dze (looks like s)
    '\u0445': 'x',  # Cyrillic small letter ha (looks like x)
    '\u0443': 'y',  # Cyrillic small letter u (looks like y)
    '\u03bf': 'o',  # Greek small letter omicron
    '\u03c1': 'p',  # Greek small letter rho
}

def detect_punycode_and_homoglyphs(url_data: Dict[str, Any]) -> Dict[str, Any]:
    hostname = (url_data.get("hostname") or "").lower()
    
    is_punycode = "xn--" in hostname
    decoded_hostname = hostname
    has_confusables = False
    confusable_chars: List[Dict[str, str]] = []

    # 1. Check if IDNA / Punycode encoded
    if is_punycode:
        try:
            decoded_hostname = idna.decode(hostname)
        except Exception:
            decoded_hostname = hostname

    # 2. Check for non-ASCII or homoglyph characters
    for char in decoded_hostname:
        if char in HOMOGLYPH_LOOKALIKES:
            has_confusables = True
            confusable_chars.append({
                "char": char,
                "unicode": f"U+{ord(char):04X}",
                "latin_lookalike": HOMOGLYPH_LOOKALIKES[char]
            })
        elif ord(char) > 127 and char != '.':
            has_confusables = True
            confusable_chars.append({
                "char": char,
                "unicode": f"U+{ord(char):04X}",
                "latin_lookalike": "?"
            })

    is_threat = is_punycode or has_confusables

    return {
        "is_punycode": is_punycode,
        "has_confusables": has_confusables,
        "is_suspicious_homoglyph": is_threat,
        "decoded_hostname": decoded_hostname if is_punycode else hostname,
        "confusable_chars": confusable_chars,
        "warning": (
            f"Punycode / Homoglyph attack detected! Domain '{hostname}' disguises as '{decoded_hostname}' using Unicode lookalikes."
            if is_threat else None
        )
    }
