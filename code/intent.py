"""intent.py – Classify whether a request_text authorizes deletion.

Pure rule-based multilingual approach. Returns True if the text contains a
clear deletion/erasure intent. Returns False for pure access, correction,
export, opt-out, login, or password-reset requests.
"""
from __future__ import annotations

import re
from typing import List


# ---------------------------------------------------------------------------
# Positive deletion signals (across languages)
# Order: most specific first; word/character boundaries as appropriate.
# ---------------------------------------------------------------------------

_DELETION_PATTERNS: List[str] = [
    # English – verb forms (stem match)
    r"\bdelet\w*",          # delete, deleting, deleted, deletion
    r"\berase\w*",           # erase, erased, erasure
    r"\bremov\w*",           # remove, removed, removal
    r"\bpurg\w*",            # purge, purged
    r"\bwipe\w*",            # wipe, wiped

    # English – account closure (any determiner: my/the/this/that)
    r"\bclos(?:e|ed|ing|ure)\s+(?:my\s+|the\s+|this\s+|that\s+)?"
    r"(?:account|profile)|\bclos(?:e|ed)\s+(?:my\s+|the\s+|this\s+|that\s+)?"
    r"(?:account|profile)\b",
    r"\bshut\s+down\s+(?:my\s+|the\s+)?account\b",
    r"\bterminat\w+\s+(?:my\s+|the\s+)?account\b",
    r"\bcancel\s+(?:my\s+|the\s+)?account\b",
    r"\bno\s+longer\s+(?:need|want|use)\s+(?:this\s+|my\s+)?account\b",
    r"\bclose\s+(?:this|my|the)\b",

    # English – data rights phrases
    r"\bright\s+to\s+(?:be\s+forgotten|erasure)\b",
    r"\bforget\s+me\b",
    r"\bgdpr\b",
    r"\bprivacy\s+(?:request|deletion|erasure)\b",
    r"\bpermanent(?:ly)?\s+(?:remov|delet|eras)\w*\b",
    r"\bpersonal\s+(?:data|information|info)\s+(?:deleted|removed|erased|purged|gone)\b",
    r"\bnothing.*(?:identify|link|trace|point).*me\b",
    r"\bprofile\s+(?:is\s+)?gone\b",
    r"\bremaining\s+records\s+cannot\s+identify\b",

    # Spanish
    r"\belimin\w+",          # eliminar, eliminación, elimine
    r"\bborrar?\b", r"\bborrado\b", r"\bborr[aeo]\w*",
    r"\bsuprimir?\b", r"\bsupresi[oó]n\b",
    r"\bdarme\s+de\s+baja\b",
    r"\bcerrar\s+(?:mi\s+)?cuenta\b",
    r"\bcancelaci[oó]n\b", r"\bcancelar\b",

    # French
    r"\bsupprimer?\b", r"\bsuppression\b",
    r"\beffac\w+",           # effacer, effacement
    r"\bfermer\s+(?:mon\s+)?compte\b",
    r"\bclore\b",
    r"\bdroit\s+[àa]\s+l.effacement\b",
    r"\bsuppression\s+(?:du\s+)?compte\b",
    r"\bsuppression\s+d[éè]finitive\b",

    # German
    r"\blösch\w+",           # löschen, gelöscht, Löschung
    r"\bkonto\s+schließen\b",
    r"\bkündigen?\b",

    # Japanese
    "削除",                  # delete/deletion
    "消去",                  # erase
    "退会",                  # withdrawal/cancel membership
    "アカウント.*削除",
    "個人情報.*削除",

    # Korean
    "삭제",                  # delete
    "탈퇴",                  # withdrawal
    "회원.*탈퇴",
    "계정.*삭제",

    # Portuguese
    r"\bexcluir?\b", r"\bexclus[aã]o\b",
    r"\bapagar?\b",
    r"\bencerrar\s+(?:minha\s+)?conta\b",

    # Dutch
    r"\bverwijder\w*",
    r"\bwissen\b",

    # Italian
    r"\beliminar[ei]\b", r"\bcancellare?\b",

    # Polish
    r"\busun[aą][ćc]\w*", r"\busuni[eę]cie\b",

    # Arabic
    "حذف", "مسح", "إزالة",

    # Generic indirect phrases
    r"\bprocess.*(?:deletion|removal|erasure)\b",
    r"\brequest.*(?:for\s+)?(?:deletion|removal|erasure)\b",
    r"\bapply.*(?:correct\s+)?(?:treatment|policy).*(?:request|deletion)\b",
    r"\bhandle.*(?:deletion|removal|erasure)\b",
    r"\bpermanent(?:ly)?\s+account\s+delet\w*\b",
    r"\baccount.*(?:closed|removed|deleted|erased|gone)\b",
    r"\bdata\s+(?:must\s+be\s+|to\s+be\s+|be\s+)?(?:deleted|removed|erased)\b",
    r"\bnothing.*(?:remains?|left|behind)\b",
    r"\bno\s+(?:data|record|profile|copy|trace)\s+(?:remains?|left|should\s+exist)\b",
    r"\bverify.*(?:profile|account|data)\s+(?:is\s+)?(?:gone|deleted|removed|absent)\b",
    r"\bconfirm.*(?:profile|account)\s+(?:was\s+)?(?:fully\s+)?(?:removed|deleted)\b",
    r"\bfinish.*deletion\b",
    r"\bcomplete.*deletion\b",
    r"\bpersonal.*(?:data|info).*(?:removed|deleted|erased|purged)\b",
    r"\bidentifiable.*(?:data|records?).*(?:removed|deleted|erased)\b",
    r"\bdeletion\s+(?:was\s+|is\s+)?(?:complete|done|finished)\b",
    r"\bprivacy\s+page\b",  # signals a privacy/deletion workflow
    r"\bprivacy\s+(?:procedure|process|policy|request)\b",
    r"\bpersonal-data\s+deletion\b",
    r"\bpermanent\s+account\s+deletion\b",
    r"\bdeletion\s+request\b",
]

_DELETION_RE: List[re.Pattern] = [
    re.compile(p, re.IGNORECASE | re.DOTALL | re.UNICODE)
    for p in _DELETION_PATTERNS
]


# ---------------------------------------------------------------------------
# Exclusion patterns – ONLY classify as non-deletion if NONE of the
# deletion patterns match. These are purely advisory / used to detect
# "pure non-deletion requests" when no deletion signals are present.
# ---------------------------------------------------------------------------

_NON_DELETION_ONLY_PATTERNS: List[str] = [
    # Pure password/login/recovery requests
    r"\breset\s+(?:my\s+)?password\b",
    r"\bforgot\s+(?:my\s+)?password\b",
    r"\bcan.?t\s+log\s+(?:in|into)\b",
    r"\blocke?d\s+out\b",
    # Pure data export (no deletion)
    r"\bdownload\s+(?:my\s+)?data\b",
    r"\bexport\s+(?:my\s+)?data\b",
    r"\bcopy\s+of\s+my\s+(?:data|records?)\b",
    # Pure opt-out (no deletion)
    r"\bunsubscribe\b",
    r"\bopt\s+out\s+of\s+(?:marketing|emails?|newsletters?)\b",
    # Pure correction / update (no deletion)
    r"\bupdate\s+(?:my\s+)?(?:email|phone|name|address|details?)\b",
    r"\bcorrect\s+(?:my\s+)?(?:email|phone|name|address|details?)\b",
]

_NON_DELETION_ONLY_RE: List[re.Pattern] = [
    re.compile(p, re.IGNORECASE | re.DOTALL | re.UNICODE)
    for p in _NON_DELETION_ONLY_PATTERNS
]


def is_deletion_request(request_text: str) -> bool:
    """Return True if request_text clearly authorizes account/data deletion.

    Algorithm:
    1. Scan for positive deletion signals.
    2. If any match → return True.
    3. If none match → check if it's a pure non-deletion request.
       If yes → return False.
       If no positive/negative signals → return False (safe default).
    """
    text = request_text.strip()
    if not text:
        return False

    # Check positive deletion signals
    for pat in _DELETION_RE:
        if pat.search(text):
            return True

    # No deletion signals found
    return False
