"""identity.py – Resolve current and historical identity for a subject email."""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set

from loader import AuditLogEntry, UserIdentity


@dataclass
class SubjectIdentity:
    user_id: Optional[str]
    emails: Set[str] = field(default_factory=set)
    phones: Set[str] = field(default_factory=set)
    email_hashes: Set[str] = field(default_factory=set)
    names: Set[str] = field(default_factory=set)

    def matches_any(self, email: Optional[str] = None,
                    phone: Optional[str] = None,
                    email_hash: Optional[str] = None,
                    user_id: Optional[str] = None,
                    lookup_key: Optional[str] = None) -> bool:
        """Return True if any supplied identifier belongs to this subject."""
        if email and email.strip().lower() in self.emails:
            return True
        if email_hash and email_hash.strip().lower() in self.email_hashes:
            return True
        if phone and phone.strip() in self.phones:
            return True
        if user_id and user_id.strip() == self.user_id:
            return True
        if lookup_key:
            lk = lookup_key.strip()
            if lk.lower() in self.emails:
                return True
            if lk.startswith("user_") and lk == self.user_id:
                return True
            if lk in self.phones:
                return True
            if lk.lower() in self.email_hashes:
                return True
        return False


class IdentityResolver:
    def __init__(self, identities: List[UserIdentity], audit_log: List[AuditLogEntry]):
        # Build quick lookup by email (lowercase)
        self._by_email: Dict[str, UserIdentity] = {}
        for u in identities:
            if u.email:
                self._by_email[u.email.lower()] = u

        # Build historical identifier map: user_id → list of old emails, phones, hashes
        self._history: Dict[str, List[AuditLogEntry]] = {}
        for a in audit_log:
            self._history.setdefault(a.user_id, []).append(a)

        self._identities = identities
        self._audit_log = audit_log

    def resolve(self, request_email: str) -> SubjectIdentity:
        """Resolve the subject from a request email.

        Tries current identity first, then scans the audit log for a user whose
        *old* email matches (i.e. the request uses a historical email address).
        """
        email_lc = request_email.strip().lower()

        # Try current identity match
        user = self._by_email.get(email_lc)

        # If not found in current identities, check audit log for old email values
        if user is None:
            for a in self._audit_log:
                if a.field_name == "email" and (
                    (a.old_value or "").strip().lower() == email_lc or
                    (a.new_value or "").strip().lower() == email_lc
                ):
                    # find the UserIdentity for this user_id
                    for u in self._identities:
                        if u.user_id == a.user_id:
                            user = u
                            break
                if user:
                    break

        subj = SubjectIdentity(user_id=user.user_id if user else None)
        subj.emails.add(email_lc)

        if user:
            subj.emails.add(user.email.lower())
            if user.phone:
                subj.phones.add(user.phone.strip())
            if user.email_hash:
                subj.email_hashes.add(user.email_hash.strip().lower())
            if user.name:
                subj.names.add(user.name.strip().lower())

            # add all historical identifiers
            for a in self._history.get(user.user_id, []):
                fn = a.field_name
                if fn == "email":
                    if a.old_value:
                        subj.emails.add(a.old_value.strip().lower())
                    if a.new_value:
                        subj.emails.add(a.new_value.strip().lower())
                elif fn == "phone":
                    if a.old_value:
                        subj.phones.add(a.old_value.strip())
                    if a.new_value:
                        subj.phones.add(a.new_value.strip())
                elif fn == "email_hash":
                    if a.old_value:
                        subj.email_hashes.add(a.old_value.strip().lower())
                    if a.new_value:
                        subj.email_hashes.add(a.new_value.strip().lower())

        subj.emails.discard("")
        subj.phones.discard("")
        subj.email_hashes.discard("")
        return subj
