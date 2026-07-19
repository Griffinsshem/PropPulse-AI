from __future__ import annotations

from typing import Protocol


class EmailSender(Protocol):
    """Interface for sending transactional emails. AuthService
    depends on this abstraction, not on any specific email provider
    — this is the Adapter Pattern from Section 7. A concrete
    implementation (SendGrid, Resend, etc.) is wired in later,
    without any change to AuthService's code."""

    def send_verification_email(self, *, to_email: str, raw_token: str) -> None: ...
    def send_password_reset_email(self, *, to_email: str, raw_token: str) -> None: ...


class NullEmailSender:
    """A no-op implementation used until a real email provider is
    wired in. Explicitly logs what WOULD have been sent, so local
    development and early testing aren't silently missing this step
    — but nothing is actually sent over the network."""

    def send_verification_email(self, *, to_email: str, raw_token: str) -> None:
        print(f"[NullEmailSender] Would send verification email to {to_email}")

    def send_password_reset_email(self, *, to_email: str, raw_token: str) -> None:
        print(f"[NullEmailSender] Would send password reset email to {to_email}")
