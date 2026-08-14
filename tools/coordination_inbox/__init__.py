"""Durable, bounded coordination between Midlane, operator, and Hunter."""

from .coordination_inbox import CoordinationInbox, CoordinationInboxError

__all__ = ["CoordinationInbox", "CoordinationInboxError"]
