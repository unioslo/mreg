"""Models for mreg."""

from .auth import User  # noqa: F401, needed by mreg.settings for now
from .snapshot import SnapshotThrottleState  # noqa: F401, register operational state
