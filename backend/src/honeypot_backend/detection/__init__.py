"""Detection of suspicious activity (RF-11).

The package is split by concern:

- :mod:`honeypot_backend.detection.matching` reads the command line of an event
  to find out which executables it invoked.
- :mod:`honeypot_backend.detection.rules` loads and validates the rule
  configuration from a TOML file.
- :mod:`honeypot_backend.detection.engine` evaluates the rules over the stored
  events and returns findings.
- :mod:`honeypot_backend.detection.service` ties the rules to the API.

Rules are explicit and deterministic: the same events and the same
configuration always produce the same findings, which is what makes
:func:`~honeypot_backend.detection.engine.DetectionEngine.run` safe to call
repeatedly.
"""

from honeypot_backend.detection.engine import Detection, DetectionEngine, detection_fingerprint
from honeypot_backend.detection.rules import (
    AuthThresholdRule,
    CommandOfInterestRule,
    FileTransferRule,
    RuleSpec,
    RulesFile,
    RuleConfigError,
    load_rules,
)
from honeypot_backend.detection.service import DetectionService, RulesUnavailable

__all__ = [
    "AuthThresholdRule",
    "CommandOfInterestRule",
    "Detection",
    "DetectionEngine",
    "DetectionService",
    "FileTransferRule",
    "RuleConfigError",
    "RuleSpec",
    "RulesFile",
    "RulesUnavailable",
    "detection_fingerprint",
    "load_rules",
]
