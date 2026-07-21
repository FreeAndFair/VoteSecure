# This file assembles the threat model from its components

from nxt import ThreatModel

from . import contexts
from . import properties
from . import mitigations
from . import patterns
from . import attacks

# Threat model version metadata (single source of truth for HTML and LaTeX)
MODEL_VERSION = "1.4"
MODEL_DATE = "July 2026"

# Build the complete threat model
model = ThreatModel(
    name="VoteSecure Threat Model",
    description="Threat model for the VoteSecure E2E-VIV protocol.",

    properties=properties.ALL,
    contexts=contexts.ALL,
    mitigations=mitigations.ALL,
    patterns=patterns.ALL,
    attacks=attacks.ALL,
)
