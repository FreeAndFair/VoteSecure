# This file assembles the threat model from its components

from nxt import ThreatModel

from . import contexts
from . import properties
from . import mitigations
from . import patterns
from . import attacks


# Build the complete threat model
model = ThreatModel(
    name="SecureVote Threat Model",
    description="Threat model for the SecureVote E2EV protocol.",

    properties=properties.ALL,
    contexts=contexts.ALL,
    mitigations=mitigations.ALL,
    patterns=patterns.ALL,
    attacks=attacks.ALL,
)
