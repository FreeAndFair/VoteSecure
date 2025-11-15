# SecureVote Threat Model - Attack Patterns
# Abstract attacks that can be instantiated as concrete attacks

from nxt import AttackPattern, MitigationApplication, OUT_OF_SCOPE
from . import mitigations as mit


# =============================================================================
# COMPROMISED DEVICE patterns
# =============================================================================

compromised_device = AttackPattern(
    id="compromised_device",
    name="Compromised device",
    description="A device that runs one or more subsystems is altered in a way that affects the system's security.",
)

malware = AttackPattern(
    id="malware",
    name="Malware",
    description="Malicious software infects the device.",
    refines=compromised_device,
    mitigations=[
        MitigationApplication(
            mitigation=mit.cybersecurity_malware,
            rationale="General cybersecurity practices aimed to protect against malware reduce the risk of device infection.",
        ),
    ],
)

intrusion = AttackPattern(
    id="intrusion",
    name="Intrusion",
    description="An adversary gains control of the device.",
    refines=compromised_device,
    mitigations=[
        MitigationApplication(
            mitigation=mit.cybersecurity_intrusion,
            rationale="General cybersecurity practices aimed to protect against intrusion reduce the risk of an adversary gaining control of a device.",
        ),
    ],
)

escalation_of_privilege = AttackPattern(
    id="escalation_of_privilege",
    name="Escalation of privilege",
    description="An adversary with restricted access to the system gains unauthorized privileges.",
    refines=compromised_device,
    mitigations=[
        MitigationApplication(
            mitigation=mit.cybersecurity_escalation,
            rationale="General cybersecurity practices aimed to protect against privilege escalation reduce the risk of an adversary gaining unauthorized privileges.",
        ),
    ],
)

supply_chain_attack = AttackPattern(
    id="supply_chain_attack",
    name="Supply chain attack",
    description="One or more software dependencies of a subsystem is programmed maliciously.",
    refines=compromised_device,
    mitigations=[
        MitigationApplication(
            mitigation=mit.dependency_minimization,
            rationale="Minimizing the number and size of dependencies reduces the likelihood of malicious dependencies impacting system security.",
        ),
        MitigationApplication(
            mitigation=mit.cybersecurity_supply_chain,
            rationale="General cybersecurity practices aimed to protect against supply chain attacks reduce the likelihood of an adversary introducing malicious dependencies.",
        ),
    ],
)

malicious_programming = AttackPattern(
    id="malicious_programming",
    name="Malicious programming",
    description="One or more subsystems is programmed maliciously.",
    refines=compromised_device,
    mitigations=[
        MitigationApplication(
            mitigation=OUT_OF_SCOPE,
            rationale="We cannot provide mitigations against our own attacks, which could even extend to this analysis.",
        ),
    ],
)

malicious_cloud_provider = AttackPattern(
    id="malicious_cloud_provider",
    name="Malicious cloud provider",
    description="One or more subsystems execute in a cloud environment where the cloud provider is malicious.",
    refines=compromised_device,
    mitigations=[
        MitigationApplication(
            mitigation=OUT_OF_SCOPE,
            rationale="A malicious cloud provider has access to the underlying hardware and therefore has full control of subsystems executing within.",
        ),
    ],
)

virtualization_attack = AttackPattern(
    id="virtualization_attack",
    name="Virtualization attack",
    description="One or more subsystems execute in a cloud environment where other cloud tenants sharing virtualized hardware are malicious.",
    refines=compromised_device,
    mitigations=[
        MitigationApplication(
            mitigation=mit.cybersecurity_virtualization,
            rationale="General cybersecurity practices aimed to prevent against virtualization-related attacks reduce the likelihood of an adversary successfully mounting such attacks.",
        ),
    ],
)

malicious_hardware = AttackPattern(
    id="malicious_hardware",
    name="Malicious hardware",
    description="One or more subsystems execute on malicious hardware.",
    refines=compromised_device,
    mitigations=[
        MitigationApplication(
            mitigation=OUT_OF_SCOPE,
            rationale="A malicious hardware vendor could design backdoors granting it full control of subsystems executing within its devices.",
        ),
    ],
)


# =============================================================================
# COMPROMISED USER DEVICE pattern
# =============================================================================

compromised_user_device = AttackPattern(
    id="compromised_user_device",
    name="Compromised user device",
    description="An adversary gains control of a user device that runs the {VA} or {BCA}. Unlike in attack {Compromised device}, this device is outside the control of the administrators of the voting system.",
)


# =============================================================================
# BROKEN CRYPTOGRAPHY patterns
# =============================================================================

broken_cryptography = AttackPattern(
    id="broken_cryptography",
    name="Broken cryptography",
    description="An aspect of the cryptography used in the system is flawed in a way that invalidates some or all of its security properties.",
)

broken_primitive = AttackPattern(
    id="broken_primitive",
    name="Broken primitive",
    description="One or more employed cryptographic primitives is fundamentally broken and is exploited.",
    refines=broken_cryptography,
    mitigations=[
        MitigationApplication(
            mitigation=mit.security_proof,
            rationale="A (preferably formal) security proof provides some level of assurance that a cryptographic primitive is not broken.",
        ),
    ],
)

insecure_implementation_owned = AttackPattern(
    id="insecure_implementation_owned",
    name="Insecure implementation---Owned",
    description="The implementation within owned source code is insecure and is exploited.",
    refines=broken_cryptography,
    mitigations=[
        MitigationApplication(
            mitigation=mit.formal_verification,
            rationale="Formal verification provides assurance that the source code satisfies its specification.",
        ),
        MitigationApplication(
            mitigation=mit.external_audits,
            rationale="External audits of the source code provide additional assurance about its security.",
        ),
    ],
)

insecure_implementation_dependency = AttackPattern(
    id="insecure_implementation_dependency",
    name="Insecure implementation---Dependency",
    description="The implementation within a software dependency is insecure and is exploited.",
    refines=broken_cryptography,
    mitigations=[
        MitigationApplication(
            mitigation=mit.dependency_minimization,
            rationale="Minimizing the number and size of dependencies reduces the likelihood of insecure dependencies impacting system security.",
        ),
        MitigationApplication(
            mitigation=mit.formally_verified_dependencies,
            rationale="Formal verification provides assurance that dependencies satisfy their specifications and the system's requirements upon them.",
        ),
    ],
)

insecure_platform = AttackPattern(
    id="insecure_platform",
    name="Insecure platform",
    description="The implementation of an operating system or hardware service (such as entropy collection) is insecure and is exploited.",
    refines=broken_cryptography,
    mitigations=[
        MitigationApplication(
            mitigation=mit.audited_platforms,
            rationale="Platform audits reduce the likelihood of insecure implementations.",
        ),
    ],
)

insecure_parameters = AttackPattern(
    id="insecure_parameters",
    name="Insecure parameters",
    description="The parameters used to instantiate the cryptographic primitive are insecure and are exploited.",
    refines=broken_cryptography,
    mitigations=[
        MitigationApplication(
            mitigation=mit.security_proof,
            rationale="A (preferably formal) security proof provides some level of assurance that cryptographic parameters are secure.",
        ),
        MitigationApplication(
            mitigation=mit.external_audits,
            rationale="External audits of the security parameters provide additional assurance about their security.",
        ),
    ],
)


# =============================================================================
# COMPROMISED NETWORK patterns
# =============================================================================

compromised_network = AttackPattern(
    id="compromised_network",
    name="Compromised network",
    description="Network behavior is altered in a way that affects the system's security.",
)

network_tampering = AttackPattern(
    id="network_tampering",
    name="Network tampering",
    description="An adversary exploits network weaknesses to add, drop, or forge protocol communications.",
    refines=compromised_network,
    mitigations=[
        MitigationApplication(
            mitigation=mit.message_signatures,
            rationale="Application-level digital signatures provide data integrity and authentication for application messages sent on the network.",
        ),
        MitigationApplication(
            mitigation=mit.tls,
            rationale="Transport layer security provides data integrity and authentication within the network.",
        ),
    ],
)

network_sabotage = AttackPattern(
    id="network_sabotage",
    name="Network sabotage",
    description="An adversary broadly disrupts network operation with respect to one or more subsystems or actors.",
    refines=compromised_network,
)


# =============================================================================
# ACTOR patterns
# =============================================================================

corruption = AttackPattern(
    id="corruption",
    name="Corruption",
    description="One or more subsystems or actors behaves maliciously.",
    mitigations=[
        MitigationApplication(
            mitigation=mit.trust_distribution,
            rationale="Distributing trust among multiple subsystems and actors reduces the likelihood that a corrupt subsystem or actor can compromise the system's security.",
        ),
        MitigationApplication(
            mitigation=mit.operational_redundancy,
            rationale="Redundancy in deployed implementations can reduce the likelihood that a corrupt subsystem or actor can compromise the system's availability.",
        ),
    ],
)

side_channel = AttackPattern(
    id="side_channel",
    name="Side channel",
    description="An adversary acquires sensitive information via unintended, indirect mechanisms (e.g., electromagnetic radiation) that arise from the execution of the protocol on physical machines and networks.",
    mitigations=[
        MitigationApplication(
            mitigation=mit.external_audits,
            rationale="External audits to evaluate side-channel resistance of implementations can often rule out or quantify the severity of specific side channel risks.",
        ),
    ],
)

phishing = AttackPattern(
    id="phishing",
    name="Phishing",
    description="An adversary acquires sensitive information from a protocol actor via deceptive means external to the protocol.",
    mitigations=[
        MitigationApplication(
            mitigation=OUT_OF_SCOPE,
            rationale="If a protocol actor can be social engineered into revealing sufficient information to enable an adversary to participate as them within the protocol, there is no way for the system to distinguish between the adversary and the legitimate actor.",
        ),
    ],
)

spoofing = AttackPattern(
    id="spoofing",
    name="Spoofing",
    description="An adversary attacks the system by masquerading as a protocol subsystem or actor.",
    mitigations=[
        MitigationApplication(
            mitigation=mit.controlled_environment,
            rationale="For some parts of the system, a controlled environment can prevent adversaries from masquerading as protocol actors (e.g., the identities of trustees can be physically verified when they enter the room housing the {AGN}). However, much of the system is run in uncontrolled environments.",
        ),
        MitigationApplication(
            mitigation=mit.message_signatures,
            rationale="Provided an adversary does not acquire the necessary signing keys (e.g., through {Phishing} or {Side channel}), the use of digitally signed messages within the protocol can prevent spoofed messages from impacting system security.",
        ),
    ],
)


# =============================================================================
# AUTO-COLLECT ALL PATTERNS
# =============================================================================

# Automatically collect all AttackPattern instances defined in this module
ALL = [obj for name, obj in globals().items()
       if isinstance(obj, AttackPattern) and not name.startswith('_')]
