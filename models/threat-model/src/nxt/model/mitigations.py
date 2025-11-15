# SecureVote Threat Model - Mitigations
# Countermeasures that prevent or reduce impact of attacks

from nxt import Mitigation, Scope


# === Verifiability Mitigations ===

cast_as_intended = Mitigation(
    id="M1",
    name="Cast as intended verifiability",
    description="A voter can verify that their ballot was cast as they intended.",
    scope=Scope.PARTIALLY_CORE,
)

recorded_as_cast = Mitigation(
    id="M2",
    name="Recorded as cast verifiability",
    description="A voter can verify that their recorded ballot is identical to the one they cast.",
    scope=Scope.PARTIALLY_CORE,
)

counted_as_recorded = Mitigation(
    id="M3",
    name="Counted as recorded verifiability",
    description="A voter can verify that their ballot was counted.",
    scope=Scope.PARTIALLY_CORE,
)

eligibility_verifiability = Mitigation(
    id="M4",
    name="Eligibility verifiability",
    description="An independent verifier can verify that no ineligible ballots were counted.",
    scope=Scope.PARTIALLY_CORE,
)

# === Cryptographic Mitigations ===

message_signatures = Mitigation(
    id="M5",
    name="Message signatures",
    description="Messages on the network are digitally signed.",
    scope=Scope.CORE,
)

tls = Mitigation(
    id="M6",
    name="TLS",
    description="Messages on the network use transport level security.",
    scope=Scope.NON_CORE,
)

# === Cybersecurity Mitigations ===

cybersecurity_malware = Mitigation(
    id="M7",
    name="Cybersecurity---Malware",
    description="The system deployment incorporates general cybersecurity practices aimed to protect against malware.",
    scope=Scope.NON_CORE,
)

cybersecurity_intrusion = Mitigation(
    id="M8",
    name="Cybersecurity---Intrusion",
    description="The system deployment incorporates general cybersecurity practices aimed to protect against intrusion.",
    scope=Scope.NON_CORE,
)

cybersecurity_escalation = Mitigation(
    id="M9",
    name="Cybersecurity---Escalation",
    description="The system deployment incorporates general cybersecurity practices aimed to protect against privilege escalation.",
    scope=Scope.NON_CORE,
)

cybersecurity_virtualization = Mitigation(
    id="M10",
    name="Cybersecurity---Virtualization",
    description="The system deployment incorporates general cybersecurity practices aimed to protect against virtualization-related attack vectors.",
    scope=Scope.NON_CORE,
)

# === Development Mitigations ===

dependency_minimization = Mitigation(
    id="M11",
    name="Dependency minimization",
    description="External software dependencies are minimized to those that are essential to system operation.",
    scope=Scope.PARTIALLY_CORE,
)

security_proof = Mitigation(
    id="M12",
    name="Security proof",
    description="A security proof of the protocol provides evidence that the selected primitives are secure with respect to precise assumptions and choices of security parameters.",
    scope=Scope.CORE,
)

formal_verification = Mitigation(
    id="M13",
    name="Formal verification",
    description="Formal verification techniques are used to formally prove implementation correctness for internal code.",
    scope=Scope.PARTIALLY_CORE,
)

external_audits = Mitigation(
    id="M14",
    name="External audits",
    description="External performers are engaged to conduct source code audits of internal code.",
    scope=Scope.NON_CORE,
)

formally_verified_dependencies = Mitigation(
    id="M15",
    name="Formally verified dependencies",
    description="External software dependencies are selected prioritizing those that have been subject to previous verification.",
    scope=Scope.PARTIALLY_CORE,
)

audited_platforms = Mitigation(
    id="M16",
    name="Audited platforms",
    description="OS/Hardware dependencies are selected prioritizing those that have been subject to audits.",
    scope=Scope.NON_CORE,
)

# === Trust & Operational Mitigations ===

trust_distribution = Mitigation(
    id="M17",
    name="Trust distribution",
    description="The actor's role is distributed such that the cooperation of several parties is required to perform its operations. An adversary must control or convince a sufficient number of parties to carry out the attack. The use of a threshold cryptographic system is an example of Trust distribution, but also of {M25} (Operational redundancy).",
    scope=Scope.PARTIALLY_CORE,
)

ballot_uniqueness_audit = Mitigation(
    id="M18",
    name="Ballot uniqueness audit",
    description="From Küsters et al.~{[[KustersEtAlClashAttacks2012]]}: In addition to checking whether the audited ballot is in fact computed with the voter's choice and the random coins provided by the browser for that ballot, a voter also ensures that all ballots (including the submitted ballot) constructed by the browser are different. For this purpose, a voter would typically record the ballots in some way, e.g., by having them emailed to her, and then compare these ballots.",
    scope=Scope.PARTIALLY_CORE,
)

tamper_evident_bulletin_board = Mitigation(
    id="M19",
    name="Tamper evident bulletin board",
    description="A hash chain is used to implement the bulletin board.",
    scope=Scope.PARTIALLY_CORE,
)

controlled_environment = Mitigation(
    id="M20",
    name="Controlled environment",
    description="The physical location housing the {AGN} as well as the hardware on which the {TA} and {TAS} run is a controlled environment with restricted access.",
    scope=Scope.NON_CORE,
)

# === Cryptographic Primitives ===

non_malleable_cryptosystem = Mitigation(
    id="M21",
    name="Non-malleable cryptosystem",
    description="A CCA2-secure cryptosystem (e.g., Naor-Yung) is used to make ciphertexts non-malleable.",
    scope=Scope.CORE,
)

proof_of_plaintext_knowledge = Mitigation(
    id="M22",
    name="Proof of plaintext knowledge",
    description="Zero-knowledge proofs of plaintext knowledge attached to cast ballots are required when casting. Adversaries casting related ballots will not be able to produce such proofs. See Bernhard et al.~{[[BernhardEtAlHowNot2012a]]}",
    scope=Scope.CORE,
)

ballot_weeding = Mitigation(
    id="M23",
    name="Ballot weeding",
    description="Duplicates are removed from the set of ballots submitted to the mixnet; see Bernhard et al.~{[[BernhardEtAlAdaptingHelios2011]]} Typically a duplicate ballot is defined as a ballot that is identical to one cast previously. It is important to carefully consider when the duplicate weeding takes place, either at cast time or during mixnet submission. For example, detection at cast time can lead to performance problems, whereas postponing this to mixnet submission time can lead to disputes.",
    scope=Scope.PARTIALLY_CORE,
)

voter_pseudonyms = Mitigation(
    id="M24",
    name="Voter pseudonyms",
    description="Data published to achieve {M4} (Eligibility verifiability) only reveals pseudonyms. Even if ballot encryption is compromised, its content cannot be linked to real identities using public information. See Haines et al.~{[[HainesEtAlSoKSecure2023]]} for other approaches to everlasting privacy.",
    scope=Scope.CORE,
)

operational_redundancy = Mitigation(
    id="M25",
    name="Operational redundancy",
    description="The use of redundant subsystems or actors allows individual elements to fail without compromising the overall operation of the system. The use of a threshold cryptographic system is an example of Operational redundancy, but also of {M17} (Trust distribution).",
    scope=Scope.PARTIALLY_CORE,
)

denial_of_service_protection = Mitigation(
    id="M26",
    name="Denial of service protection",
    description="Standard denial of service protection techniques, typically offered by cloud vendors, are employed.",
    scope=Scope.NON_CORE,
)

cybersecurity_supply_chain = Mitigation(
    id="M27",
    name="Cybersecurity---Supply chains",
    description="The system deployment incorporates general cybersecurity practices aimed to protect against supply chain attacks, for example attestation.",
    scope=Scope.NON_CORE,
)

domain_separation = Mitigation(
    id="M28",
    name="Domain separation",
    description="Cryptographic primitives are used in a way that ensures that they are not used in multiple contexts.",
    scope=Scope.PARTIALLY_CORE,
)

append_only_trustee_board = Mitigation(
    id="M29",
    name="Append-only trustee board",
    description="Each trustee maintains a local, append-only view of the protocol board.",
    scope=Scope.PARTIALLY_CORE,
)

auditable_pseudonyms = Mitigation(
    id="M30",
    name="Auditable pseudonyms",
    description="Pseudonyms can be constructed from auditable, but private, information using a one way function. This allows external auditors to privately verify that the identities certified by the EA are in fact eligible, without revealing those identities to the public (note that even if these identities were revealed, ballots are still protected by encryption).",
    scope=Scope.NON_CORE,
)

voter_specific_naor_yung_proofs = Mitigation(
    id="M31",
    name="Voter specific Naor-Yung proofs",
    description="Ballot cryptogram Naor-Yung proofs are made voter-specific, for example by including the voter's pseudonym or signature public key (or other voter derived value) in the proof challenge generation.",
    scope=Scope.CORE,
)
no_checks_on_cast_ballots = Mitigation(
    id="M32",
    name="No checks on cast ballots",
    description="An honest BCA will refuse to initiate, and an honest DBB will refuse to carry out, the ballot check protocol on a ballot that has already been cast, based on the presence of a matching cast ballot bulletin on the PBB.",
    scope=Scope.CORE,
)



# =============================================================================
# AUTO-COLLECT ALL MITIGATIONS
# =============================================================================

# Automatically collect all Mitigation instances defined in this module
ALL = [obj for name, obj in globals().items()
       if isinstance(obj, Mitigation) and not name.startswith('_')]
