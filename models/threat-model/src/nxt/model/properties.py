# SecureVote Threat Model - Properties
# Security properties with hierarchical AND composition

from nxt import Property


# === CONFIDENTIALITY ===
CONFIDENTIALITY = Property(
    id="CONFIDENTIALITY",
    description="The e-voting properties of Privacy, Everlasting privacy, Receipt-freeness, and Coercion-resistance are mapped to this security objective."
)

P1 = Property(
    id="P1",
    refines=CONFIDENTIALITY,
    description="It must not be possible to link a voter to their vote."
)

P1_1 = Property(
    id="P1.1",
    refines=P1,
    description="The only information on voter selections leaked by the voter application is the computed cryptogram."
)

P1_2 = Property(
    id="P1.2",
    refines=P1,
    description="It must not be possible for anyone to decrypt cryptograms in the absence of a threshold of trustees."
)

P1_3 = Property(
    id="P1.3",
    refines=P1,
    description="It must not be possible for anyone to determine the complete mixing permutations or randomization factors."
)

P1_4 = Property(
    id="P1.4",
    refines=P1,
    description="The decryption process must only operate on cryptograms output from the mixing process."
)

P2 = Property(
    id="P2",
    refines=CONFIDENTIALITY,
    description="It must not be possible for future computationally unbounded adversaries to link a voter to their vote using published data from past elections."
)

P3 = Property(
    id="P3",
    refines=CONFIDENTIALITY,
    description="It must not be possible for a voter to prove how they voted."
)

P3_1 = Property(
    id="P3.1",
    refines=P3,
    description="A voter does not gain a receipt that can be used to prove to anyone else that they voted in a certain way."
)

P3_2 = Property(
    id="P3.2",
    refines=P3,
    description="A voter cannot cooperate with a coercer to prove that they voted in a certain way."
)


# === INTEGRITY ===
INTEGRITY = Property(
    id="INTEGRITY",
    description="The e-voting properties of Accuracy, Eligibility, Fairness, Verifiability, and Dispute-freeness are mapped to this security objective."
)

CORRECTNESS = Property(
    id="CORRECTNESS",
    refines=INTEGRITY,
    description="Correctness is the sum of Accuracy + Eligibility + Fairness."
)

C1 = Property(id="C1", refines=CORRECTNESS, description="Votes are cast correctly.")
C1_1 = Property(id="C1.1", refines=C1, description="Each cryptogram cast by the {VA} is an encryption of data that accurately represents the voter's intent.")

C2 = Property(id="C2", refines=CORRECTNESS, description="Cast votes are correctly recorded.")
C2_1 = Property(id="C2.1", refines=C2, description="Each cryptogram recorded in the {BB} is identical to a cryptogram cast by the {VA}.")

C3 = Property(id="C3", refines=CORRECTNESS, description="Recorded votes are correctly counted.")
C3_1 = Property(id="C3.1", refines=C3, description="The set of cryptograms input to the mixing process is correct.")
C3_1_1 = Property(id="C3.1.1", refines=C3_1, description="Each cryptogram input to the mixing process must match one-to-one with an eligible voter.")
C3_1_2 = Property(id="C3.1.2", refines=C3_1, description="Each cryptogram input to the mixing process must match one-to-one with a cryptogram recorded in the ballot box.")

C3_2 = Property(id="C3.2", refines=C3, description="The set of cryptograms output by the mixing process must match one-to-one with the input set of cryptograms, such that each output cryptogram is an equivalent encryption of its matching input cryptogram.")
C3_3 = Property(id="C3.3", refines=C3, description="The set of cryptograms input to the decryption process is identical to the output of the mixing process.")
C3_4 = Property(id="C3.4", refines=C3, description="Each plaintext output by the decryption process must have been decrypted correctly.")
C3_4_1 = Property(id="C3.4.1", refines=C3_4, description="Each partial decryption of every cryptogram must have been computed correctly.")
C3_4_2 = Property(id="C3.4.2", refines=C3_4, description="Each plaintext for every cryptogram must have been computed correctly from its partial decryptions.")
C3_5 = Property(id="C3.5", refines=C3, description="The election outcome is correctly computed.")
C3_5_1 = Property(id="C3.5.1", refines=C3_5, description="The input to the tabulation algorithm is identical to the output of the decryption process.")
C3_5_2 = Property(id="C3.5.2", refines=C3_5, description="The tabulation algorithm is correctly applied.")
C3_6 = Property(id="C3.6", refines=C3, description="The set of printed ballots must match one-to-one with the decrypted plaintext outputs.")
C3_7 = Property(id="C3.7", refines=C3, description="The mixing, decryption, tabulation, and printing processes cannot begin until the election period is over and all cryptograms have been collected in the ballot box.")


# VERIFIABILITY
VERIFIABILITY = Property(id="VERIFIABILITY", refines=INTEGRITY, description="Verifiability refers to the ability to verify that {Correctness} properties hold.")
V1 = Property(id="V1", refines=VERIFIABILITY, description="Cast-as-intended verifiability")
V1_1 = Property(id="V1.1", refines=V1, description="Voters must be able to verify {C1.1} for their cryptograms.")
V2 = Property(id="V2", refines=VERIFIABILITY, description="Recorded-as-cast verifiability")
V2_1 = Property(id="V2.1", refines=V2, description="Voters must be able to verify {C2.1} for their cryptograms.")
V3 = Property(id="V3", refines=VERIFIABILITY, description="Counted-as-recorded verifiability")
V3_1 = Property(id="V3.1", refines=V3, description="Anyone must be able to verify {C3.1.2}, {C3.2}, {C3.3}, {C3.4}, and {C3.5}.")
V4 = Property(id="V4", refines=VERIFIABILITY, description="Eligibility verifiability")
V4_1 = Property(id="V4.1", refines=V4, description="Anyone must be able to verify {C3.1.1}.")
V5 = Property(id="V5", refines=VERIFIABILITY, description="Software independence")
V5_1 = Property(id="V5.1", refines=V5, description="An (undetected) change or error in the software cannot cause an undetectable change or error in an election outcome.")

# DISPUTE_FREENESS
DISPUTE_FREENESS = Property(id="DISPUTE_FREENESS", refines=INTEGRITY, description="In general, dispute-freeness refers to the existence of mechanisms to resolve disputes that may arise during the electoral process. Here, we restrict dispute-freeness to resolving three types of disputes, which yield child properties {D1}, {D2}, and {D3}. For brevity, we describe these properties as the disputes that must be resolved, but strictly speaking these properties refer to the ability to resolve said disputes.")
D1 = Property(id="D1", refines=DISPUTE_FREENESS, description="A voter claims to have cast a ballot $b$, while the election authority claims that they did not cast $b$.")
D2 = Property(id="D2", refines=DISPUTE_FREENESS, description="A voter claims to have not cast a ballot $b$, while the election authority claims that they did cast $b$.")
D3 = Property(id="D3", refines=DISPUTE_FREENESS, description="A voter claims that their device is producing incorrect cryptograms, while the election authority is unable to verify this claim.")


# === AVAILABILITY ===
AVAILABILITY = Property(id="AVAILABILITY", description="The e-voting properties of {Robustness} and {Scalability} are mapped to this security objective.")
A1 = Property(id="A1", refines=AVAILABILITY, description="Every voter must be able to cast their vote ({C1}, {C2}) such that their participation is not denied or hampered.")
A2 = Property(id="A2", refines=AVAILABILITY, description="All participants must be able to perform applicable verification operations ({V1}, {V2}, {V3}, {V4}) such that verifiability is not denied or hampered.")
A3 = Property(id="A3", refines=AVAILABILITY, description="The election outcome must be computed in a timely fashion.")
A4 = Property(id="A4", refines=AVAILABILITY, description="The election public key must be computed in a timely fashion.")


# =============================================================================
# AUTO-COLLECT ALL PROPERTIES
# =============================================================================

# Automatically collect all Property instances defined in this module
ALL = [obj for name, obj in globals().items()
       if isinstance(obj, Property) and not name.startswith('_')]
