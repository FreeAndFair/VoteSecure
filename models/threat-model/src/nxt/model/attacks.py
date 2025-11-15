# SecureVote Threat Model - Concrete Attacks
# Specific attacks instantiated from patterns

from nxt import Attack, MitigationApplication, OUT_OF_SCOPE
from . import contexts as ctx
from . import properties as prop
from . import patterns as pat
from . import mitigations as mit


# =============================================================================
# ATTACKS ON CORRECTNESS
# =============================================================================

# -----------------------------------------------------------------------------
# Mismatched encryption
# -----------------------------------------------------------------------------

mismatched_encryption = Attack(
    id="mismatched_encryption",
    name="Mismatched encryption",
)

cheating_voting_device = Attack(
    id="cheating_voting_device",
    name="Cheating voting device",
    description="The voting application encrypts a cryptogram that does not correspond to the voter's intent.",
    variant_of=pat.compromised_user_device,
    achieves=[mismatched_encryption],
    occurs_in=[ctx.VA],
    targets=[prop.C1_1],
    mitigations=[
        MitigationApplication(
            mitigation=mit.cast_as_intended,
            rationale="The ballot checking process will detect mismatched encrypted submissions. For a single compromised device, this checking process (assuming it is carried out by the voter using a different, uncompromised device) detects this attack, though only if the voter carries it out. In this case, the voter may resubmit their ballot using an uncompromised device, thwarting the attack for that voter. For large scale attacks that compromise multiple devices, the ballot checking process detects this attack with high probability if enough voters carry it out using uncompromised devices. If a procedure is in place whereby an election outcome is invalidated if a sufficient number of voters make reports of mismatched ciphertexts, the attack is additionally on {A3}. See also Malicious reporting.",
        ),
        MitigationApplication(
            mitigation=mit.recorded_as_cast,
            rationale="Ballot tracker checks on the bulletin boad will detect covert submit-and-cast of mismatched ciphertexts. For a single compromised device, this checking pocess (assuming it is carried out by the voter using a different, uncompromised device) detects this attack, though only if the voter carries it out. For large scale attacks that compromise multiple devices, the ballot tracking check detects this attack with high probability if enough voters carry it out using uncompromised devices. If this mitigation is successful, the attack may be thwarted for the voter, or becomes an attack on availability, depending on whether the voter has a recourse to correct  their submission. If the voter has a correcting recourse, the attack is thwarted for that voter.  If the voter's recourse is restricted to reporting and canceling the ballot, the attack is on {A1}. Finally, if a procedure is in place whereby an election outcome is invalidated if a sufficient number of voters make reports of mismatched ciphertexts, the attack is additionally on {A3}. See also Malicious reporting.",
        ),
    ],
)

# -----------------------------------------------------------------------------
# Ballot tampering
# -----------------------------------------------------------------------------

ballot_tampering = Attack(
    id="ballot_tampering",
    name="Ballot tampering",
)

ballot_tampering_network_in = Attack(
    id="ballot_tampering.network.IN",
    name="Network tampering",
    description="The network adds, alters or removes cryptograms.",
    variant_of=pat.network_tampering,
    achieves=[ballot_tampering],
    occurs_in=[ctx.IN],
    targets=[prop.C2_1],
    mitigations=[
        MitigationApplication(
            mitigation=mit.recorded_as_cast,
            rationale="For a single altered or removed cryptogram, the ballot tracker checking process detects this attack, though only if the voter carries it out. For large scale attacks that compromise multiple cryptograms, the ballot tracker checking process detects this attack with high probability if enough voters carry it out.",
        ),
    ],
)

ballot_tampering_network_ean = Attack(
    id="ballot_tampering.network.EAN",
    name="Network tampering",
    description="The network adds, alters or removes cryptograms.",
    variant_of=pat.network_tampering,
    achieves=[ballot_tampering],
    occurs_in=[ctx.EAN],
    targets=[prop.C2_1],
    mitigations=[
        MitigationApplication(
            mitigation=mit.recorded_as_cast,
            rationale="For a single altered or removed cryptogram, the ballot tracker checking process detects this attack, though only if the voter carries it out. For large scale attacks that compromise multiple cryptograms, the ballot tracker checking process detects this attack with high probability if enough voters carry it out.",
        ),
    ],
)

ballot_tampering_device_eas = Attack(
    id="ballot_tampering.device.EAS",
    name="Compromised device",
    description="One or more subsystems alters or removes cryptograms during input, storage in the ballot box or input to the mixing process.",
    variant_of=pat.compromised_device,
    achieves=[ballot_tampering],
    occurs_in=[ctx.EAS],
    targets=[prop.C2_1],
    mitigations=[
        MitigationApplication(
            mitigation=mit.recorded_as_cast,
            rationale="For a single altered or removed cryptogram, the ballot tracker checking process detects this attack, though only if the voter carries it out. For large scale attacks that compromise multiple cryptograms, the ballot tracker checking process detects this attack with high probability if enough voters carry it out.",
        ),
    ],
)

ballot_tampering_device_bb = Attack(
    id="ballot_tampering.device.BB",
    name="Compromised device",
    description="One or more subsystems alters or removes cryptograms during input, storage in the ballot box or input to the mixing process.",
    variant_of=pat.compromised_device,
    achieves=[ballot_tampering],
    occurs_in=[ctx.BB],
    targets=[prop.C2_1],
    mitigations=[
        MitigationApplication(
            mitigation=mit.recorded_as_cast,
            rationale="For a single altered or removed cryptogram, the ballot tracker checking process detects this attack, though only if the voter carries it out. For large scale attacks that compromise multiple cryptograms, the ballot tracker checking process detects this attack with high probability if enough voters carry it out.",
        ),
    ],
)

ballot_tampering_device_eaa = Attack(
    id="ballot_tampering.device.EAA",
    name="Compromised device",
    description="One or more subsystems alters or removes cryptograms during input, storage in the ballot box or input to the mixing process.",
    variant_of=pat.compromised_device,
    achieves=[ballot_tampering],
    occurs_in=[ctx.EAA],
    targets=[prop.C2_1],
    mitigations=[
        MitigationApplication(
            mitigation=mit.recorded_as_cast,
            rationale="For a single altered or removed cryptogram, the ballot tracker checking process detects this attack, though only if the voter carries it out. For large scale attacks that compromise multiple cryptograms, the ballot tracker checking process detects this attack with high probability if enough voters carry it out.",
        ),
    ],
)

ballot_tampering_device_est = Attack(
    id="ballot_tampering.device.EST",
    name="Compromised device",
    description="One or more subsystems alters or removes cryptograms during input, storage in the ballot box or input to the mixing process.",
    variant_of=pat.compromised_device,
    achieves=[ballot_tampering],
    occurs_in=[ctx.EST],
    targets=[prop.C2_1],
    mitigations=[
        MitigationApplication(
            mitigation=mit.recorded_as_cast,
            rationale="For a single altered or removed cryptogram, the ballot tracker checking process detects this attack, though only if the voter carries it out. For large scale attacks that compromise multiple cryptograms, the ballot tracker checking process detects this attack with high probability if enough voters carry it out.",
        ),
    ],
)

ballot_tampering_corruption_ea = Attack(
    id="ballot_tampering.corruption.EA",
    name="Corruption",
    description="The election administrator alters or removes cryptograms in the ballot box or during input to the mixing process.",
    variant_of=pat.corruption,
    achieves=[ballot_tampering],
    occurs_in=[ctx.EA],
    targets=[prop.C2_1],
    mitigations=[
        MitigationApplication(
            mitigation=mit.recorded_as_cast,
            rationale="For a single altered or removed cryptogram, the ballot tracker checking process detects this attack, though only if the voter carries it out. For large scale attacks that compromise multiple cryptograms, the ballot tracker checking process detects this attack with high probability if enough voters carry it out.",
        ),
    ],
)

# -----------------------------------------------------------------------------
# Ineligible ballots
# -----------------------------------------------------------------------------

ineligible_ballots = Attack(
    id="ineligible_ballots",
    name="Ineligible ballots",
)

ineligible_ballots_device_eas = Attack(
    id="ineligible_ballots.device.EAS",
    name="Compromised device",
    description="One or more subsystems operate such that the ballot box contains or the mixing process input contains ineligible cryptograms.",
    variant_of=pat.compromised_device,
    achieves=[ineligible_ballots],
    occurs_in=[ctx.EAS],
    targets=[prop.C2_1],
    mitigations=[
        MitigationApplication(
            mitigation=mit.eligibility_verifiability,
            rationale="The election verification process detects any cryptograms that do not have an eligible signature.",
        ),
    ],
)

ineligible_ballots_device_bb = Attack(
    id="ineligible_ballots.device.BB",
    name="Compromised device",
    description="One or more subsystems operate such that the ballot box contains or the mixing process input contains ineligible cryptograms.",
    variant_of=pat.compromised_device,
    achieves=[ineligible_ballots],
    occurs_in=[ctx.BB],
    targets=[prop.C2_1],
    mitigations=[
        MitigationApplication(
            mitigation=mit.eligibility_verifiability,
            rationale="The election verification process detects any cryptograms that do not have an eligible signature.",
        ),
    ],
)

ineligible_ballots_corruption_ea = Attack(
    id="ineligible_ballots.corruption.EA",
    name="Corruption",
    description="The election administrator manipulates a subsystem such that the ballot box or the mixing process input contain ineligible cryptograms.",
    variant_of=pat.corruption,
    achieves=[ineligible_ballots],
    occurs_in=[ctx.EA],
    targets=[prop.C2_1],
    mitigations=[
        MitigationApplication(
            mitigation=mit.eligibility_verifiability,
            rationale="The election verification process detects any cryptograms that do not have an eligible signature.",
        ),
    ],
)

ineligible_ballots_network_ean = Attack(
    id="ineligible_ballots.network.EAN",
    name="Network tampering",
    description="The network adds ineligible cryptograms during input to the mixing process.",
    variant_of=pat.network_tampering,
    achieves=[ineligible_ballots],
    occurs_in=[ctx.EAN],
    targets=[prop.C3_1],
    mitigations=[
        MitigationApplication(
            mitigation=mit.eligibility_verifiability,
            rationale="The election verification process detects any cryptograms that do not have an eligible signature.",
        ),
    ],
)

ineligible_ballots_network_eon = Attack(
    id="ineligible_ballots.network.EON",
    name="Network tampering",
    description="The network adds ineligible cryptograms during input to the mixing process.",
    variant_of=pat.network_tampering,
    achieves=[ineligible_ballots],
    occurs_in=[ctx.EON],
    targets=[prop.C3_1],
    mitigations=[
        MitigationApplication(
            mitigation=mit.eligibility_verifiability,
            rationale="The election verification process detects any cryptograms that do not have an eligible signature.",
        ),
    ],
)

ineligible_ballots_device_as = Attack(
    id="ineligible_ballots.device.AS",
    name="Compromised device",
    description="The authentication service works incorrectly.",
    variant_of=pat.compromised_device,
    achieves=[ineligible_ballots],
    occurs_in=[ctx.AS],
    targets=[prop.C3_1_1],
    mitigations=[
        MitigationApplication(
            mitigation=mit.eligibility_verifiability,
            rationale="The election verification process detects any cryptograms that do not have an eligible signature.",
        ),
    ],
)

ineligible_ballots_phishing = Attack(
    id="ineligible_ballots.phishing.CRD",
    name="Phishing",
    description="The voter is deceived into revealing their authentication credentials.",
    variant_of=pat.phishing,
    achieves=[ineligible_ballots],
    occurs_in=[ctx.CRD],
    targets=[prop.C3_1_1],
    mitigations=[
        MitigationApplication(
            mitigation=OUT_OF_SCOPE,
            rationale="Preventing this attack is outside the system scope. If a voter can be social engineered into giving somebody else full access to their required authentication credentials, the new possessor of those credentials will be able to vote on their behalf.",
        ),
    ],
)

# -----------------------------------------------------------------------------
# Bad mixing
# -----------------------------------------------------------------------------

bad_mixing = Attack(
    id="bad_mixing",
    name="Bad mixing",
)

bad_mixing_device_ta = Attack(
    id="bad_mixing.device.TA",
    name="Compromised device",
    description="The trustee application shuffles incorrectly.",
    variant_of=pat.compromised_device,
    achieves=[bad_mixing],
    occurs_in=[ctx.TA],
    targets=[prop.C3_2],
    mitigations=[
        MitigationApplication(
            mitigation=mit.counted_as_recorded,
            rationale="Mathematical proofs of correct shuffling are computed.",
        ),
    ],
)

bad_mixing_corruption_tr = Attack(
    id="bad_mixing.corruption.TR",
    name="Corruption",
    description="The trustee manipulates the subsystem to shuffle incorrectly.",
    variant_of=pat.corruption,
    achieves=[bad_mixing],
    occurs_in=[ctx.TR],
    targets=[prop.C3_2],
    mitigations=[
        MitigationApplication(
            mitigation=mit.counted_as_recorded,
            rationale="Mathematical proofs of correct shuffling are computed.",
        ),
    ],
)

bad_mixing_device_tas = Attack(
    id="bad_mixing.device.TAS",
    name="Compromised device",
    description="The trustee application server alters, adds or removes mix cryptograms.",
    variant_of=pat.compromised_device,
    achieves=[bad_mixing],
    occurs_in=[ctx.TAS],
    targets=[prop.C3_2, prop.C3_3],
    mitigations=[
        MitigationApplication(
            mitigation=mit.counted_as_recorded,
            rationale="Mathematical proofs of correct shuffling are computed.",
        ),
        MitigationApplication(
            mitigation=mit.message_signatures,
            rationale="Trustees sign messages as part of the shuffling protocol. The {TAS} would need to forge these signatures to carry out the attack while evading detection.",
        ),
    ],
)

bad_mixing_network_agn = Attack(
    id="bad_mixing.network.AGN",
    name="Network tampering",
    description="The network alters, adds or removes mix cryptograms.",
    variant_of=pat.compromised_network,
    achieves=[bad_mixing],
    occurs_in=[ctx.AGN],
    targets=[prop.C3_2, prop.C3_3],
    mitigations=[
        MitigationApplication(
            mitigation=mit.counted_as_recorded,
            rationale="Mathematical proofs of correct shuffling are computed.",
        ),
    ],
)

bad_mixing_corruption_ea = Attack(
    id="bad_mixing.corruption.EA",
    name="Corruption",
    description="The election administrator alters, adds or removes mix cryptograms.",
    variant_of=pat.corruption,
    achieves=[bad_mixing],
    occurs_in=[ctx.EA],
    targets=[prop.C3_4, prop.C3_5],
    mitigations=[
        MitigationApplication(
            mitigation=mit.counted_as_recorded,
            rationale="Mathematical proofs of correct shuffling are computed.",
        ),
        MitigationApplication(
            mitigation=mit.message_signatures,
            rationale="Trustees sign messages as part of the shuffling protocol. The {EA} would need to forge these signatures to carry out the attack while evading detection.",
        ),
    ],
)

# -----------------------------------------------------------------------------
# Bad decryption
# -----------------------------------------------------------------------------

bad_decryption = Attack(
    id="bad_decryption",
    name="Bad decryption",
)

bad_decryption_device_ta = Attack(
    id="bad_decryption.device.TA",
    name="Compromised device",
    description="The trustee application decrypts incorrectly.",
    variant_of=pat.compromised_device,
    achieves=[bad_decryption],
    occurs_in=[ctx.TA],
    targets=[prop.C3_4],
    mitigations=[
        MitigationApplication(
            mitigation=mit.counted_as_recorded,
            rationale="Mathematical proofs of correct decryption are computed.",
        ),
    ],
)

bad_decryption_device_tst = Attack(
    id="bad_decryption.device.TST",
    name="Compromised device",
    description="The trustee application decrypts incorrectly.",
    variant_of=pat.compromised_device,
    achieves=[bad_decryption],
    occurs_in=[ctx.TST],
    targets=[prop.C3_4],
    mitigations=[
        MitigationApplication(
            mitigation=mit.counted_as_recorded,
            rationale="Mathematical proofs of correct decryption are computed.",
        ),
    ],
)

bad_decryption_corruption_tr = Attack(
    id="bad_decryption.corruption.TR",
    name="Corruption",
    description="The trustee manipulates the subsystem to decrypt incorrectly.",
    variant_of=pat.corruption,
    achieves=[bad_decryption],
    occurs_in=[ctx.TR],
    targets=[prop.C3_4],
    mitigations=[
        MitigationApplication(
            mitigation=mit.counted_as_recorded,
            rationale="Mathematical proofs of correct decryption are computed.",
        ),
    ],
)

bad_decryption_device_tas = Attack(
    id="bad_decryption.device.TAS",
    name="Compromised device",
    description="One or more subsystems alter, add or remove decryption cryptograms or plaintexts.",
    variant_of=pat.compromised_device,
    achieves=[bad_decryption],
    occurs_in=[ctx.TAS],
    targets=[prop.C3_4, prop.C3_5],
    mitigations=[
        MitigationApplication(
            mitigation=mit.counted_as_recorded,
            rationale="Mathematical proofs of correct decryption are computed.",
        ),
        MitigationApplication(
            mitigation=mit.message_signatures,
            rationale="Trustees sign messages as part of the shuffling protocol. The {TAS}/{EST} would need to forge these signatures to carry out the attack while evading detection.",
        ),
    ],
)

bad_decryption_device_est = Attack(
    id="bad_decryption.device.EST",
    name="Compromised device",
    description="One or more subsystems alter, add or remove decryption cryptograms or plaintexts.",
    variant_of=pat.compromised_device,
    achieves=[bad_decryption],
    occurs_in=[ctx.EST],
    targets=[prop.C3_4, prop.C3_5],
    mitigations=[
        MitigationApplication(
            mitigation=mit.counted_as_recorded,
            rationale="Mathematical proofs of correct decryption are computed.",
        ),
        MitigationApplication(
            mitigation=mit.message_signatures,
            rationale="Trustees sign messages as part of the shuffling protocol. The {TAS}/{EST} would need to forge these signatures to carry out the attack while evading detection.",
        ),
    ],
)

bad_decryption_network_agn = Attack(
    id="bad_decryption.network.AGN",
    name="Network tampering",
    description="The network alters, adds or removes decryption cryptograms or plaintexts.",
    variant_of=pat.network_tampering,
    achieves=[bad_decryption],
    occurs_in=[ctx.AGN],
    targets=[prop.C3_4, prop.C3_5],
    mitigations=[
        MitigationApplication(
            mitigation=mit.counted_as_recorded,
            rationale="Mathematical proofs of correct decryption are computed.",
        ),
    ],
)

bad_decryption_corruption_ea = Attack(
    id="bad_decryption.corruption.EA",
    name="Corruption",
    description="The election administrator alters, adds or removes decryption cryptograms or plaintexts.",
    variant_of=pat.corruption,
    achieves=[bad_decryption],
    occurs_in=[ctx.EA],
    targets=[prop.C3_4, prop.C3_5],
    mitigations=[
        MitigationApplication(
            mitigation=mit.counted_as_recorded,
            rationale="Proofs of shuffle and decryption bind the input ciphertexts to the output plaintexts.",
        ),
        MitigationApplication(
            mitigation=mit.message_signatures,
            rationale="Trustees sign messages as part of the shuffling protocol. The {EA} would need to forge these signatures to carry out the attack while evading detection.",
        ),
    ],
)

# -----------------------------------------------------------------------------
# Bad tabulation
# -----------------------------------------------------------------------------

bad_tabulation = Attack(
    id="bad_tabulation",
    name="Bad tabulation",
)

bad_tabulation_network_ean = Attack(
    id="bad_tabulation.network.EAN",
    name="Network tampering",
    description="The network alters, adds or removes plaintexts.",
    variant_of=pat.compromised_network,
    achieves=[bad_tabulation],
    occurs_in=[ctx.EAN],
    targets=[prop.C3_4, prop.C3_5],
    mitigations=[
        MitigationApplication(
            mitigation=mit.counted_as_recorded,
            rationale="Proofs of shuffle and decryption bind the input ciphertexts to the output plaintexts.",
        ),
    ],
)

bad_tabulation_device_eas = Attack(
    id="bad_tabulation.device.EAS",
    name="Compromised device",
    description="The election administration server applies the tabulation algorithm incorrectly.",
    variant_of=pat.compromised_device,
    achieves=[bad_tabulation],
    occurs_in=[ctx.EAS],
    targets=[prop.C3_5_2],
    mitigations=[
        MitigationApplication(
            mitigation=mit.counted_as_recorded,
            rationale="Counted as recorded verifiability can be extended to include tabulation such that tabulation is independently computed by verifiers.",
        ),
    ],
)

bad_tabulation_corruption_ea = Attack(
    id="bad_tabulation.corruption.EA",
    name="Corruption",
    description="The election administrator manipulates the subsystem to tabulate incorrectly.",
    variant_of=pat.corruption,
    achieves=[bad_tabulation],
    occurs_in=[ctx.EA],
    targets=[prop.C3_5_2],
    mitigations=[
        MitigationApplication(
            mitigation=mit.counted_as_recorded,
            rationale="Counted as recorded verifiability can be extended to include tabulation such that tabulation is independently computed by verifiers.",
        ),
    ],
)

# -----------------------------------------------------------------------------
# Bad printing
# -----------------------------------------------------------------------------

bad_printing = Attack(
    id="bad_printing",
    name="Bad printing",
)

bad_printing_device_tas = Attack(
    id="bad_printing.device.TAS",
    name="Compromised device",
    description="The trustee administration server sends plaintexts to the ballot printer incorrectly.",
    variant_of=pat.compromised_device,
    achieves=[bad_printing],
    occurs_in=[ctx.TAS],
    targets=[prop.C3_6],
    mitigations=[
        MitigationApplication(
            mitigation=mit.counted_as_recorded,
            rationale="Proofs of shuffle and decryption bind the input ciphertexts to the output plaintexts.",
        ),
        MitigationApplication(
            mitigation=mit.message_signatures,
            rationale="Trustees sign messages as part of the shuffling protocol. The {TAS} would need to forge these signatures to carry out the attack while evading detection.",
        ),
    ],
)

bad_printing_device_bp = Attack(
    id="bad_printing.device.BP",
    name="Compromised device",
    description="The ballot printer prints ballots from plaintexts incorrectly.",
    variant_of=pat.compromised_device,
    achieves=[bad_printing],
    occurs_in=[ctx.BP],
    targets=[prop.C3_6],
    mitigations=[
        MitigationApplication(
            mitigation=mit.counted_as_recorded,
            rationale="Proofs of shuffle and decryption bind the input ciphertexts to the output plaintexts.",
        ),
    ],
)

bad_printing_network_agn = Attack(
    id="bad_printing.network.AGN",
    name="Network tampering",
    description="The network alters, adds, or removes plaintexts sent to the ballot printer.",
    variant_of=pat.compromised_network,
    achieves=[bad_printing],
    occurs_in=[ctx.AGN],
    targets=[prop.C3_6],
    mitigations=[
        MitigationApplication(
            mitigation=mit.counted_as_recorded,
            rationale="Proofs of shuffle and decryption bind the input ciphertexts to the output plaintexts.",
        ),
    ],
)

bad_printing_corruption_ea = Attack(
    id="bad_printing.corruption.EA",
    name="Corruption",
    description="The election administrator manipulates the set of plaintexts sent to the ballot printer, or manipulates the ballot printer itself, to print an incorrect set of ballots.",
    variant_of=pat.corruption,
    achieves=[bad_printing],
    occurs_in=[ctx.EA],
    targets=[prop.C3_6],
    mitigations=[
        MitigationApplication(
            mitigation=mit.message_signatures,
            rationale="Trustees sign messages as part of the shuffling protocol. The {EA} would need to forge these signatures to carry out the attack while evading detection.",
        ),
    ],
)

# -----------------------------------------------------------------------------
# Premature tabulation
# -----------------------------------------------------------------------------

premature_tabulation = Attack(
    id="premature_tabulation",
    name="Premature tabulation",
)

premature_tabulation_corruption_ea = Attack(
    id="premature_tabulation.corruption.EA",
    name="Corruption",
    description="Several actors cooperate to produce a premature tally.",
    variant_of=pat.corruption,
    achieves=[premature_tabulation],
    occurs_in=[ctx.EA],
    targets=[prop.C3_7],
)

premature_tabulation_corruption_tr = Attack(
    id="premature_tabulation.corruption.TR",
    name="Corruption",
    description="Several actors cooperate to produce a premature tally.",
    variant_of=pat.corruption,
    achieves=[premature_tabulation],
    occurs_in=[ctx.TR],
    targets=[prop.C3_7],
)


# =============================================================================
# ATTACKS ON VERIFIABILITY
# =============================================================================

# -----------------------------------------------------------------------------
# Malicious verification application
# -----------------------------------------------------------------------------

malicious_verification_application = Attack(
    id="malicious_verification_application",
    name="Malicious verification application",
)

cheating_ballot_checking_application = Attack(
    id="cheating_ballot_checking_application",
    name="Cheating ballot checking application",
    description="The checking application does not provide correct information about audited cryptograms.",
    variant_of=pat.compromised_user_device,
    achieves=[malicious_verification_application],
    occurs_in=[ctx.BCA],
    targets=[prop.V1],
    mitigations=[
        MitigationApplication(
            mitigation=OUT_OF_SCOPE,
            rationale="If the (ideally secondary) device used to execute cryptogram audits is compromised, cast-as-intended verifiability is broken.",
        ),
    ],
)

cheating_auditing_application = Attack(
    id="cheating_auditing_application",
    name="Cheating auditing application",
    description="The checking application does not perform election verification operations correctly. See also {[further-remarks-checking-application][further remarks on the checking application]}.",
    variant_of=pat.compromised_user_device,
    achieves=[malicious_verification_application],
    occurs_in=[ctx.VER],
    targets=[prop.V2, prop.V3],
    mitigations=[
        MitigationApplication(
            mitigation=OUT_OF_SCOPE,
            rationale="If the device used to perform ballot tracking code checks is compromised, recorded-as-cast and counted-as-recorded verifiability are broken for the user of that device. However, election audits ({V3}) can be carried out by anyone and are general verifications that do not depend on specific ballot tracking codes. Note that the compromise of arbitrary devices used to perform election verification by arbitrary users is also out of scope.",
        ),
    ],
)

# -----------------------------------------------------------------------------
# Malicious bulletin board
# -----------------------------------------------------------------------------

malicious_bulletin_board = Attack(
    id="malicious_bulletin_board",
    name="Malicious bulletin board",
)

cheating_bb_cryptogram_check = Attack(
    id="cheating_bb_cryptogram_check",
    name="Cheating BB---cryptogram check",
    description="The bulletin board does not provide correct information about cryptograms in the ballot box.",
    variant_of=pat.compromised_device,
    achieves=[malicious_bulletin_board],
    occurs_in=[ctx.BB],
    targets=[prop.V2],
)

cheating_bb_election_audit = Attack(
    id="cheating_bb_election_audit",
    name="Cheating BB---election audit",
    description="The bulletin board does not provide correct election auditing information.",
    variant_of=pat.compromised_device,
    achieves=[malicious_bulletin_board],
    occurs_in=[ctx.BB],
    targets=[prop.V2, prop.V3],
)

cheating_ea_cryptogram_check = Attack(
    id="cheating_ea_cryptogram_check",
    name="Cheating EA---cryptogram check",
    description="The election administrator manipulates the bulletin board such that it does not not provide correct information about cryptograms in the ballot box.",
    variant_of=pat.corruption,
    achieves=[malicious_bulletin_board],
    occurs_in=[ctx.EA],
    targets=[prop.V2],
)

cheating_ea_election_audit = Attack(
    id="cheating_ea_election_audit",
    name="Cheating EA---election audit",
    description="The election administrator manipulates the bulletin board such that it does not not provide correct election auditing information.",
    variant_of=pat.corruption,
    achieves=[malicious_bulletin_board],
    occurs_in=[ctx.EA],
    targets=[prop.V2, prop.V3],
)

toctou_compromised_device = Attack(
    id="toctou_compromised_device",
    name="Time of Check to Time of Use---Compromised device",
    description="The bulletin board removes cryptograms between user checks and tallying.",
    variant_of=pat.compromised_device,
    achieves=[malicious_bulletin_board],
    occurs_in=[ctx.BB],
    targets=[prop.V2, prop.V3],
    mitigations=[
        MitigationApplication(
            mitigation=mit.tamper_evident_bulletin_board,
            rationale="If multiple observers perform verifications with overlapping intervals their results become coupled. An adversary will need to account for this to remain undetected, making undetected manipulations more difficult.",
        ),
    ],
)

toctou_corruption = Attack(
    id="toctou_corruption",
    name="Time of Check to Time of Use---Corruption",
    description="The election administrator manipulates the bulletin board such that cryptograms are removed between user checks and tallying.",
    variant_of=pat.corruption,
    achieves=[malicious_bulletin_board],
    occurs_in=[ctx.EA],
    targets=[prop.V2, prop.V3],
    mitigations=[
        MitigationApplication(
            mitigation=mit.tamper_evident_bulletin_board,
            rationale="If multiple observers perform verifications with overlapping intervals their results become coupled. An adversary will need to account for this to remain undetected, making undetected manipulations more difficult.",
        ),
    ],
)

# -----------------------------------------------------------------------------
# Clash attack
# -----------------------------------------------------------------------------


clash_attack = Attack(
    id="clash_attack",
    name="Clash attack",
    description="Clash attacks break verifiability by tricking many voters into performing checks against the same cryptogram.~{[[KustersEtAlClashAttacks2012]]}",
)

clash_attack_v1 = Attack(
    id="clash_attack_v1",
    name="Clash attack v1",
    description="The voting application encrypts identical votes with identical randomness such that many voters will perform checks against the same cryptogram.~{[[KustersEtAlClashAttacks2012]]}",
    variant_of=pat.compromised_user_device,
    achieves=[clash_attack],
    occurs_in=[ctx.VD],
    targets=[prop.V2],
    mitigations=[
        MitigationApplication(
            mitigation=mit.voter_pseudonyms,
            rationale="Ballot trackers cannot be reused as they are specific to each voter pseudonym.",
        ),
        MitigationApplication(
            mitigation=mit.voter_specific_naor_yung_proofs,
            rationale="The use of voter specific Naor-Yung proofs prevents the reuse of cryptograms across different voters.",
        ),
        MitigationApplication(
            mitigation=mit.no_checks_on_cast_ballots,
            rationale="Attacks that use randomizers corresponding to cast ballots in the the ballot checking process are not possible.",
        ),
    ],
)

clash_attack_v2 = Attack(
    id="clash_attack_v2",
    name="Clash attack v2",
    description="The voting application encrypts identical votes with identical randomness. The election administrator manipulates the bulletin board such that many voters will perform checks against the same cryptogram.~{[[KustersEtAlClashAttacks2012]]}",
    targets=[prop.V2],
    achieves=[clash_attack],
)
"""
clash_attack_v2_bb = Attack(
    id="clash_attack_v2_bb",
    name="Clash attack - bb manipulation",
    description="The election administrator manipulates the bulletin board such that many voters will perform checks against the same cryptogram.~{[[KustersEtAlClashAttacks2012]]}",
    requires=[clash_attack_v2],
    variant_of=pat.corruption,
    occurs_in=[ctx.EA],
    mitigations=[
        MitigationApplication(
            mitigation=mit.ballot_uniqueness_audit,
            rationale="Cast as intended verifiability is augmented with ballot uniqueness checks.",
        ),
    ],
)

clash_attack_v2_device = Attack(
    id="clash_attack_v2_device",
    name="Clash attack - compromised voting device",
    description="The voting application encrypts identical votes with identical randomness such many voters will perform checks against the same cryptogram.~{[[KustersEtAlClashAttacks2012]]}",
    requires=[clash_attack_v2],
    variant_of=pat.compromised_user_device,
    occurs_in=[ctx.VD]
)
"""

# -----------------------------------------------------------------------------
# Broken shuffle/decryption/signature proofs
# -----------------------------------------------------------------------------

broken_shuffle_proofs = Attack(
    id="broken_shuffle_proofs",
    name="Broken shuffle proofs",
)

broken_shuffle_proofs_crypto = Attack(
    id="broken_shuffle_proofs.crypto.TA",
    name="Broken cryptography",
    description="Shuffle proofs do not prove shuffle correctness.",
    variant_of=pat.broken_cryptography,
    achieves=[broken_shuffle_proofs],
    occurs_in=[ctx.TA],
    targets=[prop.V3],
)

broken_decryption_proofs = Attack(
    id="broken_decryption_proofs",
    name="Broken decryption proofs",
)

broken_decryption_proofs_crypto = Attack(
    id="broken_decryption_proofs.crypto.TA",
    name="Broken cryptography",
    description="Decryption proofs do not prove decryption correctness.",
    variant_of=pat.broken_cryptography,
    achieves=[broken_decryption_proofs],
    occurs_in=[ctx.TA],
    targets=[prop.V3],
)

broken_signatures = Attack(
    id="broken_signatures",
    name="Broken signatures",
)

broken_signatures_crypto_va = Attack(
    id="broken_signatures.crypto.VA",
    name="Broken cryptography",
    description="Ballot signatures do not prove eligibility.",
    variant_of=pat.broken_cryptography,
    achieves=[broken_signatures],
    occurs_in=[ctx.VA],
    targets=[prop.V4],
)

broken_signatures_crypto_eas = Attack(
    id="broken_signatures.crypto.EAS",
    name="Broken cryptography",
    description="Ballot signatures do not prove eligibility.",
    variant_of=pat.broken_cryptography,
    achieves=[broken_signatures],
    occurs_in=[ctx.EAS],
    targets=[prop.V4],
)

broken_signatures_crypto_bca = Attack(
    id="broken_signatures.crypto.BCA",
    name="Broken cryptography",
    description="Ballot signatures do not prove eligibility.",
    variant_of=pat.broken_cryptography,
    achieves=[broken_signatures],
    occurs_in=[ctx.BCA],
    targets=[prop.V4],
)

# -----------------------------------------------------------------------------
# Compromised signature keys
# -----------------------------------------------------------------------------

compromised_signature_keys = Attack(
    id="compromised_signature_keys",
    name="Compromised signature keys",
)

compromised_signature_keys_phishing = Attack(
    id="compromised_signature_keys.phishing.VSIG",
    name="Phishing",
    description="The voter is deceived into revealing their ballot signing secret key material.",
    variant_of=pat.phishing,
    achieves=[compromised_signature_keys],
    occurs_in=[ctx.VSIG],
    targets=[prop.V4],
    mitigations=[
        MitigationApplication(
            mitigation=OUT_OF_SCOPE,
            rationale="If a voter can be social engineered into giving somebody else full access to all required authentication credentials including private signing keys, the new possessor of those credentials will be able to vote on their behalf, and will be able to sign ballots in a way that will pass eligibility verification.",
        ),
    ],
)

# -----------------------------------------------------------------------------
# Eligibility stuffing
# -----------------------------------------------------------------------------

eligibility_stuffing = Attack(
    id="eligibility_stuffing",
    name="Eligibility stuffing",
)

eligibility_stuffing_corruption = Attack(
    id="eligibility_stuffing.corruption.EA",
    name="Corruption",
    description="The election administrator falsely identifies arbitrary signing public keys as eligible.",
    variant_of=pat.corruption,
    achieves=[eligibility_stuffing],
    occurs_in=[ctx.EA],
    targets=[prop.V4],
    mitigations=[
        MitigationApplication(
            mitigation=mit.auditable_pseudonyms,
            rationale="If pseudonym audits are performed the EA will be caught if it falsely identifies signing public keys as eligible.",
        ),
    ],
)


# =============================================================================
# ATTACKS ON DISPUTE-FREENESS
# =============================================================================

# -----------------------------------------------------------------------------
# Forged signatures
# -----------------------------------------------------------------------------

forged_signatures = Attack(
    id="forged_signatures",
    name="Forged signatures",
)

forged_system_signature = Attack(
    id="forged_system_signature",
    name="Forged system signature",
    description="The voter forges a system signature on a ballot that was not cast.",
    variant_of=pat.broken_cryptography,
    achieves=[forged_signatures],
    occurs_in=[ctx.SIG],
    targets=[prop.D1],
)

forged_voter_signature = Attack(
    id="forged_voter_signature",
    name="Forged voter signature",
    description="The election authority forges a voter signature on a ballot that was not cast.",
    variant_of=pat.broken_cryptography,
    achieves=[forged_signatures],
    occurs_in=[ctx.SIG],
    targets=[prop.D2],
)

# -----------------------------------------------------------------------------
# Malicious reporting
# -----------------------------------------------------------------------------

malicious_reporting = Attack(
    id="malicious_reporting",
    name="Malicious reporting",
)

malicious_reporting_vd = Attack(
    id="malicious_reporting_vd",
    name="Malicious reporting of VD",
    description="A sufficient number of voters falsely claim that their voting device is producing invalid cryptograms, so the election is invalidated. This attack is possible if 1) the system does not satisfy {D3} and 2) a procedure is in place whereby an election outcome is invalidated if a sufficient number of voters make reports.",
    achieves=[malicious_reporting],
    targets=[prop.A1, prop.D3],
    mitigations=[
        MitigationApplication(
            mitigation=OUT_OF_SCOPE,
            rationale="Since the system does not satisfy D*-dispute-freeness, it may not be possible to avoid this attack except by removing election invalidation altogether. However, this undermines mitigation {M1} (Cast as intended verifiability) and {M2} (Recorded as cast verifiability) against {Mismatched encryption}.",
        ),
    ],
)

vote_receipt_replay = Attack(
    id="vote_receipt_replay",
    name="Vote receipt replay",
    description="A voter presents a receipt for a previous election as a receipt for the current election, claiming that their cryptogram should be present in the bulletin board but is not.",
    achieves=[malicious_reporting],
    targets=[prop.D1],
    mitigations=[
        MitigationApplication(
            mitigation=mit.domain_separation,
            rationale="Receipts are unique to each election, and cannot be reused in future elections.",
        ),
    ],
)


# =============================================================================
# ATTACKS ON CONFIDENTIALITY
# =============================================================================

# -----------------------------------------------------------------------------
# Physical observation
# -----------------------------------------------------------------------------

physical_observation = Attack(
    id="physical_observation",
    name="Physical observation",
)

shoulder_surfing = Attack(
    id="shoulder_surfing",
    name="Shoulder surfing",
    description="The voter is physically observed while using the voting application.",
    achieves=[physical_observation],
    targets=[prop.P1],
    mitigations=[
        MitigationApplication(
            mitigation=OUT_OF_SCOPE,
            rationale="Preventing this attack is outside the system scope. If a voter allows, or is coerced into allowing, an observer to watch their entire voting session, that observer will learn how they voted. This can be mitigated in the coercion case to some extent by allowing a voter to vote multiple times (across multiple sessions) and keep only the last one (or only a specific one, though this may not be possible without the use of out-of-band voting codes), in the hope that they can complete a non-coerced session before the voting period ends.",
        ),
    ],
)

# -----------------------------------------------------------------------------
# Leaked choices
# -----------------------------------------------------------------------------

leaked_choices = Attack(
    id="leaked_choices",
    name="Leaked choices",
)

compromised_voting_device = Attack(
    id="compromised_voting_device",
    name="Compromised voting device",
    description="The voter's choices are recorded and leaked by the device running the voting application.",
    achieves=[leaked_choices],
    targets=[prop.P1_1],
    mitigations=[
        MitigationApplication(
            mitigation=OUT_OF_SCOPE,
            rationale="Achieving control over voter's devices necessary to prevent this attack is outside the system scope.",
        ),
    ],
)

leaked_choices_side_channel = Attack(
    id="leaked_choices.side_channel.VD",
    name="Side channel",
    description="A side channel leaks voter's choices.",
    variant_of=pat.side_channel,
    achieves=[leaked_choices],
    occurs_in=[ctx.VD],
    targets=[prop.P1_1],
    mitigations=[
        MitigationApplication(
            mitigation=OUT_OF_SCOPE,
            rationale="It is impossible to prevent adversaries from observing voter devices in the uncontrolled and practically unlimited range of environments in which a user may interact with the {VA}.",
        ),
    ],
)

# -----------------------------------------------------------------------------
# Compromised key fragments
# -----------------------------------------------------------------------------

compromised_key_fragments = Attack(
    id="compromised_key_fragments",
    name="Compromised key fragments",
)

compromised_key_fragments_device_ta = Attack(
    id="compromised_key_fragments.device.TA",
    name="Compromised device",
    description="Key fragments are leaked by the trustee application.",
    variant_of=pat.compromised_device,
    achieves=[compromised_key_fragments],
    occurs_in=[ctx.TA],
    targets=[prop.P1_2],
    mitigations=[
        MitigationApplication(
            mitigation=mit.trust_distribution,
            rationale="If there are sufficient honest trustee applications, leaked key fragments will not compromise the election key.",
        ),
    ],
)

compromised_key_fragments_corruption_tr = Attack(
    id="compromised_key_fragments.corruption.TR",
    name="Corruption",
    description="Key fragments are leaked by trustees.",
    variant_of=pat.corruption,
    achieves=[compromised_key_fragments],
    occurs_in=[ctx.TR],
    targets=[prop.P1_2],
)

compromised_key_fragments_side_channel = Attack(
    id="compromised_key_fragments.side_channel.TA",
    name="Side channel",
    description="A side channel leaks key fragments.",
    variant_of=pat.side_channel,
    achieves=[compromised_key_fragments],
    occurs_in=[ctx.TA],
    targets=[prop.P1_2],
    mitigations=[
        MitigationApplication(
            mitigation=mit.controlled_environment,
            rationale="Physical proximity necessary to observe indirect signals emerging from the {TA} and related systems will be restricted. Adversaries will not be able to exploit a side channel to extract key fragments. However, corrupt trustees could potentially exploit such side channels to extract other trustees' keys.",
        ),
    ],
)

# -----------------------------------------------------------------------------
# Compromised shuffle data
# -----------------------------------------------------------------------------

compromised_shuffle_data = Attack(
    id="compromised_shuffle_data",
    name="Compromised shuffle data",
)

compromised_shuffle_data_device_ta = Attack(
    id="compromised_shuffle_data.device.TA",
    name="Compromised device",
    description="Shuffle permutations or random factors are leaked by the trustee application.",
    variant_of=pat.compromised_device,
    achieves=[compromised_shuffle_data],
    occurs_in=[ctx.TA],
    targets=[prop.P1_3],
    mitigations=[
        MitigationApplication(
            mitigation=mit.trust_distribution,
            rationale="If at least one trustee application is honest, leaked shuffle permutations or random factors will not affect the security of the shuffle.",
        ),
    ],
)

compromised_shuffle_data_corruption_tr = Attack(
    id="compromised_shuffle_data.corruption.TR",
    name="Corruption",
    description="Shuffle permutations or random factors are leaked by trustees.",
    variant_of=pat.corruption,
    achieves=[compromised_shuffle_data],
    occurs_in=[ctx.TR],
    targets=[prop.P1_3],
)

compromised_shuffle_data_side_channel = Attack(
    id="compromised_shuffle_data.side_channel.TA",
    name="Side channel",
    description="A side channel leaks permutations or random factors.",
    variant_of=pat.side_channel,
    achieves=[compromised_shuffle_data],
    occurs_in=[ctx.TA],
    targets=[prop.P1_3],
    mitigations=[
        MitigationApplication(
            mitigation=mit.controlled_environment,
            rationale="Physical proximity necessary to observe indirect signals emerging from the {TA} and related systems will be restricted. Adversaries will not be able to exploit a side channel to extract permutations or random factors.",
        ),
    ],
)

# -----------------------------------------------------------------------------
# Tally inference attack
# -----------------------------------------------------------------------------

tally_inference_attack = Attack(
    id="tally_inference_attack",
    name="Tally inference attack",
)

reduced_anonymity_set = Attack(
    id="reduced_anonymity_set",
    name="Reduced anonymity set",
    description="The number of participating voters is small enough that adversaries can infer significant information about the choices of individual voters.",
    achieves=[tally_inference_attack],
    targets=[prop.P1],
    mitigations=[
        MitigationApplication(
            mitigation=OUT_OF_SCOPE,
            rationale="The system cannot ensure that the anonymity set is large enough; the number of participating voters could be small.",
        ),
    ],
)

double_tally_attack_ea = Attack(
    id="double_tally_attack_ea",
    name="Double tally attack---EA",
    description="The election administrator rewinds the protocol and then submits a second, marginally different set of ciphertexts for tallying, revealing the choices of individual voters by comparing the result of each tally.",
    variant_of=pat.corruption,
    achieves=[tally_inference_attack],
    occurs_in=[ctx.EA],
    targets=[prop.P1],
    mitigations=[
        MitigationApplication(
            mitigation=mit.append_only_trustee_board,
            rationale="The trustee's local view of the protocol board is append-only, any attempt to submit a second set of ciphertexts will be rejected.",
        ),
    ],
)

double_tally_attack_tas = Attack(
    id="double_tally_attack_tas",
    name="Double tally attack---TAS",
    description="The trustee application server rewinds the protocol and then submits a second, marginally different set of ciphertexts for tallying, revealing the choices of individual voters by comparing the result of each tally.",
    variant_of=pat.compromised_device,
    achieves=[tally_inference_attack],
    occurs_in=[ctx.TAS],
    targets=[prop.P1],
    mitigations=[
        MitigationApplication(
            mitigation=mit.append_only_trustee_board,
            rationale="The trustee's local view of the protocol board is append-only, any attempt to submit a second set of ciphertexts will be rejected.",
        ),
    ],
)

# -----------------------------------------------------------------------------
# Broken encryption
# -----------------------------------------------------------------------------

broken_encryption = Attack(
    id="broken_encryption",
    name="Broken encryption",
)

broken_encryption_crypto = Attack(
    id="broken_encryption.crypto.PKE",
    name="Broken cryptography",
    description="The cipher used to encrypt ballots is broken.",
    variant_of=pat.broken_cryptography,
    achieves=[broken_encryption],
    occurs_in=[ctx.PKE],
    targets=[prop.P1_2],
    mitigations=[
        MitigationApplication(
            mitigation=mit.security_proof,
            rationale="A (preferably formal) security proof provides some level of assurance that a cryptographic primitive is not broken.",
        ),
    ],
)

# -----------------------------------------------------------------------------
# Unmixed decryption
# -----------------------------------------------------------------------------

unmixed_decryption = Attack(
    id="unmixed_decryption",
    name="Unmixed decryption",
)

unmixed_decryption_device_ta = Attack(
    id="unmixed_decryption.device.TA",
    name="Compromised device",
    description="Unmixed ciphertexts are decrypted and leaked by the trustee application.",
    variant_of=pat.compromised_device,
    achieves=[unmixed_decryption],
    occurs_in=[ctx.TA],
    targets=[prop.P1_4],
    mitigations=[
        MitigationApplication(
            mitigation=mit.trust_distribution,
            rationale="A single trustee application should not be able to decrypt unmixed ciphertexts on its own, assuming that the trustee threshold for decryption is chosen appropriately and there are enough honest trustees.",
        ),
    ],
)

unmixed_decryption_corruption_tr = Attack(
    id="unmixed_decryption.corruption.TR",
    name="Corruption",
    description="Unmixed ciphertexts are decrypted and leaked by trustees.",
    variant_of=pat.corruption,
    achieves=[unmixed_decryption],
    occurs_in=[ctx.TR],
    targets=[prop.P1_4],
)

# -----------------------------------------------------------------------------
# Broken ballot independence
# -----------------------------------------------------------------------------

broken_ballot_independence = Attack(
    id="broken_ballot_independence",
    name="Broken ballot independence",
)

malleability_attack = Attack(
    id="malleability_attack",
    name="Malleability attack",
    description="An adversary uses encryption malleability to construct a ballot related to a target ballot to reveal it [BPW16].",
    achieves=[broken_ballot_independence],
    targets=[prop.P1],
    mitigations=[
        MitigationApplication(
            mitigation=mit.non_malleable_cryptosystem,
            rationale="The adversary cannot cast a related ballot.",
        ),
        MitigationApplication(
            mitigation=mit.proof_of_plaintext_knowledge,
            rationale="Adversaries casting related ballots will not be able to produce proofs of plaintext knowledge. Their ballots will be rejected at submission or mixing time.",
        ),
    ],
)

ballot_copying = Attack(
    id="ballot_copying",
    name="Ballot copying",
    description="An adversary copies a target ballot to reveal it, including its proof of plaintext knowledge.",
    achieves=[broken_ballot_independence],
    targets=[prop.P1],
    mitigations=[
        MitigationApplication(
            mitigation=mit.ballot_weeding,
            rationale="Because duplicate ballots are discarded they will not feature in the output plaintexts, and cannot be used to reveal their source ballot.",
        ),
        MitigationApplication(
            mitigation=mit.voter_specific_naor_yung_proofs,
            rationale="Because proofs of plaintext knowledge are specific to each voter, copied ballots will fail verification and be discarded.",
        ),
    ],
)

# -----------------------------------------------------------------------------
# Wrong public key
# -----------------------------------------------------------------------------

wrong_public_key = Attack(
    id="wrong_public_key",
    name="Wrong public key",
)

wrong_public_key_device_tas = Attack(
    id="wrong_public_key.device.TAS",
    name="Compromised device",
    description="One or more subsystems replace the election public key.",
    variant_of=pat.compromised_device,
    achieves=[wrong_public_key],
    occurs_in=[ctx.TAS],
    targets=[prop.P1_2],
    mitigations=[
        MitigationApplication(
            mitigation=mit.message_signatures,
            rationale="Trustees sign messages as part of the key generation protocol. Assuming that the {VA} validates the signatures on received public keys, the compromised devices would need to forge these signatures to carry out the attack.",
        ),
    ],
)

wrong_public_key_device_eas = Attack(
    id="wrong_public_key.device.EAS",
    name="Compromised device",
    description="One or more subsystems replace the election public key.",
    variant_of=pat.compromised_device,
    achieves=[wrong_public_key],
    occurs_in=[ctx.EAS],
    targets=[prop.P1_2],
    mitigations=[
        MitigationApplication(
            mitigation=mit.message_signatures,
            rationale="Trustees sign messages as part of the key generation protocol. Assuming that the {VA} validates the signatures on received public keys, the compromised devices would need to forge these signatures to carry out the attack.",
        ),
    ],
)

wrong_public_key_device_est = Attack(
    id="wrong_public_key.device.EST",
    name="Compromised device",
    description="One or more subsystems replace the election public key.",
    variant_of=pat.compromised_device,
    achieves=[wrong_public_key],
    occurs_in=[ctx.EST],
    targets=[prop.P1_2],
    mitigations=[
        MitigationApplication(
            mitigation=mit.message_signatures,
            rationale="Trustees sign messages as part of the key generation protocol. Assuming that the {VA} validates the signatures on received public keys, the compromised devices would need to forge these signatures to carry out the attack.",
        ),
    ],
)

wrong_public_key_network_ean = Attack(
    id="wrong_public_key.network.EAN",
    name="Compromised network",
    description="One or more networks replace the election public key.",
    variant_of=pat.compromised_network,
    achieves=[wrong_public_key],
    occurs_in=[ctx.EAN],
    targets=[prop.P1_2],
    mitigations=[
        MitigationApplication(
            mitigation=mit.message_signatures,
            rationale="Trustees sign messages as part of the key generation protocol. Assuming that the {VA} validates the signatures on received public keys, the compromised networks would need to forge these signatures to carry out the attack.",
        ),
    ],
)

wrong_public_key_network_in = Attack(
    id="wrong_public_key.network.IN",
    name="Compromised network",
    description="One or more networks replace the election public key.",
    variant_of=pat.compromised_network,
    achieves=[wrong_public_key],
    occurs_in=[ctx.IN],
    targets=[prop.P1_2],
    mitigations=[
        MitigationApplication(
            mitigation=mit.message_signatures,
            rationale="Trustees sign messages as part of the key generation protocol. Assuming that the {VA} validates the signatures on received public keys, the compromised networks would need to forge these signatures to carry out the attack.",
        ),
    ],
)

wrong_public_key_corruption_ea = Attack(
    id="wrong_public_key.corruption.EA",
    name="Corruption",
    description="The election administrator replaces the election public key.",
    variant_of=pat.corruption,
    achieves=[wrong_public_key],
    occurs_in=[ctx.EA],
    targets=[prop.P1_2],
    mitigations=[
        MitigationApplication(
            mitigation=mit.message_signatures,
            rationale="Trustees sign messages as part of the key generation protocol. Assuming that the {VA} validates the signatures on received public keys, the EA would need to forge these signatures to carry out the attack.",
        ),
    ],
)

# -----------------------------------------------------------------------------
# Malicious public key
# -----------------------------------------------------------------------------

malicious_public_key = Attack(
    id="malicious_public_key",
    name="Malicious public key",
)

malicious_public_key_corruption = Attack(
    id="malicious_public_key.corruption.TR",
    name="Corruption",
    description="Trustees compute the public key maliciously.",
    variant_of=pat.corruption,
    achieves=[malicious_public_key],
    occurs_in=[ctx.TR],
    targets=[prop.P1_2],
    mitigations=[
        MitigationApplication(
            mitigation=OUT_OF_SCOPE,
            rationale="If a sufficient number of corrupt trustees collude to generate a malicious public key, there is no way for the system to stop them from doing so.",
        ),
    ],
)

# -----------------------------------------------------------------------------
# Future decryption
# -----------------------------------------------------------------------------

future_decryption = Attack(
    id="future_decryption",
    name="Future decryption",
)

unbounded_computation = Attack(
    id="unbounded_computation",
    name="Unbounded computation",
    description="A future computationally unbounded adversary breaks ballot encryption. The adversary can then decrypt ballots that were published for the purposes of achieving verifiability properties.",
    achieves=[future_decryption],
    targets=[prop.P2],
    mitigations=[
        MitigationApplication(
            mitigation=mit.voter_pseudonyms,
            rationale="Even if ciphertexts are decrypted in the future they cannot be linked with real identities using public information.",
        ),
    ],
)

# -----------------------------------------------------------------------------
# Proof of choices
# -----------------------------------------------------------------------------

proof_of_choices = Attack(
    id="proof_of_choices",
    name="Proof of choices",
)

randomness_extraction = Attack(
    id="randomness_extraction",
    name="Randomness extraction",
    description="The randomness used in encryption is extracted from the voting application or the ballot checking application.",
    achieves=[proof_of_choices],
    targets=[prop.P3_1],
    mitigations=[
        MitigationApplication(
            mitigation=OUT_OF_SCOPE,
            rationale="If a voter is sufficiently motivated and has sufficient knowledge/skill to extract the randomness used in encryption of their own vote (by any means, ranging from low-level debugging on-device to replacing the application with a counterfeit that reveals the randomness), the system cannot stop them from doing so. However, in the absence of such a motivated and skilled voter, this attack can be mitigated using the same techniques that mitigate against counterfeit voter/ballot-checking applications generally, as the real voting/ballot-checking application will never reveal the randomness used in encryption of a cast ballot.",
        ),
    ],
)

italian_attack = Attack(
    id="italian_attack",
    name="Italian attack",
    description="The voter emulates a signature by encoding a unique choice in a large plaintext space.",
    achieves=[proof_of_choices],
    targets=[prop.P3_1],
    mitigations=[
        MitigationApplication(
            mitigation=OUT_OF_SCOPE,
            rationale="The system has no way to restrict the sets of choices that voters can make (other than any restrictions imposed by the rules of the election). However, there is research on tally hiding voting systems such as Küsters et al.~{[[KustersEtAlOrdinosVerifiable2020]]}",
        ),
    ],
)

recording_malware = Attack(
    id="recording_malware",
    name="Recording malware",
    description="The voting device records and exfiltrates the entire voting session, including authentication and final submission, without the voter's knowledge.",
    variant_of=pat.malware,
    achieves=[proof_of_choices],
    targets=[prop.P1],
    mitigations=[
        MitigationApplication(
            mitigation=OUT_OF_SCOPE,
            rationale="While there are mitigations that can be applied to prevent malicious software from infecting the voting device, these can only be applied by voters of their own accord and are therefore out of scope.",
        ),
    ],
)

manual_recording = Attack(
    id="manual_recording",
    name="Manual recording",
    description="The voter records their own entire voting session, including authentication and final submission, using device screen recording capabilities or an external camera.",
    achieves=[proof_of_choices],
    targets=[prop.P3_2],
    mitigations=[
        MitigationApplication(
            mitigation=OUT_OF_SCOPE,
            rationale="While it is possible on some platforms to mitigate this attack with respect to on-device screen recording capabilities (by either disabling/restricting screen recording, or corrupting/obstructing screen recordings when they are detected), it is not possible for the system to prevent a voter from using a completely separate video recording device to record their own voting session in its entirety. This is, essentially, the digital analogue to {Physical observation.Shoulder surfing} (Shoulder surfing).",
        ),
    ],
)


# =============================================================================
# ATTACKS ON AVAILABILITY
# =============================================================================

# -----------------------------------------------------------------------------
# Denial of service
# -----------------------------------------------------------------------------

denial_of_service = Attack(
    id="denial_of_service",
    name="Denial of service",
)

targeted_dos_infrastructure = Attack(
    id="targeted_dos_infrastructure",
    name="Targeted DoS (Infrastructure)",
    description="One or more components of the system infrastructure are targeted by a denial of service attack preventing timely access to the voting system (e.g., an attack on the authentication service preventing authentication of voters).",
    achieves=[denial_of_service],
    targets=[prop.A1, prop.A2],
    mitigations=[
        MitigationApplication(
            mitigation=mit.denial_of_service_protection,
            rationale="This attack can be mitigated by standard denial of service mitigation techniques typically used for Internet services. These include the deployment of protective services such as Akamai and Cloudflare (especially for large/high stakes elections), proper configuration of firewall rules on election administration networks and cloud-based services, and per-client rate limiting of requests to prevent application-level denial of service (e.g., submission of many bad protocol messages by corrupted clients delaying the processing of legitimate protocol messages).",
        ),
    ],
)

indiscriminate_dos = Attack(
    id="indiscriminate_dos",
    name="Indiscriminate DoS",
    description="Internet infrastructure as a whole in one or more regions running an election is degraded to the point of unusability by a denial of service attack.",
    achieves=[denial_of_service],
    targets=[prop.A1, prop.A2],
    mitigations=[
        MitigationApplication(
            mitigation=OUT_OF_SCOPE,
            rationale="Preventing this attack is outside the system scope, as the system cannot control Internet infrastructure. However, it can be mitigated by geographic diversity of servers for elections where such diversity can be achieved (e.g., parts of the infrastructure in the cloud can be replicated across multiple cloud regions so that regional disruptions don't take down the entire system).",
        ),
    ],
)

targeted_dos_voters = Attack(
    id="targeted_dos_voters",
    name="Targeted DoS (Voters)",
    description="A specific voter or group of voters is targeted by a denial of service attack preventing timely access to the voting system.",
    achieves=[denial_of_service],
    targets=[prop.A1, prop.A2],
    mitigations=[
        MitigationApplication(
            mitigation=OUT_OF_SCOPE,
            rationale="Preventing this attack is outside the system scope, as the system cannot control the Internet access capabilities of the voters. One way to mitigate this attack is to provide voters with Internet access at locations like public libraries, election offices, coffee shops, etc., that would allow them to cast their ballots outside their ``home'' network (which is presumably what is being targeted in this scenario). Another is for the voting period to be long enough that such a targeted DoS does not prevent the voter from accessing the voting system at some convenient time during the voting period.",
        ),
    ],
)

spoofing_attack = Attack(
    id="spoofing_attack",
    name="Spoofing",
    description="The voter is deceived into voting through a counterfeit application.",
    variant_of=pat.spoofing,
    achieves=[denial_of_service, mismatched_encryption, leaked_choices],
    occurs_in=[ctx.VA],
    targets=[prop.C1_1, prop.P1, prop.A1, prop.A2],
    mitigations=[
        MitigationApplication(
            mitigation=OUT_OF_SCOPE,
            rationale="If a sufficiently capable counterfeit application exists, and a voter is deceived into voting with it, it can effectively carry out any other attack on this list that involves a compromised voter application, though all mitigations against those attacks also serve as mitigations against this one. There are also several ways to mitigate this attack by reducing both the likelihood of such a counterfeit application existing and and the likelihood of such an application successfully deceiving voters. These include the use of trusted mobile application stores, high-profile announcements to voters to only trust applications from specific sources, and other techniques commonly used to validate software distributions.",
        ),
    ],
)

# -----------------------------------------------------------------------------
# Internal sabotage
# -----------------------------------------------------------------------------

internal_sabotage = Attack(
    id="internal_sabotage",
    name="Internal sabotage",
)

subsystem_sabotage = Attack(
    id="subsystem_sabotage",
    name="Subsystem sabotage",
    description="One or more subsystems fail to operate in a timely fashion.",
    variant_of=pat.compromised_device,
    achieves=[internal_sabotage],
    occurs_in=[ctx.SUB],
    targets=[prop.A1, prop.A2, prop.A3, prop.A4],
    mitigations=[
        MitigationApplication(
            mitigation=mit.operational_redundancy,
            rationale="A subsystem employing redundancy allows it to continue operating even if an instance of it fails. Note this mitigation is distinct from (and at a layer ``above'') mitigations aimed at preventing such an instance from being compromised to begin with.",
        ),
    ],
)

network_sabotage_agn = Attack(
    id="network_sabotage.AGN",
    name="Network sabotage",
    description="One or more networks fail to operate in a timely fashion.",
    variant_of=pat.network_sabotage,
    achieves=[internal_sabotage],
    occurs_in=[ctx.AGN],
    targets=[prop.A1, prop.A2, prop.A3, prop.A4],
    mitigations=[
        MitigationApplication(
            mitigation=mit.operational_redundancy,
            rationale="Redundant networks provide multiple paths for traffic allowing data to be transferred in the event of failures.",
        ),
    ],
)

network_sabotage_ean = Attack(
    id="network_sabotage.EAN",
    name="Network sabotage",
    description="One or more networks fail to operate in a timely fashion.",
    variant_of=pat.network_sabotage,
    achieves=[internal_sabotage],
    occurs_in=[ctx.EAN],
    targets=[prop.A1, prop.A2, prop.A3, prop.A4],
    mitigations=[
        MitigationApplication(
            mitigation=mit.operational_redundancy,
            rationale="Redundant networks provide multiple paths for traffic allowing data to be transferred in the event of failures.",
        ),
    ],
)

network_sabotage_eon = Attack(
    id="network_sabotage.EON",
    name="Network sabotage",
    description="One or more networks fail to operate in a timely fashion.",
    variant_of=pat.network_sabotage,
    achieves=[internal_sabotage],
    occurs_in=[ctx.EON],
    targets=[prop.A1, prop.A2, prop.A3, prop.A4],
    mitigations=[
        MitigationApplication(
            mitigation=mit.operational_redundancy,
            rationale="Redundant networks provide multiple paths for traffic allowing data to be transferred in the event of failures.",
        ),
    ],
)

tally_sabotage = Attack(
    id="tally_sabotage",
    name="Tally sabotage---Overwhelming corruption",
    description="A number of trustees sufficient to prevent decryption choose not to participate, or are prevented from participating, in the decryption/mixing/tallying process.",
    achieves=[internal_sabotage],
    targets=[prop.A3],
    mitigations=[
        MitigationApplication(
            mitigation=OUT_OF_SCOPE,
            rationale="The use of multiple trustees in a threshold configuration is already a redundancy mechanism against tally disruption. If this mechanism fails there is no recourse. The number of trustees, the required threshold, and the trustees themselves should be chosen accordingly.",
        ),
    ],
)

keygen_sabotage = Attack(
    id="keygen_sabotage",
    name="Keygen sabotage---Corruption",
    description="One or more trustees choose not to participate, or are prevented from participating, in the key generation process.",
    variant_of=pat.corruption,
    achieves=[internal_sabotage],
    occurs_in=[ctx.TR],
    targets=[prop.A4],
    mitigations=[
        MitigationApplication(
            mitigation=OUT_OF_SCOPE,
            rationale="The selection of trustees is assumed to be done in a way such that the likelihood of them choosing not to participate is mimimal. In the event that not enough trustees are able to participate in key generation, new trustees must be chosen.",
        ),
    ],
)

election_sabotage = Attack(
    id="election_sabotage",
    name="Election sabotage---Corruption",
    description="The election authority disrupts the election.",
    variant_of=pat.corruption,
    achieves=[internal_sabotage],
    occurs_in=[ctx.EA],
    targets=[prop.A1, prop.A2, prop.A3, prop.A4],
    mitigations=[
        MitigationApplication(
            mitigation=OUT_OF_SCOPE,
            rationale="The election authority has the ability to disrupt the election in myriad ways, ranging from simply never initiating the counting process to intentionally disabling/destroying some or all of the subsystems. The system cannot mitigate against these.",
        ),
    ],
)


# =============================================================================
# AUTO-COLLECT ALL ATTACKS
# =============================================================================

# Automatically collect all Attack instances defined in this module
ALL = [obj for name, obj in globals().items()
       if isinstance(obj, Attack) and not name.startswith('_')]
