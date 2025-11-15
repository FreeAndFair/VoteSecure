# SecureVote Threat Model - Contexts
# Contexts represent "where" an attack is carried out

from nxt import Context, ContextKind


# === Subsystems ===
AS = Context(id="AS", name="Authentication Service", kind=ContextKind.SUBSYSTEM)
BB = Context(id="BB", name="Ballot Box", kind=ContextKind.SUBSYSTEM)
BCA = Context(id="BCA", name="Ballot Check Application", kind=ContextKind.SUBSYSTEM)
BP = Context(id="BP", name="Ballot Printer", kind=ContextKind.SUBSYSTEM)
EAA = Context(id="EAA", name="Election Administrator Application", kind=ContextKind.SUBSYSTEM)
EAS = Context(id="EAS", name="Election Administration Server", kind=ContextKind.SUBSYSTEM)
EST = Context(id="EST", name="Election Administration Storage", kind=ContextKind.SUBSYSTEM)
PBB = Context(id="PBB", name="Public Bulletin Board", kind=ContextKind.SUBSYSTEM)
TA = Context(id="TA", name="Trustee Application", kind=ContextKind.SUBSYSTEM)
TAS = Context(id="TAS", name="Trustee Administration Server", kind=ContextKind.SUBSYSTEM)
TST = Context(id="TST", name="Trustee Storage", kind=ContextKind.SUBSYSTEM)
VA = Context(id="VA", name="Voting Application", kind=ContextKind.SUBSYSTEM)
VD = Context(id="VD", name="Voting Device", kind=ContextKind.SUBSYSTEM)
VER = Context(id="VER", name="Verifier Application", kind=ContextKind.SUBSYSTEM)
SUB = Context(id="SUB", name="All subsystems", kind=ContextKind.SUBSYSTEM)

# === Networks ===
AGN = Context(id="AGN", name="Air-Gapped Network", kind=ContextKind.NETWORK)
EAN = Context(id="EAN", name="Election Administration Network", kind=ContextKind.NETWORK)
EON = Context(id="EON", name="Election Office Network", kind=ContextKind.NETWORK)
IN = Context(id="IN", name="Internet", kind=ContextKind.NETWORK)

# === Actors ===
EA = Context(id="EA", name="Election Administrator", kind=ContextKind.ACTOR)
TR = Context(id="TR", name="Trustee", kind=ContextKind.ACTOR)
VO = Context(id="VO", name="Voter", kind=ContextKind.ACTOR)

# === Primitives ===
DPOK = Context(id="DPOK", name="Decryption Proof", kind=ContextKind.PRIMITIVE)
PKE = Context(id="PKE", name="Public key encryption", kind=ContextKind.PRIMITIVE)
POPK = Context(id="POPK", name="Proof of Plaintext Knowledge", kind=ContextKind.PRIMITIVE)
SIG = Context(id="SIG", name="Digital Signature", kind=ContextKind.PRIMITIVE)
SPOK = Context(id="SPOK", name="Shuffle Proof", kind=ContextKind.PRIMITIVE)

# === Data ===
CRD = Context(id="CRD", name="Voter credentials", kind=ContextKind.DATA)
VSIG = Context(id="VSIG", name="Voter signature keys", kind=ContextKind.DATA)


# =============================================================================
# AUTO-COLLECT ALL CONTEXTS
# =============================================================================

# Automatically collect all Context instances defined in this module
ALL = [obj for name, obj in globals().items()
       if isinstance(obj, Context) and not name.startswith('_')]
