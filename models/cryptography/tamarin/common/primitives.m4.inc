dnl
dnl Tamarin built-ins, functions, equations, macros, and restrictions used
dnl across the models.
dnl
dnl @author Daniel M. Zimmerman
dnl @copyright Free & Fair 2025-26
dnl @version 0.2
dnl
dnl We always include all the Tamarin built-ins we might need, if they
dnl aren't already included.
ifdef(<!defined_bool!>, <!!>, <!include(m4_utils/defined_bool.m4)!>)dnl
ifdef(<!foreach!>, <!!>, <!include(m4_utils/foreach.m4)!>)dnl
ifdef(<!forloop!>, <!!>, <!include(m4_utils/forloop.m4)!>)dnl
ifdef(<!PRIMITIVES_BUILTINS!>, <!!>, <!
define(<!PRIMITIVES_BUILTINS!>)dnl
builtins:
  symmetric-encryption, asymmetric-encryption, hashing, natural-numbers, multiset
!>)dnl
dnl
ifelse(eval((!defined_bool(<!INCLUDED_EUFCMA_SIGNING!>)) && defined_bool(<!USE_EUFCMA_SIGNING!>)), eval(1), <!
define(<!INCLUDED_EUFCMA_SIGNING!>)dnl
/*
  We use restrictions to model signature verification with EUF-CMA security
  as described in Chapter 15 of the Tamarin book. Thus, any rule that depends
  on a signature being valid must include the following action fact:

    SignatureVerified(sig, e1_sig(sig), pk(e3_sig(sig)), ver_msg, ver_pk, true)

  where "sig" is the signature, ver_msg is the message actually being verified,
  and ver_pk is the public key it is being verified against. Note that there
  is no "verify" function; the only way to verify a signature (or model what
  happens if it does not verify) is with the Verified action fact. Note also
  that "sign" here takes 3 arguments - the message, some random value, and the
  signing key - to model possible nondeterminism in signatures for the same
  message and signing key.
 */

functions:
  sign/3, e1_sig/1 [private], e3_sig/1 [private], true/0, false/0

equations:
  e1_sig(sign(x, y, z)) = x,
  e3_sig(sign(x, y, z)) = z

/*
  This restriction states that an honestly generated key, an honestly
  generated signature, and the correct message must verify as true.
 */
restriction SignatureCorrectness:
  "
    All sig m pk #t1 #t2.
            HonestSignatureKey(pk)@t1
          &
            SignatureVerified(sig, m, pk, m, pk, false)@t2
      ==>
          F
  "

/*
  This restriction states that if a signature verification succeeds
  against an honest public key, then the signature must have been
  honestly produced.
 */
restriction SignatureUnforgeability:
  "
    All sig sigm sigpk verm verpk #t1 #t2.
            HonestSignatureKey(verpk)@t1
          &
            SignatureVerified(sig, sigm, sigpk, verm, verpk, true)@t2
      ==>
            sigm = verm
          &
            sigpk = verpk
  "

/*
  This restriction states that the signature verification procedure
  is deterministic.
 */
restriction SignatureDeterminism:
  "
    All sig sigm sigpk verm verpk res1 res2 #t1 #t2.
            SignatureVerified(sig, sigm, sigpk, verm, verpk, res1)@t1
          &
            SignatureVerified(sig, sigm, sigpk, verm, verpk, res2)@t2
      ==>
          res1 = res2
  "
!>, <!!>)dnl
dnl
ifelse(eval((!defined_bool(<!INCLUDED_ABSTRACTED_NAOR_YUNG!>)) && defined_bool(<!USE_ABSTRACTED_NAOR_YUNG!>)), eval(1), <!
define(<!USE_ABSTRACTED_NAOR_YUNG!>)dnl
include(common/trustee_defaults.m4.inc)dnl
define(<!TRUSTEE_CHECK_VALUES!>, <!forloop(<!TN!>, <!1!>, TRUSTEE_COUNT, <!check_value(p<!!>TN<!!>)<!!>ifelse(eval(TN < TRUSTEE_COUNT), eval(1), <!, !>, <!!>)!>)!>)dnl
/*
  Ballots are encrypted using the Naor-Yung construction with the election
  public key and a randomizer, such that either the election private key
  (a threshold number of private trustee shares) or the randomizer can be
  used to decrypt them. In the real system, this will be done with
  exponentiation-heavy group operation, which are not really feasible to
  model in Tamarin (yet; though we may be able to do a model closer to that
  implementation in the future thanks to a Tamarin extension allowing
  associative/commutative operators, see https://hal.science/hal-05196126
  for details). Thus, we use an equational abstraction for the encryption
  that models the ability to either decrypt with the randomness or combine
  partial decryptions with a threshold number of private key shares,
  maintains the property that an encryption consists of two ciphertexts
  and a corresponding proof, and allows for checking the corresponding
  proof.

  We also define functions to abstract the generation of private key
  shares, pairwise shares, and the election public key, as follows:

  The "pairwise_share" function generates a pairwise share for
  a specific trustee from a private share; its two parameters are
  the private share and the trustee name.

  The "check_value" function generates a check value from a private
  share. In a real secret sharing scheme, the number of such values
  would match the threshold, but in this abstraction we have only
  one - since they are public, and since we're not actually computing
  products and exponents, it makes no difference in this model.

  The "valid_share" function checks that a given piece of data is
  a valid pairwise share for the provided check value. Its two
  parameters are a check value and the piece of data, and it returns
  true if the piece of data is a valid pairwise share.

  The "election_pubkey" function computes an election public key
  from an ordered list of check values. Its <!!>TRUSTEE_COUNT<!!> parameters
  are the public check values generated by the trustees, which should
  be the same as viewed by all of the trustees. We might need to change
  the modeling of this later to make it more faithful to the actual
  cryptographic operations.
 */

functions:
  ny_encrypt_c1/3,        /* ciphertext 1 */
  ny_encrypt_c2/3,        /* ciphertext 2 */
  ny_encrypt_p/3,         /* encryption proof */
  ny_decrypt/3,           /* decryption function */
  ny_partial_decrypt/3,   /* partial decryption function */
  ny_partial_dec_proof/3, /* partial decryption proof */
  ny_combine/<!!>TRUSTEE_THRESHOLD<!!>,           /* partial decryption combination */
  ny_check/3,             /* encryption proof check function */
  ny_pd_check/2,          /* partial decryption proof check function */
  pairwise_share/2,       /* trustee share */
  check_value/1,          /* check value for share */
  valid_share/2,          /* validity test for share with check value */
  threshold_pubkey/<!!>TRUSTEE_COUNT<!!>      /* public key for threshold key */

equations:
  /* A pairwise share and check value are, together, valid if they
     were computed from the same randomness. */
  valid_share(check_value, pairwise_share(p, t)) = true,

  /* A ciphertext encrypted with any key can be decrypted with the
    randomness. */
  ny_decrypt(ny_encrypt_c1(pt, x, r), ny_encrypt_c2(pt, x, r), r) = pt,

  /* A ciphertext encrypted with a "regular" public key can be decrypted with
     the corresponding private key. */
  ny_decrypt(ny_encrypt_c1(pt, pk(k), r), ny_encrypt_c2(pt, pk(k), r), k) = pt,

  /* A ciphertext encrypted with a threshold public key can be decrypted by
     combining partial decryptions with a threshold number of private shares.
     We restrict them to be combined in the correct order. This can be a _lot_
     of equations for high numbers of trustees with low thresholds. */
dnl
dnl We loop over the VALID_TRUSTEE_SUBSEQUENCES to get all the valid
dnl "private keys" that can decrypt a ballot encrypted with the threshold
dnl public key.
dnl
foreach(<!SUBSEQ!>, VALID_TRUSTEE_SUBSEQUENCES,
<!  ny_combine(foreach(<!PRIVSHARE!>, SUBSEQ, <!ifelse(PRIVSHARE, <!|!>, <!,!>, <!
      ny_partial_decrypt(ny_encrypt_c1(pt, threshold_pubkey(<!!>TRUSTEE_CHECK_VALUES<!!>), r), ny_encrypt_c2(pt, threshold_pubkey(<!!>TRUSTEE_CHECK_VALUES<!!>), r), p<!!>PRIVSHARE)!>)!>)
    ) = pt,
!>)dnl

  /* An encryption proof can be verified if it was generated from the
     same parameters as the ciphertexts. */
  ny_check(ny_encrypt_c1(pt, k, r), ny_encrypt_c2(pt, k, r), ny_encrypt_p(pt, k, r)) = true,

  /* A partial decryption proof can be verified if it was generated from
     the same parameters as the partial decryption. */
  ny_pd_check(ny_partial_decrypt(c1, c2, ps), ny_partial_dec_proof(c1, c2, ps)) = true
!>, <!!>)dnl
dnl
ifelse(eval(!defined_bool(<!INCLUDED_EQUALITY!>) && defined_bool(<!USE_EQUALITY!>)), eval(1), <!
define(<!INCLUDED_EQUALITY!>)dnl
/*
  Restriction that a rule can only execute if two values are equivalent.
 */
restriction Equality:
  "All x y #i. Eq(x, y)@i ==> x = y"
!>, <!!>)dnl
dnl
ifelse(eval(!defined_bool(<!INCLUDED_INEQUALITY!>) && defined_bool(<!USE_INEQUALITY!>)), eval(1), <!
define(<!INCLUDED_INEQUALITY!>)dnl
/*
  Restriction that a rule can only execute if two values are not equivalent.
 */
restriction Inequality:
  "All x #i. Neq(x, x)@i ==> F"
!>, <!!>)dnl
dnl
ifelse(eval(!defined_bool(<!INCLUDED_ONLYONCE!>) && defined_bool(<!USE_ONLYONCE!>)), eval(1), <!
define(<!INCLUDED_ONLYONCE!>)dnl
/*
  Restriction that a rule can only be executed once in the entire trace.
 */
restriction OnlyOnce:
  "All #i #j. OnlyOnce()@i & OnlyOnce()@#j ==> #i = #j"
!>, <!!>)dnl
dnl
ifelse(eval(!defined_bool(<!INCLUDED_UNIQUE!>) && defined_bool(<!USE_UNIQUE!>)), eval(1), <!
define(<!INCLUDED_UNIQUE!>)dnl
/*
  Restriction that a rule specified by a single value can only be executed
  once in the entire trace.
 */
restriction Unique:
  "All x #i #j. Unique(x)@i & Unique(x)@j ==> #i = #j"
!>, <!!>)dnl
dnl
ifelse(eval(!defined_bool(<!INCLUDED_LESSTHAN!>) && defined_bool(<!USE_LESSTHAN!>)), eval(1), <!
define(<!INCLUDED_LESSTHAN!>)dnl
/*
  Restriction that a rule can only be executed if one natural number is
  less than another.
 */
restriction LessThan:
  "All %x %y #i. LessThan(%x, %y)@i ==> %x << %y"
!>, <!!>)dnl
dnl
ifelse(eval(!defined_bool(<!INCLUDED_ATMOST!>) && defined_bool(<!USE_ATMOST!>)), eval(1), <!
define(<!INCLUDED_ATMOST!>)dnl
/*
  Restriction that a rule can only be executed if one natural number is
  at most (less than or equal to) another.
 */
restriction AtMost:
  "All %x %y #i. AtMost(%x, %y)@i ==> %x << %y | %x = %y"
!>, <!!>)dnl
dnl
ifelse(eval(!defined_bool(<!INCLUDED_NOTINMULTISET!>) && defined_bool(<!USE_NOTINMULTISET!>)), eval(1), <!
define(<!INCLUDED_NOTINMULTISET!>)dnl
/*
  Restriction that a multiset must not contain the specified member.
 */
restriction NotInMultiset:
  "
    All m s #i.
          NotInMultiset(m, s)@i
      ==>
          All x y. s = x + y ==> not (m = x)
  "
!>, <!!>)dnl
dnl
ifelse(eval(!defined_bool(<!INCLUDED_INMULTISET!>) && defined_bool(<!USE_INMULTISET!>)), eval(1), <!
define(<!INCLUDED_INMULTISET!>)dnl
/*
  Restriction that a multiset must contain the specified member.
 */
restriction InMultiset:
  "
    All m s #i.
          InMultiset(m, s)@i
      ==>
          Ex x. s = m + x
  "
!>, <!!>)dnl
ifelse(eval(!defined_bool(<!INCLUDED_PSEUDONYM!>) && defined_bool(<!USE_PSEUDONYM!>)), eval(1), <!
define(<!INCLUDED_PSEUDONYM!>)dnl
functions:
  pseudonym/1 [private] /* voter pseudonym */
!>, <!!>)dnl
