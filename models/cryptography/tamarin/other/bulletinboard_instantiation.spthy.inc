/*
  Bulletin Board Instantiation

  These rules and lemmas instantiate bulletin boards and verify
  some bulletin board executability properties.

  @author Daniel M. Zimmerman
  @copyright Free & Fair 2025-26
  @version 0.2
 */

/*
  This rule creates public bulletin boards.
 */
rule BulletinBoard_Test_Create [role="BulletinBoardTester"]:
    [ Fr(~reqid),
      In(m) ]
  --[ BB_Trace_Test_Create_Requested(~reqid, m) ]->
    [ BB_Create_Request(~reqid, m),
      BB_Test_Create_Requested(~reqid, m) ]

/*
  This rule waits for acknowledgement of public bulletin board creation.
 */
rule BulletinBoard_Test_Receive_Created [role="BulletinBoardTester"]:
    [ BB_Test_Create_Requested(reqid, m),
      !BB_Root(reqid, bbid, m, root_eid) ]
  --[ BB_Trace_Test_Create_Acknowledged(reqid, bbid) ]->
    [ BB_Test_Append(bbid) ]

/*
  This rule appends to created public bulletin boards. Note that it
  picks effectively a random element on the board to append to, so
  it will sometimes fail (and result in that trace getting "stuck"
  waiting for a message to be appended).
 */
rule BulletinBoard_Test_Append [role="BulletinBoardTester"]:
    [ BB_Test_Append(bbid),
      !BB_Root(reqid, bbid, r, root_eid),
      !BB_Entry(bbid, eid, m, prev_eid) ]
  --[ BB_Trace_Test_Append_Requested(bbid, m, eid) ]->
    [ BB_Append_Request(bbid, m, eid),
      BB_Test_Append_Requested(bbid, m, eid) ]

/*
  This rule teminates bulletin boards.
 */
rule BulletinBoard_Test_Terminate [role="BulletinBoardTester"]:
    [ BB_Test_Append(bbid),
      !BB_Root(reqid, bbid, r, root_eid),
      !BB_Entry(bbid, eid, m, prev_eid) ]
  --[ BB_Trace_Test_Stopped(bbid) ]->
    [ BB_Terminate_Request(bbid, eid) ]

/*
  This rule waits for a message to be posted to the bulletin board and
  then re-starts the "append or terminate" loop.
 */
rule BulletinBoard_Test_Receive_Append_Acknowledgement [role="BulletinBoardTester"]:
    [ BB_Test_Append_Requested(bbid, m, prev_eid),
      !BB_Root(reqid, bbid, r, root_eid),
      !BB_Entry(bbid, eid, m, prev_eid) ]
  --[ BB_Trace_Test_Append_Acknowledged(bbid, m, eid) ]->
    [ BB_Test_Append(bbid) ]

/*
  Executability lemmas must start with "Executability" in order to be
  automatically checked in CV.
 */

/*
  This lemma states that an execution exists where a bulletin board has
  (at least) one entry after the root entry.
 */
lemma Executability_BB_OneNonRootEntry:
  exists-trace
  "
    Ex reqid bbid m0 eid0 m1 eid1 #i #j.
        BB_Trace_Root(reqid, bbid, m0, eid0)@i
      &
        BB_Trace_Entry(bbid, eid0, m0, 'root')@i
      &
        BB_Trace_Entry(bbid, eid1, m1, eid0)@j
      &
        #i < #j
  "

/*
  This lemma states that an execution exists where a bulletin board has
  (at least) two entries after the root entry.
 */
lemma Executability_BB_TwoNonRootEntries:
  exists-trace
  "
     Ex reqid bbid m0 eid0 m1 eid1 m2 eid2 #i #j #k.
          BB_Trace_Root(reqid, bbid, m0, eid0)@i
        &
          BB_Trace_Entry(bbid, eid0, m0, 'root')@i
        &
          BB_Trace_Entry(bbid, eid1, m1, eid0)@j
        &
          BB_Trace_Entry(bbid, eid2, m2, eid1)@k
        &
          #i < #j
        &
          #j < #k
  "

/*
  This lemma states that creation of a bulletin board is acknowledged at some point.
 */
lemma Executability_BB_Acknowledge:
  exists-trace
  "
    Ex reqid bbid #i.
      BB_Trace_Test_Create_Acknowledged(reqid, bbid)@i
  "

/*
  This lemma states that appending to a bulletin board is acknowledged at some point.
 */
lemma Executability_BB_Append:
  exists-trace
  "
    Ex bbid m eid #i.
      BB_Trace_Test_Append_Acknowledged(bbid, m, eid)@i
  "

/*
  This lemma states that a hash chain can in fact be created and
  appended to.
 */
lemma Executability_BB_Stopped:
  exists-trace
  "
    Ex bbid last_eid #i #j.
        BB_Trace_Test_Stopped(bbid)@i
      &
        BB_Trace_Last(bbid, last_eid)@j
  "
