package 'Needham-Schroeder Symmetric Key Protocol' {
  doc /*
    This is the system and network architecture for the Needham-Schroeder cryptographic protocol.

    @author Daniel M. Zimmerman
    @copyright 2024-25 Free & Fair
    @history Created December 2024, last revised February 2025

    @refine NeedhamSchroeder.lando |= NeedhamSchroederSymmetric
    @refine NeedhamSchroeder.sysml |= NeedhamSchroeder.cry
    Lando domain concepts refined into SysMLv2 item defs and port defs;
    SysMLv2 message structures refined into Cryptol type definitions.
  */

  // @todo dmz figure out how to connect flows and events and messages properly in the protocol models
  // @design dmz this package is empty; while we would ideally make the rest of the
  // packages defined below subpackages of this one, that is incompatible with the way
  // the Jupyter/SysMLv2 integration parses SysML (every cell must be a self-contained
  // SysMLv2 construct parsable in the context of the previously evaluated cells). It
  // remains to be seen whether we can actually write this package usefully with the
  // Jupyter/SysMLv2 integration, or whether we'll need some external scripting to
  // assemble the packages defined in this notebook into a larger external package.
}
alias 'NSS' for 'Needham-Schroeder Symmetric Key Protocol';
// @todo dmz figure out why this alias doesn't actually work in %viz, below

package 'SimpleCryptography' {
  // @refine NeedhamSchroeder.lando:19 |= "Basic Cryptography" subsystem
  // @refine NeedhamSchroeder.lando:89 |= "Communicating Parties" subsystem
  // @refine SimpleCryptography |= NeedhamSchroeder.cry::Identity, Key, Nonce

  item def Identity {
    doc /* The identity of a protocol party. */
  }

  item def Key {
    doc /* A cryptographic key. */
  }

  item def SymmetricKey specializes Key {
    doc /* A symmetric cryptographic key. */
    ref item holders : Identity[2..*] {
      doc /* The identities of the intended holders of this symmetric key. */
    }
  }

  item def Message {
    doc /* A message sent from one party to another. */
  }

  item def Nonce {
    doc /* A value generated for use in a protocol. */
  }

  item def EncryptedMessage specializes Message {
    doc /* An encrypted message. */

    // we assume here that a message can only be encrypted for one recipient, because
    // the protocol we're modeling doesn't need anything more

    ref item sender : Identity {
      doc /* The party that encrypted the message. */
    }
    ref item recipient : Identity {
      doc /* The party for whom the messaage is intended. */
    }
  }
}

package NeedhamSchroederSymmetricMessage {
  private import SimpleCryptography::*;

  item def RequestSessionKey specializes Message {
    doc /* The message sent from A to S to request a session key. */
    ref item party_a : Identity;
    ref item party_b : Identity;
    ref item nonce_a : Nonce;
  }

  port def RequestSessionKeyPort {
    doc /* The port used to send request session key messages. */
    out item msg: RequestSessionKey;
  }

  item def SessionKey specializes EncryptedMessage {
    doc /* The message sent from S to party A with the session key. */
    ref item nonce_a : Nonce;
    ref item session_key : SymmetricKey;
    ref item party_b : Identity;
    ref item message_for_b : EncapsulatedSessionKey;
  }

  port def SessionKeyPort {
    doc /* The port used to send session key messages. */
    out item msg: SessionKey;
  }

  item def EncapsulatedSessionKey specializes EncryptedMessage {
    doc /* The message included for B in S's session key response. */
    ref item session_key : SymmetricKey;
    ref item party_a : Identity;
  }

  port def EncapsulatedSessionKeyPort {
    doc /* The port used to send encapsulated session key messages. */
    out item msg: EncapsulatedSessionKey;
  }

  item def SessionKeyConfirmation specializes EncryptedMessage {
    doc /* The key confirmation messages sent from B to A, and then A to B, after the session key is established. */
    ref item nonce : Nonce;
  }

  port def SessionKeyConfirmationPort {
    doc /* The port used to send session key confirmation messages. This is a bidirectional port because both parties need to both send and receive this message. */
    out item msgOut: SessionKeyConfirmation;
    in item msgIn: SessionKeyConfirmation;
  }
}

package NeedhamSchroederFixedSymmetricMessage {
  private import SimpleCryptography::*;

  // aliases of the broken protocol messages we need to change, for convenience
  alias BrokenRequestSessionKey for NeedhamSchroederSymmetricMessage::RequestSessionKey;
  alias BrokenSessionKey for NeedhamSchroederSymmetricMessage::SessionKey;
  alias BrokenEncapsulatedSessionKey for NeedhamSchroederSymmetricMessage::EncapsulatedSessionKey;

  // aliases of the ports that are used for the broken protocol messages, for convenience
  alias BrokenRequestSessionKeyPort for NeedhamSchroederSymmetricMessage::RequestSessionKeyPort;
  alias BrokenSessionKeyPort for NeedhamSchroederSymmetricMessage::SessionKeyPort;
  alias BrokenEncapsulatedSessionKeyPort for NeedhamSchroederSymmetricMessage::EncapsulatedSessionKeyPort;

  item def SessionInitiation specializes Message {
    doc /* The initiation message sent from A to B to request communication. */
    ref item party_a : Identity;
  }

  port def SessionInitiationPort {
    doc /* The port used to send session initiation messages. */
    out item msg: SessionInitiation;
  }

  item def SessionInitiationResponse specializes EncryptedMessage {
    doc /* The initiation response sent from B to A, to be forwarded to S. */
    ref item party_a : Identity;
    ref item nonce_b_prime : Nonce;
  }

  port def SessionInitiationResponsePort {
    doc /* The port used to send session initiation response messages. */
    out item msg: SessionInitiationResponse;
  }

  item def RequestSessionKey specializes BrokenRequestSessionKey {
    doc /* The message sent from A to S to request a session key. The fixed version adds the response from B to the session initiation. */
    ref item response_from_b : SessionInitiationResponse;
  }

  port def RequestSessionKeyPort {
    doc /* The port used to send request session key messages. */
    out item msg: RequestSessionKey;
  }

  item def SessionKey specializes BrokenSessionKey {
    doc /* The message sent from S to party A with the session key. The fixed version uses the fixed encapsulated session key. */
    ref item message_for_b : EncapsulatedSessionKey :>> message_for_b;
  }

  port def SessionKeyPort {
    doc /* The port used to send session key messages. */
    out item msg: SessionKey;
  }

  item def EncapsulatedSessionKey specializes BrokenEncapsulatedSessionKey {
    doc /* The message included for B in S's session key response. The fixed version includes the nonce from the session initiation response. */
    ref item nonce_b_prime : Nonce;
  }

  port def EncapsulatedSessionKeyPort {
    doc /* The port used to send encapsulated session key messages. */
    out item msg: EncapsulatedSessionKey;
  }

  // The session key confirmation and its port from the broken protocol can be used as-is.
  alias SessionKeyConfirmation for NeedhamSchroederSymmetricMessage::SessionKeyConfirmation;
  alias SessionKeyConfirmationPort for NeedhamSchroederSymmetricMessage::SessionKeyConfirmationPort;
}

package NeedhamSchroederSymmetricParty {
  private import Collections::KeyValuePair;
  private import Collections::Map;
  private import SimpleCryptography::*;
  private import NeedhamSchroederSymmetricMessage::*;

  attribute def IdentityAndSymmetricKeyPair specializes KeyValuePair {
    ref part key : Identity :>> KeyValuePair::key;
    ref part val : SymmetricKey :>> KeyValuePair::val;
  }

  attribute def IdentityToSymmetricKeyMap specializes Map {
    attribute elements : IdentityAndSymmetricKeyPair[0..*] :>> Map::elements;
  }

  part def TrustedServer {
    doc /* The trusted server. */

    ref part identity : Identity {
      doc /* The server's identity. */
    }

    attribute shared_keys : IdentityToSymmetricKeyMap {
      doc /* A map from identities to symmetric keys. */
    }

    port requestSessionKeyIn: ~RequestSessionKeyPort;
    port sessionKeyOut: SessionKeyPort;
  }

  part def InitiatingParty {
    doc /* The initiating party. */

    ref part identity : Identity {
      doc /* The party's identity. */
    }

    ref part server_key : SymmetricKey {
      doc /* The symmetric key shared with the server. */
    }

    attribute session_keys : IdentityToSymmetricKeyMap {
      doc /* A map from identities to session keys. */
    }

    port requestSessionKeyOut: RequestSessionKeyPort;
    port sessionKeyIn: ~SessionKeyPort;
    port encapsulatedSessionKeyOut: EncapsulatedSessionKeyPort;
    port sessionKeyConfirmationInOut: SessionKeyConfirmationPort;
  }

  part def RespondingParty {
    doc /* The responding party. */

    ref part identity : Identity {
      doc /* The party's identity. */
    }

    ref part server_key : SymmetricKey {
      doc /* The symmetric key shared with the server. */
    }

    attribute session_keys : IdentityToSymmetricKeyMap {
      doc /* A map from identities to session keys. */
    }

    port encapsulatedSessionKeyIn: ~EncapsulatedSessionKeyPort;
    port sessionKeyConfirmationInOut: SessionKeyConfirmationPort;
  }
}

package NeedhamSchroederFixedSymmetricParty {
  private import Collections::KeyValuePair;
  private import Collections::Map;
  private import SimpleCryptography::*;
  private import NeedhamSchroederFixedSymmetricMessage::*;

  attribute def IdentityAndSymmetricKeyPair specializes KeyValuePair {
    ref part key : Identity :>> KeyValuePair::key;
    ref part val : SymmetricKey :>> KeyValuePair::val;
  }

  attribute def IdentityToSymmetricKeyMap specializes Map {
    attribute elements : IdentityAndSymmetricKeyPair[0..*] :>> Map::elements;
  }

  part def TrustedServer {
    doc /* The trusted server. */

    ref part identity : Identity {
      doc /* The server's identity. */
    }

    attribute shared_keys : IdentityToSymmetricKeyMap {
      doc /* A map from identities to symmetric keys. */
    }

    port requestSessionKeyIn: ~RequestSessionKeyPort;
    port sessionKeyOut: SessionKeyPort;
  }

  part def InitiatingParty {
    doc /* The initiating party. */

    ref part identity : Identity {
      doc /* The party's identity. */
    }

    ref part server_key : SymmetricKey {
      doc /* The symmetric key shared with the server. */
    }

    attribute session_keys : IdentityToSymmetricKeyMap {
      doc /* A map from identities to session keys. */
    }

    port sessionInitiationOut: SessionInitiationPort;
    port sessionInitiationResponseIn: ~SessionInitiationResponsePort;
    port requestSessionKeyOut: RequestSessionKeyPort;
    port sessionKeyIn: ~SessionKeyPort;
    port encapsulatedSessionKeyOut: EncapsulatedSessionKeyPort;
    port sessionKeyConfirmationInOut: SessionKeyConfirmationPort;
  }

  part def RespondingParty {
    doc /* The responding party. */

    ref part identity : Identity {
      doc /* The party's identity. */
    }

    ref part server_key : SymmetricKey {
      doc /* The symmetric key shared with the server. */
    }

    attribute session_keys : IdentityToSymmetricKeyMap {
      doc /* A map from identities to session keys. */
    }

    port sessionInitiationIn: ~SessionInitiationPort;
    port sessionInitiationResponseOut: SessionInitiationResponsePort;
    port encapsulatedSessionKeyIn: ~EncapsulatedSessionKeyPort;
    port sessionKeyConfirmationInOut: SessionKeyConfirmationPort;
  }
}

package NeedhamSchroederSymmetricProtocol {
  // @refine NeedhamSchroeder.lando:128 |= "Original Protocol Actions"
  // @refine NeedhamSchroederSymmetricProtocol |= NeedhamSchroeder.cry::needhamSchroeder
  // @refine NeedhamSchroederSymmetricProtocol |= needham_schroeder_symmetric_rules.spthy

  private import SimpleCryptography::*;
  private import NeedhamSchroederSymmetricMessage::*;
  private import NeedhamSchroederSymmetricParty::*;

  // Here, we specify the protocol participants and their event occurrences,
  // in the style "receive something, then send something" - at each step (except
  // the first), the participants are waiting for events to occur.

  part Server : TrustedServer {
    // When the server receives a request for a sesssion key, it sends one.
    event occurrence receiveRequestSessionKey;
    then event occurrence sendSessionKey;
  }

  part Alice : InitiatingParty {
    // Alice sends a session key request to the server to start the protocol.
    // This is the only "send" event that is not triggered by a "receive".
    event occurrence sendRequestSessionKey;

    // When Alice gets the session key, she sends the copy encapsulated
    // inside to Bob.
    event occurrence receiveSessionKey;
    then event occurrence sendEncapsulatedSessionKey;

    // When Alice receives Bob's confirmation, she sends one of her own.
    event occurrence receiveSessionKeyConfirmation;
    then event occurrence sendSessionKeyConfirmation;
  }

  part Bob : RespondingParty {
    // When Bob receives an encapsulated session key from Alice,
    // he sends a confirmation.
    event occurrence receiveEncapsulatedSessionKey;
    then event occurrence sendSessionKeyConfirmation;

    // When Bob receives Alice's session key confirmation, the protocol
    // is concluded. This is the only "receive" event that doesn't have
    // a corresponding "send".
    event occurrence receiveSessionKeyConfirmation;
  }

  // Flows of messages among the parties
  flow Alice.requestSessionKeyOut to Server.requestSessionKeyIn;
  flow Server.sessionKeyOut to Alice.sessionKeyIn;
  flow Alice.encapsulatedSessionKeyOut to Bob.encapsulatedSessionKeyIn;
  flow Bob.sessionKeyConfirmationInOut to Alice.sessionKeyConfirmationInOut;
  // @design dmz is the next flow necessary, given te bidirectionality of this port?
  flow Alice.sessionKeyConfirmationInOut to Bob.sessionKeyConfirmationInOut;

  // The protocol sequence for the messages
  // @design dmz I'm not sure exactly how to tie this to the flows, from a SysML syntax point of view

  occurrence ProtocolSequence {
    // The messages of the protocol. Here, we specify the actual messages
    // that correspond to the events that occur for each participant.

    message requestSessionKeyMessage of RequestSessionKey
      from Alice.sendRequestSessionKey
      to Server.receiveRequestSessionKey;

    message sessionKeyMessage of SessionKey
      from Server.sendSessionKey
      to Alice.receiveSessionKey;

    message encapsulatedSessionKeyMessage of EncapsulatedSessionKey
      from Alice.sendEncapsulatedSessionKey
      to Bob.receiveEncapsulatedSessionKey;

    message sessionKeyConfirmationMessage_1 of SessionKeyConfirmation
      from Bob.sendSessionKeyConfirmation
      to Alice.receiveSessionKeyConfirmation;

    message sessionKeyConfirmationMessage_2 of SessionKeyConfirmation
      from Alice.sendSessionKeyConfirmation
      to Bob.receiveSessionKeyConfirmation;
  }
}

package NeedhamSchroederFixedSymmetricProtocol {
  // @refine NeedhamSchroeder.lando:164 |= "Fixed Protocol Actions"
  // @refine NeedhamSchroederFixedSymmetricProtocol |= NeedhamSchroeder.cry::needhamSchroederFixed
  // @refine NeedhamSchroederFixedSymmetricProtocol |= needham_schroeder_fixed_symmetric_rules.spthy

  private import SimpleCryptography::*;
  private import NeedhamSchroederFixedSymmetricMessage::*;
  private import NeedhamSchroederFixedSymmetricParty::*;

  // Here, we specify the protocol participants and their event occurrences,
  // in the style "receive something, then send something" - at each step (except
  // the first), the participants are waiting for events to occur.

  part Server : TrustedServer {
    // When the server receives a request for a sesssion key, it sends one.
    event occurrence receiveRequestSessionKey;
    then event occurrence sendSessionKey;
  }

  part Alice : InitiatingParty {
    // Alice sends a session initiation to Bob to start the protocol. This
    // is the only "send" event that is not triggered by a "receive".
    event occurrence sendSessionInitiation;

    // When Alice gets Bob's response, she asks the server for a session key.
    event occurrence receiveSessionInitiationResponse;
    then event occurrence sendRequestSessionKey;

    // When Alice gets the session key, she sends the copy encapsulated
    // inside to Bob.
    event occurrence receiveSessionKey;
    then event occurrence sendEncapsulatedSessionKey;

    // When Alice receives Bob's confirmation, she sends one of her own.
    event occurrence receiveSessionKeyConfirmation;
    then event occurrence sendSessionKeyConfirmation;
  }

  part Bob : RespondingParty {
    // When Bob receives a session initiation from Alice, he responds.
    event occurrence receiveSessionInitiation;
    then event occurrence sendSessionInitiationResponse;

    // When Bob receives an encapsulated session key from Alice,
    // he sends a confirmation.
    event occurrence receiveEncapsulatedSessionKey;
    then event occurrence sendSessionKeyConfirmation;

    // When Bob receives Alice's session key confirmation, the protocol
    // is concluded. This is the only "receive" event that doesn't have
    // a corresponding "send".
    event occurrence receiveSessionKeyConfirmation;
  }

  // Flows of messages among the parties
  flow Alice.sessionInitiationOut to Bob.sessionInitiationIn;
  flow Bob.sessionInitiationResponseOut to Alice.sessionInitiationResponseIn;
  flow Alice.requestSessionKeyOut to Server.requestSessionKeyIn;
  flow Server.sessionKeyOut to Alice.sessionKeyIn;
  flow Alice.encapsulatedSessionKeyOut to Bob.encapsulatedSessionKeyIn;
  flow Bob.sessionKeyConfirmationInOut to Alice.sessionKeyConfirmationInOut;
  // @design dmz is the next flow necessary, given te bidirectionality of this port?
  flow Alice.sessionKeyConfirmationInOut to Bob.sessionKeyConfirmationInOut;

  occurrence ProtocolSequence {
    // The messages of the protocol. Here, we specify the actual messages
    // that correspond to the events that occur for each participant.

    message sessionInitiationMessage of SessionInitiation
      from Alice.sendSessionInitiation
      to Bob.receiveSessionInitiation;

    message sessionInitiationResponseMessage of SessionInitiationResponse
      from Bob.sendSessionInitiationResponse
      to Alice.receiveSessionInitiationResponse;

    message requestSessionKeyMessage of RequestSessionKey
      from Alice.sendRequestSessionKey
      to Server.receiveRequestSessionKey;

    message sessionKeyMessage of SessionKey
      from Server.sendSessionKey
      to Alice.receiveSessionKey;

    message encapsulatedSessionKeyMessage of EncapsulatedSessionKey
      from Alice.sendEncapsulatedSessionKey
      to Bob.receiveEncapsulatedSessionKey;

    message sessionKeyConfirmationMessage_1 of SessionKeyConfirmation
      from Bob.sendSessionKeyConfirmation
      to Alice.receiveSessionKeyConfirmation;

    message sessionKeyConfirmationMessage_2 of SessionKeyConfirmation
      from Alice.sendSessionKeyConfirmation
      to Bob.receiveSessionKeyConfirmation;
  }
}
