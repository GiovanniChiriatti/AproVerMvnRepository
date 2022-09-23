module CryptoLibraryXXX

import ../StandardLibrary
export *

signature:

	domain Alice subsetof Agent
	domain Bob subsetof Agent
	domain Eve subsetof Agent


	enum domain StateAlice = {IDLE_M0 | WAITING_M1 | SEND_M2 | END_A}
	enum domain StateBob = {WAITING_M0 | SEND_M1 | WAITING_M2 | END_B}

	enum domain Message = {M0 | M1 | M2} 

	enum domain Knowledge ={ID_A|NA|NB|PRIVKA|PRIVKB|PRIVKE|PUBKA|PUBKB|PUBKE}

	//DOMAIN OF POSSIBLE RECEIVER
	enum domain Receiver={AG_B|AG_E}
	///DOMAIN OF THE ATTACKER MODE
	enum domain Modality = {ACTIVE | PASSIVE}

	domain KnowledgeNonce subsetof Any
	domain KnowledgeIdentityCertificate subsetof Any
	domain KnowledgeBitString subsetof Any
	domain KnowledgeSymKey subsetof Any
	domain KnowledgeAsymPrivKey subsetof Any
	domain KnowledgeAsymPubKey subsetof Any
	domain KnowledgeSignPrivKey subsetof Any
	domain KnowledgeSignPubKey subsetof Any
	domain KnowledgeTag subsetof Any
	domain KnowledgeDigest subsetof Any
	domain KnowledgeHash subsetof Any
	domain KnowledgeTimestamp subsetof Any
	domain KnowledgeOther subsetof Any

	//range on which apply the cryptographic function
	domain  FieldPosition subsetof Integer
	domain  Level subsetof Integer
	domain  EncField1 subsetof Integer
	domain  EncField2 subsetof Integer
	domain  SignField1 subsetof Integer
	domain  SignField2 subsetof Integer
	domain  HashField1 subsetof Integer
	domain  HashField2 subsetof Integer

	//state of the actor
	controlled internalStateA: Alice -> StateAlice
	controlled internalStateB: Bob -> StateBob

	//name of the message
	controlled protocolMessage: Prod(Agent,Agent)-> Message
	// content of the message and in which field it goes
	controlled messageField: Prod(Agent,Agent,FieldPosition,Message)->Knowledge

	//attaker mode
	monitored chosenMode: Modality
	//controlled for saving the attacker modality choice
	controlled mode: Modality

	// FUNCTIONS SELECT THE RECEIVER
	static name:Receiver -> Agent
	//Receiver chosen
	controlled receiver:Receiver
	//Receiver chosen by user
	monitored chosenReceiver:Receiver

	/*------------------------------------------------------------------- */
	//            Knowledge  management of the principals 
	/*------------------------------------------------------------------- */
	controlled knowsNonce:Prod(Agent,KnowledgeNonce)->Boolean

	controlled knowsIdentityCertificate:Prod(Agent,KnowledgeIdentityCertificate)->Boolean

	controlled knowsBitString:Prod(Agent,KnowledgeBitString)->Boolean

	controlled knowsSymKey:Prod(Agent,KnowledgeSymKey)->Boolean

	controlled knowsAsymPubKey:Prod(Agent,KnowledgeAsymPubKey)->Boolean

	controlled knowsAsymPrivKey:Prod(Agent,KnowledgeAsymPrivKey)->Boolean

	controlled knowsSignPubKey:Prod(Agent,KnowledgeSignPubKey)->Boolean

	controlled knowsSignPrivKey:Prod(Agent,KnowledgeSignPrivKey)->Boolean

	controlled knowsTag:Prod(Agent,KnowledgeTag)->Boolean

	controlled knowsDigest:Prod(Agent,KnowledgeDigest)->Boolean

	controlled knowsHash:Prod(Agent,KnowledgeHash)->Boolean

	controlled knowsTimestamp:Prod(Agent,KnowledgeTimestamp)->Boolean

	controlled knowsOther:Prod(Agent,KnowledgeOther)->Boolean

	/*------------------------------------------------------------------- */
	//                  Cryptographic functions
	/*------------------------------------------------------------------- */
	//hash function applied from the field HashField1 to HashField2, the nesting level is Level
	static hash: Prod(Message,Level,HashField1,HashField2)-> KnowledgeTag
	static verifyHash: Prod(Message,Level,HashField1,HashField2,KnowledgeTag)-> Boolean

	//sign function applied from the field SignField1 to SignField2, the nesting level is Level
	controlled sign: Prod(Message,Level,SignField1,SignField2)-> KnowledgeSignPrivKey
	static verifySign: Prod(Message,Level,SignField1,SignField2,Agent)-> Boolean
	static sign_keyAssociation: KnowledgeSignPrivKey -> KnowledgeSignPubKey

	//asymmetric encryption function applied from the field EncField1 to EncField2
	//the nesting level is Level
	controlled asymEnc: Prod(Message,Level,EncField1,EncField2)-> KnowledgeAsymPubKey
	static asymDec: Prod(Message,Level,EncField1,EncField2,Agent)-> Boolean
	static asim_keyAssociation: KnowledgeAsymPubKey -> KnowledgeAsymPrivKey

	//symmetric encryption function applied from the field EncField1 to EncField2
	//the nesting level is Level
	controlled symEnc: Prod(Message,Level,EncField1,EncField2)-> KnowledgeSymKey
	static symDec: Prod(Message,Level,EncField1,EncField2,Agent)-> Boolean

	static diffieHellman:Prod(KnowledgeAsymPubKey,KnowledgeAsymPrivKey)->KnowledgeSymKey

	static agentA: Alice
	static agentB: Bob
	static agentE: Eve

definitions:
	function name($a in Receiver)=
			switch( $a )
				case AG_A:agentA
				case AG_E:agentE
				case AG_B:agentB
			endswitch

		function verifySign($m in Message,$l in Level,$f1 in SignField1,$f2 in SignField2,$d in Agent)=
			if(knowsSignPubKey($d,sign_keyAssociation(sign($m,$l,$f1,$f2)))=true)then
				true
			else
				false
			endif

		function symDec($m in Message,$l in Level,$f1 in EncField1,$f2 in EncField2,$d in Agent)=
			if(knowsSymKey($d,symEnc($m,$l,$f1,$f2))=true)then
				true
			else
				false
			endif

		function asymDec($m in Message,$l in Level,$f1 in EncField1,$f2 in EncField2,$d in Agent)=
			if(knowsAsymPrivKey($d,asim_keyAssociation(asymEnc($m,$l,$f1,$f2)))=true)then
				true
			else
				false
			endif

