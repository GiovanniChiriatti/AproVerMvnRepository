module CryptoLibrarySSL
 
import ../StandardLibrary 
export *

// A->B:{SKAB}PUBKB
// B->A:{NB}SKAB
// A->B:{CA,{NB}SIGNPRIVKA}SKAB
signature:

	domain Alice subsetof Agent
	domain Bob subsetof Agent
	domain Eve subsetof Agent
	
	enum domain StateAlice = {IDLE_A | WAITING_NK | END_A}
	enum domain StateBob = {WAITING_KAB | WAITING_CSNK | END_B}
	
	enum domain Message = {KK | NK | CSNK}
	
	enum domain Knowledge ={ NB | CA |
							 PRIVKA | PRIVKB | PRIVKE |
							 PUBKA | PUBKB | PUBKE |
							 SKAB | SKAE | SKEB | 
							 SIGNPRIVKA | SIGNPRIVKB | SIGNPRIVKE |
							 SIGNPUBKA | SIGNPUBKB | SIGNPUBKE}
	
	//DOMAIN OF POSSIBLE RECEIVER 
	enum domain Receiver={AG_B|AG_E|AG_S}
	//DOMAIN OF THE ATTACKER MODE
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
	
	domain FieldPosition subsetof Integer
	domain Level subsetof Integer
	domain EncField1 subsetof Integer
	domain EncField2 subsetof Integer
	domain SignField1 subsetof Integer
	domain SignField2 subsetof Integer
	domain HashField1 subsetof Integer
	domain HashField2 subsetof Integer
	
	controlled internalStateA: Alice -> StateAlice
	controlled internalStateB: Bob -> StateBob
	
	controlled protocolMessage: Prod(Agent,Agent)-> Message
	controlled messageField: Prod(Agent,Agent,FieldPosition,Message)->Knowledge
	
	monitored chosenMode: Modality
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
	
	controlled knowsHash:Prod(Agent,KnowledgeTag)->Boolean
	
	
	/*------------------------------------------------------------------- */
	//                  Cryptographic functions
	/*------------------------------------------------------------------- */
	static hash: Prod(Message,Level,HashField1,HashField2)-> KnowledgeTag
	static verifyHash: Prod(Message,Level,HashField1,HashField2,KnowledgeTag)-> Boolean
	
	controlled sign: Prod(Message,Level,SignField1,SignField2)-> KnowledgeSignPrivKey
	static verifySign: Prod(Message,Level,SignField1,SignField2,Agent)-> Boolean
	static sign_keyAssociation: KnowledgeSignPrivKey -> KnowledgeSignPubKey
	
	controlled asymEnc: Prod(Message,Level,EncField1,EncField2)-> KnowledgeAsymPubKey
	static asymDec: Prod(Message,Level,EncField1,EncField2,Agent)-> Boolean
	static asim_keyAssociation: KnowledgeAsymPubKey -> KnowledgeAsymPrivKey
	
	controlled symEnc: Prod(Message,Level,EncField1,EncField2)-> KnowledgeSymKey
	static symDec: Prod(Message,Level,EncField1,EncField2,Agent)-> Boolean
	
	static diffieHellman:Prod(KnowledgeAsymPubKey,KnowledgeAsymPrivKey)->KnowledgeSymKey
	
	static agentA: Alice
	static agentB: Bob
	static agentE: Eve
	
definitions:
	function name($a in Receiver)=
		switch( $a )
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
	
