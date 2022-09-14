module CryptoLibrary 

export *

signature:

	domain Alice subsetof Agent
	domain Bob subsetof Agent
	domain Eve subsetof Agent
	
	enum domain StateAlice = {}
	enum domain StateBob = {}
	
	enum domain Message = {}
	
	enum domain Knowledge ={}
	
	enum domain Modality = {ACTIVE | PASSIVE}
	
	domain KnowledgeBitString subsetof Any
	domain KnowledgeSymKey subsetof Any
	domain KnowledgeAsymPrivKey subsetof Any
	domain KnowledgeAsymPubKey subsetof Any
	domain KnowledgeSignPrivKey subsetof Any
	domain KnowledgeSignPubKey subsetof Any
	
	domain FieldPosition subsetof Integer
	domain Level subsetof Integer
	domain EncField1 subsetof Integer
	domain EncField2 subsetof Integer
	domain SignField1 subsetof Integer
	domain SignField2 subsetof Integer
	domain HashField1 subsetof Integer
	domain HashField2 subsetof Integer
	
	controlled controllerState: Alice -> StateAlice
	controlled slaveState: Bob -> StateBob
	
	controlled protocolMessage: Prod(Agent,Agent)-> Message
	controlled messageField: Prod(Agent,Agent,FieldPosition,Message)->Knowledge
	
	monitored chosenMode: Modality
	controlled mode: Modality
	
	/*------------------------------------------------------------------- */
	//            Knowledge  management of the principals 
	/*------------------------------------------------------------------- */
	controlled knowsBitString:Prod(Agent,KnowledgeBitString)->Boolean
	
	controlled knowsSymKey:Prod(Agent,KnowledgeSymKey)->Boolean
	
	controlled knowsAsymPubKey:Prod(Agent,KnowledgeAsymPubKey)->Boolean
	
	controlled knowsAsymPrivKey:Prod(Agent,KnowledgeAsymPrivKey)->Boolean
	
	controlled knowsSignPubKey:Prod(Agent,KnowledgeSignPubKey)->Boolean
	
	controlled knowsSignPrivKey:Prod(Agent,KnowledgeSignPrivKey)->Boolean
	
	controlled knowsHash:Prod(Agent,Tag)->Boolean
	
	controlled knowsSignPrivKey:Prod(Agent,KnowledgeSignPrivKey)->Boolean
	
	/*------------------------------------------------------------------- */
	//                  Cryptographic functions
	/*------------------------------------------------------------------- */
	static hash: Prod(Message,Level,HashField1,HashField2)-> Tag
	static verifyHash: Prod(Message,Level,HashField1,HashField2,Tag)-> Boolean
	
	controlled sign: Prod(Message,Level,SignField1,SignField2)-> KnowledgeSignPrivKey
	static verifySign: Prod(Message,Level,SignField1,SignField2,Agent)-> Boolean
	
	controlled asymEnc: Prod(Message,Level,EncField1,EncField2)-> KnowledgeAsymPubKey
	static asymDec: Prod(Message,Level,EncField1,EncField2,Agent)-> Boolean
	static asim_keyAssociation: KnowledgeAsymPubKey -> KnowledgeAsymPrivKey
	
	controlled symEnc: Prod(Message,Level,EncField1,EncField2)-> KnowledgeSymKey
	static symDec: Prod(Message,Level,EncField1,EncField2,Agent)-> Boolean
	
	static diffieHellman:Prod(KnowledgeAsymPubKey,KnowledgeAsymPrivKey)->KnowledgeSymKey
	
	static nodeA: Alice
	static nodeB: Bob
	static nodeE: Eve
	
definitions:
	function verifySign($m in Message,$l in Level,$f1 in EncField1,$f2 in EncField2,$d in Agent)=
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
	
