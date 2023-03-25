asm SSL

import StandardLibrary 
//import CryptoLibrarySSL

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

	

	domain Level = {1}
	domain FieldPosition = {1:2}
	domain EncField1={1}
	domain EncField2={2}
	
	domain KnowledgeNonce = {NB}
	domain KnowledgeIdentityCertificate = {CA}
	domain KnowledgeAsymPrivKey = {PRIVKA , PRIVKB , PRIVKE }
	domain KnowledgeAsymPubKey = {PUBKA , PUBKB ,PUBKE}
	domain KnowledgeSignPrivKey = {SIGNPRIVKA , SIGNPRIVKB , SIGNPRIVKE }
	domain KnowledgeSignPubKey = {SIGNPUBKA , SIGNPUBKB , SIGNPUBKE}
	domain KnowledgeSymKey  = {SKAB , SKAE , SKEB}
	
	function asim_keyAssociation($a in KnowledgeAsymPubKey)=
		switch( $a )
			case PUBKE: PRIVKE
			case PUBKB: PRIVKB
			case PUBKA: PRIVKA
		endswitch
		
	function sign_keyAssociation($b in KnowledgeSignPrivKey)=
		switch( $b )
			case SIGNPRIVKA: SIGNPUBKA
			case SIGNPRIVKB: SIGNPUBKB
			case SIGNPRIVKE: SIGNPUBKE
		endswitch
		
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
	
	/*ATTACKER RULES*/
	rule r_message_replay_KK =
		let ($b=agentB,$a=agentA) in
			if(protocolMessage($a ,self)=KK and protocolMessage(self,$b )!=KK and mode=PASSIVE)then
				if(asymDec(KK,1,1,1,self)=true)then
					par
						knowsSymKey(self,messageField($a,self,1,KK)):=true
						protocolMessage(self,$b):=KK
						messageField(self,$b,1,KK):=messageField($a,self,1,KK)
						asymEnc(KK,1,1,1):= PUBKB 	
					endpar
				else
					par
						protocolMessage(self,$b):=KK
						messageField(self,$b,1,KK):= messageField($a,self,1,KK)
					endpar
				endif
			else
				if(protocolMessage($a ,self)=KK and protocolMessage(self,$b )!=KK and mode=ACTIVE)then
					if(asymDec(KK,1,1,1,self)=true)then
						par
							knowsSymKey(self,messageField($a,self,1,KK)):=true
							protocolMessage(self,$b):=KK
							messageField(self,$b,1,KK):=SKEB
							asymEnc(KK,1,1,1):= PUBKB 	
						endpar
					else
						par
							protocolMessage(self,$b):=KK
							messageField(self,$b,1,KK):= messageField($a,self,1,KK)
						endpar
					endif
				endif
			endif
		endlet
		
	rule r_message_replay_NK =
		let ($b=agentB,$a=agentA) in
			if(protocolMessage($b ,self)=NK and protocolMessage(self,$a )!=NK and mode=PASSIVE)then
				if(symDec(NK,1,1,1,self)=true)then
					par
						knowsNonce(self,messageField($b,self,1,NK)):=true
						protocolMessage(self,$a ):= NK
						messageField(self,$a,1,KK):= messageField($b,self,1,NK)
						symEnc(NK,1,1,1):= messageField($a,self,1,KK)
					endpar
				else
					par
						protocolMessage(self,$a ):= NK
						messageField(self,$a,1,NK):= messageField($b,self,1,NK)
					endpar
				endif
			else
				if(protocolMessage($b ,self)=NK and protocolMessage(self,$a )!=NK and mode=ACTIVE)then
					if(symDec(NK,1,1,1,self)=true)then
						par
							knowsNonce(self,messageField($b,self,1,NK)):=true
							protocolMessage(self,$a ):= NK
							messageField(self,$a,1,KK):= messageField($b,self,1,NK)
							symEnc(NK,1,1,1):= messageField($a,self,1,KK)
						endpar
					else
						par
							protocolMessage(self,$a ):= NK
							messageField(self,$a,1,NK):= messageField($b,self,1,NK)
						endpar
					endif
				endif
			endif
		endlet
		
	rule r_message_replay_CSNK =
		let ($b=agentB,$a=agentA) in
			if(protocolMessage($a ,self)=CSNK and protocolMessage(self,$b )!=CSNK and mode=PASSIVE)then				
				if(symDec(CSNK,2,1,2,self)=true)then
					par
						knowsNonce(self,messageField($a,self,1,CSNK)):=true
						protocolMessage(self,$b ):= CSNK
						messageField(self,$b,1,CSNK):= messageField($a,self,1,CSNK)
						messageField(self,$b,2,CSNK):= messageField($a,self,2,CSNK)
						symEnc(CSNK,2,1,2):=SKEB
						sign(CSNK,1,2,2):=SIGNPRIVKA
					endpar
				else
					par
						protocolMessage(self,$b ):= CSNK
						messageField(self,$b,1,CSNK):= messageField($a,self,1,CSNK)
						messageField(self,$b,2,CSNK):= messageField($a,self,2,CSNK)
					endpar
				endif
			else
				if(protocolMessage($a ,self)=CSNK and protocolMessage(self,$b )!=CSNK and mode=ACTIVE)then				
					if(symDec(CSNK,2,1,2,self)=true)then
						par
							knowsNonce(self,messageField($a,self,1,CSNK)):=true
							protocolMessage(self,$b ):= CSNK
							messageField(self,$b,1,CSNK):= messageField($a,self,1,CSNK)
							messageField(self,$b,2,CSNK):= messageField($a,self,2,CSNK)
							symEnc(CSNK,2,1,2):=SKEB
						endpar
					else
						par
							protocolMessage(self,$b ):= CSNK
							messageField(self,$b,1,CSNK):= messageField($a,self,1,CSNK)
							messageField(self,$b,2,CSNK):= messageField($a,self,2,CSNK)
						endpar
					endif
				endif
			endif
		endlet
		
	 	
	/*HONEST AGENT RULES*/	
	rule r_message_KK =
		let ($e=agentE) in
			if(internalStateA(self)=IDLE_A)then
				if(receiver=AG_B)then
					par
						protocolMessage(self,$e):= KK
						messageField(self,$e,1,KK):= SKAB
						asymEnc(KK,1,1,1):=PUBKB
						internalStateA(self):= WAITING_NK					
					endpar
				else
					if(receiver=AG_E)then
						par
							protocolMessage(self,$e):= KK
							messageField(self,$e,1,KK):= SKAE
							asymEnc(KK,1,1,1):=PUBKE
							internalStateA(self):= WAITING_NK					
						endpar
					endif
				endif
			endif
		endlet
		
	rule r_message_NK =
		let ($e=agentE) in
			if(internalStateB(self)=WAITING_KAB  and protocolMessage($e ,self)=KK)then
				if(asymDec(KK,1,1,1,self)=true)then
					par
						knowsSymKey(self,messageField($e,self,1,KK)):=true
						protocolMessage(self,$e):=NK
						messageField(self,$e,1,NK):= NB
						symEnc(NK,1,1,1):= messageField($e,self,1,KK)
						internalStateB(self):= WAITING_CSNK						
					endpar
				endif
			endif			
		endlet
		
	rule r_message_CSNK=
		let ($e=agentE) in
			if(internalStateA(self)=WAITING_NK  and protocolMessage($e ,self)=NK)then				
				if(receiver=AG_B)then
					if(symDec(NK,1,1,1,self)=true)then
						par
							protocolMessage(self,$e ):=CSNK
							messageField(self,$e,1,CSNK):=CA
							messageField(self,$e,2,CSNK):=messageField($e,self,1,NK)
							sign(CSNK,1,2,2):= SIGNPRIVKA
							symEnc(CSNK,2,1,2):= messageField(self,$e,1,KK)
							internalStateA(self):= END_A
						endpar
					endif	
				else
					if(symDec(NK,1,1,1,self)=true)then
						par
							protocolMessage(self,$e ):=CSNK
							messageField(self,$e,1,CSNK):=CA
							messageField(self,$e,2,CSNK):=messageField($e,self,1,KK)
							sign(CSNK,1,2,2):= SIGNPRIVKA
							symEnc(CSNK,2,1,2):= messageField(self,$e,1,KK)
							internalStateA(self):= END_A
						endpar
					endif		
				endif
			endif
		endlet
	
	rule r_check_CSNK =
		let ($e=agentE) in
			if(internalStateB(self)=WAITING_CSNK  and protocolMessage($e ,self)=CSNK)then				
				if(symDec(CSNK,2,1,2,self)=true)then
					if(verifySign(CSNK,1,2,2,self)=true)then
						internalStateB(self):= END_B
					endif
				endif		
			endif
		endlet
		
		
rule r_agentERule  =
		par
			r_message_replay_KK[]
			r_message_replay_NK[]
			r_message_replay_CSNK[]
		endpar
	
	
	rule r_agentARule  =
		par
			r_message_KK[]
			r_message_CSNK[]
		endpar
		
	rule r_agentBRule  =
		par
			r_message_NK[]
			r_check_CSNK[]
		endpar

	main rule r_Main =
		par
			program(agentA)
			program(agentB)
			program(agentE)
		endpar
		
	
default init s0:
	function internalStateA($a in Alice)=IDLE_A
	function internalStateB($b in Bob)=WAITING_KAB
	function receiver=chosenReceiver
	function knowsNonce($a in Agent, $n in KnowledgeNonce)=if($a=agentB and $n=NB)then true else false endif
	function knowsIdentityCertificate($a in Agent, $i in KnowledgeIdentityCertificate)=if($a=agentA and $i=CA) then false endif 
	function knowsAsymPrivKey($a in Agent ,$k in KnowledgeAsymPrivKey)=if(($a=agentA and $k=PRIVKA) or ($a=agentB and $k=PRIVKB) or ($a=agentE and $k=PRIVKE)) then true else false endif
	function knowsAsymPubKey($a in Agent ,$pk in KnowledgeAsymPubKey)=true
	function knowsSymKey($a in Agent ,$sk in KnowledgeSymKey)=if((($a=agentA or $a=agentE) and $sk=SKAE) or (($a=agentA or $a=agentB) and $sk=SKAB) or (($a=agentB or $a=agentE) and $sk=SKEB)) then true else false endif
// Aggiunto..................
//	function knowsSignPubKey($a in Agent ,$sk in KnowledgeSignPubKey)=if((($a=agentA or $a=agentB or $a=agentE) and ($sk=SIGNPUBKA or $sk=SIGNPUBKB or $sk=SIGNPUBKE))) then true else false endif
	function knowsSignPubKey($a in Agent ,$sk in KnowledgeSignPubKey)=true
	
	function mode=chosenMode
	
	agent Alice:
		r_agentARule[]

	agent Bob:
		r_agentBRule[]
		
	agent Eve:
	r_agentERule[]
