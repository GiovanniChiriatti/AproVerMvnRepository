asm SSL

import CryptoLibrarySSL

// A->B:{SKAB}PUBKB      KK
// B->A:{NB}SKAB         NK
// A->B:{CA,{NB}SIGNPRIVKA}SKAB

signature:



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
	
	/*ATTACKER RULES*/
	rule r_message_replay_KK =
		let ($b=agentB,$a=agentA) in
			if(protocolMessage($a ,self)=KK and protocolMessage(self,$b )!=KK and mode=PASSIVE)then
				if(asymDec(KK,1,1,1,self)=true)then
					par
						knowsSymKey(self,messageField($a,self,1,KK)):=true
						protocolMessage(self,$b):=KK
						messageField(self,$b,1,KK):=messageField($a,self,1,KK)
						//asymEnc(KK,1,1,1):= PUBKB 	
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
	//-------------------------------------------- Questo sotto è giusto (nel messaggio precedente è asteriscato
						symEnc(NK,1,1,1):= messageField($a,self,1,KK)
					endpar
				else
					par
						protocolMessage(self,$a ):= NK
						messageField(self,$a,1,KK):= messageField($b,self,1,NK)
					endpar
				endif
			else
				if(protocolMessage($b ,self)=NK and protocolMessage(self,$a )!=NK and mode=ACTIVE)then
					if(symDec(NK,1,1,1,self)=true)then
						par
							knowsNonce(self,messageField($b,self,1,NK)):=true
							protocolMessage(self,$a ):= NK
//------------------------------------------       Come mai si fa riferimento al messaggio rpecedente (KK)?
							messageField(self,$a,1,NK):= messageField($b,self,1,NK)
//------------------------------------------       Come mai si fa riferimento al messaggio rpecedente (KK)?
							symEnc(NK,1,1,1):= messageField($a,self,1,KK)
						endpar
					else
						par
							protocolMessage(self,$a ):= NK
//------------------------------------------       Come mai si fa riferimento al messaggio rpecedente (KK)?
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
//------------------- non manca :knowsIdentityCertificate(self,messageField($a,self,1,CSNK)):=true
// ------------------------------ è sicuro che il sia il field 1 e non il 2 se si perchè?
						knowsNonce(self,messageField($a,self,1,CSNK)):=true
						protocolMessage(self,$b ):= CSNK
						messageField(self,$b,1,CSNK):= messageField($a,self,1,CSNK)
						messageField(self,$b,2,CSNK):= messageField($a,self,2,CSNK)
						//symEnc(CSNK,2,1,2):=SKEB
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
//------------------- non manca :knowsIdentityCertificate(self,messageField($a,self,1,CSNK)):=true
// ------------------------------ è sicuro che il sia il field 1 e non il 2, se si perchè??
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
//------------------- non manca :knowsNonce(self,messageField($e,self,1,M1)):=true
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
//------------------- non manca :knowsNonce(self,messageField($e,self,1,M1)):=true
							protocolMessage(self,$e ):=CSNK
							messageField(self,$e,1,CSNK):=CA
							messageField(self,$e,2,CSNK):=messageField($e,self,1,NK)
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
	function mode=chosenMode
	
	agent Alice:
		r_agentARule[]

	agent Bob:
		r_agentBRule[]
		
	agent Eve:
	r_agentERule[]
