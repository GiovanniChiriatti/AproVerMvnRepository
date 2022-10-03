asm Needham_Schroeder

import CryptoLibraryNS

// A->B:{NA,A}PUBKB
// B->A:{NA,NB}PUBKA
// A->B:{NB}PKB


signature:



definitions:
	domain Level = {1}
	domain FieldPosition = {1:2}
	domain EncField1={1}
	domain EncField2={2}
	
	domain KnowledgeNonce = {NE,NA,NB}
	domain KnowledgeIdentityCertificate = {ID_A,ID_B,ID_E}
	domain KnowledgeAsymPrivKey = {PRIVKA , PRIVKB , PRIVKE }
	domain KnowledgeAsymPubKey = {PUBKA , PUBKB ,PUBKE}
	
	function asim_keyAssociation($a in KnowledgeAsymPubKey)=
		switch( $a )
			case PUBKE: PRIVKE
			case PUBKB: PRIVKB
			case PUBKA: PRIVKA
		endswitch
	
	/*ATTACKER RULES*/
	rule r_message_replay_NAK =
		//choose what agets are interested by the message
		let ($b=agentB,$a=agentA) in
			//check the reception of the message and the modality of the attack
			if(protocolMessage($a ,self)=NAK and protocolMessage(self,$b )!=NAK and mode=PASSIVE)then
				//in passsive mode if the attacker knows the decryption key, the message payload is readable and it can be added to the attacker knowledge
				// the message must be sent unaltered
				if(asymDec(NAK,1,1,2,self)=true)then
					par
						knowsNonce(self,messageField($a,self,1,NAK)):=true
						knowsIdentityCertificate(self,messageField($a,self,2,NAK)):=true
						protocolMessage(self,$b ):= NAK
						messageField(self,$b,1,NAK):=messageField($a,self,1,NAK)
						messageField(self,$b,2,NAK):=messageField($a,self,2,NAK)
						//asymEnc(NAK,1,1,2 ):=PUBKB
					endpar
				else
					par
						protocolMessage(self,$b ):= NAK
						messageField(self,$b,1,NAK):=messageField($a,self,1,NAK)
						messageField(self,$b,2,NAK):=messageField($a,self,2,NAK)
					endpar
				endif
			else
				//check the reception of the message and the modality of the attack				
				if(protocolMessage($a ,self)=NAK and protocolMessage(self,$b )!=NAK and mode=ACTIVE)then
					// in the active mode the attacker can forge the message with all his knowledge 
					if(asymDec(NAK,1,1,2,self)=true)then
						par
							knowsNonce(self,messageField($a,self,1,NAK)):=true
							knowsIdentityCertificate(self,messageField($a,self,2,NAK)):=true
							protocolMessage(self,$b ):= NAK
							messageField(self,$b,1,NAK):=messageField($a,self,1,NAK)
							messageField(self,$b,2,NAK):=messageField($a,self,2,NAK)
							asymEnc(NAK,1,1,2 ):=PUBKB
						endpar
					else
						par
							protocolMessage(self,$b ):= NAK
							messageField(self,$b,1,NAK):=messageField($a,self,1,NAK)
							messageField(self,$b,2,NAK):=messageField($a,self,2,NAK)
						endpar
					endif
				endif	
			endif
			
		endlet
		
	rule r_message_replay_NNK =
		let ($b=agentB,$a=agentA) in
			if(protocolMessage($b ,self)=NNK and protocolMessage(self,$a )!=NNK and mode=PASSIVE)then
				if(asymDec(NNK,1,1,2,self)=true)then
					par
						knowsNonce(self,messageField($b,self,1,NNK)):=true
						knowsNonce(self,messageField($b,self,2,NNK)):=true
						protocolMessage(self,$a ):= NNK
						messageField(self,$b,1,NNK):=messageField($b,self,1,NNK)
						messageField(self,$b,2,NNK):=messageField($b,self,2,NNK)
						//asymEnc(NNK,1,1,2 ):=PUBKA			
					endpar
				else
					par
						protocolMessage(self,$a ):= NNK
						messageField(self,$b,1,NNK):=messageField($a,self,1,NNK) 
						messageField(self,$b,2,NNK):=messageField($a,self,2,NNK) )
						//asymEnc(NNK,1,1,2 ):=PUBKA	
					endpar
				endif
			else
				if(protocolMessage($b ,self)=NNK and protocolMessage(self,$a )!=NNK and mode=ACTIVE)then
					if(asymDec(NNK,1,1,2,self)=true)then
						par
							knowsNonce(self,messageField($b,self,1,NNK)):=true
							knowsNonce(self,messageField($b,self,2,NNK)):=true
							protocolMessage(self,$a ):= NNK
							messageField(self,$b,1,NNK):=messageField($b,self,1,NNK)
							messageField(self,$b,2,NNK):=messageField($b,self,2,NNK)
							asymEnc(NNK,1,1,2 ):=PUBKA			
						endpar
					else
						par
							protocolMessage(self,$a ):= NNK
							messageField(self,$b,1,NNK):=messageField($a,self,1,NNK) 
							messageField(self,$b,2,NNK):=messageField($a,self,2,NNK)
//----------------------> non capisco quando va messa l'istruzione di uso della crittografia e quando no    ----- asymEnc(NNK,1,1,2 ):=PUBKA
							asymEnc(NNK,1,1,2 ):=PUBKA	
						endpar
					endif
				endif
			endif
		endlet
		
	rule r_message_replay_NK =
		let ($b=agentB,$a=agentA) in
			if(protocolMessage($a ,self)=NK and protocolMessage(self,$b )!=NK and mode=PASSIVE)then				
				if(asymDec(NK,1,1,1,self)=true)then
					par
						knowsNonce(self,messageField($a,self,1,NK)):=true
						protocolMessage(self,$b ):= NK						
						//asymEnc(NK,1,1,1 ):=PUBKB
//---> manca 	messageField(self,$b,1,M2):=messageField($a,self,1,M2)
					endpar
				else
						protocolMessage(self,$b ):= NK
//---> manca messageField(self,$b,1,M2):=messageField($a,self,1,M2)
				endif
			else
				if(protocolMessage($a ,self)=NK and protocolMessage(self,$b )!=NK and mode=ACTIVE)then				
					if(asymDec(NK,1,1,1,self)=true)then
						par
							knowsNonce(self,messageField($a,self,1,NK)):=true
							protocolMessage(self,$b ):= NK	
//---> manca messageField(self,$b,1,M2):=messageField($a,self,1,M2)					
							asymEnc(NK,1,1,1 ):=PUBKB	
						endpar
					else
							protocolMessage(self,$b ):= NK
//----> manca messageField(self,$b,1,M2):=messageField($a,self,1,M2)
					endif
				endif
			endif
			
		endlet	
		
	 	
	/*HONEST AGENT RULES*/	
	rule r_message_NAK =		
		let ($e=agentE) in
			if(internalStateA(self)=IDLE_A)then
				if(receiver=AG_B)then
					par
						protocolMessage(self,$e ):= NAK
						messageField(self,$e,1,NAK):=NA
						messageField(self,$e,2,NAK):=ID_A
						asymEnc(NAK,1,1,2 ):=PUBKB
						internalStateA(self):= WAITING_NNK
					endpar
				else
					if(receiver=AG_E)then
						par
							protocolMessage(self,$e ):= NAK
							messageField(self,$e,1,NAK):=NA
							messageField(self,$e,2,NAK):=ID_A
							asymEnc(NAK,1,1,2 ):=PUBKE
							internalStateA(self):= WAITING_NNK
						endpar
					endif
				endif
			endif
		endlet
		
	rule r_message_NNK =
		let ($e=agentE) in
			if(internalStateB(self)=WAITING_NAK  and protocolMessage($e ,self)=NAK)then
				if(asymDec(NAK,1,1,2,self)=true)then
					par
						knowsNonce(self,messageField($e,self,1,NAK)):=true
						knowsIdentityCertificate(self,messageField($e,self,2,NAK)):=true
						protocolMessage(self,$e):=NNK
						messageField(self,$e,1,NNK):=NA ---->(messageField($e,self,1,M0))
						messageField(self,$e,2,NNK):=NB
						asymEnc(NNK,1,1,2):=PUBKA
						internalStateB(self):= WAITING_NK						
					endpar
				endif
			endif			
		endlet
		
	rule r_message_NK =
		let ($e=agentE) in
			if(internalStateA(self)=WAITING_NNK  and protocolMessage($e ,self)=NNK)then				
				if(receiver=AG_B)then
					if(asymDec(NNK,1,1,2,self)=true)then
						par
							knowsNonce(self,messageField($e,self,1,NNK)):=true
							knowsNonce(self,messageField($e,self,2,NNK)):=true
							protocolMessage(self,$e ):=NK
							messageField(self,$e,1,NK):=NB	---->(messageField($e,self,2,M1))						
							asymEnc(NK,1,1,1):=PUBKB 
							internalStateA(self):= END_A
						endpar
					endif	
				else
					if(asymDec(NNK,1,1,2,self)=true)then
						par
							knowsNonce(self,messageField($e,self,1,NNK)):=true
							knowsNonce(self,messageField($e,self,2,NNK)):=true
							protocolMessage(self,$e ):=NK
							messageField(self,$e,1,NK):=NB	
							asymEnc(NK,1,1,1):=PUBKE
							internalStateA(self):= END_A
						endpar
					endif		
				endif
			endif
		endlet
		
	rule r_check_NK =
		let ($e=agentE) in
			if(internalStateB(self)=WAITING_NK  and protocolMessage($e ,self)=NK)then				
				if(asymDec(NK,1,1,1,self)=true)then					
						internalStateB(self):= END_B					
				endif		
			endif
		endlet
		
		
	rule r_agentERule  =		
		par				
			r_message_replay_NAK[]
			r_message_replay_NNK[] 
			r_message_replay_NK[]
		endpar

		
	rule r_agentARule  =
		par
			r_message_NAK[]
			r_message_NK[]
		endpar
		
	rule r_agentBRule  =
		par
			r_message_NNK[]
			r_check_NK[]
		endpar

	main rule r_Main =
		par
			program(agentA)
			program(agentB)
			program(agentE)
		endpar
		
	
default init s0:
	function internalStateA($a in Alice)=IDLE_A
	function internalStateB($b in Bob)=WAITING_NAK
	function receiver=chosenReceiver
	function knowsNonce($a in Agent, $n in KnowledgeNonce)=if($a=agentA and $n=NA) then true else if($a=agentB and $n=NB)then true else false endif endif
	function knowsIdentityCertificate($a in Agent, $i in KnowledgeIdentityCertificate)=if($a=agentA and $i=ID_A) then true else if($a=agentB and $i=ID_B)then true else false endif endif
	function knowsAsymPrivKey($a in Agent ,$k in KnowledgeAsymPrivKey)=if(($a=agentA and $k=PRIVKA) or ($a=agentB and $k=PRIVKB) or ($a=agentE and $k=PRIVKE)) then true else false endif
	function knowsAsymPubKey($a in Agent ,$pk in KnowledgeAsymPubKey)=true
	function mode=chosenMode
	
	agent Alice:
		r_agentARule[]

	agent Bob:
		r_agentBRule[]
		
	agent Eve:
	r_agentERule[]
