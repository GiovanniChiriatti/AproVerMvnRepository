asm YAHALOM

import CryptoLibraryYAHALOM


signature:

definitions:
	domain Level = {1}
	domain FieldPosition = {1:6}
	domain EncField1={1:4}
	domain EncField2={2:4}

	domain KnowledgeNonce = {NA,NB}
	domain KnowledgeIdentityCertificate = {CA,CB}
	domain KnowledgeSymKey = {KAB,KAS,KBS,KES}


	/*ATTACKER RULES*/
	rule r_message_replay_REQCOM =
		//choose what agets are interested by the message
		let ($b=agentB,$a=agentA) in
		  par 
			//check the reception of the message and the modality of the attack
			if(protocolMessage($a,self)=REQCOM and protocolMessage(self,$b)!=REQCOM and mode=PASSIVE)then
			        //in passsive mode if the attacker knows the decryption key, the message payload is readable and it can be added to the attacker knowledge
			        // the message must be sent unaltered
		          par 
                            	protocolMessage(self,$b):=REQCOM
                            	messageField(self,$b,1,REQCOM):=messageField($a,self,1,REQCOM)
                            	messageField(self,$b,2,REQCOM):=messageField($a,self,2,REQCOM)
                            	knowsIdentityCertificate(self,messageField($a,self,1,REQCOM)):=true
                            	knowsNonce(self,messageField($a,self,2,REQCOM)):=true
		          endpar 
			endif 
			        //check the reception of the message and the modality of the attack
			if(protocolMessage($a,self)=REQCOM and protocolMessage(self,$b)!=REQCOM and mode=ACTIVE)then
		          par 
                            	protocolMessage(self,$b):=REQCOM
                            	messageField(self,$b,1,REQCOM):=messageField($a,self,1,REQCOM)
                            	messageField(self,$b,2,REQCOM):=messageField($a,self,2,REQCOM)
                            	knowsIdentityCertificate(self,messageField($a,self,1,REQCOM)):=true
                            	knowsNonce(self,messageField($a,self,2,REQCOM)):=true
		          endpar 
			endif 
		  endpar 
		endlet 
	rule r_message_replay_ENCKBS =
		//choose what agets are interested by the message
		let ($b=agentS,$a=agentB) in
		  par 
			//check the reception of the message and the modality of the attack
			if(protocolMessage($a,self)=ENCKBS and protocolMessage(self,$b)!=ENCKBS and mode=PASSIVE)then
			        //in passsive mode if the attacker knows the decryption key, the message payload is readable and it can be added to the attacker knowledge
			        // the message must be sent unaltered
		          par 
                            	protocolMessage(self,$b):=ENCKBS
                            	knowsIdentityCertificate(self,messageField($a,self,1,ENCKBS)):=true
                            	messageField(self,$b,1,ENCKBS):=messageField($a,self,1,ENCKBS)
                            	symEnc(ENCKBS,1,2,4):=KES
		          endpar 
			endif 
			if(protocolMessage($a,self)=ENCKBS and protocolMessage(self,$b)!=ENCKBS and mode=PASSIVE)then
			        if(symDec(ENCKBS,1,2,4,self)=true)then
			  		  par 
                            	knowsIdentityCertificate(self,messageField($a,self,2,ENCKBS)):=true
                            	knowsOther(self,messageField($a,self,3,ENCKBS)):=true
                            	knowsNonce(self,messageField($a,self,4,ENCKBS)):=true
                            	messageField(self,$b,2,ENCKBS):=messageField($a,self,2,ENCKBS)
                            	messageField(self,$b,3,ENCKBS):=messageField($a,self,3,ENCKBS)
                            	messageField(self,$b,4,ENCKBS):=messageField($a,self,4,ENCKBS)
			  		  endpar 
				    else 
			  		  par 
                            	messageField(self,$b,2,REQCOM):=messageField($a,self,2,ENCKBS)
                            	messageField(self,$b,3,REQCOM):=messageField($a,self,3,ENCKBS)
                            	messageField(self,$b,4,REQCOM):=messageField($a,self,4,ENCKBS)
			  		  endpar 
					endif 
			endif 
			        //check the reception of the message and the modality of the attack
			if(protocolMessage($a,self)=ENCKBS and protocolMessage(self,$b)!=ENCKBS and mode=ACTIVE)then
		          par 
                            	protocolMessage(self,$b):=ENCKBS
                            	knowsIdentityCertificate(self,messageField($a,self,1,ENCKBS)):=true
                            	messageField(self,$b,1,ENCKBS):=messageField($a,self,1,ENCKBS)
                            	symEnc(ENCKBS,1,2,4):=KES
		          endpar 
			endif 
			if(protocolMessage($a,self)=ENCKBS and protocolMessage(self,$b)!=ENCKBS and mode=ACTIVE)then
			        if(symDec(ENCKBS,1,2,4,self)=true)then
			  		  par 
                            	knowsIdentityCertificate(self,messageField($a,self,2,ENCKBS)):=true
                            	knowsOther(self,messageField($a,self,3,ENCKBS)):=true
                            	knowsNonce(self,messageField($a,self,4,ENCKBS)):=true
                            	messageField(self,$b,2,ENCKBS):=messageField($a,self,2,ENCKBS)
                            	messageField(self,$b,3,ENCKBS):=messageField($a,self,3,ENCKBS)
                            	messageField(self,$b,4,ENCKBS):=messageField($a,self,4,ENCKBS)
			  		  endpar 
				    else 
			  		  par 
                            	messageField(self,$b,2,REQCOM):=messageField($a,self,2,ENCKBS)
                            	messageField(self,$b,3,REQCOM):=messageField($a,self,3,ENCKBS)
                            	messageField(self,$b,4,REQCOM):=messageField($a,self,4,ENCKBS)
			  		  endpar 
					endif 
			endif 
		  endpar 
		endlet 
	rule r_message_replay_GENKEYSES =
		//choose what agets are interested by the message
		let ($b=agentA,$a=agentS) in
		  par 
			//check the reception of the message and the modality of the attack
			if(protocolMessage($a,self)=GENKEYSES and protocolMessage(self,$b)!=GENKEYSES and mode=PASSIVE)then
			        //in passsive mode if the attacker knows the decryption key, the message payload is readable and it can be added to the attacker knowledge
			        // the message must be sent unaltered
		          par 
                            	protocolMessage(self,$b):=GENKEYSES
                            	symEnc(GENKEYSES,1,1,4):=KES
                            	symEnc(GENKEYSES,1,5,6):=KES
		          endpar 
			endif 
			if(protocolMessage($a,self)=GENKEYSES and protocolMessage(self,$b)!=GENKEYSES and mode=PASSIVE)then
			  par 
			        if(symDec(GENKEYSES,1,1,4,self)=true)then
			  		  par 
                            	knowsIdentityCertificate(self,messageField($a,self,1,GENKEYSES)):=true
                            	knowsSymKey(self,messageField($a,self,2,GENKEYSES)):=true
                            	knowsNonce(self,messageField($a,self,3,GENKEYSES)):=true
                            	knowsOther(self,messageField($a,self,4,GENKEYSES)):=true
                            	messageField(self,$b,1,GENKEYSES):=messageField($a,self,1,GENKEYSES)
                            	messageField(self,$b,2,GENKEYSES):=messageField($a,self,2,GENKEYSES)
                            	messageField(self,$b,3,GENKEYSES):=messageField($a,self,3,GENKEYSES)
                            	messageField(self,$b,4,GENKEYSES):=messageField($a,self,4,GENKEYSES)
			  		  endpar 
				    else 
			  		  par 
                            	messageField(self,$b,1,REQCOM):=messageField($a,self,1,GENKEYSES)
                            	messageField(self,$b,2,REQCOM):=messageField($a,self,2,GENKEYSES)
                            	messageField(self,$b,3,REQCOM):=messageField($a,self,3,GENKEYSES)
                            	messageField(self,$b,4,REQCOM):=messageField($a,self,4,GENKEYSES)
			  		  endpar 
					endif 
			        if(symDec(GENKEYSES,1,5,6,self)=true)then
			  		  par 
                            	knowsIdentityCertificate(self,messageField($a,self,5,GENKEYSES)):=true
                            	knowsSymKey(self,messageField($a,self,6,GENKEYSES)):=true
                            	messageField(self,$b,5,GENKEYSES):=messageField($a,self,5,GENKEYSES)
                            	messageField(self,$b,6,GENKEYSES):=messageField($a,self,6,GENKEYSES)
			  		  endpar 
				    else 
			  		  par 
                            	messageField(self,$b,5,REQCOM):=messageField($a,self,5,GENKEYSES)
                            	messageField(self,$b,6,REQCOM):=messageField($a,self,6,GENKEYSES)
			  		  endpar 
					endif 
			  endpar 
			endif 
			        //check the reception of the message and the modality of the attack
			if(protocolMessage($a,self)=GENKEYSES and protocolMessage(self,$b)!=GENKEYSES and mode=ACTIVE)then
		          par 
                            	protocolMessage(self,$b):=GENKEYSES
                            	symEnc(GENKEYSES,1,1,4):=KES
                            	symEnc(GENKEYSES,1,5,6):=KES
		          endpar 
			endif 
			if(protocolMessage($a,self)=GENKEYSES and protocolMessage(self,$b)!=GENKEYSES and mode=ACTIVE)then
			  par 
			        if(symDec(GENKEYSES,1,1,4,self)=true)then
			  		  par 
                            	knowsIdentityCertificate(self,messageField($a,self,1,GENKEYSES)):=true
                            	knowsSymKey(self,messageField($a,self,2,GENKEYSES)):=true
                            	knowsNonce(self,messageField($a,self,3,GENKEYSES)):=true
                            	knowsOther(self,messageField($a,self,4,GENKEYSES)):=true
                            	messageField(self,$b,1,GENKEYSES):=messageField($a,self,1,GENKEYSES)
                            	messageField(self,$b,2,GENKEYSES):=KES
                            	messageField(self,$b,3,GENKEYSES):=messageField($a,self,3,GENKEYSES)
                            	messageField(self,$b,4,GENKEYSES):=messageField($a,self,4,GENKEYSES)
			  		  endpar 
				    else 
			  		  par 
                            	messageField(self,$b,1,REQCOM):=messageField($a,self,1,GENKEYSES)
                            	messageField(self,$b,2,REQCOM):=messageField($a,self,2,GENKEYSES)
                            	messageField(self,$b,3,REQCOM):=messageField($a,self,3,GENKEYSES)
                            	messageField(self,$b,4,REQCOM):=messageField($a,self,4,GENKEYSES)
			  		  endpar 
					endif 
			        if(symDec(GENKEYSES,1,5,6,self)=true)then
			  		  par 
                            	knowsIdentityCertificate(self,messageField($a,self,5,GENKEYSES)):=true
                            	knowsSymKey(self,messageField($a,self,6,GENKEYSES)):=true
                            	messageField(self,$b,5,GENKEYSES):=messageField($a,self,5,GENKEYSES)
                            	messageField(self,$b,6,GENKEYSES):=KES
			  		  endpar 
				    else 
			  		  par 
                            	messageField(self,$b,5,REQCOM):=messageField($a,self,5,GENKEYSES)
                            	messageField(self,$b,6,REQCOM):=messageField($a,self,6,GENKEYSES)
			  		  endpar 
					endif 
			  endpar 
			endif 
		  endpar 
		endlet 
	rule r_message_replay_FRWVRNB =
		//choose what agets are interested by the message
		let ($b=agentB,$a=agentA) in
		  par 
			//check the reception of the message and the modality of the attack
			if(protocolMessage($a,self)=FRWVRNB and protocolMessage(self,$b)!=FRWVRNB and mode=PASSIVE)then
			        //in passsive mode if the attacker knows the decryption key, the message payload is readable and it can be added to the attacker knowledge
			        // the message must be sent unaltered
		          par 
                            	protocolMessage(self,$b):=FRWVRNB
                            	symEnc(FRWVRNB,1,1,2):=KES
                            	symEnc(FRWVRNB,1,3,3):=messageField($b,self,2,GENKEYSES)
		          endpar 
			endif 
			if(protocolMessage($a,self)=FRWVRNB and protocolMessage(self,$b)!=FRWVRNB and mode=PASSIVE)then
			  par 
			        if(symDec(FRWVRNB,1,1,2,self)=true)then
			  		  par 
                            	knowsIdentityCertificate(self,messageField($a,self,1,FRWVRNB)):=true
                            	knowsSymKey(self,messageField($a,self,2,FRWVRNB)):=true
                            	messageField(self,$b,1,FRWVRNB):=messageField($a,self,1,FRWVRNB)
                            	messageField(self,$b,2,FRWVRNB):=messageField($a,self,2,FRWVRNB)
			  		  endpar 
				    else 
			  		  par 
                            	messageField(self,$b,1,REQCOM):=messageField($a,self,1,FRWVRNB)
                            	messageField(self,$b,2,REQCOM):=messageField($a,self,2,FRWVRNB)
			  		  endpar 
					endif 
			        if(symDec(FRWVRNB,1,3,3,self)=true)then
			  		  par 
                            	knowsNonce(self,messageField($a,self,3,FRWVRNB)):=true
                            	messageField(self,$b,3,FRWVRNB):=messageField($a,self,3,FRWVRNB)
			  		  endpar 
				    else 
                            	messageField(self,$b,3,REQCOM):=messageField($a,self,3,FRWVRNB)
					endif 
			  endpar 
			endif 
			        //check the reception of the message and the modality of the attack
			if(protocolMessage($a,self)=FRWVRNB and protocolMessage(self,$b)!=FRWVRNB and mode=ACTIVE)then
		          par 
                            	protocolMessage(self,$b):=FRWVRNB
                            	symEnc(FRWVRNB,1,1,2):=KES
                            	symEnc(FRWVRNB,1,3,3):=messageField($b,self,2,GENKEYSES)
		          endpar 
			endif 
			if(protocolMessage($a,self)=FRWVRNB and protocolMessage(self,$b)!=FRWVRNB and mode=ACTIVE)then
			  par 
			        if(symDec(FRWVRNB,1,1,2,self)=true)then
			  		  par 
                            	knowsIdentityCertificate(self,messageField($a,self,1,FRWVRNB)):=true
                            	knowsSymKey(self,messageField($a,self,2,FRWVRNB)):=true
                            	messageField(self,$b,1,FRWVRNB):=messageField($a,self,1,FRWVRNB)
                            	messageField(self,$b,2,FRWVRNB):=KES
			  		  endpar 
				    else 
			  		  par 
                            	messageField(self,$b,1,REQCOM):=messageField($a,self,1,FRWVRNB)
                            	messageField(self,$b,2,REQCOM):=messageField($a,self,2,FRWVRNB)
			  		  endpar 
					endif 
			        if(symDec(FRWVRNB,1,3,3,self)=true)then
			  		  par 
                            	knowsNonce(self,messageField($a,self,3,FRWVRNB)):=true
                            	messageField(self,$b,3,FRWVRNB):=messageField($a,self,3,FRWVRNB)
			  		  endpar 
				    else 
                            	messageField(self,$b,3,REQCOM):=messageField($a,self,3,FRWVRNB)
					endif 
			  endpar 
			endif 
		  endpar 
		endlet 

	/*HONEST AGENT RULES*/	
	rule r_message_REQCOM =
		let ($e=agentE) in
			if(internalStateA(self)=IDLE_REQCOM)then 
			        if(receiver=AG_B)then
			                par
			                       protocolMessage(self,$e):=REQCOM
			                       messageField(self,$e,1,REQCOM):=CA
			                       messageField(self,$e,2,REQCOM):=NA
			                       internalStateS(agentS):=WAITING_ENCKBS
			                endpar
			        else
			                if(receiver=AG_E)then
			                        par
			                              protocolMessage(self,$e):=REQCOM
			                              messageField(self,$e,1,REQCOM):=CA
			                              messageField(self,$e,2,REQCOM):=NA
			                              internalStateS(agentS):=WAITING_ENCKBS
			                        endpar
			                endif
			        endif
			endif
		endlet
	rule r_message_ENCKBS =
		let ($e=agentE) in
			if(internalStateB(self)=WAITING_REQCOM and protocolMessage($e,self)=REQCOM)then
			     if(receiver=AG_S)then
			                par
                            	        	knowsIdentityCertificate(self,messageField($e,self,1,REQCOM)):=true
                            	        	knowsNonce(self,messageField($e,self,2,REQCOM)):=true
			                      protocolMessage(self,$e):=ENCKBS
			                      messageField(self,$e,1,ENCKBS):=CB
			                      messageField(self,$e,2,ENCKBS):=messageField($e,self,1,REQCOM)
			                      messageField(self,$e,3,ENCKBS):=messageField($e,self,2,REQCOM)
			                      messageField(self,$e,4,ENCKBS):=NB
			                      symEnc(ENCKBS,1,1,3):=KBS
			                      internalStateA(agentA):=WAITING_GENKEYSES
			                endpar
			else
			                par
                            	        	knowsIdentityCertificate(self,messageField($e,self,1,REQCOM)):=true
                            	        	knowsOther(self,messageField($e,self,2,REQCOM)):=true
			                      protocolMessage(self,$e):=ENCKBS
			                      messageField(self,$e,1,ENCKBS):=CB
			                      messageField(self,$e,2,ENCKBS):=messageField($e,self,1,REQCOM)
			                      messageField(self,$e,3,ENCKBS):=messageField($e,self,2,REQCOM)
			                      messageField(self,$e,4,ENCKBS):=NB
			                      symEnc(ENCKBS,1,1,3):=KES
			                      internalStateA(agentA):=WAITING_GENKEYSES
			                endpar
				endif
			endif
		endlet
	rule r_message_GENKEYSES =
		let ($e=agentE) in
			if(internalStateS(self)=WAITING_ENCKBS and protocolMessage($e,self)=ENCKBS)then
 			        if(symDec(ENCKBS,1,2,4,self)=true ) then
			                par
						knowsIdentityCertificate(self,messageField($e,self,1,REQCOM)):=true
						knowsNonce(self,messageField($e,self,2,REQCOM)):=true
						knowsOther(self,messageField($e,self,3,REQCOM)):=true
	 		                      protocolMessage(self,$e):=GENKEYSES
			                      messageField(self,$e,1,GENKEYSES):=messageField($e,self,1,ENCKBS)
			                      messageField(self,$e,2,GENKEYSES):=KES
			                      messageField(self,$e,3,GENKEYSES):=messageField($e,self,3,ENCKBS)
			                      messageField(self,$e,4,GENKEYSES):=messageField($e,self,4,ENCKBS)
 			                      symEnc(GENKEYSES,1,1,4):=KES
			                      messageField(self,$e,5,GENKEYSES):=messageField($e,self,2,ENCKBS)
			                      messageField(self,$e,6,GENKEYSES):=messageField($e,self,2,GENKEYSES)
 			                      symEnc(GENKEYSES,1,5,6):=KES
			                      internalStateB(agentB):=WAITING_FRWVRNB
			                endpar
			        endif
			endif
		endlet
	rule r_message_FRWVRNB =
		let ($e=agentE) in
			if(internalStateA(self)=WAITING_GENKEYSES and protocolMessage($e,self)=GENKEYSES)then
			     if(receiver=AG_B)then
 			        if(symDec(GENKEYSES,1,1,4,self)=true  and symDec(GENKEYSES,1,5,6,self)=true ) then
			                par
                            	        	knowsIdentityCertificate(self,messageField($e,self,1,REQCOM)):=true
                            	        	knowsSymKey(self,messageField($e,self,2,REQCOM)):=true
                            	        	knowsNonce(self,messageField($e,self,3,REQCOM)):=true
                            	        	knowsNonce(self,messageField($e,self,4,REQCOM)):=true
			                      protocolMessage(self,$e):=FRWVRNB
			                      messageField(self,$e,1,FRWVRNB):=messageField($e,self,5,GENKEYSES)
			                      messageField(self,$e,2,FRWVRNB):=messageField($e,self,6,GENKEYSES)
			                      symEnc(FRWVRNB,1,1,2):=KBS
			                      messageField(self,$e,3,FRWVRNB):=messageField($e,self,4,GENKEYSES)
			                      symEnc(FRWVRNB,1,1,1):=messageField(self,$e,2,GENKEYSES)
			                      internalStateA(agentA):=END_A
			                endpar
			        endif
			else
 			        if(symDec(GENKEYSES,1,1,4,self)=true  and symDec(GENKEYSES,1,5,6,self)=true ) then
			                par
                            	        	knowsIdentityCertificate(self,messageField($e,self,1,REQCOM)):=true
                            	        	knowsSymKey(self,messageField($e,self,2,REQCOM)):=true
                            	        	knowsNonce(self,messageField($e,self,3,REQCOM)):=true
                            	        	knowsNonce(self,messageField($e,self,4,REQCOM)):=true
			                      protocolMessage(self,$e):=FRWVRNB
			                      messageField(self,$e,1,FRWVRNB):=messageField($e,self,5,GENKEYSES)
			                      messageField(self,$e,2,FRWVRNB):=messageField($e,self,6,GENKEYSES)
			                      symEnc(FRWVRNB,1,1,2):=messageField(self,$e,2,FRWVRNB)
			                      messageField(self,$e,3,FRWVRNB):=messageField($e,self,4,GENKEYSES)
			                      symEnc(FRWVRNB,1,1,1):=messageField(self,$e,2,FRWVRNB)
			                      internalStateA(agentA):=END_A
			                endpar
			        endif
				endif
			endif
		endlet
	rule r_check_FRWVRNB =
		let ($e=agentE) in
			if(internalStateB(self)=WAITING_FRWVRNB and protocolMessage($e,self)=FRWVRNB)then
			        if(symDec(FRWVRNB,1,1,2,self)= true and symDec(FRWVRNB,1,1,1,self)= true) then
			             par
			                      internalStateB(agentB):=END_B
			                      internalStateS(agentS):=END_S
			            endpar
			        endif
			endif
		endlet

	rule r_agentERule  =
	  par
            r_message_replay_REQCOM[]
            r_message_replay_ENCKBS[]
            r_message_replay_GENKEYSES[]
            r_message_replay_FRWVRNB[]
	  endpar

	rule r_agentARule  =
	  par
            r_message_REQCOM[]
            r_message_FRWVRNB[]
	  endpar

	rule r_agentBRule  =
	  par
            r_message_ENCKBS[]
            r_check_FRWVRNB[]
	  endpar

	rule r_agentSRule  =
            r_message_GENKEYSES[]

	main rule r_Main =
	  par
             program(agentA)
             program(agentB)
             program(agentS)
             program(agentE)
	  endpar
default init s0:
	function internalStateA($a in Alice)=IDLE_REQCOM
	function internalStateB($b in Bob)=WAITING_REQCOM
	function receiver=chosenReceiver
	function knowsNonce($a in Agent, $n in KnowledgeNonce)=if($a=agentA and $n=NA) then true else if($a=agentB and $n=NB) then true else false endif endif
	function knowsIdentityCertificate($a in Agent, $i in KnowledgeIdentityCertificate)=if($a=agentA and $i=CA) then true else if($a=agentB and $i=CA) or ($a=agentB and $i=CB) then true else if($a=agentS and $i=CB) then true else false endif endif endif
	function knowsOther($a in Agent, $ho in KnowledgeOther)=if($a=agentA and $ho=NA) then true else if($a=agentB and $ho=NB) or ($a=agentB and $ho=NA) then true else if($a=agentS and $ho=NB) then true else false endif endif endif
	function knowsSymKey($a in Agent ,$sk in KnowledgeSymKey)=if(($a=agentA and $sk=KAS) or ($a=agentA and $sk=KAB) or ($a=agentB and $sk=KBS) or ($a=agentE and $sk=KES) or ($a=agentS and $sk=KAB) or ($a=agentS and $sk=KBS) or ($a=agentS and $sk=KAS)) then true else false endif
	function knowsSignPubKey($a in Agent ,$spu in KnowledgeSignPubKey)=if(($a=agentA and $spu=KAS) or ($a=agentB and $spu=KBS) or ($a=agentE and $spu=KES) or ($a=agentS and $spu=KAB) or ($a=agentS and $spu=KBS) or ($a=agentS and $spu=KAS)) then true else false endif
	function knowsSignPrivKey($a in Agent ,$spr in KnowledgeSignPrivKey)=true
	function mode=chosenMode

	agent Alice:
		r_agentARule[]

	agent Bob:
		r_agentBRule[]

	agent Eve:
		r_agentERule[]

	agent Server:
		r_agentSRule[]
