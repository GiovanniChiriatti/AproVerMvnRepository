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
	rule r_message_replay_MA =
		//choose what agets are interested by the message
		let ($b=agentB,$a=agentA) in
			//check the reception of the message and the modality of the attack
			if(protocolMessage($a,self)=MA and protocolMessage(self,$b)!=MA and mode=PASSIVE)then
			        //in passsive mode if the attacker knows the decryption key, the message payload is readable and it can be added to the attacker knowledge
			        // the message must be sent unaltered
			                par
                                              knowsIdentityCertificate(self,messageField($a,self,1,MA)):=true
                                              knowsNonce(self,messageField($a,self,2,MA)):=true
                                              protocolMessage(self,$b):=MA
                                              messageField(self,$b,1,MA):=messageField($a,self,1,MA)
                                              messageField(self,$b,2,MA):=messageField($a,self,2,MA)
			                endpar
			else
			        //check the reception of the message and the modality of the attack
			        if(protocolMessage($a,self)=MA and protocolMessage(self,$b)!=MA and mode=ACTIVE)then
			                          par
                                                       knowsIdentityCertificate(self,messageField($a,self,1,MA)):=true
                                                       knowsNonce(self,messageField($a,self,2,MA)):=true
                                                       protocolMessage(self,$b):=MA
                                                       messageField(self,$b,1,MA):=messageField($a,self,1,MA)
                                                       messageField(self,$b,2,MA):=messageField($a,self,2,MA)
			                          endpar
			        endif
			endif
		endlet
	rule r_message_replay_MB =
		//choose what agets are interested by the message
		let ($b=agentS,$a=agentB) in
			//check the reception of the message and the modality of the attack
			if(protocolMessage($a,self)=MB and protocolMessage(self,$b)!=MB and mode=PASSIVE)then
			        //in passsive mode if the attacker knows the decryption key, the message payload is readable and it can be added to the attacker knowledge
			        // the message must be sent unaltered
			                par
                                              knowsIdentityCertificate(self,messageField($a,self,1,MB)):=true
                                              protocolMessage(self,$b):=MB
                                              messageField(self,$b,1,MB):=messageField($a,self,1,MB)
			                endpar
			else
			        //check the reception of the message and the modality of the attack
			        if(protocolMessage($a,self)=MB and protocolMessage(self,$b)!=MB and mode=ACTIVE)then
			                          par
                                                       knowsIdentityCertificate(self,messageField($a,self,1,MB)):=true
                                                       protocolMessage(self,$b):=MB
                                                       messageField(self,$b,1,MB):=messageField($a,self,1,MB)
			                          endpar
			        endif
			endif
		endlet
	rule r_message_replay_MB1 =
		//choose what agets are interested by the message
		let ($b=agentS,$a=agentB) in
			//check the reception of the message and the modality of the attack
			if(protocolMessage($a,self)=MB and protocolMessage(self,$b)!=MB and mode=PASSIVE)then
			        //in passsive mode if the attacker knows the decryption key, the message payload is readable and it can be added to the attacker knowledge
			        // the message must be sent unaltered
			        if(symDec(MB,1,2,4,self)=true)then
			                par
                                              knowsIdentityCertificate(self,messageField($a,self,2,MB)):=true
                                              knowsOther(self,messageField($a,self,3,MB)):=true
                                              knowsNonce(self,messageField($a,self,4,MB)):=true
                                              protocolMessage(self,$b):=MB
                                              messageField(self,$b,2,MB):=messageField($a,self,2,MB)
                                              messageField(self,$b,3,MB):=messageField($a,self,3,MB)
                                              messageField(self,$b,4,MB):=messageField($a,self,4,MB)
			                      symEnc(MB,1,2,4):=KES
			                endpar
			        else
			                par
                                              protocolMessage(self,$b):=MB
                                              messageField(self,$b,2,MA):=messageField($a,self,2,MB)
                                              messageField(self,$b,3,MA):=messageField($a,self,3,MB)
                                              messageField(self,$b,4,MA):=messageField($a,self,4,MB)
			                      symEnc(MB,1,2,4):=KES
			                endpar
			        endif
			else
			        //check the reception of the message and the modality of the attack
			        if(protocolMessage($a,self)=MB and protocolMessage(self,$b)!=MB and mode=ACTIVE)then
			                 // in the active mode the attacker can forge the message with all his knowledge
			                 if(symDec(MB,1,2,4,self)=true)then
			                          par
                                                       knowsIdentityCertificate(self,messageField($a,self,2,MB)):=true
                                                       knowsOther(self,messageField($a,self,3,MB)):=true
                                                       knowsNonce(self,messageField($a,self,4,MB)):=true
                                                       protocolMessage(self,$b):=MB
                                                       messageField(self,$b,2,MB):=messageField($a,self,2,MB)
                                                       messageField(self,$b,3,MB):=messageField($a,self,3,MB)
                                                       messageField(self,$b,4,MB):=messageField($a,self,4,MB)
			                               symEnc(MB,1,2,4):=KES
			                          endpar
			                 else
			                          par
                                                       protocolMessage(self,$b):=MB
                                                       messageField(self,$b,2,MA):=messageField($a,self,2,MB)
                                                       messageField(self,$b,3,MA):=messageField($a,self,3,MB)
                                                       messageField(self,$b,4,MA):=messageField($a,self,4,MB)
			                               symEnc(MB,1,2,4):=KES
			                          endpar
			                 endif
			        endif
			endif
		endlet
	rule r_message_replay_MC =
		//choose what agets are interested by the message
		let ($b=agentA,$a=agentS) in
			//check the reception of the message and the modality of the attack
			if(protocolMessage($a,self)=MC and protocolMessage(self,$b)!=MC and mode=PASSIVE)then
			        //in passsive mode if the attacker knows the decryption key, the message payload is readable and it can be added to the attacker knowledge
			        // the message must be sent unaltered
			        if(symDec(MC,1,1,4,self)=true)then
			                par
                                              knowsIdentityCertificate(self,messageField($a,self,1,MC)):=true
                                              knowsSymKey(self,messageField($a,self,2,MC)):=true
                                              knowsNonce(self,messageField($a,self,3,MC)):=true
                                              knowsOther(self,messageField($a,self,4,MC)):=true
                                              protocolMessage(self,$b):=MC
                                              messageField(self,$b,1,MC):=messageField($a,self,1,MC)
                                              messageField(self,$b,2,MC):=messageField($a,self,2,MC)
                                              messageField(self,$b,3,MC):=messageField($a,self,3,MC)
                                              messageField(self,$b,4,MC):=messageField($a,self,4,MC)
			                      symEnc(MC,1,1,4):=KES
			                endpar
			        else
			                par
                                              protocolMessage(self,$b):=MC
                                              messageField(self,$b,1,MA):=messageField($a,self,1,MC)
                                              messageField(self,$b,2,MA):=messageField($a,self,2,MC)
                                              messageField(self,$b,3,MA):=messageField($a,self,3,MC)
                                              messageField(self,$b,4,MA):=messageField($a,self,4,MC)
			                      symEnc(MC,1,1,4):=KES
			                endpar
			        endif
			else
			        //check the reception of the message and the modality of the attack
			        if(protocolMessage($a,self)=MC and protocolMessage(self,$b)!=MC and mode=ACTIVE)then
			                 // in the active mode the attacker can forge the message with all his knowledge
			                 if(symDec(MC,1,1,4,self)=true)then
			                          par
                                                       knowsIdentityCertificate(self,messageField($a,self,1,MC)):=true
                                                       knowsSymKey(self,messageField($a,self,2,MC)):=true
                                                       knowsNonce(self,messageField($a,self,3,MC)):=true
                                                       knowsOther(self,messageField($a,self,4,MC)):=true
                                                       protocolMessage(self,$b):=MC
                                                       messageField(self,$b,1,MC):=messageField($a,self,1,MC)
                                                       messageField(self,$b,2,MC):=KES
                                                       messageField(self,$b,3,MC):=messageField($a,self,3,MC)
                                                       messageField(self,$b,4,MC):=messageField($a,self,4,MC)
			                               symEnc(MC,1,1,4):=KES
			                          endpar
			                 else
			                          par
                                                       protocolMessage(self,$b):=MC
                                                       messageField(self,$b,1,MA):=messageField($a,self,1,MC)
                                                       messageField(self,$b,2,MA):=messageField($a,self,2,MC)
                                                       messageField(self,$b,3,MA):=messageField($a,self,3,MC)
                                                       messageField(self,$b,4,MA):=messageField($a,self,4,MC)
			                               symEnc(MC,1,1,4):=KES
			                          endpar
			                 endif
			        endif
			endif
		endlet
	rule r_message_replay_MC1 =
		//choose what agets are interested by the message
		let ($b=agentA,$a=agentS) in
			//check the reception of the message and the modality of the attack
			if(protocolMessage($a,self)=MC and protocolMessage(self,$b)!=MC and mode=PASSIVE)then
			        //in passsive mode if the attacker knows the decryption key, the message payload is readable and it can be added to the attacker knowledge
			        // the message must be sent unaltered
			        if(symDec(MC,1,5,6,self)=true)then
			                par
                                              knowsIdentityCertificate(self,messageField($a,self,5,MC)):=true
                                              knowsSymKey(self,messageField($a,self,6,MC)):=true
                                              protocolMessage(self,$b):=MC
                                              messageField(self,$b,5,MC):=messageField($a,self,5,MC)
                                              messageField(self,$b,6,MC):=messageField($a,self,6,MC)
			                      symEnc(MC,1,5,6):=KES
			                endpar
			        else
			                par
                                              protocolMessage(self,$b):=MC
                                              messageField(self,$b,5,MA):=messageField($a,self,5,MC)
                                              messageField(self,$b,6,MA):=messageField($a,self,6,MC)
			                      symEnc(MC,1,5,6):=KES
			                endpar
			        endif
			else
			        //check the reception of the message and the modality of the attack
			        if(protocolMessage($a,self)=MC and protocolMessage(self,$b)!=MC and mode=ACTIVE)then
			                 // in the active mode the attacker can forge the message with all his knowledge
			                 if(symDec(MC,1,5,6,self)=true)then
			                          par
                                                       knowsIdentityCertificate(self,messageField($a,self,5,MC)):=true
                                                       knowsSymKey(self,messageField($a,self,6,MC)):=true
                                                       protocolMessage(self,$b):=MC
                                                       messageField(self,$b,5,MC):=messageField($a,self,5,MC)
                                                       messageField(self,$b,6,MC):=KES
			                               symEnc(MC,1,5,6):=KES
			                          endpar
			                 else
			                          par
                                                       protocolMessage(self,$b):=MC
                                                       messageField(self,$b,5,MA):=messageField($a,self,5,MC)
                                                       messageField(self,$b,6,MA):=messageField($a,self,6,MC)
			                               symEnc(MC,1,5,6):=KES
			                          endpar
			                 endif
			        endif
			endif
		endlet
	rule r_message_replay_MD =
		//choose what agets are interested by the message
		let ($b=agentB,$a=agentA) in
			//check the reception of the message and the modality of the attack
			if(protocolMessage($a,self)=MD and protocolMessage(self,$b)!=MD and mode=PASSIVE)then
			        //in passsive mode if the attacker knows the decryption key, the message payload is readable and it can be added to the attacker knowledge
			        // the message must be sent unaltered
			        if(symDec(MD,1,1,2,self)=true)then
			                par
                                              knowsIdentityCertificate(self,messageField($a,self,1,MD)):=true
                                              knowsSymKey(self,messageField($a,self,2,MD)):=true
                                              protocolMessage(self,$b):=MD
                                              messageField(self,$b,1,MD):=messageField($a,self,1,MD)
                                              messageField(self,$b,2,MD):=messageField($a,self,2,MD)
			                      symEnc(MD,1,1,2):=KES
			                endpar
			        else
			                par
                                              protocolMessage(self,$b):=MD
                                              messageField(self,$b,1,MA):=messageField($a,self,1,MD)
                                              messageField(self,$b,2,MA):=messageField($a,self,2,MD)
			                      symEnc(MD,1,1,2):=KES
			                endpar
			        endif
			else
			        //check the reception of the message and the modality of the attack
			        if(protocolMessage($a,self)=MD and protocolMessage(self,$b)!=MD and mode=ACTIVE)then
			                 // in the active mode the attacker can forge the message with all his knowledge
			                 if(symDec(MD,1,1,2,self)=true)then
			                          par
                                                       knowsIdentityCertificate(self,messageField($a,self,1,MD)):=true
                                                       knowsSymKey(self,messageField($a,self,2,MD)):=true
                                                       protocolMessage(self,$b):=MD
                                                       messageField(self,$b,1,MD):=messageField($a,self,1,MD)
                                                       messageField(self,$b,2,MD):=KES
			                               symEnc(MD,1,1,2):=KES
			                          endpar
			                 else
			                          par
                                                       protocolMessage(self,$b):=MD
                                                       messageField(self,$b,1,MA):=messageField($a,self,1,MD)
                                                       messageField(self,$b,2,MA):=messageField($a,self,2,MD)
			                               symEnc(MD,1,1,2):=KES
			                          endpar
			                 endif
			        endif
			endif
		endlet
	rule r_message_replay_MD1 =
		//choose what agets are interested by the message
		let ($b=agentB,$a=agentA) in
			//check the reception of the message and the modality of the attack
			if(protocolMessage($a,self)=MD and protocolMessage(self,$b)!=MD and mode=PASSIVE)then
			        //in passsive mode if the attacker knows the decryption key, the message payload is readable and it can be added to the attacker knowledge
			        // the message must be sent unaltered
			        if(symDec(MD,1,3,3,self)=true)then
			                par
                                              knowsNonce(self,messageField($a,self,3,MD)):=true
                                              protocolMessage(self,$b):=MD
                                              messageField(self,$b,3,MD):=messageField($a,self,3,MD)
			                      symEnc(MD,1,3,3):=messageField($b,self,2,MC)
			                endpar
			        else
			                par
                                              protocolMessage(self,$b):=MD
                                              messageField(self,$b,3,MA):=messageField($a,self,3,MD)
			                      symEnc(MD,1,3,3):=messageField($b,self,2,MC)
			                endpar
			        endif
			else
			        //check the reception of the message and the modality of the attack
			        if(protocolMessage($a,self)=MD and protocolMessage(self,$b)!=MD and mode=ACTIVE)then
			                 // in the active mode the attacker can forge the message with all his knowledge
			                 if(symDec(MD,1,3,3,self)=true)then
			                          par
                                                       knowsNonce(self,messageField($a,self,3,MD)):=true
                                                       protocolMessage(self,$b):=MD
                                                       messageField(self,$b,3,MD):=messageField($a,self,3,MD)
			                               symEnc(MD,1,3,3):=messageField($b,self,2,MC)
			                          endpar
			                 else
			                          par
                                                       protocolMessage(self,$b):=MD
                                                       messageField(self,$b,3,MA):=messageField($a,self,3,MD)
			                               symEnc(MD,1,3,3):=messageField($b,self,2,MC)
			                          endpar
			                 endif
			        endif
			endif
		endlet

	/*HONEST AGENT RULES*/	
	rule r_message_MA =
		let ($e=agentE) in
			if(internalStateA(self)=IDLE_MA)then 
			        if(receiver=AG_B)then
			                par
			                       protocolMessage(self,$e):=MA
			                       messageField(self,$e,1,MA):=CA
			                       messageField(self,$e,2,MA):=NA
			                       internalStateS(agentS):=WAITING_MB
			                endpar
			        else
			                if(receiver=AG_E)then
			                        par
			                              protocolMessage(self,$e):=MA
			                              messageField(self,$e,1,MA):=CA
			                              messageField(self,$e,2,MA):=NA
			                              internalStateS(agentS):=WAITING_MB
			                        endpar
			                endif
			        endif
			endif
		endlet
	rule r_message_MB =
		let ($e=agentE) in
			if(internalStateB(self)=WAITING_MA and protocolMessage($e,self)=MA)then
			     if(receiver=AG_S)then
			                par
                            	              knowsIdentityCertificate(self,messageField($e,self,1,MA)):=true
                            	              knowsNonce(self,messageField($e,self,2,MA)):=true
			                      protocolMessage(self,$e):=MB
			                      messageField(self,$e,1,MB):=CB
			                      messageField(self,$e,2,MB):=messageField($e,self,1,MA)
			                      messageField(self,$e,3,MB):=messageField($e,self,2,MA)
			                      messageField(self,$e,4,MB):=NB
			                      symEnc(MB,1,1,3):=KBS
			                      internalStateA(agentA):=WAITING_MC
			                endpar
			else
			                par
                            	              knowsIdentityCertificate(self,messageField($e,self,1,MA)):=true
                            	              knowsOther(self,messageField($e,self,2,MA)):=true
			                      protocolMessage(self,$e):=MB
			                      messageField(self,$e,1,MB):=CB
			                      messageField(self,$e,2,MB):=messageField($e,self,1,MA)
			                      messageField(self,$e,3,MB):=messageField($e,self,2,MA)
			                      messageField(self,$e,4,MB):=NB
			                      symEnc(MB,1,1,3):=KES
			                      internalStateA(agentA):=WAITING_MC
			                endpar
				endif
			endif
		endlet
	rule r_message_MC =
		let ($e=agentE) in
			if(internalStateS(self)=WAITING_MB and protocolMessage($e,self)=MB)then
 			        if(symDec(MB,1,2,4,self)=true ) then
			                par
					      knowsIdentityCertificate(self,messageField($e,self,1,MA)):=true
					      knowsNonce(self,messageField($e,self,2,MA)):=true
					      knowsOther(self,messageField($e,self,3,MA)):=true
	 		                      protocolMessage(self,$e):=MC
			                      messageField(self,$e,1,MC):=messageField($e,self,1,MB)
			                      messageField(self,$e,2,MC):=KES
			                      messageField(self,$e,3,MC):=messageField($e,self,3,MB)
			                      messageField(self,$e,4,MC):=messageField($e,self,4,MB)
 			                      symEnc(MC,1,1,4):=KES
			                      messageField(self,$e,5,MC):=messageField($e,self,2,MB)
			                      messageField(self,$e,6,MC):=messageField($e,self,2,MC)
 			                      symEnc(MC,1,5,6):=KES
			                      internalStateB(agentB):=WAITING_MD
			                endpar
			        endif
			endif
		endlet
	rule r_message_MD =
		let ($e=agentE) in
			if(internalStateA(self)=WAITING_MC and protocolMessage($e,self)=MC)then
			     if(receiver=AG_B)then
 			        if(symDec(MC,1,1,4,self)=true  and symDec(MC,1,5,6,self)=true ) then
			                par
                            	              knowsIdentityCertificate(self,messageField($e,self,1,MA)):=true
                            	              knowsSymKey(self,messageField($e,self,2,MA)):=true
                            	              knowsNonce(self,messageField($e,self,3,MA)):=true
                            	              knowsNonce(self,messageField($e,self,4,MA)):=true
			                      protocolMessage(self,$e):=MD
			                      messageField(self,$e,1,MD):=messageField($e,self,5,MC)
			                      messageField(self,$e,2,MD):=messageField($e,self,6,MC)
			                      symEnc(MD,1,1,2):=KBS
			                      messageField(self,$e,3,MD):=messageField($e,self,4,MC)
			                      symEnc(MD,1,1,1):=messageField(self,$e,2,MC)
			                      internalStateA(agentA):=END_A
			                endpar
			        endif
			else
 			        if(symDec(MC,1,1,4,self)=true  and symDec(MC,1,5,6,self)=true ) then
			                par
                            	              knowsIdentityCertificate(self,messageField($e,self,1,MA)):=true
                            	              knowsSymKey(self,messageField($e,self,2,MA)):=true
                            	              knowsNonce(self,messageField($e,self,3,MA)):=true
                            	              knowsNonce(self,messageField($e,self,4,MA)):=true
			                      protocolMessage(self,$e):=MD
			                      messageField(self,$e,1,MD):=messageField($e,self,5,MC)
			                      messageField(self,$e,2,MD):=messageField($e,self,6,MC)
			                      symEnc(MD,1,1,2):=messageField(self,$e,2,MD)
			                      messageField(self,$e,3,MD):=messageField($e,self,4,MC)
			                      symEnc(MD,1,1,1):=messageField(self,$e,2,MD)
			                      internalStateA(agentA):=END_A
			                endpar
			        endif
				endif
			endif
		endlet
	rule r_check_MD =
		let ($e=agentE) in
			if(internalStateB(self)=WAITING_MD and protocolMessage($e,self)=MD)then
			        if(symDec(MD,1,1,2,self)= true and symDec(MD,1,1,1,self)= true) then
			             par
			                      internalStateB(agentB):=END_B
			                      internalStateS(agentS):=END_S
			            endpar
			        endif
			endif
		endlet

	rule r_agentERule  =
	  par
            r_message_replay_MA[]
            r_message_replay_MB[]
            r_message_replay_MB1[]
            r_message_replay_MC[]
            r_message_replay_MC1[]
            r_message_replay_MD[]
            r_message_replay_MD1[]
	  endpar

	rule r_agentARule  =
	  par
            r_message_MA[]
            r_message_MD[]
	  endpar

	rule r_agentBRule  =
	  par
            r_message_MB[]
            r_check_MD[]
	  endpar

	rule r_agentSRule  =
            r_message_MC[]

	main rule r_Main =
	  par
             program(agentA)
             program(agentB)
             program(agentS)
             program(agentE)
	  endpar
default init s0:
	function internalStateA($a in Alice)=IDLE_MA
	function internalStateB($b in Bob)=WAITING_MA
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
