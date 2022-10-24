asm Needham_SchroederNSSYM

import CryptoLibraryNSSYM


signature:

definitions:
	domain Level = {1:2}
	domain FieldPosition = {1:5}
	domain EncField1={1:5}
	domain EncField2={2:5}

	domain KnowledgeNonce = {NA,NB}
	domain KnowledgeIdentityCertificate = {CA,CB}
	domain KnowledgeSymKey = {KAB,KAS,KBS,KEA,KEB,KES}


	/*ATTACKER RULES*/
	rule r_message_replay_MA =
		//choose what agets are interested by the message
		let ($b=agentS,$a=agentA) in
			//check the reception of the message and the modality of the attack
			if(protocolMessage($a,self)=MA and protocolMessage(self,$b)!=MA and mode=PASSIVE)then
			        //in passsive mode if the attacker knows the decryption key, the message payload is readable and it can be added to the attacker knowledge
			        // the message must be sent unaltered
			                par
                                              knowsIdentityCertificate(self,messageField($a,self,1,MA)):=true
                                              knowsIdentityCertificate(self,messageField($a,self,2,MA)):=true
                                              knowsNonce(self,messageField($a,self,3,MA)):=true
                                              protocolMessage(self,$b):=MA
                                              messageField(self,$b,1,MA):=messageField($a,self,1,MA)
                                              messageField(self,$b,2,MA):=messageField($a,self,2,MA)
                                              messageField(self,$b,3,MA):=messageField($a,self,3,MA)
			                endpar
			else
			        //check the reception of the message and the modality of the attack
			        if(protocolMessage($a,self)=MA and protocolMessage(self,$b)!=MA and mode=ACTIVE)then
			                          par
                                                       knowsIdentityCertificate(self,messageField($a,self,1,MA)):=true
                                                       knowsIdentityCertificate(self,messageField($a,self,2,MA)):=true
                                                       knowsNonce(self,messageField($a,self,3,MA)):=true
                                                       protocolMessage(self,$b):=MA
                                                       messageField(self,$b,1,MA):=messageField($a,self,1,MA)
                                                       messageField(self,$b,2,MA):=messageField($a,self,2,MA)
                                                       messageField(self,$b,3,MA):=messageField($a,self,3,MA)
			                          endpar
			        endif
			endif
		endlet
	rule r_message_replay_MB =
		//choose what agets are interested by the message
		let ($b=agentA,$a=agentS) in
			//check the reception of the message and the modality of the attack
			if(protocolMessage($a,self)=MB and protocolMessage(self,$b)!=MB and mode=PASSIVE)then
			        //in passsive mode if the attacker knows the decryption key, the message payload is readable and it can be added to the attacker knowledge
			        // the message must be sent unaltered
			        if(symDec(MB,2,1,5,self)=true)then
			                par
                                              knowsNonce(self,messageField($a,self,1,MB)):=true
                                              knowsSymKey(self,messageField($a,self,2,MB)):=true
                                              knowsIdentityCertificate(self,messageField($a,self,3,MB)):=true
                                              knowsSymKey(self,messageField($a,self,4,MB)):=true
                                              knowsIdentityCertificate(self,messageField($a,self,5,MB)):=true
                                              protocolMessage(self,$b):=MB
                                              messageField(self,$b,1,MB):=messageField($a,self,1,MB)
                                              messageField(self,$b,2,MB):=messageField($a,self,2,MB)
                                              messageField(self,$b,3,MB):=messageField($a,self,3,MB)
                                              messageField(self,$b,4,MB):=messageField($a,self,4,MB)
                                              messageField(self,$b,5,MB):=messageField($a,self,5,MB)
			                      symEnc(MB,2,1,5):=KEA
			                endpar
			        else
			                par
                                              protocolMessage(self,$b):=MB
                                              messageField(self,$b,1,MA):=messageField($a,self,1,MB)
                                              messageField(self,$b,2,MA):=messageField($a,self,2,MB)
                                              messageField(self,$b,3,MA):=messageField($a,self,3,MB)
                                              messageField(self,$b,4,MA):=messageField($a,self,4,MB)
                                              messageField(self,$b,5,MA):=messageField($a,self,5,MB)
			                      symEnc(MB,2,1,5):=KEA
			                endpar
			        endif
			else
			        //check the reception of the message and the modality of the attack
			        if(protocolMessage($a,self)=MB and protocolMessage(self,$b)!=MB and mode=ACTIVE)then
			                 // in the active mode the attacker can forge the message with all his knowledge
			                 if(symDec(MB,2,1,5,self)=true)then
			                          par
                                                       knowsNonce(self,messageField($a,self,1,MB)):=true
                                                       knowsSymKey(self,messageField($a,self,2,MB)):=true
                                                       knowsIdentityCertificate(self,messageField($a,self,3,MB)):=true
                                                       knowsSymKey(self,messageField($a,self,4,MB)):=true
                                                       knowsIdentityCertificate(self,messageField($a,self,5,MB)):=true
                                                       protocolMessage(self,$b):=MB
                                                       messageField(self,$b,1,MB):=messageField($a,self,1,MB)
                                                       messageField(self,$b,2,MB):=KEA
                                                       messageField(self,$b,3,MB):=messageField($a,self,3,MB)
                                                       messageField(self,$b,4,MB):=KEA
                                                       messageField(self,$b,5,MB):=messageField($a,self,5,MB)
			                               symEnc(MB,2,1,5):=KEA
			                          endpar
			                 else
			                          par
                                                       protocolMessage(self,$b):=MB
                                                       messageField(self,$b,1,MA):=messageField($a,self,1,MB)
                                                       messageField(self,$b,2,MA):=messageField($a,self,2,MB)
                                                       messageField(self,$b,3,MA):=messageField($a,self,3,MB)
                                                       messageField(self,$b,4,MA):=messageField($a,self,4,MB)
                                                       messageField(self,$b,5,MA):=messageField($a,self,5,MB)
			                               symEnc(MB,2,1,5):=KEA
			                          endpar
			                 endif
			        endif
			endif
		endlet
	rule r_message_replay_MC =
		//choose what agets are interested by the message
		let ($b=agentB,$a=agentA) in
			//check the reception of the message and the modality of the attack
			if(protocolMessage($a,self)=MC and protocolMessage(self,$b)!=MC and mode=PASSIVE)then
			        //in passsive mode if the attacker knows the decryption key, the message payload is readable and it can be added to the attacker knowledge
			        // the message must be sent unaltered
			        if(symDec(MC,1,1,2,self)=true)then
			                par
                                              knowsSymKey(self,messageField($a,self,1,MC)):=true
                                              knowsIdentityCertificate(self,messageField($a,self,2,MC)):=true
                                              protocolMessage(self,$b):=MC
                                              messageField(self,$b,1,MC):=messageField($a,self,1,MC)
                                              messageField(self,$b,2,MC):=messageField($a,self,2,MC)
			                      symEnc(MC,1,1,2):=KEA
			                endpar
			        else
			                par
                                              protocolMessage(self,$b):=MC
                                              messageField(self,$b,1,MA):=messageField($a,self,1,MC)
                                              messageField(self,$b,2,MA):=messageField($a,self,2,MC)
			                      symEnc(MC,1,1,2):=KEA
			                endpar
			        endif
			else
			        //check the reception of the message and the modality of the attack
			        if(protocolMessage($a,self)=MC and protocolMessage(self,$b)!=MC and mode=ACTIVE)then
			                 // in the active mode the attacker can forge the message with all his knowledge
			                 if(symDec(MC,1,1,2,self)=true)then
			                          par
                                                       knowsSymKey(self,messageField($a,self,1,MC)):=true
                                                       knowsIdentityCertificate(self,messageField($a,self,2,MC)):=true
                                                       protocolMessage(self,$b):=MC
                                                       messageField(self,$b,1,MC):=KEA
                                                       messageField(self,$b,2,MC):=messageField($a,self,2,MC)
			                               symEnc(MC,1,1,2):=KEA
			                          endpar
			                 else
			                          par
                                                       protocolMessage(self,$b):=MC
                                                       messageField(self,$b,1,MA):=messageField($a,self,1,MC)
                                                       messageField(self,$b,2,MA):=messageField($a,self,2,MC)
			                               symEnc(MC,1,1,2):=KEA
			                          endpar
			                 endif
			        endif
			endif
		endlet
	rule r_message_replay_MD =
		//choose what agets are interested by the message
		let ($b=agentA,$a=agentB) in
			//check the reception of the message and the modality of the attack
			if(protocolMessage($a,self)=MD and protocolMessage(self,$b)!=MD and mode=PASSIVE)then
			        //in passsive mode if the attacker knows the decryption key, the message payload is readable and it can be added to the attacker knowledge
			        // the message must be sent unaltered
			        if(symDec(MD,1,1,1,self)=true)then
			                par
                                              knowsNonce(self,messageField($a,self,1,MD)):=true
                                              protocolMessage(self,$b):=MD
                                              messageField(self,$b,1,MD):=messageField($a,self,1,MD)
			                      symEnc(MD,1,1,1):=messageField($b,self,1,MC)
			                endpar
			        else
			                par
                                              protocolMessage(self,$b):=MD
                                              messageField(self,$b,1,MA):=messageField($a,self,1,MD)
			                      symEnc(MD,1,1,1):=messageField($b,self,1,MC)
			                endpar
			        endif
			else
			        //check the reception of the message and the modality of the attack
			        if(protocolMessage($a,self)=MD and protocolMessage(self,$b)!=MD and mode=ACTIVE)then
			                 // in the active mode the attacker can forge the message with all his knowledge
			                 if(symDec(MD,1,1,1,self)=true)then
			                          par
                                                       knowsNonce(self,messageField($a,self,1,MD)):=true
                                                       protocolMessage(self,$b):=MD
                                                       messageField(self,$b,1,MD):=messageField($a,self,1,MD)
			                               symEnc(MD,1,1,1):=messageField($b,self,1,MC)
			                          endpar
			                 else
			                          par
                                                       protocolMessage(self,$b):=MD
                                                       messageField(self,$b,1,MA):=messageField($a,self,1,MD)
			                               symEnc(MD,1,1,1):=messageField($b,self,1,MC)
			                          endpar
			                 endif
			        endif
			endif
		endlet
	rule r_message_replay_ME =
		//choose what agets are interested by the message
		let ($b=agentB,$a=agentA) in
			//check the reception of the message and the modality of the attack
			if(protocolMessage($a,self)=ME and protocolMessage(self,$b)!=ME and mode=PASSIVE)then
			        //in passsive mode if the attacker knows the decryption key, the message payload is readable and it can be added to the attacker knowledge
			        // the message must be sent unaltered
			        if(symDec(ME,1,1,1,self)=true)then
			                par
                                              knowsNonce(self,messageField($a,self,1,ME)):=true
                                              protocolMessage(self,$b):=ME
                                              messageField(self,$b,1,ME):=messageField($a,self,1,ME)
			                      symEnc(ME,1,1,1):=KEA
			                endpar
			        else
			                par
                                              protocolMessage(self,$b):=ME
                                              messageField(self,$b,1,MA):=messageField($a,self,1,ME)
			                      symEnc(ME,1,1,1):=KEA
			                endpar
			        endif
			else
			        //check the reception of the message and the modality of the attack
			        if(protocolMessage($a,self)=ME and protocolMessage(self,$b)!=ME and mode=ACTIVE)then
			                 // in the active mode the attacker can forge the message with all his knowledge
			                 if(symDec(ME,1,1,1,self)=true)then
			                          par
                                                       knowsNonce(self,messageField($a,self,1,ME)):=true
                                                       protocolMessage(self,$b):=ME
                                                       messageField(self,$b,1,ME):=messageField($a,self,1,ME)
			                               symEnc(ME,1,1,1):=KEA
			                          endpar
			                 else
			                          par
                                                       protocolMessage(self,$b):=ME
                                                       messageField(self,$b,1,MA):=messageField($a,self,1,ME)
			                               symEnc(ME,1,1,1):=KEA
			                          endpar
			                 endif
			        endif
			endif
		endlet

	/*HONEST AGENT RULES*/	
	rule r_message_MA =
		let ($e=agentE) in
			if(internalStateA(self)=IDLE_MA)then 
			        if(receiver=AG_S)then
			                par
			                       protocolMessage(self,$e):=MA
			                       messageField(self,$e,1,MA):=CA
			                       messageField(self,$e,2,MA):=CB
			                       messageField(self,$e,3,MA):=NA
			                       internalStateA(self):=WAITING_MB
			                endpar
			        else
			                if(receiver=AG_E)then
			                        par
			                              protocolMessage(self,$e):=MA
			                              messageField(self,$e,1,MA):=CA
			                              messageField(self,$e,2,MA):=CB
			                              messageField(self,$e,3,MA):=NA
			                              internalStateA(self):=WAITING_MB
			                        endpar
			                endif
			        endif
			endif
		endlet
	rule r_message_MB =
		let ($e=agentE) in
			if(internalStateS(self)=WAITING_MA and protocolMessage($e,self)=MA)then
			                par
                                  knowsIdentityCertificate(self,messageField($e,self,1,MA)):=true
                                  knowsIdentityCertificate(self,messageField($e,self,2,MA)):=true
                                  knowsNonce(self,messageField($e,self,3,MA)):=true
			                      protocolMessage(self,$e):=MB
			                      messageField(self,$e,1,MB):=messageField($e,self,3,MA)
			                      messageField(self,$e,2,MB):=KEA
			                      messageField(self,$e,3,MB):=messageField($e,self,2,MA)
			                      messageField(self,$e,4,MB):=messageField($e,self,2,MB)
			                      messageField(self,$e,5,MB):=messageField($e,self,1,MA)
 			                      symEnc(MB,2,1,5):=KEA
			                      internalStateB(self):=WAITING_MC
			                endpar
			endif
	endlet
	rule r_message_MC =
		let ($e=agentE) in
			if(internalStateA(self)=WAITING_MB and protocolMessage($e,self)=MB)then
			        if(receiver=AG_B)then
   			           if(symDec(MB,2,1,5,self)=true)then
			                par
                                  knowsNonce(self,messageField($e,self,1,MA)):=true
                                  knowsSymKey(self,messageField($e,self,2,MA)):=true
                                  knowsIdentityCertificate(self,messageField($e,self,3,MA)):=true
                                  knowsSymKey(self,messageField($e,self,4,MA)):=true
                                  knowsIdentityCertificate(self,messageField($e,self,5,MA)):=true
			                      protocolMessage(self,$e):=MC
			                      messageField(self,$e,1,MC):=messageField($e,self,4,MB)
			                      messageField(self,$e,2,MC):=messageField($e,self,5,MB)
			                      symEnc(MC,1,1,2):=KBS
			                      internalStateA(self):=WAITING_MD
			                endpar
			        endif
			else
			           if(symDec(MB,2,1,5,self)=true)then
			                par
                                  knowsNonce(self,messageField($e,self,1,MA)):=true
                                  knowsSymKey(self,messageField($e,self,2,MA)):=true
                                  knowsIdentityCertificate(self,messageField($e,self,3,MA)):=true
                                  knowsSymKey(self,messageField($e,self,4,MA)):=true
                                  knowsIdentityCertificate(self,messageField($e,self,5,MA)):=true
			                      protocolMessage(self,$e):=MC
			                      messageField(self,$e,1,MC):=messageField($e,self,4,MB)
			                      messageField(self,$e,2,MC):=messageField($e,self,5,MB)
			                      symEnc(MC,1,1,2):=messageField(self,$e,1,MC)
			                      internalStateA(self):=WAITING_MD
			                endpar
				  endif
				endif
			endif
		endlet
	rule r_message_MD =
		let ($e=agentE) in
			if(internalStateB(self)=WAITING_MC and protocolMessage($e,self)=MC)then
			        if(symDec(MC,1,1,2,self)=true)then
			                par
                                  knowsSymKey(self,messageField($e,self,1,MA)):=true
                                  knowsIdentityCertificate(self,messageField($e,self,2,MA)):=true
			                      protocolMessage(self,$e):=MD
			                      messageField(self,$e,1,MD):=NB
 			                      symEnc(MD,1,1,1):=messageField($e,self,1,MC)
			                      internalStateB(self):=WAITING_ME
			                endpar
			        endif
			endif
	endlet
	rule r_message_ME =
		let ($e=agentE) in
			if(internalStateA(self)=WAITING_MD and protocolMessage($e,self)=MD)then
			        if(receiver=AG_B)then
   			           if(symDec(MD,1,1,1,self)=true)then
			                par
                                  knowsNonce(self,messageField($e,self,1,MA)):=true
			                      protocolMessage(self,$e):=ME
			                      messageField(self,$e,1,ME):=messageField($e,self,1,MD)
			                      symEnc(ME,1,1,1):=messageField(self,$e,4,MB)
			                      internalStateA(self):=END_A
			                endpar
			        endif
			else
			           if(symDec(MD,1,1,1,self)=true)then
			                par
                                  knowsNonce(self,messageField($e,self,1,MA)):=true
			                      protocolMessage(self,$e):=ME
			                      messageField(self,$e,1,ME):=messageField($e,self,1,MD)
			                      symEnc(ME,1,1,1):=messageField(self,$e,1,MC)
			                      internalStateA(self):=END_A
			                endpar
				  endif
				endif
			endif
		endlet
	rule r_check_ME =
		let ($e=agentE) in
			if(internalStateB(self)=WAITING_ME and protocolMessage($e,self)=ME)then
			        if(symDec(ME,1,1,1,self)= true) then
			             par
			                      internalStateB(self):=END_B
			                      internalStateS(self):=END_S
			            endpar
			        endif
			endif
		endlet

	rule r_agentERule  =
	  par
            r_message_replay_MA[]
            r_message_replay_MB[]
            r_message_replay_MC[]
            r_message_replay_MD[]
            r_message_replay_ME[]
	  endpar

	rule r_agentARule  =
	  par
            r_message_MA[]
            r_message_MC[]
            r_message_ME[]
	  endpar

	rule r_agentBRule  =
	  par
            r_message_MD[]
            r_check_ME[]
	  endpar

	rule r_agentSRule  =
            r_message_MB[]

	main rule r_Main =
	  par
             program(agentA)
             program(agentB)
             program(agentS)
             program(agentE)
	  endpar
default init s0:
	function internalStateA($a in Alice)=IDLE_MA
	function internalStateS($b in Server)=WAITING_MA
	function receiver=chosenReceiver
	function knowsNonce($a in Agent, $n in KnowledgeNonce)=if($a=agentA and $n=NA) then true else if($a=agentB and $n=NB) then true else false endif endif
	function knowsIdentityCertificate($a in Agent, $i in KnowledgeIdentityCertificate)=if($a=agentA and $i=CA) or ($a=agentA and $i=CB) then true else if($a=agentB and $i=CA) or ($a=agentB and $i=CB) then true else false endif endif
	function knowsSymKey($a in Agent ,$sk in KnowledgeSymKey)=if(($a=agentA and $sk=KAS) or ($a=agentA and $sk=KBS) or ($a=agentA and $sk=KAB) or ($a=agentB and $sk=KBS) or ($a=agentB and $sk=KAB) or ($a=agentE and $sk=KEA) or ($a=agentE and $sk=KEB) or ($a=agentE and $sk=KES) or ($a=agentS and $sk=KAS) or ($a=agentS and $sk=KBS) or ($a=agentS and $sk=KAB)) then true else false endif
	function knowsSignPubKey($a in Agent ,$spu in KnowledgeSignPubKey)=if(($a=agentA and $spu=KAS) or ($a=agentA and $spu=KBS) or ($a=agentB and $spu=KBS) or ($a=agentE and $spu=KEA) or ($a=agentE and $spu=KEB) or ($a=agentE and $spu=KES) or ($a=agentS and $spu=KAS) or ($a=agentS and $spu=KBS) or ($a=agentS and $spu=KAB)) then true else false endif
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
