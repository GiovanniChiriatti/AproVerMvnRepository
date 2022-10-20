asm Needham_Schroeder4

import CryptoLibraryNS4


signature:

definitions:
	domain Level = {1}
	domain FieldPosition = {1:2}
	domain EncField1={1}
	domain EncField2={2}

	domain KnowledgeNonce = {NA,NB,NE}
	domain KnowledgeIdentityCertificate = {ID_A,ID_B,ID_E}
	domain KnowledgeAsymPubKey = {PUBKA,PUBKB,PUBKE}
	domain KnowledgeAsymPrivKey = {PRIVKA,PRIVKB,PRIVKE}

	function asim_keyAssociation($a in KnowledgeAsymPubKey)=
	       switch( $a )
	              case PUBKA: PRIVKA
	              case PUBKB: PRIVKB
	              case PUBKE: PRIVKE
	       endswitch

	/*ATTACKER RULES*/
	rule r_message_replay_MA =
		//choose what agets are interested by the message
		let ($b=agentB,$a=agentA) in
			//check the reception of the message and the modality of the attack
			if(protocolMessage($a,self)=MA and protocolMessage(self,$b)!=MA and mode=PASSIVE)then
			        //in passsive mode if the attacker knows the decryption key, the message payload is readable and it can be added to the attacker knowledge
			        // the message must be sent unaltered
			        if(asymDec(MA,1,1,2,self)=true)then
			                par
                                              knowsNonce(self,messageField($a,self,1,MA)):=true
                                              knowsIdentityCertificate(self,messageField($a,self,2,MA)):=true
                                              protocolMessage(self,$b):=MA
                                              messageField(self,$b,1,MA):=messageField($a,self,1,MA)
                                              messageField(self,$b,2,MA):=messageField($a,self,2,MA)
			                               asymEnc(MA,1,1,2):=PUBKB
			                endpar
			        else
			                par
                                              protocolMessage(self,$b):=MA
                                              messageField(self,$b,1,MA):=messageField($a,self,1,MA)
                                              messageField(self,$b,2,MA):=messageField($a,self,2,MA)
			                endpar
			        endif
			else
			        //check the reception of the message and the modality of the attack
			        if(protocolMessage($a,self)=MA and protocolMessage(self,$b)!=MA and mode=ACTIVE)then
			                 // in the active mode the attacker can forge the message with all his knowledge
			                 if(asymDec(MA,1,1,2,self)=true)then
			                          par
                                                       knowsNonce(self,messageField($a,self,1,MA)):=true
                                                       knowsIdentityCertificate(self,messageField($a,self,2,MA)):=true
                                                       protocolMessage(self,$b):=MA
                                                       messageField(self,$b,1,MA):=messageField($a,self,1,MA)
                                                       messageField(self,$b,2,MA):=messageField($a,self,2,MA)
			                               asymEnc(MA,1,1,2):=PUBKB
			                          endpar
			                 else
			                          par
                                                       protocolMessage(self,$b):=MA
                                                       messageField(self,$b,1,MA):=messageField($a,self,1,MA)
                                                       messageField(self,$b,2,MA):=messageField($a,self,2,MA)
			                          endpar
			                 endif
			        endif
			endif
		endlet
	rule r_message_replay_MB =
		//choose what agets are interested by the message
		let ($b=agentA,$a=agentB) in
			//check the reception of the message and the modality of the attack
			if(protocolMessage($a,self)=MB and protocolMessage(self,$b)!=MB and mode=PASSIVE)then
			        //in passsive mode if the attacker knows the decryption key, the message payload is readable and it can be added to the attacker knowledge
			        // the message must be sent unaltered
			        if(asymDec(MB,1,1,2,self)=true)then
			                par
                                              knowsNonce(self,messageField($a,self,1,MB)):=true
                                              knowsNonce(self,messageField($a,self,2,MB)):=true
                                              protocolMessage(self,$b):=MB
                                              messageField(self,$b,1,MB):=messageField($a,self,1,MB)
                                              messageField(self,$b,2,MB):=messageField($a,self,2,MB)
			                               asymEnc(MB,1,1,2):=PUBKA
			                endpar
			        else
			                par
                                              protocolMessage(self,$b):=MB
                                              messageField(self,$b,1,MB):=messageField($a,self,1,MB)
                                              messageField(self,$b,2,MB):=messageField($a,self,2,MB)
			                endpar
			        endif
			else
			        //check the reception of the message and the modality of the attack
			        if(protocolMessage($a,self)=MB and protocolMessage(self,$b)!=MB and mode=ACTIVE)then
			                 // in the active mode the attacker can forge the message with all his knowledge
			                 if(asymDec(MB,1,1,2,self)=true)then
			                          par
                                                       knowsNonce(self,messageField($a,self,1,MB)):=true
                                                       knowsNonce(self,messageField($a,self,2,MB)):=true
                                                       protocolMessage(self,$b):=MB
                                                       messageField(self,$b,1,MB):=messageField($a,self,1,MB)
                                                       messageField(self,$b,2,MB):=messageField($a,self,2,MB)
			                               asymEnc(MB,1,1,2):=PUBKA
			                          endpar
			                 else
			                          par
                                                       protocolMessage(self,$b):=MB
                                                       messageField(self,$b,1,MB):=messageField($a,self,1,MB)
                                                       messageField(self,$b,2,MB):=messageField($a,self,2,MB)
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
			        if(asymDec(MC,1,1,1,self)=true)then
			                par
                                              knowsNonce(self,messageField($a,self,1,MC)):=true
                                              protocolMessage(self,$b):=MC
                                              messageField(self,$b,1,MC):=messageField($a,self,1,MC)
			                               asymEnc(MC,1,1,1):=PUBKB
			                endpar
			        else
			                par
                                              protocolMessage(self,$b):=MC
                                              messageField(self,$b,1,MC):=messageField($a,self,1,MC)
			                endpar
			        endif
			else
			        //check the reception of the message and the modality of the attack
			        if(protocolMessage($a,self)=MC and protocolMessage(self,$b)!=MC and mode=ACTIVE)then
			                 // in the active mode the attacker can forge the message with all his knowledge
			                 if(asymDec(MC,1,1,1,self)=true)then
			                          par
                                                       knowsNonce(self,messageField($a,self,1,MC)):=true
                                                       protocolMessage(self,$b):=MC
                                                       messageField(self,$b,1,MC):=messageField($a,self,1,MC)
			                               asymEnc(MC,1,1,1):=PUBKB
			                          endpar
			                 else
			                          par
                                                       protocolMessage(self,$b):=MC
                                                       messageField(self,$b,1,MC):=messageField($a,self,1,MC)
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
			                       messageField(self,$e,1,MA):=NA
			                       messageField(self,$e,2,MA):=ID_A
			                       asymEnc(MA,1,1,2):=PUBKB
			                       internalStateA(self):=WAITING_MB
			                endpar
			        else
			                if(receiver=AG_E)then
			                        par
			                              protocolMessage(self,$e):=MA
			                              messageField(self,$e,1,MA):=NA
			                              messageField(self,$e,2,MA):=ID_A
			                              asymEnc(MA,1,1,2):=PUBKE
			                              internalStateA(self):=WAITING_MB
			                        endpar
			                endif
			        endif
			endif
		endlet
	rule r_message_MB =
		let ($e=agentE) in
			if(internalStateB(self)=WAITING_MA and protocolMessage($e,self)=MA)then
			        if(asymDec(MA,1,1,2,self)=true)then
			                par
                                              knowsNonce(self,messageField($e,self,1,MA)):=true
                                              knowsIdentityCertificate(self,messageField($e,self,2,MA)):=true
			                      protocolMessage(self,$e):=MB
			                      messageField(self,$e,1,MB):=messageField($e,self,1,MA)
			                      messageField(self,$e,2,MB):=NB
			                      asymEnc(MB,1,1,2):=PUBKA
			                      internalStateB(self):=WAITING_MC
			                endpar
			        endif
			endif
	endlet
	rule r_message_MC =
		let ($e=agentE) in
			if(internalStateA(self)=WAITING_MB and protocolMessage($e,self)=MB)then
			        if(receiver=AG_B)then
			           if(asymDec(MB,1,1,2,self)=true)then
			                par
                                              knowsNonce(self,messageField($e,self,1,MB)):=true
                                              knowsNonce(self,messageField($e,self,2,MB)):=true
			                      protocolMessage(self,$e):=MC
			                      messageField(self,$e,1,MC):=messageField($e,self,2,MB)
			                      asymEnc(MC,1,1,1):=PUBKB
			                      internalStateA(self):=END_A
			                endpar
			        endif
			else
			           if(asymDec(MB,1,1,2,self)=true)then
			                par
                                              knowsNonce(self,messageField($e,self,1,MB)):=true
                                              knowsNonce(self,messageField($e,self,2,MB)):=true
			                      protocolMessage(self,$e):=MC
			                      messageField(self,$e,1,MC):=messageField($e,self,2,MB)
			                      asymEnc(MC,1,1,1):=PUBKE
			                      internalStateA(self):=END_A
			                endpar
				  endif
				endif
			endif
		endlet
	rule r_check_MC =
		let ($e=agentE) in
			if(internalStateB(self)=WAITING_MC and protocolMessage($e,self)=MC)then
			        if(asymDec(MC,1,1,1,self)= true) then
			                      internalStateB(self):=END_B
			        endif
			endif
		endlet

	rule r_agentERule  =
	  par
            r_message_replay_MA[]
            r_message_replay_MB[]
            r_message_replay_MC[]
	  endpar

	rule r_agentARule  =
	  par
            r_message_MA[]
            r_message_MC[]
	  endpar

	rule r_agentBRule  =
	  par
            r_message_MB[]
            r_check_MC[]
	  endpar

	main rule r_Main =
	  par
             program(agentA)
             program(agentB)
             program(agentE)
	  endpar
default init s0:
	function internalStateA($a in Alice)=IDLE_MA
	function internalStateB($b in Bob)=WAITING_MA
	function receiver=chosenReceiver
	function knowsNonce($a in Agent, $n in KnowledgeNonce)=if($a=agentA and $n=NA) then true else if($a=agentB and $n=NB) or ($a=agentB and $n=NA) then true else if($a=agentE and $n=NE) then true else false endif endif endif
	function knowsIdentityCertificate($a in Agent, $i in KnowledgeIdentityCertificate)=if($a=agentA and $i=ID_A) then true else if($a=agentB and $i=ID_B) then true else if($a=agentE and $i=ID_E) then true else false endif endif endif
	function knowsAsymPrivKey($a in Agent ,$k in KnowledgeAsymPrivKey)=if(($a=agentA and $k=PRIVKA) or ($a=agentB and $k=PRIVKB) or ($a=agentE and $k=PRIVKE)) then true else false endif
	function knowsAsymPubKey($a in Agent ,$pk in KnowledgeAsymPubKey)=true
	function mode=chosenMode

	agent Alice:
		r_agentARule[]

	agent Bob:
		r_agentBRule[]

	agent Eve:
		r_agentERule[]
