asm fff

import CryptoLibraryfff


signature:

definitions:
	domain Level = {1:2}
	domain FieldPosition = {1:2}
	domain EncField1={1}
	domain EncField2={2}

	domain KnowledgeNonce = {NB}
	domain KnowledgeIdentityCertificate = {CA}
	domain KnowledgeSymKey = {SKAB,SKAE,SKEB}
	domain KnowledgeAsymPubKey = {PUBKA,PUBKB,PUBKE}
	domain KnowledgeAsymPrivKey = {PRIVKA,PRIVKB,PRIVKE}
	domain KnowledgeSignPrivKey = {SIGNPRIVKA,SIGNPRIVKB,SIGNPRIVKE}
	domain KnowledgeSignPubKey = {SIGNPUBKA,SIGNPUBKB,SIGNPUBKE}

	function asim_keyAssociation($a in KnowledgeAsymPubKey)=
	       switch( $a )
	              case PUBKA: PRIVKA
	              case PUBKB: PRIVKB
	              case PUBKE: PRIVKE
	       endswitch
	function sign_keyAssociation($b in KnowledgeSignPrivKey)=
	       switch( $b )
	              case SIGNPRIVKA: SIGNPUBKA
	              case SIGNPRIVKB: SIGNPUBKB
	              case SIGNPRIVKE: SIGNPUBKE
	       endswitch

	/*ATTACKER RULES*/
	rule r_message_replay_MA =
		//choose what agets are interested by the message
		let ($b=agentB,$a=agentA) in
			//check the reception of the message and the modality of the attack
			if(protocolMessage($a,self)=MA and protocolMessage(self,$b)!=MA and mode=PASSIVE)then
			        //in passsive mode if the attacker knows the decryption key, the message payload is readable and it can be added to the attacker knowledge
			        // the message must be sent unaltered
			        if(asymDec(MA,1,1,1,self)=true)then
			                par
                                              knowsSymKey(self,messageField($a,self,1,MA)):=true
                                              protocolMessage(self,$b):=MA
                                              messageField(self,$b,1,MA):=messageField($a,self,1,MA)
			                               asymEnc(MA,1,1,1):=PUBKB
			                endpar
			        else
			                par
                                              protocolMessage(self,$b):=MA
                                              messageField(self,$b,1,MA):=messageField($a,self,1,MA)
			                endpar
			        endif
			else
			        //check the reception of the message and the modality of the attack
			        if(protocolMessage($a,self)=MA and protocolMessage(self,$b)!=MA and mode=ACTIVE)then
			                 // in the active mode the attacker can forge the message with all his knowledge
			                 if(asymDec(MA,1,1,1,self)=true)then
			                          par
                                                       knowsSymKey(self,messageField($a,self,1,MA)):=true
                                                       protocolMessage(self,$b):=MA
                                                       messageField(self,$b,1,MA):=SKEB
			                               asymEnc(MA,1,1,1):=PUBKB
			                          endpar
			                 else
			                          par
                                                       protocolMessage(self,$b):=MA
                                                       messageField(self,$b,1,MA):=messageField($a,self,1,MA)
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
			        if(symDec(MB,1,1,1,self)=true)then
			                par
                                              knowsNonce(self,messageField($a,self,1,MB)):=true
                                              protocolMessage(self,$b):=MB
                                              messageField(self,$b,1,MB):=messageField($a,self,1,MB)
			                               symEnc(MB,1,1,1):=messageField($b,self,1,MA)
			                endpar
			        else
			                par
                                              protocolMessage(self,$b):=MB
                                              messageField(self,$b,1,MB):=messageField($a,self,1,MB)
			                endpar
			        endif
			else
			        //check the reception of the message and the modality of the attack
			        if(protocolMessage($a,self)=MB and protocolMessage(self,$b)!=MB and mode=ACTIVE)then
			                 // in the active mode the attacker can forge the message with all his knowledge
			                 if(symDec(MB,1,1,1,self)=true)then
			                          par
                                                       knowsNonce(self,messageField($a,self,1,MB)):=true
                                                       protocolMessage(self,$b):=MB
                                                       messageField(self,$b,1,MB):=messageField($a,self,1,MB)
			                               symEnc(MB,1,1,1):=messageField($b,self,1,MA)
			                          endpar
			                 else
			                          par
                                                       protocolMessage(self,$b):=MB
                                                       messageField(self,$b,1,MB):=messageField($a,self,1,MB)
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
			        if(symDec(MC,2,1,2,self)=true)then
			                par
                                              knowsIdentityCertificate(self,messageField($a,self,1,MC)):=true
                                              knowsNonce(self,messageField($a,self,2,MC)):=true
                                              protocolMessage(self,$b):=MC
                                              messageField(self,$b,1,MC):=messageField($a,self,1,MC)
                                              messageField(self,$b,2,MC):=messageField($a,self,2,MC)
			                               symEnc(MC,2,1,2):=SKEB
			                endpar
			        else
			                par
                                              protocolMessage(self,$b):=MC
                                              messageField(self,$b,1,MC):=messageField($a,self,1,MC)
                                              messageField(self,$b,2,MC):=messageField($a,self,2,MC)
			                endpar
			        endif
			else
			        //check the reception of the message and the modality of the attack
			        if(protocolMessage($a,self)=MC and protocolMessage(self,$b)!=MC and mode=ACTIVE)then
			                 // in the active mode the attacker can forge the message with all his knowledge
			                 if(symDec(MC,2,1,2,self)=true)then
			                          par
                                                       knowsIdentityCertificate(self,messageField($a,self,1,MC)):=true
                                                       knowsNonce(self,messageField($a,self,2,MC)):=true
                                                       protocolMessage(self,$b):=MC
                                                       messageField(self,$b,1,MC):=messageField($a,self,1,MC)
                                                       messageField(self,$b,2,MC):=messageField($a,self,2,MC)
			                               symEnc(MC,2,1,2):=SKEB
			                          endpar
			                 else
			                          par
                                                       protocolMessage(self,$b):=MC
                                                       messageField(self,$b,1,MC):=messageField($a,self,1,MC)
                                                       messageField(self,$b,2,MC):=messageField($a,self,2,MC)
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
			                       messageField(self,$e,1,MA):=SKAB
			                       asymEnc(MA,1,1,1):=PUBKB
			                       internalStateA(self):=WAITING_MB
			                endpar
			        else
			                if(receiver=AG_E)then
			                        par
			                              protocolMessage(self,$e):=MA
			                              messageField(self,$e,1,MA):=SKAE
			                              asymEnc(MA,1,1,1):=PUBKE
			                              internalStateA(self):=WAITING_MB
			                        endpar
			                endif
			        endif
			endif
		endlet
	rule r_message_MB =
		let ($e=agentE) in
			if(internalStateB(self)=WAITING_MA and protocolMessage($e,self)=MA)then
			        if(asymDec(MA,1,1,1,self)=true)then
			                par
                                              knowsSymKey(self,messageField($e,self,1,MA)):=true
			                      protocolMessage(self,$e):=MB
			                      messageField(self,$e,1,MB):=NB
			                      symEnc(MB,1,1,1):=messageField($e,self,1,MA)
			                      internalStateB(self):=WAITING_MC
			                endpar
			        endif
			endif
	endlet
	rule r_message_MC =
		let ($e=agentE) in
			if(internalStateA(self)=WAITING_MB and protocolMessage($e,self)=MB)then
			        if(receiver=AG_B)then
			           if(symDec(MB,1,1,1,self)=true)then
			                par
                                              knowsNonce(self,messageField($e,self,1,MB)):=true
			                      protocolMessage(self,$e):=MC
			                      messageField(self,$e,1,MC):=CA
			                      messageField(self,$e,2,MC):=messageField($e,self,1,MB)
			                      sign(MC,1,2,2):=SIGNPRIVKA
			                      symEnc(MC,2,1,2):=messageField(self,$e,1,MA)
			                      internalStateA(self):=END_A
			                endpar
			        endif
			else
			           if(symDec(MB,1,1,1,self)=true)then
			                par
                                              knowsNonce(self,messageField($e,self,1,MB)):=true
			                      protocolMessage(self,$e):=MC
			                      messageField(self,$e,1,MC):=CA
			                      messageField(self,$e,2,MC):=messageField($e,self,1,MB)
			                      sign(MC,1,2,2):=SIGNPRIVKA
			                      symEnc(MC,2,1,2):=messageField(self,$e,1,MA)
			                      internalStateA(self):=END_A
			                endpar
				  endif
				endif
			endif
		endlet
	rule r_check_MC =
		let ($e=agentE) in
			if(internalStateB(self)=WAITING_MC and protocolMessage($e,self)=MC)then
			        if(symDec(MC,2,1,2,self)=true)then
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
	function knowsNonce($a in Agent, $n in KnowledgeNonce)=if($a=agentB and $n=NB) then true else false endif
	function knowsIdentityCertificate($a in Agent, $i in KnowledgeIdentityCertificate)=if($a=agentA and $i=CA) then true else false endif
	function knowsAsymPrivKey($a in Agent ,$k in KnowledgeAsymPrivKey)=if(($a=agentA and $k=PRIVKA) or ($a=agentB and $k=PRIVKB) or ($a=agentE and $k=PRIVKE)) then true else false endif
	function knowsAsymPubKey($a in Agent ,$pk in KnowledgeAsymPubKey)=true
	function knowsSymKey($a in Agent ,$sk in KnowledgeSymKey)=if(($a=agentA and $sk=SKAB) or ($a=agentA and $sk=SKAE) or ($a=agentB and $sk=SKAB) or ($a=agentB and $sk=SKEB) or ($a=agentE and $sk=SKEB) or ($a=agentE and $sk=SKAE)) then true else false endif
	function knowsSignPubKey($a in Agent ,$spu in KnowledgeSignPubKey)=if(($a=agentA and $spu=SKAB) or ($a=agentA and $spu=SKAE) or ($a=agentB and $spu=SKAB) or ($a=agentB and $spu=SKEB) or ($a=agentE and $spu=SKEB) or ($a=agentE and $spu=SKAE)) then true else false endif
	function knowsSignPrivKey($a in Agent ,$spr in KnowledgeSignPrivKey)=true
	function mode=chosenMode

	agent Alice:
		r_agentARule[]

	agent Bob:
		r_agentBRule[]

	agent Eve:
		r_agentERule[]
