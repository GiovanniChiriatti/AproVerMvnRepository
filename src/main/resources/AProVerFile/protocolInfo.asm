asm XXX

import CryptoLibraryXXX


signature:

definitions:
	domain Level = {1}
	domain FieldPosition = {1:2}
	domain EncField1={1}
	domain EncField2={2}

	domain KnowledgeNonce = {NA,NB,NE}
	domain KnowledgeIdentityCertificate = {ID_A,ID_B,ID_E}
	domain KnowledgeSymKey = {PKSYM}
	domain KnowledgeAsymPrivKey = {PRIVKA,PRIVKB,PRIVKE}
	domain KnowledgeAsymPubKey = {PUBKA,PUBKB,PUBKE}

	function asim_keyAssociation($a in KnowledgeAsymPubKey)=
	       switch( $a )
	              case PRIVKA: PUBKA
	              case PRIVKB: PUBKB
	              case PRIVKE: PUBKE
	       endswitch

	/*ATTACKER RULES*/
	rule r_message_replay_M0 =
		//choose what agets are interested by the message
		let ($b=agentB,$a=agentA) in
			//check the reception of the message and the modality of the attack
			if(protocolMessage($a ,self)=M0 and protocolMessage(self,$b)!=M0 and mode=PASSIVE)then
			        //in passsive mode if the attacker knows the decryption key, the message payload is readable and it can be added to the attacker knowledge
			        // the message must be sent unaltered
			        if(asymDec(M0,1,1,2,self)=true)then
			                par
                                              knowsNonce(self,messageField($a,self,1,M0)):=true
                                              knowsIdentityCertificate(self,messageField($a,self,2,M0)):=true
                                              protocolMessage(self,$b):= M0
                                              messageField(self,$b,1,M0):=messageField(typeActor,self,1,M0)
                                              messageField(self,$b,2,M0):=messageField(typeActor,self,2,M0)
			                endpar
			        else
			                par
                                              protocolMessage(self,$b):= M0
                                              messageField(self,$b,1,M0):=messageField(typeActor,self,1,M0)
                                              messageField(self,$b,2,M0):=messageField(typeActor,self,2,M0)
			                endpar
			        endif
			else
			        //check the reception of the message and the modality of the attack
			        if(protocolMessage($a ,self)=M0 and protocolMessage(self,$b)!=M0 and mode=ACTIVE)then
			                 // in the active mode the attacker can forge the message with all his knowledge
			                 if(asymDec(M0,1,1,2,self)=true)then
			                          par
                                                       knowsNonce(self,messageField($a,self,1,M0)):=true
                                                       knowsIdentityCertificate(self,messageField($a,self,2,M0)):=true
                                                       protocolMessage(self,$b):= M0
                                                       messageField(self,$b,1,M0):=messageField(typeActor,self,1,M0)
                                                       messageField(self,$b,2,M0):=messageField(typeActor,self,2,M0)
			                               asymEnc(M0,1,1,2):=PUBKB
			                          endpar
			                 else
			                          par
                                                       protocolMessage(self,$b):= M0
                                                       messageField(self,$b,1,M0):=messageField(typeActor,self,1,M0)
                                                       messageField(self,$b,2,M0):=messageField(typeActor,self,2,M0)
			                          endpar
			                 endif
			        endif
			endif
		endlet
	rule r_message_replay_M1 =
		//choose what agets are interested by the message
		let ($b=agentA,$a=agentB) in
			//check the reception of the message and the modality of the attack
			if(protocolMessage($a ,self)=M1 and protocolMessage(self,$b)!=M1 and mode=PASSIVE)then
			        //in passsive mode if the attacker knows the decryption key, the message payload is readable and it can be added to the attacker knowledge
			        // the message must be sent unaltered
			        if(asymDec(M1,1,1,2,self)=true)then
			                par
                                              knowsNonce(self,messageField($a,self,1,M1)):=true
                                              knowsNonce(self,messageField($a,self,2,M1)):=true
                                              protocolMessage(self,$b):= M1
                                              messageField(self,$b,1,M1):=messageField(typeActor,self,1,M1)
                                              messageField(self,$b,2,M1):=messageField(typeActor,self,2,M1)
			                endpar
			        else
			                par
                                              protocolMessage(self,$b):= M1
                                              messageField(self,$b,1,M1):=messageField(typeActor,self,1,M1)
                                              messageField(self,$b,2,M1):=messageField(typeActor,self,2,M1)
			                endpar
			        endif
			else
			        //check the reception of the message and the modality of the attack
			        if(protocolMessage($a ,self)=M1 and protocolMessage(self,$b)!=M1 and mode=ACTIVE)then
			                 // in the active mode the attacker can forge the message with all his knowledge
			                 if(asymDec(M1,1,1,2,self)=true)then
			                          par
                                                       knowsNonce(self,messageField($a,self,1,M1)):=true
                                                       knowsNonce(self,messageField($a,self,2,M1)):=true
                                                       protocolMessage(self,$b):= M1
                                                       messageField(self,$b,1,M1):=messageField(typeActor,self,1,M1)
                                                       messageField(self,$b,2,M1):=messageField(typeActor,self,2,M1)
			                               asymEnc(M1,1,1,2):=PUBKA
			                          endpar
			                 else
			                          par
                                                       protocolMessage(self,$b):= M1
                                                       messageField(self,$b,1,M1):=messageField(typeActor,self,1,M1)
                                                       messageField(self,$b,2,M1):=messageField(typeActor,self,2,M1)
			                          endpar
			                 endif
			        endif
			endif
		endlet
	rule r_message_replay_M2 =
		//choose what agets are interested by the message
		let ($b=agentB,$a=agentA) in
			//check the reception of the message and the modality of the attack
			if(protocolMessage($a ,self)=M2 and protocolMessage(self,$b)!=M2 and mode=PASSIVE)then
			        //in passsive mode if the attacker knows the decryption key, the message payload is readable and it can be added to the attacker knowledge
			        // the message must be sent unaltered
			        if(asymDec(M2,1,1,1,self)=true)then
			                par
                                              knowsNonce(self,messageField($a,self,1,M2)):=true
                                              protocolMessage(self,$b):= M2
                                              messageField(self,$b,1,M2):=messageField(typeActor,self,1,M2)
			                endpar
			        else
			                par
                                              protocolMessage(self,$b):= M2
                                              messageField(self,$b,1,M2):=messageField(typeActor,self,1,M2)
			                endpar
			        endif
			else
			        //check the reception of the message and the modality of the attack
			        if(protocolMessage($a ,self)=M2 and protocolMessage(self,$b)!=M2 and mode=ACTIVE)then
			                 // in the active mode the attacker can forge the message with all his knowledge
			                 if(asymDec(M2,1,1,1,self)=true)then
			                          par
                                                       knowsNonce(self,messageField($a,self,1,M2)):=true
                                                       protocolMessage(self,$b):= M2
                                                       messageField(self,$b,1,M2):=messageField(typeActor,self,1,M2)
			                               asymEnc(M2,1,1,1):=PUBKB
			                          endpar
			                 else
			                          par
                                                       protocolMessage(self,$b):= M2
                                                       messageField(self,$b,1,M2):=messageField(typeActor,self,1,M2)
			                          endpar
			                 endif
			        endif
			endif
		endlet

	/*HONEST AGENT RULES*/	
	rule r_message_M0 =
		let ($e=agentE) in
			if(internalStateA(self)=IDLE_M0)then)
			        if(receiver=AG_B)then
			                par
			                       protocolMessage(self,$e):=M0
			                       messageField(self,$e,1,M0):=NA
			                       messageField(self,$e,2,M0):=ID_A
			                       asymEnc(M0,1,1,2):=PUBKB
			                       internalStateA(self):=WAITING_M1
			                endpar
			        else
			                if(receiver=AG_E)then
			                        par
			                              protocolMessage(self,$e):=M0
			                              messageField(self,$e,1,M0):=NA
			                              messageField(self,$e,2,M0):=ID_A
			                              asymEnc(M0,1,1,2):=PUBKE
			                              internalStateA(self):=WAITING_M1
			                        endpar
			                endif
			        endif
			endif
	rule r_message_M1 =
		let ($e=agentE) in
			if(internalStateB(self)=WAITING_M0 and protocolMessage($e,self)=M0)then
			        if(asymDec(M0,1,1,2,self)=true)then
                                              knowsNonce(self,messageField($e,self,1,M0)):=true
                                              knowsIdentityCertificate(self,messageField($e,self,2,M0)):=true
			                      protocolMessage(self,$e):=M1
			                      messageField(self,$e,1,M1):=NA
			                      messageField(self,$e,2,M1):=NB
			                      asymEnc(M1,1,1,2):=PUBKA
			                      internalStateB(self):=WAITING_M2
			                endpar
			        endif
			endif
	rule r_message_M2 =
		let ($e=agentE) in
			if(internalStateA(self)=WAITING_M1 and protocolMessage($e,self)=M1)then
			        if(receiver=AG_B)then
			           if(asymDec(M1,1,1,2,self)=true)then
			                par
                                              knowsNonce(self,messageField($e,self,1,M1)):=true
                                              knowsNonce(self,messageField($e,self,2,M1)):=true
			                      protocolMessage(self,$e):=M2
			                      messageField(self,$e,1,M2):=NB
			                      asymEnc(M2,1,1,1):=PUBKB
			                      internalStateA(self):=END_A
			                endpar
			        endif
			else
			           if(asymDec(M1,1,1,2,self)=true)then
			                par
                                              knowsNonce(self,messageField($e,self,1,M1)):=true
                                              knowsNonce(self,messageField($e,self,2,M1)):=true
			                      protocolMessage(self,$e):=M2
			                      messageField(self,$e,1,M2):=NB
			                      asymEnc(M2,1,1,1):=PUBKE
			                      internalStateA(self):=END_A
			                endpar
				  endif
				endif
			endif
		endlet
	rule r_check_M2 =
		let ($e=agentE) in
			if(internalStateB(self)=WAITING_M2 and protocolMessage($e,self)=M2)then
			        if(asymDec(M2,1,1,1,self)=true)then
			                      internalStateB(self):=END_B
			        endif
			endif
		endlet

	rule r_agentERule  =
	  par
            r_message_replay_M0[]
            r_message_replay_M1[]
            r_message_replay_M2[]
	  endpar

	rule r_agentARule  =
	  par
            r_message_M0[]
            r_message_M2[]
	  endpar

	rule r_agentBRule  =
	  par
            r_message_M1[]
            r_check_M2[]
	  endpar

	main rule r_Main =
	  par
             program(agentA)
             program(agentB)
             program(agentE)
	  endpar
default init s0:
	function internalStateA($a in Alice)=IDLE_M0
	function internalStateB($b in Bob)=WAITING_M0
	function receiver=chosenReceiver
	function knowsNonce($a in Agent, $n in KnowledgeNonce)=if($a=agentA and $n=NA) then true else if($a=agentB and $n=NB) or ($a=agentB and $n=NA) then true else if($a=agentE and $n=NE) then true else false endif endif endif
	function knowsIdentityCertificate($a in Agent, $i in KnowledgeIdentityCertificate)=if($a=agentA and $i=ID_A) then true else if($a=agentB and $i=ID_B) then true else if($a=agentE and $i=ID_E) then true else false endif endif endif
	function knowsAsymPrivKey($a in Agent ,$k in KnowledgeAsymPrivKey)=if(($a=agentA and $k=PRIVKA) or ($a=agentB and $k=PRIVKB) or ($a=agentE and $k=PRIVKE)) then true else false endif
	function knowsAsymPubKey($a in Agent ,$pk in KnowledgeAsymPubKey)=true
	function knowsSymKey($a in Agent ,$sk in KnowledgeSymKey)=if(($a=agentA and $sk=PKSYM)) then true else false endif
	function knowsSignPubKey($a in Agent ,$sk in KnowledgeSignPubKey)=if(($a=agentA and $sk=PKSYM)) then true else false endif
	function knowsSignPrivKey($a in Agent ,$spr in KnowledgeSignPrivKey)=true
