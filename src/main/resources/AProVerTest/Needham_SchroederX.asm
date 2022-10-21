asm Needham_SchroederX

import CryptoLibraryNSX


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
	rule r_message_replay_NAK =
		//choose what agets are interested by the message
		let ($b=agentB,$a=agentA) in
			//check the reception of the message and the modality of the attack
			if(protocolMessage($a,self)=NAK and protocolMessage(self,$b)!=NAK and mode=PASSIVE)then
			        //in passsive mode if the attacker knows the decryption key, the message payload is readable and it can be added to the attacker knowledge
			        // the message must be sent unaltered
			        if(asymDec(NAK,1,1,2,self)=true)then
			                par
                                              knowsNonce(self,messageField($a,self,1,NAK)):=true
                                              knowsIdentityCertificate(self,messageField($a,self,2,NAK)):=true
                                              protocolMessage(self,$b):=NAK
                                              messageField(self,$b,1,NAK):=messageField($a,self,1,NAK)
                                              messageField(self,$b,2,NAK):=messageField($a,self,2,NAK)
			                      asymEnc(NAK,1,1,2):=PUBKB
			                endpar
			        else
			                par
                                              protocolMessage(self,$b):=NAK
                                              messageField(self,$b,1,NAK):=messageField($a,self,1,NAK)
                                              messageField(self,$b,2,NAK):=messageField($a,self,2,NAK)
			                      asymEnc(NAK,1,1,2):=PUBKB
			                endpar
			        endif
			else
			        //check the reception of the message and the modality of the attack
			        if(protocolMessage($a,self)=NAK and protocolMessage(self,$b)!=NAK and mode=ACTIVE)then
			                 // in the active mode the attacker can forge the message with all his knowledge
			                 if(asymDec(NAK,1,1,2,self)=true)then
			                          par
                                                       knowsNonce(self,messageField($a,self,1,NAK)):=true
                                                       knowsIdentityCertificate(self,messageField($a,self,2,NAK)):=true
                                                       protocolMessage(self,$b):=NAK
                                                       messageField(self,$b,1,NAK):=messageField($a,self,1,NAK)
                                                       messageField(self,$b,2,NAK):=messageField($a,self,2,NAK)
			                               asymEnc(NAK,1,1,2):=PUBKB
			                          endpar
			                 else
			                          par
                                                       protocolMessage(self,$b):=NAK
                                                       messageField(self,$b,1,NAK):=messageField($a,self,1,NAK)
                                                       messageField(self,$b,2,NAK):=messageField($a,self,2,NAK)
			                               asymEnc(NAK,1,1,2):=PUBKB
			                          endpar
			                 endif
			        endif
			endif
		endlet
	rule r_message_replay_NNK =
		//choose what agets are interested by the message
		let ($b=agentA,$a=agentB) in
			//check the reception of the message and the modality of the attack
			if(protocolMessage($a,self)=NNK and protocolMessage(self,$b)!=NNK and mode=PASSIVE)then
			        //in passsive mode if the attacker knows the decryption key, the message payload is readable and it can be added to the attacker knowledge
			        // the message must be sent unaltered
			        if(asymDec(NNK,1,1,2,self)=true)then
			                par
                                              knowsNonce(self,messageField($a,self,1,NNK)):=true
                                              knowsNonce(self,messageField($a,self,2,NNK)):=true
                                              protocolMessage(self,$b):=NNK
                                              messageField(self,$b,1,NNK):=messageField($a,self,1,NNK)
                                              messageField(self,$b,2,NNK):=messageField($a,self,2,NNK)
			                      asymEnc(NNK,1,1,2):=PUBKA
			                endpar
			        else
			                par
                                              protocolMessage(self,$b):=NNK
                                              messageField(self,$b,1,NAK):=messageField($a,self,1,NNK)
                                              messageField(self,$b,2,NAK):=messageField($a,self,2,NNK)
			                      asymEnc(NNK,1,1,2):=PUBKA
			                endpar
			        endif
			else
			        //check the reception of the message and the modality of the attack
			        if(protocolMessage($a,self)=NNK and protocolMessage(self,$b)!=NNK and mode=ACTIVE)then
			                 // in the active mode the attacker can forge the message with all his knowledge
			                 if(asymDec(NNK,1,1,2,self)=true)then
			                          par
                                                       knowsNonce(self,messageField($a,self,1,NNK)):=true
                                                       knowsNonce(self,messageField($a,self,2,NNK)):=true
                                                       protocolMessage(self,$b):=NNK
                                                       messageField(self,$b,1,NNK):=messageField($a,self,1,NNK)
                                                       messageField(self,$b,2,NNK):=messageField($a,self,2,NNK)
			                               asymEnc(NNK,1,1,2):=PUBKA
			                          endpar
			                 else
			                          par
                                                       protocolMessage(self,$b):=NNK
                                                       messageField(self,$b,1,NAK):=messageField($a,self,1,NNK)
                                                       messageField(self,$b,2,NAK):=messageField($a,self,2,NNK)
			                               asymEnc(NNK,1,1,2):=PUBKA
			                          endpar
			                 endif
			        endif
			endif
		endlet
	rule r_message_replay_NK =
		//choose what agets are interested by the message
		let ($b=agentB,$a=agentA) in
			//check the reception of the message and the modality of the attack
			if(protocolMessage($a,self)=NK and protocolMessage(self,$b)!=NK and mode=PASSIVE)then
			        //in passsive mode if the attacker knows the decryption key, the message payload is readable and it can be added to the attacker knowledge
			        // the message must be sent unaltered
			        if(asymDec(NK,1,1,1,self)=true)then
			                par
                                              knowsNonce(self,messageField($a,self,1,NK)):=true
                                              protocolMessage(self,$b):=NK
                                              messageField(self,$b,1,NK):=messageField($a,self,1,NK)
			                      asymEnc(NK,1,1,1):=PUBKB
			                endpar
			        else
			                par
                                              protocolMessage(self,$b):=NK
                                              messageField(self,$b,1,NAK):=messageField($a,self,1,NK)
			                      asymEnc(NK,1,1,1):=PUBKB
			                endpar
			        endif
			else
			        //check the reception of the message and the modality of the attack
			        if(protocolMessage($a,self)=NK and protocolMessage(self,$b)!=NK and mode=ACTIVE)then
			                 // in the active mode the attacker can forge the message with all his knowledge
			                 if(asymDec(NK,1,1,1,self)=true)then
			                          par
                                                       knowsNonce(self,messageField($a,self,1,NK)):=true
                                                       protocolMessage(self,$b):=NK
                                                       messageField(self,$b,1,NK):=messageField($a,self,1,NK)
			                               asymEnc(NK,1,1,1):=PUBKB
			                          endpar
			                 else
			                          par
                                                       protocolMessage(self,$b):=NK
                                                       messageField(self,$b,1,NAK):=messageField($a,self,1,NK)
			                               asymEnc(NK,1,1,1):=PUBKB
			                          endpar
			                 endif
			        endif
			endif
		endlet

	/*HONEST AGENT RULES*/	
	rule r_message_NAK =
		let ($e=agentE) in
			if(internalStateA(self)=IDLE_NAK)then 
			        if(receiver=AG_B)then
			                par
			                       protocolMessage(self,$e):=NAK
			                       messageField(self,$e,1,NAK):=NA
			                       messageField(self,$e,2,NAK):=ID_A
			                       asymEnc(NAK,1,1,2):=PUBKB
			                       internalStateA(self):=WAITING_NNK
			                endpar
			        else
			                if(receiver=AG_E)then
			                        par
			                              protocolMessage(self,$e):=NAK
			                              messageField(self,$e,1,NAK):=NA
			                              messageField(self,$e,2,NAK):=ID_A
			                              asymEnc(NAK,1,1,2):=PUBKE
			                              internalStateA(self):=WAITING_NNK
			                        endpar
			                endif
			        endif
			endif
		endlet
	rule r_message_NNK =
		let ($e=agentE) in
			if(internalStateB(self)=WAITING_NAK and protocolMessage($e,self)=NAK)then
			        if(asymDec(NAK,1,1,2,self)=true)then
			                par
                                  knowsNonce(self,messageField($e,self,1,NAK)):=true
                                  knowsIdentityCertificate(self,messageField($e,self,2,NAK)):=true
			                      protocolMessage(self,$e):=NNK
			                      messageField(self,$e,1,NNK):=messageField($e,self,1,NAK)
			                      messageField(self,$e,2,NNK):=NB
 			                      asymEnc(NNK,1,1,2):=PUBKA
			                      internalStateB(self):=WAITING_NK
			                endpar
			        endif
			endif
	endlet
	rule r_message_NK =
		let ($e=agentE) in
			if(internalStateA(self)=WAITING_NNK and protocolMessage($e,self)=NNK)then
			        if(receiver=AG_B)then
   			           if(asymDec(NNK,1,1,2,self)=true)then
			                par
                                  knowsNonce(self,messageField($e,self,1,NAK)):=true
                                  knowsNonce(self,messageField($e,self,2,NAK)):=true
			                      protocolMessage(self,$e):=NK
			                      messageField(self,$e,1,NK):=messageField($e,self,2,NNK)
			                      asymEnc(NK,1,1,1):=PUBKB
			                      internalStateA(self):=END_A
			                endpar
			        endif
			else
			           if(asymDec(NNK,1,1,2,self)=true)then
			                par
                                  knowsNonce(self,messageField($e,self,1,NAK)):=true
                                  knowsNonce(self,messageField($e,self,2,NAK)):=true
			                      protocolMessage(self,$e):=NK
			                      messageField(self,$e,1,NK):=messageField($e,self,2,NNK)
			                      asymEnc(NK,1,1,1):=PUBKE
			                      internalStateA(self):=END_A
			                endpar
				  endif
				endif
			endif
		endlet
	rule r_check_NK =
		let ($e=agentE) in
			if(internalStateB(self)=WAITING_NK and protocolMessage($e,self)=NK)then
			        if(asymDec(NK,1,1,1,self)= true) then
			                      internalStateB(self):=END_B
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
	function internalStateA($a in Alice)=IDLE_NAK
	function internalStateB($b in Bob)=WAITING_NAK
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