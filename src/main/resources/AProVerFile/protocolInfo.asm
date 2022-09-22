asm XXX

import CryptoLibraryXXX


signature:

definitions:
	domain Level = {1}
	domain FieldPosition = {1:3}
	domain EncField1={1}
	domain EncField2={2}

	domain KnowledgeNonce = {NA,NB,NE}
	domain KnowledgeIdentityCertificate = {ID_A,ID_B,ID_E}
	domain KnowledgeAsymPrivKey = {PRIVKA,PRIVKB,PUBKE}
	domain KnowledgeAsymPubKey = {PUBKA,PUBKB,PRIVKE}

	function asim_keyAssociation($a in KnowledgeAsymPubKey)=
	       switch( $a )
	              case PRIVKA: PUBKA
	              case PRIVKB: PUBKB
	              case PUBKE: PRIVKE
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
                                              messageField(self,$b,1,M0):=messageField($a,self,1,M0)
                                              messageField(self,$b,2,M0):=messageField($a,self,2,M0)
			                endpar
			        else
			                par
                                              protocolMessage(self,$b):= M0
                                              messageField(self,$b,1,M0):=messageField($a,self,1,M0)
                                              messageField(self,$b,2,M0):=messageField($a,self,2,M0)
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
                                                       messageField(self,$b,1,M0):=messageField($a,self,1,M0)
                                                       messageField(self,$b,2,M0):=messageField($a,self,2,M0)
			                               asymDec(M0,1,1,2):=PUBKB
			                          endpar
			                 else
			                          par
                                                       protocolMessage(self,$b):= M0
                                                       messageField(self,$b,1,M0):=messageField($a,self,1,M0)
                                                       messageField(self,$b,2,M0):=messageField($a,self,2,M0)
			                          endpar
			                 endif
			         endif
			endif
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
                                              messageField(self,$b,1,M1):=messageField($a,self,1,M1)
                                              messageField(self,$b,2,M1):=messageField($a,self,2,M1)
			                endpar
			        else
			                par
                                              protocolMessage(self,$b):= M1
                                              messageField(self,$b,1,M1):=messageField($a,self,1,M1)
                                              messageField(self,$b,2,M1):=messageField($a,self,2,M1)
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
                                                       messageField(self,$b,1,M1):=messageField($a,self,1,M1)
                                                       messageField(self,$b,2,M1):=messageField($a,self,2,M1)
			                               asymDec(M1,1,1,2):=PUBKA
			                          endpar
			                 else
			                          par
                                                       protocolMessage(self,$b):= M1
                                                       messageField(self,$b,1,M1):=messageField($a,self,1,M1)
                                                       messageField(self,$b,2,M1):=messageField($a,self,2,M1)
			                          endpar
			                 endif
			         endif
			endif
