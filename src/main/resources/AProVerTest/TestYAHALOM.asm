asm TestYAHALOM

import StandardLibrary


signature:

	domain Alice subsetof Agent
	domain Bob subsetof Agent
	domain Eve subsetof Agent
	domain Server subsetof Agent


	enum domain StateAlice = {IDLE_REQCOM | WAITING_FRWVRNB | CHECK_END_A | END_A}
	enum domain StateBob = {WAITING_ENCKBS | CHECK_END_B | END_B}
	enum domain StateServer = {WAITING_GENKEYSES | CHECK_END_S | END_S}

	enum domain Message = {REQCOM | ENCKBS | GENKEYSES | FRWVRNB} 

	enum domain Knowledge ={CA|CB|KAB|KAS|KBS|KES|NA|NB}

	//DOMAIN OF POSSIBLE RECEIVER
	enum domain Receiver={AG_A|AG_B|AG_E|AG_S}
	///DOMAIN OF THE ATTACKER MODE
	enum domain Modality = {ACTIVE | PASSIVE}

	domain KnowledgeNonce subsetof Any
	domain KnowledgeIdentityCertificate subsetof Any
	domain KnowledgeBitString subsetof Any
	domain KnowledgeSymKey subsetof Any
	domain KnowledgeAsymPrivKey subsetof Any
	domain KnowledgeAsymPubKey subsetof Any
	domain KnowledgeSignPrivKey subsetof Any
	domain KnowledgeSignPubKey subsetof Any
	domain KnowledgeTag subsetof Any
	domain KnowledgeDigest subsetof Any
	domain KnowledgeHash subsetof Any
	domain KnowledgeTimestamp subsetof Any
	domain KnowledgeOther subsetof Any

	//range on which apply the cryptographic function
	domain  FieldPosition subsetof Integer
	domain  Level subsetof Integer
	domain  EncField1 subsetof Integer
	domain  EncField2 subsetof Integer
	domain  SignField1 subsetof Integer
	domain  SignField2 subsetof Integer
	domain  HashField1 subsetof Integer
	domain  HashField2 subsetof Integer
	domain  NumMsg subsetof Integer

	//state of the actor
	controlled internalStateA: Alice -> StateAlice
	controlled internalStateB: Bob -> StateBob
	controlled internalStateS: Server -> StateServer

	//name of the message
	controlled protocolMessage: Prod(NumMsg,Agent,Agent)-> Message
	// content of the message and in which field it goes
	controlled messageField: Prod(Agent,Agent,FieldPosition,Message)->Knowledge

	//attaker mode
	monitored chosenMode: Modality
	//controlled for saving the attacker modality choice
	controlled mode: Modality

	// FUNCTIONS SELECT THE RECEIVER
	static name:Receiver -> Agent
	//Receiver chosen
	controlled receiver:Receiver
	//Receiver chosen by user
	monitored chosenReceiver:Receiver

	/*------------------------------------------------------------------- */
	//            Knowledge  management of the principals 
	/*------------------------------------------------------------------- */
	controlled knowsNonce:Prod(Agent,KnowledgeNonce)->Boolean

	controlled knowsIdentityCertificate:Prod(Agent,KnowledgeIdentityCertificate)->Boolean

	controlled knowsBitString:Prod(Agent,KnowledgeBitString)->Boolean

	controlled knowsSymKey:Prod(Agent,KnowledgeSymKey)->Boolean

	controlled knowsAsymPubKey:Prod(Agent,KnowledgeAsymPubKey)->Boolean

	controlled knowsAsymPrivKey:Prod(Agent,KnowledgeAsymPrivKey)->Boolean

	controlled knowsSignPubKey:Prod(Agent,KnowledgeSignPubKey)->Boolean

	controlled knowsSignPrivKey:Prod(Agent,KnowledgeSignPrivKey)->Boolean

	controlled knowsTag:Prod(Agent,KnowledgeTag)->Boolean

	controlled knowsDigest:Prod(Agent,KnowledgeDigest)->Boolean

	controlled knowsHash:Prod(Agent,KnowledgeHash)->Boolean

	controlled knowsTimestamp:Prod(Agent,KnowledgeTimestamp)->Boolean

	controlled knowsOther:Prod(Agent,KnowledgeOther)->Boolean

	/*------------------------------------------------------------------- */
	//                  Cryptographic functions
	/*------------------------------------------------------------------- */
	//hash function applied from the field HashField1 to HashField2, the nesting level is Level
	controlled hash: Prod(Message,Level,HashField1,HashField2)-> KnowledgeHash
	static verifyHash: Prod(Message,Level,HashField1,HashField2,Agent)-> Boolean

	//sign function applied from the field SignField1 to SignField2, the nesting level is Level
	controlled sign: Prod(Message,Level,SignField1,SignField2)-> KnowledgeSignPrivKey
	static verifySign: Prod(Message,Level,SignField1,SignField2,Agent)-> Boolean
	static sign_keyAssociation: KnowledgeSignPrivKey -> KnowledgeSignPubKey

	//asymmetric encryption function applied from the field EncField1 to EncField2
	//the nesting level is Level
	controlled asymEnc: Prod(Message,Level,EncField1,EncField2)-> KnowledgeAsymPubKey
	static asymDec: Prod(Message,Level,EncField1,EncField2,Agent)-> Boolean
	static asim_keyAssociation: KnowledgeAsymPubKey -> KnowledgeAsymPrivKey

	//symmetric encryption function applied from the field EncField1 to EncField2
	//the nesting level is Level
	controlled symEnc: Prod(Message,Level,EncField1,EncField2)-> KnowledgeSymKey
	static symDec: Prod(Message,Level,EncField1,EncField2,Agent)-> Boolean

	static agentA: Alice
	static agentB: Bob
	static agentE: Eve
	static agentS: Server

definitions:
	domain Level = {1}
	domain FieldPosition = {1:6}
	domain EncField1={1:6}
	domain EncField2={1:6}
	domain NumMsg={0:15}

	domain KnowledgeNonce = {NA,NB}
	domain KnowledgeIdentityCertificate = {CA,CB}
	domain KnowledgeSymKey = {KAB,KAS,KBS,KES}

	function name($a in Receiver)=
			switch( $a )
				case AG_A:agentA
				case AG_E:agentE
				case AG_B:agentB
				case AG_S:agentS
			endswitch

		function verifySign($m in Message,$l in Level,$f1 in SignField1,$f2 in SignField2,$d in Agent)=
			if(knowsSignPubKey($d,sign_keyAssociation(sign($m,$l,$f1,$f2)))=true)then
				true
			else
				false
			endif

		function symDec($m in Message,$l in Level,$f1 in EncField1,$f2 in EncField2,$d in Agent)=
			if(knowsSymKey($d,symEnc($m,$l,$f1,$f2))=true)then
				true
			else
				false
			endif

		function asymDec($m in Message,$l in Level,$f1 in EncField1,$f2 in EncField2,$d in Agent)=
			if(knowsAsymPrivKey($d,asim_keyAssociation(asymEnc($m,$l,$f1,$f2)))=true)then
				true
			else
				false
			endif

		function verifyHash($m in Message,$l in Level,$f1 in HashField1,$f2 in HashField2,$d in Agent)=
			if(knowsHash($d,hash($m,$l,$f1,$f2))=true)then
				true
			else
				false
			endif



	/*ATTACKER RULES*/
	rule r_message_replay_REQCOM =
		//choose what agets are interested by the message
		let ($b=agentB,$a=agentA) in
		  par 
			//check the reception of the message and the modality of the attack
			if(protocolMessage(0,$a,self)=REQCOM and protocolMessage(0,self,$b)!=REQCOM and mode=PASSIVE)then
			        //in passsive mode if the attacker knows the decryption key, the message payload is readable and it can be added to the attacker knowledge
			        // the message must be sent unaltered
		          par 
                 	protocolMessage(0,self,$b):=REQCOM
                 	messageField(self,$b,1,REQCOM):=messageField($a,self,1,REQCOM)
                 	messageField(self,$b,2,REQCOM):=messageField($a,self,2,REQCOM)
                 	knowsIdentityCertificate(self,messageField($a,self,1,REQCOM)):=true
                 	knowsNonce(self,messageField($a,self,2,REQCOM)):=true
		          endpar 
			endif 
			        //check the reception of the message and the modality of the attack
			if(protocolMessage(0,$a,self)=REQCOM and protocolMessage(0,self,$b)!=REQCOM and mode=ACTIVE)then
		          par 
                 	protocolMessage(0,self,$b):=REQCOM
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
			if(protocolMessage(1,$a,self)=ENCKBS and protocolMessage(1,self,$b)!=ENCKBS and mode=PASSIVE)then
			        //in passsive mode if the attacker knows the decryption key, the message payload is readable and it can be added to the attacker knowledge
			        // the message must be sent unaltered
		          par 
                 	protocolMessage(1,self,$b):=ENCKBS
                 	messageField(self,$b,1,ENCKBS):=messageField($a,self,1,ENCKBS)
                 	messageField(self,$b,2,ENCKBS):=messageField($a,self,2,ENCKBS)
                 	messageField(self,$b,3,ENCKBS):=messageField($a,self,3,ENCKBS)
                 	messageField(self,$b,4,ENCKBS):=messageField($a,self,4,ENCKBS)
                 	knowsIdentityCertificate(self,messageField($a,self,1,ENCKBS)):=true
			        if(symDec(ENCKBS,1,2,4,self)=true)then
                      par 
                    	knowsIdentityCertificate(self,messageField($a,self,2,ENCKBS)):=true
                    	knowsNonce(self,messageField($a,self,3,ENCKBS)):=true
                    	knowsNonce(self,messageField($a,self,4,ENCKBS)):=true
			            symEnc(ENCKBS,1,2,4):=KBS
                      endpar 
			        endif 
		          endpar 
			endif 
			        //check the reception of the message and the modality of the attack
			if(protocolMessage(1,$a,self)=ENCKBS and protocolMessage(1,self,$b)!=ENCKBS and mode=ACTIVE)then
		          par 
                 	protocolMessage(1,self,$b):=ENCKBS
                 	messageField(self,$b,1,ENCKBS):=messageField($a,self,1,ENCKBS)
                 	messageField(self,$b,2,ENCKBS):=messageField($a,self,2,ENCKBS)
                 	messageField(self,$b,3,ENCKBS):=messageField($a,self,3,ENCKBS)
                 	messageField(self,$b,4,ENCKBS):=messageField($a,self,4,ENCKBS)
                 	knowsIdentityCertificate(self,messageField($a,self,1,ENCKBS)):=true
			        if(symDec(ENCKBS,1,2,4,self)=true)then
	   			     par 
                    	knowsIdentityCertificate(self,messageField($a,self,2,ENCKBS)):=true
                    	knowsNonce(self,messageField($a,self,3,ENCKBS)):=true
                    	knowsNonce(self,messageField($a,self,4,ENCKBS)):=true
			        	symEnc(ENCKBS,1,2,4):=KBS
	   			     endpar 
			        endif 
		          endpar 
			endif 
		  endpar 
		endlet 
	rule r_message_replay_GENKEYSES =
		//choose what agets are interested by the message
		let ($b=agentA,$a=agentS) in
		  par 
			//check the reception of the message and the modality of the attack
			if(protocolMessage(2,$a,self)=GENKEYSES and protocolMessage(2,self,$b)!=GENKEYSES and mode=PASSIVE)then
			        //in passsive mode if the attacker knows the decryption key, the message payload is readable and it can be added to the attacker knowledge
			        // the message must be sent unaltered
		          par 
                 	protocolMessage(2,self,$b):=GENKEYSES
                 	messageField(self,$b,1,GENKEYSES):=messageField($a,self,1,GENKEYSES)
                 	messageField(self,$b,2,GENKEYSES):=messageField($a,self,2,GENKEYSES)
                 	messageField(self,$b,3,GENKEYSES):=messageField($a,self,3,GENKEYSES)
                 	messageField(self,$b,4,GENKEYSES):=messageField($a,self,4,GENKEYSES)
                 	messageField(self,$b,5,GENKEYSES):=messageField($a,self,5,GENKEYSES)
                 	messageField(self,$b,6,GENKEYSES):=messageField($a,self,6,GENKEYSES)
			        if(symDec(GENKEYSES,1,1,4,self)=true)then
                      par 
                    	knowsIdentityCertificate(self,messageField($a,self,1,GENKEYSES)):=true
                    	knowsSymKey(self,messageField($a,self,2,GENKEYSES)):=true
                    	knowsNonce(self,messageField($a,self,3,GENKEYSES)):=true
                    	knowsNonce(self,messageField($a,self,4,GENKEYSES)):=true
			            symEnc(GENKEYSES,1,1,4):=KAS
                      endpar 
			        endif 
			        if(symDec(GENKEYSES,1,5,6,self)=true)then
                      par 
                    	knowsIdentityCertificate(self,messageField($a,self,5,GENKEYSES)):=true
                    	knowsSymKey(self,messageField($a,self,6,GENKEYSES)):=true
			            symEnc(GENKEYSES,1,5,6):=KBS
                      endpar 
			        endif 
		          endpar 
			endif 
			        //check the reception of the message and the modality of the attack
			if(protocolMessage(2,$a,self)=GENKEYSES and protocolMessage(2,self,$b)!=GENKEYSES and mode=ACTIVE)then
		          par 
                 	protocolMessage(2,self,$b):=GENKEYSES
                 	messageField(self,$b,1,GENKEYSES):=messageField($a,self,1,GENKEYSES)
                 	messageField(self,$b,3,GENKEYSES):=messageField($a,self,3,GENKEYSES)
                 	messageField(self,$b,4,GENKEYSES):=messageField($a,self,4,GENKEYSES)
                 	messageField(self,$b,5,GENKEYSES):=messageField($a,self,5,GENKEYSES)
			        if(symDec(GENKEYSES,1,1,4,self)=true)then
	   			     par 
			         	messageField(self,$b,2,GENKEYSES):=KES
                    	knowsIdentityCertificate(self,messageField($a,self,1,GENKEYSES)):=true
                    	knowsSymKey(self,messageField($a,self,2,GENKEYSES)):=true
                    	knowsNonce(self,messageField($a,self,3,GENKEYSES)):=true
                    	knowsNonce(self,messageField($a,self,4,GENKEYSES)):=true
			        	symEnc(GENKEYSES,1,1,4):=KAS
	   			     endpar 
			        else 
			         	messageField(self,$b,2,GENKEYSES):=messageField($a,self,2,GENKEYSES)
			        endif 
			        if(symDec(GENKEYSES,1,5,6,self)=true)then
	   			     par 
			         	messageField(self,$b,6,GENKEYSES):=KES
                    	knowsIdentityCertificate(self,messageField($a,self,5,GENKEYSES)):=true
                    	knowsSymKey(self,messageField($a,self,6,GENKEYSES)):=true
			        	symEnc(GENKEYSES,1,5,6):=KBS
	   			     endpar 
			        else 
			         	messageField(self,$b,6,GENKEYSES):=messageField($a,self,6,GENKEYSES)
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
			if(protocolMessage(3,$a,self)=FRWVRNB and protocolMessage(3,self,$b)!=FRWVRNB and mode=PASSIVE)then
			        //in passsive mode if the attacker knows the decryption key, the message payload is readable and it can be added to the attacker knowledge
			        // the message must be sent unaltered
		          par 
                 	protocolMessage(3,self,$b):=FRWVRNB
                 	messageField(self,$b,1,FRWVRNB):=messageField($a,self,1,FRWVRNB)
                 	messageField(self,$b,2,FRWVRNB):=messageField($a,self,2,FRWVRNB)
                 	messageField(self,$b,3,FRWVRNB):=messageField($a,self,3,FRWVRNB)
			        if(symDec(FRWVRNB,1,1,2,self)=true)then
                      par 
                    	knowsIdentityCertificate(self,messageField($a,self,1,FRWVRNB)):=true
                    	knowsSymKey(self,messageField($a,self,2,FRWVRNB)):=true
			            symEnc(FRWVRNB,1,1,2):=KBS
                      endpar 
			        endif 
			        if(symDec(FRWVRNB,1,3,3,self)=true)then
                      par 
                    	knowsNonce(self,messageField($a,self,3,FRWVRNB)):=true
			            symEnc(FRWVRNB,1,3,3):=messageField($b,self,6,GENKEYSES)
                      endpar 
			        endif 
		          endpar 
			endif 
			        //check the reception of the message and the modality of the attack
			if(protocolMessage(3,$a,self)=FRWVRNB and protocolMessage(3,self,$b)!=FRWVRNB and mode=ACTIVE)then
		          par 
                 	protocolMessage(3,self,$b):=FRWVRNB
                 	messageField(self,$b,1,FRWVRNB):=messageField($a,self,1,FRWVRNB)
                 	messageField(self,$b,3,FRWVRNB):=messageField($a,self,3,FRWVRNB)
			        if(symDec(FRWVRNB,1,1,2,self)=true)then
	   			     par 
			         	messageField(self,$b,2,FRWVRNB):=KES
                    	knowsIdentityCertificate(self,messageField($a,self,1,FRWVRNB)):=true
                    	knowsSymKey(self,messageField($a,self,2,FRWVRNB)):=true
			        	symEnc(FRWVRNB,1,1,2):=KBS
	   			     endpar 
			        else 
			         	messageField(self,$b,2,FRWVRNB):=messageField($a,self,2,FRWVRNB)
			        endif 
			        if(symDec(FRWVRNB,1,3,3,self)=true)then
	   			     par 
                    	knowsNonce(self,messageField($a,self,3,FRWVRNB)):=true
			        	symEnc(FRWVRNB,1,3,3):=KES
	   			     endpar 
			        endif 
		          endpar 
			endif 
		  endpar 
		endlet 

	/*HONEST AGENT RULES*/	
	rule r_message_REQCOM =
		let ($e=agentE) in
			if(internalStateA(self)=IDLE_REQCOM)then 
			   if(receiver!=AG_E)then
			     par
			         protocolMessage(0,self,$e):=REQCOM
			         messageField(self,$e,1,REQCOM):=CA
			         messageField(self,$e,2,REQCOM):=NA
			         internalStateA(self):=WAITING_FRWVRNB
			     endpar
			   else
			       if(receiver=AG_E)then
			         par
			            protocolMessage(0,self,$e):=REQCOM
			            messageField(self,$e,1,REQCOM):=CA
			            messageField(self,$e,2,REQCOM):=NA
			            internalStateA(self):=WAITING_FRWVRNB
			         endpar
			       endif
			   endif
			endif
		endlet
	rule r_message_ENCKBS =
		let ($e=agentE) in
			if(internalStateB(self)=WAITING_ENCKBS and protocolMessage(0,$e,self)=REQCOM)then
			   if(receiver!=AG_E)then
			          par
			            knowsIdentityCertificate(self,messageField($e,self,1,REQCOM)):=true
			            knowsNonce(self,messageField($e,self,2,REQCOM)):=true
			            protocolMessage(1,self,$e):=ENCKBS
			            messageField(self,$e,1,ENCKBS):=CB
			            messageField(self,$e,2,ENCKBS):=messageField($e,self,1,REQCOM)
			            messageField(self,$e,3,ENCKBS):=messageField($e,self,2,REQCOM)
			            messageField(self,$e,4,ENCKBS):=NB
			            symEnc(ENCKBS,1,2,4):=KBS
			            internalStateB(self):=CHECK_END_B
			          endpar
			   else
			          par
			            knowsIdentityCertificate(self,messageField($e,self,1,REQCOM)):=true
			            knowsNonce(self,messageField($e,self,2,REQCOM)):=true
			            protocolMessage(1,self,$e):=ENCKBS
			            messageField(self,$e,1,ENCKBS):=CB
			            messageField(self,$e,2,ENCKBS):=messageField($e,self,1,REQCOM)
			            messageField(self,$e,3,ENCKBS):=messageField($e,self,2,REQCOM)
			            messageField(self,$e,4,ENCKBS):=NB
			            symEnc(ENCKBS,1,2,4):=KBS
			            internalStateB(self):=CHECK_END_B
			         endpar
			   endif
			endif
		endlet
	rule r_message_GENKEYSES =
		let ($e=agentE) in
			if(internalStateS(self)=WAITING_GENKEYSES and protocolMessage(1,$e,self)=ENCKBS)then
			   if(receiver!=AG_E)then
			    par
			            knowsIdentityCertificate(self,messageField($e,self,1,ENCKBS)):=true
 			        if(symDec(ENCKBS,1,2,4,self)=true ) then
			          par
			            knowsIdentityCertificate(self,messageField($e,self,2,ENCKBS)):=true
			            knowsNonce(self,messageField($e,self,3,ENCKBS)):=true
			            knowsNonce(self,messageField($e,self,4,ENCKBS)):=true
			            protocolMessage(2,self,$e):=GENKEYSES
			            messageField(self,$e,1,GENKEYSES):=messageField($e,self,1,ENCKBS)
			            messageField(self,$e,2,GENKEYSES):=KAB
			            messageField(self,$e,3,GENKEYSES):=messageField($e,self,3,ENCKBS)
			            messageField(self,$e,4,GENKEYSES):=messageField($e,self,4,ENCKBS)
			            symEnc(GENKEYSES,1,1,4):=KAS
			            messageField(self,$e,5,GENKEYSES):=messageField($e,self,2,ENCKBS)
			            messageField(self,$e,6,GENKEYSES):=KAB
			            symEnc(GENKEYSES,1,5,6):=KBS
			            internalStateS(self):=END_S
			          endpar
			        endif
			    endpar
			   else
			    par
			            knowsIdentityCertificate(self,messageField($e,self,1,ENCKBS)):=true
 			        if(symDec(ENCKBS,1,2,4,self)=true  and receiver=AG_E) then
			          par
			            knowsIdentityCertificate(self,messageField($e,self,2,ENCKBS)):=true
			            knowsNonce(self,messageField($e,self,3,ENCKBS)):=true
			            knowsNonce(self,messageField($e,self,4,ENCKBS)):=true
			            protocolMessage(2,self,$e):=GENKEYSES
			            messageField(self,$e,1,GENKEYSES):=messageField($e,self,1,ENCKBS)
			            messageField(self,$e,2,GENKEYSES):=KAB
			            messageField(self,$e,3,GENKEYSES):=messageField($e,self,3,ENCKBS)
			            messageField(self,$e,4,GENKEYSES):=messageField($e,self,4,ENCKBS)
			            symEnc(GENKEYSES,1,1,4):=KAS
			            messageField(self,$e,5,GENKEYSES):=messageField($e,self,2,ENCKBS)
			            messageField(self,$e,6,GENKEYSES):=KAB
			            symEnc(GENKEYSES,1,5,6):=KBS
			            internalStateS(self):=END_S
			         endpar
			        endif
			    endpar
			   endif
			endif
		endlet
	rule r_message_FRWVRNB =
		let ($e=agentE) in
			if(internalStateA(self)=WAITING_FRWVRNB and protocolMessage(2,$e,self)=GENKEYSES)then
			   if(receiver!=AG_E)then
 			        if(symDec(GENKEYSES,1,1,4,self)=true ) then
			          par
			            knowsIdentityCertificate(self,messageField($e,self,1,GENKEYSES)):=true
			            knowsSymKey(self,messageField($e,self,2,GENKEYSES)):=true
			            knowsNonce(self,messageField($e,self,3,GENKEYSES)):=true
			            knowsNonce(self,messageField($e,self,4,GENKEYSES)):=true
			            protocolMessage(3,self,$e):=FRWVRNB
			            messageField(self,$e,1,FRWVRNB):=messageField($e,self,5,GENKEYSES)
			            messageField(self,$e,2,FRWVRNB):=messageField($e,self,6,GENKEYSES)
			            symEnc(FRWVRNB,1,1,2):=KBS
			            messageField(self,$e,3,FRWVRNB):=messageField($e,self,4,GENKEYSES)
			            symEnc(FRWVRNB,1,3,3):=messageField($e,self,6,GENKEYSES)
			            internalStateA(self):=END_A
			          endpar
			        endif
			   else
 			        if(symDec(GENKEYSES,1,1,4,self)=true  and receiver=AG_E) then
			          par
			            knowsIdentityCertificate(self,messageField($e,self,1,GENKEYSES)):=true
			            knowsSymKey(self,messageField($e,self,2,GENKEYSES)):=true
			            knowsNonce(self,messageField($e,self,3,GENKEYSES)):=true
			            knowsNonce(self,messageField($e,self,4,GENKEYSES)):=true
			            protocolMessage(3,self,$e):=FRWVRNB
			            messageField(self,$e,1,FRWVRNB):=messageField($e,self,5,GENKEYSES)
			            messageField(self,$e,2,FRWVRNB):=messageField($e,self,6,GENKEYSES)
			            symEnc(FRWVRNB,1,1,2):=KBS
			            messageField(self,$e,3,FRWVRNB):=messageField($e,self,4,GENKEYSES)
			            symEnc(FRWVRNB,1,3,3):=messageField($e,self,6,GENKEYSES)
			            internalStateA(self):=END_A
			         endpar
			        endif
			   endif
			endif
		endlet
	rule r_check_FRWVRNB =
		let ($e=agentE) in
			if(internalStateB(self)=CHECK_END_B and protocolMessage(3,$e,self)=FRWVRNB)then
			  par
			        internalStateB(self):=END_B
			        if(symDec(FRWVRNB,1,1,2,self)=true)then
                      par 
                    	knowsIdentityCertificate(self,messageField($e,self,1,FRWVRNB)):=true
                    	knowsSymKey(self,messageField($e,self,2,FRWVRNB)):=true
                      endpar 
			        endif 
			        if(symDec(FRWVRNB,1,3,3,self)=true)then
                    	knowsNonce(self,messageField($e,self,3,FRWVRNB)):=true
			        endif 
			  endpar
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
	function internalStateA($a in  Alice)=IDLE_REQCOM
	function internalStateB($b in  Bob)=WAITING_ENCKBS
	function internalStateS($s in  Server)=WAITING_GENKEYSES
	function receiver=chosenReceiver
	function knowsNonce($a in Agent, $n in KnowledgeNonce)=if($a=agentA and $n=NA) then true else if($a=agentB and $n=NB) then true else false endif endif
	function knowsIdentityCertificate($a in Agent, $i in KnowledgeIdentityCertificate)=if($a=agentA and $i=CA) then true else if($a=agentB and $i=CA) or ($a=agentB and $i=CB) then true else if($a=agentS and $i=CB) then true else false endif endif endif
	function knowsSymKey($a in Agent ,$sk in KnowledgeSymKey)=if(($a=agentA and $sk=KAS) or ($a=agentB and $sk=KBS) or ($a=agentE and $sk=KES) or ($a=agentS and $sk=KAB) or ($a=agentS and $sk=KBS) or ($a=agentS and $sk=KAS)) then true else false endif
	function mode=chosenMode

	agent Alice:
		r_agentARule[]

	agent Bob:
		r_agentBRule[]

	agent Eve:
		r_agentERule[]

	agent Server:
		r_agentSRule[]
