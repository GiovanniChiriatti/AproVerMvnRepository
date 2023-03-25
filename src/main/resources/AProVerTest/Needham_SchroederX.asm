asm Needham_SchroederX

import StandardLibrary


signature:

	domain Alice subsetof Agent
	domain Bob subsetof Agent
	domain Eve subsetof Agent


	enum domain StateAlice = {IDLE_NAK | WAITING_NK | CHECK_END_A | END_A}
	enum domain StateBob = {WAITING_NNK | CHECK_END_B | END_B}

	enum domain Message = {NAK | NNK | NK} 

	enum domain Knowledge ={ID_A|ID_B|ID_E|NA|NB|NE|PRIVKA|PRIVKB|PRIVKE|PUBKA|PUBKB|PUBKE}

	//DOMAIN OF POSSIBLE RECEIVER
	enum domain Receiver={AG_A|AG_B|AG_E}
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
	static hash: Prod(Message,Level,HashField1,HashField2)-> KnowledgeTag
	static verifyHash: Prod(Message,Level,HashField1,HashField2,KnowledgeTag)-> Boolean

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

	static diffieHellman:Prod(KnowledgeAsymPubKey,KnowledgeAsymPrivKey)->KnowledgeSymKey

	static agentA: Alice
	static agentB: Bob
	static agentE: Eve

definitions:
	domain Level = {1}
	domain FieldPosition = {1:2}
	domain EncField1={1}
	domain EncField2={2}
	domain NumMsg={0:15}

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
	       
	function name($a in Receiver)=
			switch( $a )
				case AG_A:agentA
				case AG_E:agentE
				case AG_B:agentB
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

	       

	/*ATTACKER RULES*/
	rule r_message_replay_NAK =
		//choose what agets are interested by the message
		let ($b=agentB,$a=agentA) in
		  par 
			//check the reception of the message and the modality of the attack
			if(protocolMessage(0,$a,self)=NAK and protocolMessage(0,self,$b)!=NAK and mode=PASSIVE)then
			        //in passsive mode if the attacker knows the decryption key, the message payload is readable and it can be added to the attacker knowledge
			        // the message must be sent unaltered
		          par 
                 	protocolMessage(0,self,$b):=NAK
                 	messageField(self,$b,1,NAK):=messageField($a,self,1,NAK)
                 	messageField(self,$b,2,NAK):=messageField($a,self,2,NAK)
			        if(asymDec(NAK,1,1,2,self)=true)then
                      par 
                    	knowsNonce(self,messageField($a,self,1,NAK)):=true
                    	knowsIdentityCertificate(self,messageField($a,self,2,NAK)):=true
			            asymEnc(NAK,1,1,2):=PUBKB
                      endpar 
			        endif 
		          endpar 
			endif 
			        //check the reception of the message and the modality of the attack
			if(protocolMessage(0,$a,self)=NAK and protocolMessage(0,self,$b)!=NAK and mode=ACTIVE)then
		          par 
                 	protocolMessage(0,self,$b):=NAK
                 	messageField(self,$b,1,NAK):=messageField($a,self,1,NAK)
                 	messageField(self,$b,2,NAK):=messageField($a,self,2,NAK)
			        if(asymDec(NAK,1,1,2,self)=true)then
	   			     par 
                    	knowsNonce(self,messageField($a,self,1,NAK)):=true
                    	knowsIdentityCertificate(self,messageField($a,self,2,NAK)):=true
			        	asymEnc(NAK,1,1,2):=PUBKB
	   			     endpar 
			        endif 
		          endpar 
			endif 
		  endpar 
		endlet 
	rule r_message_replay_NNK =
		//choose what agets are interested by the message
		let ($b=agentA,$a=agentB) in
		  par 
			//check the reception of the message and the modality of the attack
			if(protocolMessage(1,$a,self)=NNK and protocolMessage(1,self,$b)!=NNK and mode=PASSIVE)then
			        //in passsive mode if the attacker knows the decryption key, the message payload is readable and it can be added to the attacker knowledge
			        // the message must be sent unaltered
		          par 
                 	protocolMessage(1,self,$b):=NNK
                 	messageField(self,$b,1,NNK):=messageField($a,self,1,NNK)
                 	messageField(self,$b,2,NNK):=messageField($a,self,2,NNK)
			        if(asymDec(NNK,1,1,2,self)=true)then
                      par 
                    	knowsNonce(self,messageField($a,self,1,NNK)):=true
                    	knowsNonce(self,messageField($a,self,2,NNK)):=true
			            asymEnc(NNK,1,1,2):=PUBKA
                      endpar 
			        endif 
		          endpar 
			endif 
			        //check the reception of the message and the modality of the attack
			if(protocolMessage(1,$a,self)=NNK and protocolMessage(1,self,$b)!=NNK and mode=ACTIVE)then
		          par 
                 	protocolMessage(1,self,$b):=NNK
                 	messageField(self,$b,1,NNK):=messageField($a,self,1,NNK)
                 	messageField(self,$b,2,NNK):=messageField($a,self,2,NNK)
			        if(asymDec(NNK,1,1,2,self)=true)then
	   			     par 
                    	knowsNonce(self,messageField($a,self,1,NNK)):=true
                    	knowsNonce(self,messageField($a,self,2,NNK)):=true
			        	asymEnc(NNK,1,1,2):=PUBKA
	   			     endpar 
			        endif 
		          endpar 
			endif 
		  endpar 
		endlet 
	rule r_message_replay_NK =
		//choose what agets are interested by the message
		let ($b=agentB,$a=agentA) in
		  par 
			//check the reception of the message and the modality of the attack
			if(protocolMessage(2,$a,self)=NK and protocolMessage(2,self,$b)!=NK and mode=PASSIVE)then
			        //in passsive mode if the attacker knows the decryption key, the message payload is readable and it can be added to the attacker knowledge
			        // the message must be sent unaltered
		          par 
                 	protocolMessage(2,self,$b):=NK
                 	messageField(self,$b,1,NK):=messageField($a,self,1,NK)
			        if(asymDec(NK,1,1,1,self)=true)then
                      par 
                    	knowsNonce(self,messageField($a,self,1,NK)):=true
			            asymEnc(NK,1,1,1):=PUBKB
                      endpar 
			        endif 
		          endpar 
			endif 
			        //check the reception of the message and the modality of the attack
			if(protocolMessage(2,$a,self)=NK and protocolMessage(2,self,$b)!=NK and mode=ACTIVE)then
		          par 
                 	protocolMessage(2,self,$b):=NK
                 	messageField(self,$b,1,NK):=messageField($a,self,1,NK)
			        if(asymDec(NK,1,1,1,self)=true)then
	   			     par 
                    	knowsNonce(self,messageField($a,self,1,NK)):=true
			        	asymEnc(NK,1,1,1):=PUBKB
	   			     endpar 
			        endif 
		          endpar 
			endif 
		  endpar 
		endlet 

	/*HONEST AGENT RULES*/	
	rule r_message_NAK =
		let ($e=agentE) in
			if(internalStateA(self)=IDLE_NAK)then 
			   if(receiver!=AG_E)then
			     par
			         protocolMessage(0,self,$e):=NAK
			         messageField(self,$e,1,NAK):=NA
			         messageField(self,$e,2,NAK):=ID_A
			         asymEnc(NAK,1,1,2):=PUBKB
			         internalStateA(self):=WAITING_NK
			     endpar
			   else
			       if(receiver=AG_E)then
			         par
			            protocolMessage(0,self,$e):=NAK
			            messageField(self,$e,1,NAK):=NA
			            messageField(self,$e,2,NAK):=ID_A
			            asymEnc(NAK,1,1,2):=PUBKE
			            internalStateA(self):=WAITING_NK
			         endpar
			       endif
			   endif
			endif
		endlet
	rule r_message_NNK =
		let ($e=agentE) in
			if(internalStateB(self)=WAITING_NNK and protocolMessage(0,$e,self)=NAK)then
			   if(receiver!=AG_E)then
 			        if(asymDec(NAK,1,1,2,self)=true ) then
			          par
			            knowsNonce(self,messageField($e,self,1,NAK)):=true
			            knowsIdentityCertificate(self,messageField($e,self,2,NAK)):=true
			            protocolMessage(1,self,$e):=NNK
			            messageField(self,$e,1,NNK):=NA
			            messageField(self,$e,2,NNK):=NB
			            asymEnc(NNK,1,1,2):=PUBKA
			            internalStateB(self):=CHECK_END_B
			          endpar
			        endif
			   else
 			        if(asymDec(NAK,1,1,2,self)=true  and receiver=AG_E) then
			          par
			            knowsNonce(self,messageField($e,self,1,NAK)):=true
			            knowsIdentityCertificate(self,messageField($e,self,2,NAK)):=true
			            protocolMessage(1,self,$e):=NNK
			            messageField(self,$e,1,NNK):=messageField($e,self,1,NAK)
			            messageField(self,$e,2,NNK):=NB
			            asymEnc(NNK,1,1,2):=PUBKA
			            internalStateB(self):=CHECK_END_B
			         endpar
			        endif
			   endif
			endif
		endlet
	rule r_message_NK =
		let ($e=agentE) in
			if(internalStateA(self)=WAITING_NK and protocolMessage(1,$e,self)=NNK)then
			   if(receiver!=AG_E)then
 			        if(asymDec(NNK,1,1,2,self)=true ) then
			          par
			            knowsNonce(self,messageField($e,self,1,NNK)):=true
			            knowsNonce(self,messageField($e,self,2,NNK)):=true
			            protocolMessage(2,self,$e):=NK
			            messageField(self,$e,1,NK):=NB
			            asymEnc(NK,1,1,1):=PUBKB
			            internalStateA(self):=END_A
			          endpar
			        endif
			   else
 			        if(asymDec(NNK,1,1,2,self)=true  and receiver=AG_E) then
			          par
			            knowsNonce(self,messageField($e,self,1,NNK)):=true
			            knowsNonce(self,messageField($e,self,2,NNK)):=true
			            protocolMessage(2,self,$e):=NK
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
			if(internalStateB(self)=CHECK_END_B and protocolMessage(2,$e,self)=NK)then
			        if(asymDec(NK,1,1,1,self)= true) then
			          par
			            knowsNonce(self,messageField($e,self,1,NK)):=true
			            internalStateB(self):=END_B
			          endpar
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
	function internalStateA($a in  Alice)=IDLE_NAK
	function internalStateB($b in  Bob)=WAITING_NNK
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
