asm TestNeedham_SchroederNSSYM

import StandardLibrary


signature:

	domain Alice subsetof Agent
	domain Bob subsetof Agent
	domain Eve subsetof Agent
	domain Server subsetof Agent


	enum domain StateAlice = {IDLE_MA | WAITING_MC | CHECK_END_A | END_A}
	enum domain StateBob = {WAITING_MD | CHECK_END_B | END_B}
	enum domain StateServer = {WAITING_MB | CHECK_END_S | END_S}

	enum domain Message = {MA | MB | MC | MD} 

	enum domain Knowledge ={CA|CB|CE|KAB|KAS|KBS|KEA|KEB|KES|NA|NB}

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
	controlled chosenMode: Modality
	//controlled for saving the attacker modality choice
	controlled mode: Modality

	// FUNCTIONS SELECT THE RECEIVER
	static name:Receiver -> Agent
	//Receiver chosen
	controlled receiver:Receiver
	//Receiver chosen by user
	controlled chosenReceiver:Receiver

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
	domain Level = {1:2}
	domain FieldPosition = {1:5}
	domain EncField1={1:5}
	domain EncField2={2:5}
	domain NumMsg={0:15}

	domain KnowledgeNonce = {NA,NB}
	domain KnowledgeIdentityCertificate = {CA,CB,CE}
	domain KnowledgeSymKey = {KAB,KAS,KBS,KEA,KEB,KES}

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
	rule r_message_replay_MA =
		//choose what agets are interested by the message
		let ($b=agentS,$a=agentA) in
		  par 
			//check the reception of the message and the modality of the attack
			if(protocolMessage(0,$a,self)=MA and protocolMessage(0,self,$b)!=MA and mode=PASSIVE)then
			        //in passsive mode if the attacker knows the decryption key, the message payload is readable and it can be added to the attacker knowledge
			        // the message must be sent unaltered
		          par 
                 	protocolMessage(0,self,$b):=MA
                 	messageField(self,$b,1,MA):=messageField($a,self,1,MA)
                 	messageField(self,$b,2,MA):=messageField($a,self,2,MA)
                 	messageField(self,$b,3,MA):=messageField($a,self,3,MA)
                 	knowsIdentityCertificate(self,messageField($a,self,1,MA)):=true
                 	knowsIdentityCertificate(self,messageField($a,self,2,MA)):=true
                 	knowsNonce(self,messageField($a,self,3,MA)):=true
		          endpar 
			endif 
			        //check the reception of the message and the modality of the attack
			if(protocolMessage(0,$a,self)=MA and protocolMessage(0,self,$b)!=MA and mode=ACTIVE)then
		          par 
                 	protocolMessage(0,self,$b):=MA
                 	messageField(self,$b,1,MA):=messageField($a,self,1,MA)
                 	messageField(self,$b,2,MA):=messageField($a,self,2,MA)
                 	messageField(self,$b,3,MA):=messageField($a,self,3,MA)
                 	knowsIdentityCertificate(self,messageField($a,self,1,MA)):=true
                 	knowsIdentityCertificate(self,messageField($a,self,2,MA)):=true
                 	knowsNonce(self,messageField($a,self,3,MA)):=true
		          endpar 
			endif 
		  endpar 
		endlet 
	rule r_message_replay_MB =
		//choose what agets are interested by the message
		let ($b=agentA,$a=agentS) in
		  par 
			//check the reception of the message and the modality of the attack
			if(protocolMessage(1,$a,self)=MB and protocolMessage(1,self,$b)!=MB and mode=PASSIVE)then
			        //in passsive mode if the attacker knows the decryption key, the message payload is readable and it can be added to the attacker knowledge
			        // the message must be sent unaltered
		          par 
                 	protocolMessage(1,self,$b):=MB
                 	messageField(self,$b,1,MB):=messageField($a,self,1,MB)
                 	messageField(self,$b,2,MB):=messageField($a,self,2,MB)
                 	messageField(self,$b,3,MB):=messageField($a,self,3,MB)
                 	messageField(self,$b,4,MB):=messageField($a,self,4,MB)
                 	messageField(self,$b,5,MB):=messageField($a,self,5,MB)
			        if(symDec(MB,2,1,5,self)=true)then
                      par 
			        	knowsNonce(self,messageField($a,self,1,MB)):=true
			        	knowsSymKey(self,messageField($a,self,2,MB)):=true
			        	knowsIdentityCertificate(self,messageField($a,self,3,MB)):=true
			            if(symDec(MB,1,4,5,self)=true)then
	   			 	       par 
	   			 	          	knowsSymKey(self,messageField($a,self,4,MB)):=true
	   			 	          	knowsIdentityCertificate(self,messageField($a,self,5,MB)):=true
	   			 	       endpar 
			            endif 
			            symEnc(MB,2,1,5):=KAS
                      endpar 
			        endif 
		          endpar 
			endif 
			        //check the reception of the message and the modality of the attack
			if(protocolMessage(1,$a,self)=MB and protocolMessage(1,self,$b)!=MB and mode=ACTIVE)then
		          par 
                 	protocolMessage(1,self,$b):=MB
                 	messageField(self,$b,1,MB):=messageField($a,self,1,MB)
                 	messageField(self,$b,3,MB):=messageField($a,self,3,MB)
                 	messageField(self,$b,5,MB):=messageField($a,self,5,MB)
			        if(symDec(MB,2,1,5,self)=true)then
	   			     par 
			         	messageField(self,$b,2,MB):=KEA
			         	messageField(self,$b,4,MB):=KEA
			        	knowsNonce(self,messageField($a,self,1,MB)):=true
			        	knowsSymKey(self,messageField($a,self,2,MB)):=true
			        	knowsIdentityCertificate(self,messageField($a,self,3,MB)):=true
			            if(symDec(MB,1,4,5,self)=true)then
	   			 	       par 
	   			 	          	knowsSymKey(self,messageField($a,self,4,MB)):=true
	   			 	          	knowsIdentityCertificate(self,messageField($a,self,5,MB)):=true
	   			 	       endpar 
			            endif 
			        	symEnc(MB,2,1,5):=KAS
	   			     endpar 
			        else 
	   			     par 
			         	messageField(self,$b,2,MB):=messageField($a,self,2,MB)
			         	messageField(self,$b,4,MB):=messageField($a,self,4,MB)
	   			     endpar 
			        endif 
		          endpar 
			endif 
		  endpar 
		endlet 
	rule r_message_replay_MC =
		//choose what agets are interested by the message
		let ($b=agentB,$a=agentA) in
		  par 
			//check the reception of the message and the modality of the attack
			if(protocolMessage(2,$a,self)=MC and protocolMessage(2,self,$b)!=MC and mode=PASSIVE)then
			        //in passsive mode if the attacker knows the decryption key, the message payload is readable and it can be added to the attacker knowledge
			        // the message must be sent unaltered
		          par 
                 	protocolMessage(2,self,$b):=MC
                 	messageField(self,$b,1,MC):=messageField($a,self,1,MC)
                 	messageField(self,$b,2,MC):=messageField($a,self,2,MC)
			        if(symDec(MC,1,1,2,self)=true)then
                      par 
                    	knowsSymKey(self,messageField($a,self,1,MC)):=true
                    	knowsIdentityCertificate(self,messageField($a,self,2,MC)):=true
			            symEnc(MC,1,1,2):=KEB
                      endpar 
			        endif 
		          endpar 
			endif 
			        //check the reception of the message and the modality of the attack
			if(protocolMessage(2,$a,self)=MC and protocolMessage(2,self,$b)!=MC and mode=ACTIVE)then
		          par 
                 	protocolMessage(2,self,$b):=MC
                 	messageField(self,$b,2,MC):=messageField($a,self,2,MC)
			        if(symDec(MC,1,1,2,self)=true)then
	   			     par 
			         	messageField(self,$b,1,MC):=KEB
                    	knowsSymKey(self,messageField($a,self,1,MC)):=true
                    	knowsIdentityCertificate(self,messageField($a,self,2,MC)):=true
			        	symEnc(MC,1,1,2):=KBS
	   			     endpar 
			        else 
			         	messageField(self,$b,1,MC):=messageField($a,self,1,MC)
			        endif 
		          endpar 
			endif 
		  endpar 
		endlet 
	rule r_message_replay_MD =
		//choose what agets are interested by the message
		let ($b=agentA,$a=agentB) in
		  par 
			//check the reception of the message and the modality of the attack
			if(protocolMessage(3,$a,self)=MD and protocolMessage(3,self,$b)!=MD and mode=PASSIVE)then
			        //in passsive mode if the attacker knows the decryption key, the message payload is readable and it can be added to the attacker knowledge
			        // the message must be sent unaltered
		          par 
                 	protocolMessage(3,self,$b):=MD
                 	messageField(self,$b,1,MD):=messageField($a,self,1,MD)
			        if(symDec(MD,1,1,1,self)=true)then
                      par 
                    	knowsNonce(self,messageField($a,self,1,MD)):=true
			            symEnc(MD,1,1,1):=messageField($b,self,1,MC)
                      endpar 
			        endif 
		          endpar 
			endif 
			        //check the reception of the message and the modality of the attack
			if(protocolMessage(3,$a,self)=MD and protocolMessage(3,self,$b)!=MD and mode=ACTIVE)then
		          par 
                 	protocolMessage(3,self,$b):=MD
                 	messageField(self,$b,1,MD):=messageField($a,self,1,MD)
			        if(symDec(MD,1,1,1,self)=true)then
	   			     par 
                    	knowsNonce(self,messageField($a,self,1,MD)):=true
			        	symEnc(MD,1,1,1):=messageField($b,self,1,MC)
	   			     endpar 
			        endif 
		          endpar 
			endif 
		  endpar 
		endlet 

	/*HONEST AGENT RULES*/	
	rule r_message_MA =
		let ($e=agentE) in
			if(internalStateA(self)=IDLE_MA)then 
			   if(receiver!=AG_E)then
			     par
			         protocolMessage(0,self,$e):=MA
			         messageField(self,$e,1,MA):=CA
			         messageField(self,$e,2,MA):=CB
			         messageField(self,$e,3,MA):=NA
			         internalStateA(self):=WAITING_MC
			     endpar
			   else
			       if(receiver=AG_E)then
			         par
			            protocolMessage(0,self,$e):=MA
			            messageField(self,$e,1,MA):=CA
			            messageField(self,$e,2,MA):=CB
			            messageField(self,$e,3,MA):=NA
			            internalStateA(self):=WAITING_MC
			         endpar
			       endif
			   endif
			endif
		endlet
	rule r_message_MB =
		let ($e=agentE) in
			if(internalStateS(self)=WAITING_MB and protocolMessage(0,$e,self)=MA)then
			   if(receiver!=AG_E)then
			          par
			            knowsIdentityCertificate(self,messageField($e,self,1,MA)):=true
			            knowsIdentityCertificate(self,messageField($e,self,2,MA)):=true
			            knowsNonce(self,messageField($e,self,3,MA)):=true
			            protocolMessage(1,self,$e):=MB
			            messageField(self,$e,1,MB):=messageField($e,self,3,MA)
			            messageField(self,$e,2,MB):=KAB
			            messageField(self,$e,3,MB):=messageField($e,self,2,MA)
			            messageField(self,$e,4,MB):=KAB
			            messageField(self,$e,5,MB):=messageField($e,self,1,MA)
			            symEnc(MB,1,4,5):=KBS
			            symEnc(MB,2,1,5):=KAS
			            internalStateS(self):=END_S
			          endpar
			   else
			          par
			            knowsIdentityCertificate(self,messageField($e,self,1,MA)):=true
			            knowsIdentityCertificate(self,messageField($e,self,2,MA)):=true
			            knowsNonce(self,messageField($e,self,3,MA)):=true
			            protocolMessage(1,self,$e):=MB
			            messageField(self,$e,1,MB):=messageField($e,self,3,MA)
			            messageField(self,$e,2,MB):=KAB
			            messageField(self,$e,3,MB):=messageField($e,self,2,MA)
			            messageField(self,$e,4,MB):=KAB
			            messageField(self,$e,5,MB):=messageField($e,self,1,MA)
			            symEnc(MB,1,4,5):=KBS
			            symEnc(MB,2,1,5):=KAS
			            internalStateS(self):=END_S
			         endpar
			   endif
			endif
		endlet
	rule r_message_MC =
		let ($e=agentE) in
			if(internalStateA(self)=WAITING_MC and protocolMessage(1,$e,self)=MB)then
			   if(receiver!=AG_E)then
 			        if(symDec(MB,2,1,5,self)=true ) then
			          par
			            knowsNonce(self,messageField($e,self,1,MB)):=true
			            knowsSymKey(self,messageField($e,self,2,MB)):=true
			            knowsIdentityCertificate(self,messageField($e,self,3,MB)):=true
			            if(symDec(MB,1,4,5,self)=true)then
	   			 	       par 
	   			 	          knowsSymKey(self,messageField($e,self,4,MB)):=true
	   			 	          knowsIdentityCertificate(self,messageField($e,self,5,MB)):=true
	   			 	       endpar 
			            endif 
			            protocolMessage(2,self,$e):=MC
			            messageField(self,$e,1,MC):=messageField($e,self,4,MB)
			            messageField(self,$e,2,MC):=messageField($e,self,5,MB)
			            symEnc(MC,1,1,2):=KBS
			            internalStateA(self):=CHECK_END_A
			          endpar
			        endif
			   else
 			        if(symDec(MB,2,1,5,self)=true  and receiver=AG_E) then
			          par
			            knowsNonce(self,messageField($e,self,1,MB)):=true
			            knowsSymKey(self,messageField($e,self,2,MB)):=true
			            knowsIdentityCertificate(self,messageField($e,self,3,MB)):=true
			            if(symDec(MB,1,4,5,self)=true)then
	   			 	       par 
	   			 	          knowsSymKey(self,messageField($e,self,4,MB)):=true
	   			 	          knowsIdentityCertificate(self,messageField($e,self,5,MB)):=true
	   			 	       endpar 
			            endif 
			            protocolMessage(2,self,$e):=MC
			            messageField(self,$e,1,MC):=messageField($e,self,4,MB)
			            messageField(self,$e,2,MC):=messageField($e,self,5,MB)
			            symEnc(MC,1,1,2):=KBS
			            internalStateA(self):=CHECK_END_A
			         endpar
			        endif
			   endif
			endif
		endlet
	rule r_message_MD =
		let ($e=agentE) in
			if(internalStateB(self)=WAITING_MD and protocolMessage(2,$e,self)=MC)then
			   if(receiver!=AG_E)then
 			        if(symDec(MC,1,1,2,self)=true ) then
			          par
			            knowsSymKey(self,messageField($e,self,1,MC)):=true
			            knowsIdentityCertificate(self,messageField($e,self,2,MC)):=true
			            protocolMessage(3,self,$e):=MD
			            messageField(self,$e,1,MD):=NB
			            symEnc(MD,1,1,1):=messageField($e,self,1,MC)
			            internalStateB(self):=END_B
			          endpar
			        endif
			   else
 			        if(symDec(MC,1,1,2,self)=true  and receiver=AG_E) then
			          par
			            knowsSymKey(self,messageField($e,self,1,MC)):=true
			            knowsIdentityCertificate(self,messageField($e,self,2,MC)):=true
			            protocolMessage(3,self,$e):=MD
			            messageField(self,$e,1,MD):=NB
			            symEnc(MD,1,1,1):=messageField($e,self,1,MC)
			            internalStateB(self):=END_B
			         endpar
			        endif
			   endif
			endif
		endlet
	rule r_check_MD =
		let ($e=agentE) in
			if(internalStateA(self)=CHECK_END_A and protocolMessage(3,$e,self)=MD)then
			  par
			        internalStateA(self):=END_A
			        if(symDec(MD,1,1,1,self)=true)then
                    	knowsNonce(self,messageField($e,self,1,MD)):=true
			        endif 
			  endpar
			endif
		endlet

	rule r_agentERule  =
	  par
            r_message_replay_MA[]
            r_message_replay_MB[]
            r_message_replay_MC[]
            r_message_replay_MD[]
	  endpar

	rule r_agentARule  =
	  par
            r_message_MA[]
            r_message_MC[]
            r_check_MD[]
	  endpar

	rule r_agentBRule  =
            r_message_MD[]

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
	function internalStateA($a in  Alice)=IDLE_MA
	function internalStateB($b in  Bob)=WAITING_MD
	function internalStateS($s in  Server)=WAITING_MB
	function receiver=chosenReceiver
	function knowsNonce($a in Agent, $n in KnowledgeNonce)=if($a=agentA and $n=NA) then true else if($a=agentB and $n=NB) then true else false endif endif
	function knowsIdentityCertificate($a in Agent, $i in KnowledgeIdentityCertificate)=if($a=agentA and $i=CA) or ($a=agentA and $i=CB) or ($a=agentA and $i=CE) then true else if($a=agentB and $i=CA) or ($a=agentB and $i=CB) or ($a=agentB and $i=CE) then true else if($a=agentE and $i=CE) then true else false endif endif endif
	function knowsSymKey($a in Agent ,$sk in KnowledgeSymKey)=if(($a=agentA and $sk=KAS) or ($a=agentB and $sk=KBS) or ($a=agentB and $sk=KEB) or ($a=agentE and $sk=KEA) or ($a=agentE and $sk=KEB) or ($a=agentE and $sk=KES) or ($a=agentS and $sk=KAS) or ($a=agentS and $sk=KBS) or ($a=agentS and $sk=KAB)) then true else false endif
	function mode=chosenMode

	agent Alice:
		r_agentARule[]

	agent Bob:
		r_agentBRule[]

	agent Eve:
		r_agentERule[]

	agent Server:
		r_agentSRule[]
