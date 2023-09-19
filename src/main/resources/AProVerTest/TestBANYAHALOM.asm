asm TestBANYAHALOM

import StandardLibrary


signature:
	domain Alice subsetof Agent
	domain Bob subsetof Agent
	domain Eve subsetof Agent
	domain Server subsetof Agent


	enum domain StateAlice = {IDLE_MA | CHECK_END_A | END_A}
	enum domain StateBob = {WAITING_MB | WAITING_MD | CHECK_END_B | END_B}
	enum domain StateEve = {WAITING_MC | WAITING_MF | CHECK_END_E | END_E}
	enum domain StateServer = {WAITING_ME | CHECK_END_S | END_S}

	enum domain Message = {MA | MB | MC | MD | ME | MF} 

	enum domain Knowledge ={CA|CB|KAB|KAS|KBS|KNA|NA|NB|NB2}

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
	controlled internalStateE: Eve -> StateEve
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
	domain FieldPosition = {1:7}
	domain EncField1={1:7}
	domain EncField2={1:7}
	domain NumMsg={0:15}

	domain KnowledgeNonce = {NA,NB,NB2}
	domain KnowledgeIdentityCertificate = {CA,CB}
	domain KnowledgeSymKey = {KAB,KAS,KBS,KNA}

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
		let ($b=agentB,$a=agentA) in
		  par 
			//check the reception of the message and the modality of the attack
			if(protocolMessage(0,$a,self)=MA and protocolMessage(0,self,$b)!=MA and mode=PASSIVE)then
			        //in passsive mode if the attacker knows the decryption key, the message payload is readable and it can be added to the attacker knowledge
			        // the message must be sent unaltered
		          par 
                 	protocolMessage(0,self,$b):=MA
                 	messageField(self,$b,1,MA):=messageField($a,self,1,MA)
                 	messageField(self,$b,2,MA):=messageField($a,self,2,MA)
                 	knowsIdentityCertificate(self,messageField($a,self,1,MA)):=true
                 	knowsNonce(self,messageField($a,self,2,MA)):=true
		          endpar 
			endif 
			        //check the reception of the message and the modality of the attack
			if(protocolMessage(0,$a,self)=MA and protocolMessage(0,self,$b)!=MA and mode=ACTIVE)then
		          par 
                 	protocolMessage(0,self,$b):=MA
                 	messageField(self,$b,1,MA):=messageField($a,self,1,MA)
                 	messageField(self,$b,2,MA):=messageField($a,self,2,MA)
                 	knowsIdentityCertificate(self,messageField($a,self,1,MA)):=true
                 	knowsNonce(self,messageField($a,self,2,MA)):=true
		          endpar 
			endif 
		  endpar 
		endlet 
	rule r_message_replay_MB =
		//choose what agets are interested by the message
		let ($b=agentS,$a=agentB) in
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
                 	knowsIdentityCertificate(self,messageField($a,self,1,MB)):=true
                 	knowsNonce(self,messageField($a,self,2,MB)):=true
			        if(symDec(MB,1,3,4,self)=true)then
                      par 
                    	knowsIdentityCertificate(self,messageField($a,self,3,MB)):=true
                    	knowsNonce(self,messageField($a,self,4,MB)):=true
			            symEnc(MB,1,3,4):=KBS
                      endpar 
			        endif 
		          endpar 
			endif 
			        //check the reception of the message and the modality of the attack
			if(protocolMessage(1,$a,self)=MB and protocolMessage(1,self,$b)!=MB and mode=ACTIVE)then
		          par 
                 	protocolMessage(1,self,$b):=MB
                 	messageField(self,$b,1,MB):=messageField($a,self,1,MB)
                 	messageField(self,$b,2,MB):=messageField($a,self,2,MB)
                 	messageField(self,$b,3,MB):=messageField($a,self,3,MB)
                 	messageField(self,$b,4,MB):=messageField($a,self,4,MB)
                 	knowsIdentityCertificate(self,messageField($a,self,1,MB)):=true
                 	knowsNonce(self,messageField($a,self,2,MB)):=true
			        if(symDec(MB,1,3,4,self)=true)then
	   			     par 
                    	knowsIdentityCertificate(self,messageField($a,self,3,MB)):=true
                    	knowsNonce(self,messageField($a,self,4,MB)):=true
			        	symEnc(MB,1,3,4):=KBS
	   			     endpar 
			        endif 
		          endpar 
			endif 
		  endpar 
		endlet 
	rule r_message_replay_ME =
		//choose what agets are interested by the message
		let ($b=agentA,$a=agentS) in
		  par 
			//check the reception of the message and the modality of the attack
			if(protocolMessage(4,$a,self)=ME and protocolMessage(4,self,$b)!=ME and mode=PASSIVE)then
			        //in passsive mode if the attacker knows the decryption key, the message payload is readable and it can be added to the attacker knowledge
			        // the message must be sent unaltered
			          par
			            knowsIdentityCertificate(self,messageField(agentB,self,1,MD)):=true
			            knowsNonce(self,messageField(agentB,self,2,MD)):=true
                 	protocolMessage(4,self,$b):=ME
                 	messageField(self,$b,1,ME):=messageField($a,self,1,ME)
                 	messageField(self,$b,2,ME):=messageField($a,self,2,ME)
                 	messageField(self,$b,3,ME):=messageField($a,self,3,ME)
                 	messageField(self,$b,4,ME):=messageField($a,self,4,ME)
                 	messageField(self,$b,5,ME):=messageField($a,self,5,ME)
                 	messageField(self,$b,6,ME):=messageField($a,self,6,ME)
                 	messageField(self,$b,7,ME):=messageField($a,self,7,ME)
                 	knowsNonce(self,messageField($a,self,1,ME)):=true
			        if(symDec(ME,1,2,4,self)=true)then
                      par 
                    	knowsIdentityCertificate(self,messageField($a,self,2,ME)):=true
                    	knowsSymKey(self,messageField($a,self,3,ME)):=true
                    	knowsNonce(self,messageField($a,self,4,ME)):=true
			            symEnc(ME,1,2,4):=KAS
                      endpar 
			        endif 
			        if(symDec(ME,1,5,7,self)=true)then
                      par 
                    	knowsIdentityCertificate(self,messageField($a,self,5,ME)):=true
                    	knowsSymKey(self,messageField($a,self,6,ME)):=true
                    	knowsNonce(self,messageField($a,self,7,ME)):=true
			            symEnc(ME,1,5,7):=KBS
                      endpar 
			        endif 
		          endpar 
			endif 
			        //check the reception of the message and the modality of the attack
			if(protocolMessage(4,$a,self)=ME and protocolMessage(4,self,$b)!=ME and mode=ACTIVE)then
			          par
			            knowsIdentityCertificate(self,messageField(agentB,self,1,MD)):=true
			            knowsNonce(self,messageField(agentB,self,2,MD)):=true
                 	protocolMessage(4,self,$b):=ME
                 	messageField(self,$b,1,ME):=messageField($a,self,1,ME)
                 	messageField(self,$b,2,ME):=messageField($a,self,2,ME)
                 	messageField(self,$b,4,ME):=messageField($a,self,4,ME)
                 	messageField(self,$b,5,ME):=messageField($a,self,5,ME)
                 	messageField(self,$b,7,ME):=messageField($a,self,7,ME)
                 	knowsNonce(self,messageField($a,self,1,ME)):=true
			        if(symDec(ME,1,2,4,self)=true)then
	   			     par 
			         	messageField(self,$b,3,ME):=KNA
                    	knowsIdentityCertificate(self,messageField($a,self,2,ME)):=true
                    	knowsSymKey(self,messageField($a,self,3,ME)):=true
                    	knowsNonce(self,messageField($a,self,4,ME)):=true
			        	symEnc(ME,1,2,4):=KAS
	   			     endpar 
			        else 
			         	messageField(self,$b,3,ME):=messageField($a,self,3,ME)
			        endif 
			        if(symDec(ME,1,5,7,self)=true)then
	   			     par 
			         	messageField(self,$b,6,ME):=KNA
                    	knowsIdentityCertificate(self,messageField($a,self,5,ME)):=true
                    	knowsSymKey(self,messageField($a,self,6,ME)):=true
                    	knowsNonce(self,messageField($a,self,7,ME)):=true
			        	symEnc(ME,1,5,7):=KBS
	   			     endpar 
			        else 
			         	messageField(self,$b,6,ME):=messageField($a,self,6,ME)
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
			         messageField(self,$e,2,MA):=NA
			         internalStateA(self):=CHECK_END_A
			     endpar
			   else
			       if(receiver=AG_E)then
			         par
			            protocolMessage(0,self,$e):=MA
			            messageField(self,$e,1,MA):=CA
			            messageField(self,$e,2,MA):=NA
			            internalStateA(self):=CHECK_END_A
			         endpar
			       endif
			   endif
			endif
		endlet
	rule r_message_MB =
		let ($e=agentE) in
			if(internalStateB(self)=WAITING_MB and protocolMessage(0,$e,self)=MA)then
			   if(receiver!=AG_E)then
			          par
			            knowsIdentityCertificate(self,messageField($e,self,1,MA)):=true
			            knowsNonce(self,messageField($e,self,2,MA)):=true
			            protocolMessage(1,self,$e):=MB
			            messageField(self,$e,1,MB):=CB
			            messageField(self,$e,2,MB):=NB
			            messageField(self,$e,3,MB):=messageField($e,self,1,MA)
			            messageField(self,$e,4,MB):=messageField($e,self,2,MA)
			            symEnc(MB,1,3,4):=KBS
			            internalStateB(self):=WAITING_MD
			          endpar
			   else
			          par
			            knowsIdentityCertificate(self,messageField($e,self,1,MA)):=true
			            knowsNonce(self,messageField($e,self,2,MA)):=true
			            protocolMessage(1,self,$e):=MB
			            messageField(self,$e,1,MB):=CB
			            messageField(self,$e,2,MB):=NB
			            messageField(self,$e,3,MB):=messageField($e,self,1,MA)
			            messageField(self,$e,4,MB):=messageField($e,self,2,MA)
			            symEnc(MB,1,3,4):=KBS
			            internalStateB(self):=WAITING_MD
			         endpar
			   endif
			endif
		endlet
	rule r_message_MC =
		let ($b=agentB,$t=agentS) in
			if(internalStateE(self)=WAITING_MC and protocolMessage(1,self,$t)=MB)then
			     par
			            protocolMessage(2,self,$b):=MC
			            messageField(self,$b,1,MC):=messageField(agentA,self,1,MA)
			            messageField(self,$b,2,MC):=KNA
			            messageField(self,$b,3,MC):=messageField($b,self,2,MB)
			            internalStateE(self):=WAITING_MF
			          endpar
			   endif
		endlet
	rule r_message_MD =
		let ($e=agentE) in
			if(internalStateB(self)=WAITING_MD and protocolMessage(2,$e,self)=MC)then
			          par
			            knowsSymKey(self,messageField($e,self,2,MC)):=true
			            knowsNonce(self,messageField($e,self,3,MC)):=true
			            protocolMessage(3,self,$e):=MD
			            messageField(self,$e,1,MD):=CB
			            messageField(self,$e,2,MD):=NB2
			            messageField(self,$e,3,MD):=messageField($e,self,1,MC)
			            messageField(self,$e,4,MD):=messageField($e,self,2,MC)
			            messageField(self,$e,5,MD):=messageField($e,self,3,MC)
			            symEnc(MD,1,3,5):=KBS
			            internalStateB(self):=CHECK_END_B
			          endpar
			   endif
		endlet
	rule r_message_ME =
		let ($e=agentE,$f=agentB) in
			if(internalStateS(self)=WAITING_ME and protocolMessage(3,$f,$e)=MD)then
			   if(receiver!=AG_E)then
			    par
			            knowsIdentityCertificate(self,messageField($e,self,1,MB)):=true
			            knowsNonce(self,messageField($e,self,2,MB)):=true
 			        if(symDec(MB,1,3,4,self)=true ) then
			          par
			            knowsIdentityCertificate(self,messageField($e,self,3,MB)):=true
			            knowsNonce(self,messageField($e,self,4,MB)):=true
			            protocolMessage(4,self,$e):=ME
			            messageField(self,$e,1,ME):=messageField($e,self,2,MB)
			            messageField(self,$e,2,ME):=messageField($e,self,1,MB)
			            messageField(self,$e,3,ME):=KAB
			            messageField(self,$e,4,ME):=messageField($e,self,4,MB)
			            symEnc(ME,1,2,4):=KAS
			            messageField(self,$e,5,ME):=messageField($e,self,3,MB)
			            messageField(self,$e,6,ME):=KAB
			            messageField(self,$e,7,ME):=messageField($e,self,2,MB)
			            symEnc(ME,1,5,7):=KBS
			            internalStateS(self):=END_S
			          endpar
			        endif
			    endpar
			   else
			    par
			            knowsIdentityCertificate(self,messageField($e,self,1,MB)):=true
			            knowsNonce(self,messageField($e,self,2,MB)):=true
 			        if(symDec(MB,1,3,4,self)=true  and receiver=AG_E) then
			          par
			            knowsIdentityCertificate(self,messageField($e,self,3,MB)):=true
			            knowsNonce(self,messageField($e,self,4,MB)):=true
			            protocolMessage(4,self,$e):=ME
			            messageField(self,$e,1,ME):=messageField($e,self,2,MB)
			            messageField(self,$e,2,ME):=messageField($e,self,1,MB)
			            messageField(self,$e,3,ME):=KAB
			            messageField(self,$e,4,ME):=messageField($e,self,4,MB)
			            symEnc(ME,1,2,4):=KAS
			            messageField(self,$e,5,ME):=messageField($e,self,3,MB)
			            messageField(self,$e,6,ME):=KAB
			            messageField(self,$e,7,ME):=messageField($e,self,2,MB)
			            symEnc(ME,1,5,7):=KBS
			            internalStateS(self):=END_S
			         endpar
			        endif
			    endpar
			   endif
			endif
		endlet
	rule r_message_MF =
		let ($b=agentB,$t=agentA) in
			if(internalStateE(self)=WAITING_MF and protocolMessage(4,self,$t)=ME)then
			     par
			            protocolMessage(5,self,$b):=MF
			            messageField(self,$b,1,MF):=messageField($b,self,3,MD)
			            messageField(self,$b,2,MF):=messageField($b,self,4,MD)
			            messageField(self,$b,3,MF):=messageField($b,self,5,MD)
			            symEnc(MF,1,1,3):=KBS
			            messageField(self,$b,4,MF):=messageField($b,self,5,MD)
			            symEnc(MF,1,4,4):=messageField(self,$b,2,MC)
			            internalStateE(self):=END_E
			          endpar
			   endif
		endlet
	rule r_check_ME =
		let ($e=agentE ,$t=agentB) in
			if(internalStateA(self)=CHECK_END_A and protocolMessage(4,$e,self)=ME and protocolMessage(5,$e,$t)=MF)then
			  par
			        internalStateA(self):=END_A
                 	knowsNonce(self,messageField($e,self,1,ME)):=true
			        if(symDec(ME,1,2,4,self)=true)then
                      par 
                    	knowsIdentityCertificate(self,messageField($e,self,2,ME)):=true
                    	knowsSymKey(self,messageField($e,self,3,ME)):=true
                    	knowsNonce(self,messageField($e,self,4,ME)):=true
                      endpar 
			        endif 
			        if(symDec(ME,1,5,7,self)=true)then
                      par 
                    	knowsIdentityCertificate(self,messageField($e,self,5,ME)):=true
                    	knowsSymKey(self,messageField($e,self,6,ME)):=true
                    	knowsNonce(self,messageField($e,self,7,ME)):=true
                      endpar 
			        endif 
			  endpar
			endif
		endlet
	rule r_check_MF =
		let ($e=agentE) in
			if(internalStateB(self)=CHECK_END_B and protocolMessage(5,$e,self)=MF)then
			  par
			        internalStateB(self):=END_B
			        if(symDec(MF,1,1,3,self)=true)then
                      par 
                    	knowsIdentityCertificate(self,messageField($e,self,1,MF)):=true
                    	knowsSymKey(self,messageField($e,self,2,MF)):=true
                    	knowsNonce(self,messageField($e,self,3,MF)):=true
                      endpar 
			        endif 
			        if(symDec(MF,1,3,3,self)=true)then
                    	knowsNonce(self,messageField($e,self,4,MF)):=true
			        endif 
			  endpar
			endif
		endlet

	rule r_agentERule  =
	  par
            r_message_replay_MA[]
            r_message_replay_MB[]
            r_message_replay_ME[]
            r_message_MC[]
            r_message_MF[]
	  endpar

	rule r_agentARule  =
	  par
            r_message_MA[]
            r_check_ME[]
	  endpar

	rule r_agentBRule  =
	  par
            r_message_MB[]
            r_message_MD[]
            r_check_MF[]
	  endpar

	rule r_agentSRule  =
            r_message_ME[]

	main rule r_Main =
	  par
             program(agentA)
             program(agentB)
             program(agentS)
             program(agentE)
	  endpar
default init s0:
	function internalStateA($a in  Alice)=IDLE_MA
	function internalStateB($b in  Bob)=WAITING_MB
	function internalStateS($s in  Server)=WAITING_ME
	function internalStateE($e in  Eve)=WAITING_MC
	function receiver=chosenReceiver
	function knowsNonce($a in Agent, $n in KnowledgeNonce)=if($a=agentA and $n=NA) then true else if($a=agentB and $n=NB) or ($a=agentB and $n=NB2) then true else false endif endif
	function knowsIdentityCertificate($a in Agent, $i in KnowledgeIdentityCertificate)=if($a=agentA and $i=CA) then true else if($a=agentB and $i=CB) then true else false endif endif
	function knowsSymKey($a in Agent ,$sk in KnowledgeSymKey)=if(($a=agentA and $sk=KAS) or ($a=agentB and $sk=KBS) or ($a=agentE and $sk=KNA) or ($a=agentS and $sk=KAB) or ($a=agentS and $sk=KBS) or ($a=agentS and $sk=KAS)) then true else false endif
	function mode=chosenMode

	agent Alice:
		r_agentARule[]

	agent Bob:
		r_agentBRule[]

	agent Eve:
		r_agentERule[]

	agent Server:
		r_agentSRule[]
