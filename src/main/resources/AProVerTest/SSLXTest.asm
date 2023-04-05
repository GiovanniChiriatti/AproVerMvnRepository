asm SSLXTest

import StandardLibrary


signature:

	domain Alice subsetof Agent
	domain Bob subsetof Agent
	domain Eve subsetof Agent


	enum domain StateAlice = {IDLE_KK | WAITING_CSNK | CHECK_END_A | END_A}
	enum domain StateBob = {WAITING_NK | CHECK_END_B | END_B}

	enum domain Message = {KK | NK | CSNK} 

	enum domain Knowledge ={CA|NB|PRIVKA|PRIVKB|PRIVKE|PUBKA|PUBKB|PUBKE|SIGNPRIVKA|SIGNPRIVKB|SIGNPRIVKE|SIGNPUBKA|SIGNPUBKB|SIGNPUBKE|SKAB|SKAE|SKEB}

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
	domain Level = {1:2}
	domain FieldPosition = {1:2}
	domain EncField1={1}
	domain EncField2={2}
	domain NumMsg={0:15}

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
	rule r_message_replay_KK =
		//choose what agets are interested by the message
		let ($b=agentB,$a=agentA) in
		  par 
			//check the reception of the message and the modality of the attack
			if(protocolMessage(0,$a,self)=KK and protocolMessage(0,self,$b)!=KK and mode=PASSIVE)then
			        //in passsive mode if the attacker knows the decryption key, the message payload is readable and it can be added to the attacker knowledge
			        // the message must be sent unaltered
		          par 
                 	protocolMessage(0,self,$b):=KK
                 	messageField(self,$b,1,KK):=messageField($a,self,1,KK)
			        if(asymDec(KK,1,1,1,self)=true)then
                      par 
                    	knowsSymKey(self,messageField($a,self,1,KK)):=true
			            asymEnc(KK,1,1,1):=PUBKB
                      endpar 
			        endif 
		          endpar 
			endif 
			        //check the reception of the message and the modality of the attack
			if(protocolMessage(0,$a,self)=KK and protocolMessage(0,self,$b)!=KK and mode=ACTIVE)then
		          par 
                 	protocolMessage(0,self,$b):=KK
			        if(asymDec(KK,1,1,1,self)=true)then
	   			     par 
			         	messageField(self,$b,1,KK):=SKEB
                    	knowsSymKey(self,messageField($a,self,1,KK)):=true
			        	asymEnc(KK,1,1,1):=PUBKB
	   			     endpar 
			        else 
			         	messageField(self,$b,1,KK):=messageField($a,self,1,KK)
			        endif 
		          endpar 
			endif 
		  endpar 
		endlet 
	rule r_message_replay_NK =
		//choose what agets are interested by the message
		let ($b=agentA,$a=agentB) in
		  par 
			//check the reception of the message and the modality of the attack
			if(protocolMessage(1,$a,self)=NK and protocolMessage(1,self,$b)!=NK and mode=PASSIVE)then
			        //in passsive mode if the attacker knows the decryption key, the message payload is readable and it can be added to the attacker knowledge
			        // the message must be sent unaltered
		          par 
                 	protocolMessage(1,self,$b):=NK
                 	messageField(self,$b,1,NK):=messageField($a,self,1,NK)
			        if(symDec(NK,1,1,1,self)=true)then
                      par 
                    	knowsNonce(self,messageField($a,self,1,NK)):=true
			            symEnc(NK,1,1,1):=messageField($b,self,1,KK)
                      endpar 
			        endif 
		          endpar 
			endif 
			        //check the reception of the message and the modality of the attack
			if(protocolMessage(1,$a,self)=NK and protocolMessage(1,self,$b)!=NK and mode=ACTIVE)then
		          par 
                 	protocolMessage(1,self,$b):=NK
                 	messageField(self,$b,1,NK):=messageField($a,self,1,NK)
			        if(symDec(NK,1,1,1,self)=true)then
	   			     par 
                    	knowsNonce(self,messageField($a,self,1,NK)):=true
			        	symEnc(NK,1,1,1):=messageField($b,self,1,KK)
	   			     endpar 
			        endif 
		          endpar 
			endif 
		  endpar 
		endlet 
	rule r_message_replay_CSNK =
		//choose what agets are interested by the message
		let ($b=agentB,$a=agentA) in
		  par 
			//check the reception of the message and the modality of the attack
			if(protocolMessage(2,$a,self)=CSNK and protocolMessage(2,self,$b)!=CSNK and mode=PASSIVE)then
			        //in passsive mode if the attacker knows the decryption key, the message payload is readable and it can be added to the attacker knowledge
			        // the message must be sent unaltered
		          par 
                 	protocolMessage(2,self,$b):=CSNK
                 	messageField(self,$b,1,CSNK):=messageField($a,self,1,CSNK)
                 	messageField(self,$b,2,CSNK):=messageField($a,self,2,CSNK)
			        if(symDec(CSNK,2,1,2,self)=true)then
                      par 
			        	knowsIdentityCertificate(self,messageField($a,self,1,CSNK)):=true
			            if(verifySign(CSNK,1,2,2,self)=true)then
	   			 	          	knowsNonce(self,messageField($a,self,2,CSNK)):=true
			            endif 
			            symEnc(CSNK,2,1,2):=SKEB
                      endpar 
			        endif 
		          endpar 
			endif 
			        //check the reception of the message and the modality of the attack
			if(protocolMessage(2,$a,self)=CSNK and protocolMessage(2,self,$b)!=CSNK and mode=ACTIVE)then
		          par 
                 	protocolMessage(2,self,$b):=CSNK
                 	messageField(self,$b,1,CSNK):=messageField($a,self,1,CSNK)
                 	messageField(self,$b,2,CSNK):=messageField($a,self,2,CSNK)
			        if(symDec(CSNK,2,1,2,self)=true)then
	   			     par 
			        	knowsIdentityCertificate(self,messageField($a,self,1,CSNK)):=true
			            if(verifySign(CSNK,1,2,2,self)=true)then
	   			 	          	knowsNonce(self,messageField($a,self,2,CSNK)):=true
			            endif 
			        	symEnc(CSNK,2,1,2):=SKEB
	   			     endpar 
			        endif 
		          endpar 
			endif 
		  endpar 
		endlet 

	/*HONEST AGENT RULES*/	
	rule r_message_KK =
		let ($e=agentE) in
			if(internalStateA(self)=IDLE_KK)then 
			   if(receiver!=AG_E)then
			     par
			         protocolMessage(0,self,$e):=KK
			         messageField(self,$e,1,KK):=SKAB
			         asymEnc(KK,1,1,1):=PUBKB
			         internalStateA(self):=WAITING_CSNK
			     endpar
			   else
			       if(receiver=AG_E)then
			         par
			            protocolMessage(0,self,$e):=KK
			            messageField(self,$e,1,KK):=SKAE
			            asymEnc(KK,1,1,1):=PUBKE
			            internalStateA(self):=WAITING_CSNK
			         endpar
			       endif
			   endif
			endif
		endlet
	rule r_message_NK =
		let ($e=agentE) in
			if(internalStateB(self)=WAITING_NK and protocolMessage(0,$e,self)=KK)then
			   if(receiver!=AG_E)then
 			        if(asymDec(KK,1,1,1,self)=true ) then
			          par
			            knowsSymKey(self,messageField($e,self,1,KK)):=true
			            protocolMessage(1,self,$e):=NK
			            messageField(self,$e,1,NK):=NB
			            symEnc(NK,1,1,1):=messageField($e,self,1,KK)
			            internalStateB(self):=CHECK_END_B
			          endpar
			        endif
			   else
 			        if(asymDec(KK,1,1,1,self)=true  and receiver=AG_E) then
			          par
			            knowsSymKey(self,messageField($e,self,1,KK)):=true
			            protocolMessage(1,self,$e):=NK
			            messageField(self,$e,1,NK):=NB
			            symEnc(NK,1,1,1):=messageField($e,self,1,KK)
			            internalStateB(self):=CHECK_END_B
			         endpar
			        endif
			   endif
			endif
		endlet
	rule r_message_CSNK =
		let ($e=agentE) in
			if(internalStateA(self)=WAITING_CSNK and protocolMessage(1,$e,self)=NK)then
			   if(receiver!=AG_E)then
 			        if(symDec(NK,1,1,1,self)=true ) then
			          par
			            knowsNonce(self,messageField($e,self,1,NK)):=true
			            protocolMessage(2,self,$e):=CSNK
			            messageField(self,$e,1,CSNK):=CA
			            messageField(self,$e,2,CSNK):=messageField($e,self,1,NK)
			            sign(CSNK,1,2,2):=SIGNPRIVKA
			            symEnc(CSNK,2,1,2):=messageField(self,$e,1,KK)
			            internalStateA(self):=END_A
			          endpar
			        endif
			   else
 			        if(symDec(NK,1,1,1,self)=true  and receiver=AG_E) then
			          par
			            knowsNonce(self,messageField($e,self,1,NK)):=true
			            protocolMessage(2,self,$e):=CSNK
			            messageField(self,$e,1,CSNK):=CA
			            messageField(self,$e,2,CSNK):=messageField($e,self,1,NK)
			            sign(CSNK,1,2,2):=SIGNPRIVKA
			            symEnc(CSNK,2,1,2):=messageField(self,$e,1,KK)
			            internalStateA(self):=END_A
			         endpar
			        endif
			   endif
			endif
		endlet
	rule r_check_CSNK =
		let ($e=agentE) in
			if(internalStateB(self)=CHECK_END_B and protocolMessage(2,$e,self)=CSNK)then
			  par
			        internalStateB(self):=END_B
			        if(symDec(CSNK,2,1,2,self)=true)then
                      par 
			        	knowsIdentityCertificate(self,messageField($e,self,1,CSNK)):=true
			        	knowsNonce(self,messageField($e,self,2,CSNK)):=true
                      endpar 
			        endif 
			  endpar
			endif
		endlet

	rule r_agentERule  =
	  par
            r_message_replay_KK[]
            r_message_replay_NK[]
            r_message_replay_CSNK[]
	  endpar

	rule r_agentARule  =
	  par
            r_message_KK[]
            r_message_CSNK[]
	  endpar

	rule r_agentBRule  =
	  par
            r_message_NK[]
            r_check_CSNK[]
	  endpar

	main rule r_Main =
	  par
             program(agentA)
             program(agentB)
             program(agentE)
	  endpar
default init s0:
	function internalStateA($a in  Alice)=IDLE_KK
	function internalStateB($b in  Bob)=WAITING_NK
	function receiver=chosenReceiver
	function knowsNonce($a in Agent, $n in KnowledgeNonce)=if($a=agentB and $n=NB) then true else false endif
	function knowsIdentityCertificate($a in Agent, $i in KnowledgeIdentityCertificate)=if($a=agentA and $i=CA) then true else false endif
	function knowsAsymPrivKey($a in Agent ,$k in KnowledgeAsymPrivKey)=if(($a=agentA and $k=PRIVKA) or ($a=agentB and $k=PRIVKB) or ($a=agentE and $k=PRIVKE)) then true else false endif
	function knowsAsymPubKey($a in Agent ,$pk in KnowledgeAsymPubKey)=true
	function knowsSymKey($a in Agent ,$sk in KnowledgeSymKey)=if(($a=agentA and $sk=SKAB) or ($a=agentA and $sk=SKAE) or ($a=agentB and $sk=SKAB) or ($a=agentB and $sk=SKEB) or ($a=agentB and $sk=SKAB) or ($a=agentE and $sk=SKEB) or ($a=agentE and $sk=SKAE)) then true else false endif
	function knowsSignPrivKey($a in Agent ,$spr in KnowledgeSignPrivKey)=if(($a=agentA and $spr=SIGNPRIVKA) or ($a=agentB and $spr=SIGNPRIVKB) or ($a=agentE and $spr=SIGNPRIVKE)) then true else false endif
	function knowsSignPubKey($a in Agent ,$spu in KnowledgeSignPubKey)=true
	function mode=chosenMode

	agent Alice:
		r_agentARule[]

	agent Bob:
		r_agentBRule[]

	agent Eve:
		r_agentERule[]
