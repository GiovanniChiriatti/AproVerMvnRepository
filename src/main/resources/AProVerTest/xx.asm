asm xx

import CryptoLibraryxx


signature:

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
