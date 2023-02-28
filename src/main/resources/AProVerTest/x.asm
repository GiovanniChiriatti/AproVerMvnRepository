asm x

import CryptoLibraryx


signature:

definitions:
	domain Level = {1:2}
	domain FieldPosition = {1:5}
	domain EncField1={1:5}
	domain EncField2={2:5}

	domain KnowledgeNonce = {NA,NB}
	domain KnowledgeIdentityCertificate = {CA,CB,CE}
	domain KnowledgeSymKey = {KAB,KAS,KBS,KEA,KEB,KES}


	/*ATTACKER RULES*/
	rule r_message_replay_MA =
		//choose what agets are interested by the message
		let ($b=agentS,$a=agentA) in
		  par 
			//check the reception of the message and the modality of the attack
			if(protocolMessage($a,self)=MA and protocolMessage(self,$b)!=MA and mode=PASSIVE)then
			        //in passsive mode if the attacker knows the decryption key, the message payload is readable and it can be added to the attacker knowledge
			        // the message must be sent unaltered
		          par 
                 	protocolMessage(self,$b):=MA
                 	messageField(self,$b,1,MA):=messageField($a,self,1,MA)
                 	messageField(self,$b,2,MA):=messageField($a,self,2,MA)
                 	messageField(self,$b,3,MA):=messageField($a,self,3,MA)
                 	knowsIdentityCertificate(self,messageField($a,self,1,MA)):=true
                 	knowsIdentityCertificate(self,messageField($a,self,2,MA)):=true
                 	knowsNonce(self,messageField($a,self,3,MA)):=true
		          endpar 
			endif 
			        //check the reception of the message and the modality of the attack
			if(protocolMessage($a,self)=MA and protocolMessage(self,$b)!=MA and mode=ACTIVE)then
		          par 
                 	protocolMessage(self,$b):=MA
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
			if(protocolMessage($a,self)=MB and protocolMessage(self,$b)!=MB and mode=PASSIVE)then
			        //in passsive mode if the attacker knows the decryption key, the message payload is readable and it can be added to the attacker knowledge
			        // the message must be sent unaltered
		          par 
                 	protocolMessage(self,$b):=MB
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
			            symEnc(MB,2,1,5):=KEA
                      endpar 
			        endif 
		          endpar 
			endif 
			        //check the reception of the message and the modality of the attack
			if(protocolMessage($a,self)=MB and protocolMessage(self,$b)!=MB and mode=ACTIVE)then
		          par 
                 	protocolMessage(self,$b):=MB
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
			if(protocolMessage($a,self)=MC and protocolMessage(self,$b)!=MC and mode=PASSIVE)then
			        //in passsive mode if the attacker knows the decryption key, the message payload is readable and it can be added to the attacker knowledge
			        // the message must be sent unaltered
		          par 
                 	protocolMessage(self,$b):=MC
                 	messageField(self,$b,1,MC):=messageField($a,self,1,MC)
                 	messageField(self,$b,2,MC):=messageField($a,self,2,MC)
			        if(symDec(MC,1,1,2,self)=true)then
                      par 
                    	knowsSymKey(self,messageField($a,self,1,MC)):=true
                    	knowsIdentityCertificate(self,messageField($a,self,2,MC)):=true
			            symEnc(MC,1,1,2):=KEA
                      endpar 
			        endif 
		          endpar 
			endif 
			        //check the reception of the message and the modality of the attack
			if(protocolMessage($a,self)=MC and protocolMessage(self,$b)!=MC and mode=ACTIVE)then
		          par 
                 	protocolMessage(self,$b):=MC
                 	messageField(self,$b,2,MC):=messageField($a,self,2,MC)
			        if(symDec(MC,1,1,2,self)=true)then
	   			     par 
			         	messageField(self,$b,1,MC):=KEA
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
			if(protocolMessage($a,self)=MD and protocolMessage(self,$b)!=MD and mode=PASSIVE)then
			        //in passsive mode if the attacker knows the decryption key, the message payload is readable and it can be added to the attacker knowledge
			        // the message must be sent unaltered
		          par 
                 	protocolMessage(self,$b):=MD
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
			if(protocolMessage($a,self)=MD and protocolMessage(self,$b)!=MD and mode=ACTIVE)then
		          par 
                 	protocolMessage(self,$b):=MD
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
			         protocolMessage(self,$e):=MA
			         messageField(self,$e,1,MA):=CA
			         messageField(self,$e,2,MA):=CB
			         messageField(self,$e,3,MA):=NA
			         internalStateA(agentA):=WAITING_MB
			     endpar
			   else
			       if(receiver=AG_E)then
			         par
			            protocolMessage(self,$e):=MA
			            messageField(self,$e,1,MA):=CA
			            messageField(self,$e,2,MA):=CB
			            messageField(self,$e,3,MA):=NA
			            internalStateA(agentA):=WAITING_MB
			         endpar
			       endif
			   endif
			endif
		endlet
	rule r_message_MB =
		let ($e=agentE) in
			if(internalStateS(self)=WAITING_MA and protocolMessage($e,self)=MA)then
			   if(receiver!=AG_E)then
			          par
			            knowsIdentityCertificate(self,messageField($e,self,1,MA)):=true
			            knowsIdentityCertificate(self,messageField($e,self,2,MA)):=true
			            knowsNonce(self,messageField($e,self,3,MA)):=true
			            protocolMessage(self,$e):=MB
			            messageField(self,$e,1,MB):=NA
			            messageField(self,$e,2,MB):=KAB
			            messageField(self,$e,3,MB):=CB
			            messageField(self,$e,4,MB):=KAB
			            messageField(self,$e,5,MB):=CA
			            symEnc(MB,1,4,5):=KBS
			            symEnc(MB,2,1,5):=KAS
			            internalStateB(agentB):=WAITING_MC
			          endpar
			   else
			          par
			            knowsIdentityCertificate(self,messageField($e,self,1,MA)):=true
			            knowsIdentityCertificate(self,messageField($e,self,2,MA)):=true
			            knowsNonce(self,messageField($e,self,3,MA)):=true
			            protocolMessage(self,$e):=MB
			            messageField(self,$e,1,MB):=messageField($e,self,3,MA)
			            messageField(self,$e,2,MB):=KAB
			            messageField(self,$e,3,MB):=messageField($e,self,2,MA)
			            messageField(self,$e,4,MB):=KAB
			            messageField(self,$e,5,MB):=messageField($e,self,1,MA)
			            symEnc(MB,1,4,5):=KBS
			            symEnc(MB,2,1,5):=KAS
			            internalStateB(agentB):=WAITING_MC
			         endpar
			   endif
			endif
		endlet
	rule r_message_MC =
		let ($e=agentE) in
			if(internalStateA(self)=WAITING_MB and protocolMessage($e,self)=MB)then
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
			            protocolMessage(self,$e):=MC
			            messageField(self,$e,1,MC):=KAB
			            messageField(self,$e,2,MC):=CA
			            symEnc(MC,1,1,2):=KBS
			            internalStateA(agentA):=WAITING_MD
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
			            protocolMessage(self,$e):=MC
			            messageField(self,$e,1,MC):=messageField($e,self,4,MB)
			            messageField(self,$e,2,MC):=messageField($e,self,5,MB)
			            symEnc(MC,1,1,2):=KBS
			            internalStateA(agentA):=WAITING_MD
			         endpar
			        endif
			   endif
			endif
		endlet
	rule r_message_MD =
		let ($e=agentE) in
			if(internalStateB(self)=WAITING_MC and protocolMessage($e,self)=MC)then
			   if(receiver!=AG_E)then
 			        if(symDec(MC,1,1,2,self)=true ) then
			          par
			            knowsSymKey(self,messageField($e,self,1,MC)):=true
			            knowsIdentityCertificate(self,messageField($e,self,2,MC)):=true
			            protocolMessage(self,$e):=MD
			            messageField(self,$e,1,MD):=NB
			            symEnc(MD,1,1,1):=messageField($e,self,1,MC)
			            internalStateB(agentB):=END_B
			          endpar
			        endif
			   else
 			        if(symDec(MC,1,1,2,self)=true  and receiver=AG_E) then
			          par
			            knowsSymKey(self,messageField($e,self,1,MC)):=true
			            knowsIdentityCertificate(self,messageField($e,self,2,MC)):=true
			            protocolMessage(self,$e):=MD
			            messageField(self,$e,1,MD):=NB
			            symEnc(MD,1,1,1):=messageField($e,self,1,MC)
			            internalStateB(agentB):=END_B
			         endpar
			        endif
			   endif
			endif
		endlet
	rule r_check_MD =
		let ($e=agentE) in
			if(internalStateA(self)=WAITING_MD and protocolMessage($e,self)=MD)then
			        if(symDec(MD,1,1,1,self)= true and symDec(MB,2,1,5,self)= true) then
			             par
			                      internalStateA(agentA):=END_A
			                      internalStateS(agentS):=END_S
			            endpar
			        endif
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
	function internalStateA($a in Alice)=IDLE_MA
	function internalStateS($b in Server)=WAITING_MA
	function receiver=chosenReceiver
	function knowsNonce($a in Agent, $n in KnowledgeNonce)=if($a=agentA and $n=NA) then true else if($a=agentB and $n=NB) then true else false endif endif
	function knowsIdentityCertificate($a in Agent, $i in KnowledgeIdentityCertificate)=if($a=agentA and $i=CA) or ($a=agentA and $i=CB) or ($a=agentA and $i=CE) then true else if($a=agentB and $i=CA) or ($a=agentB and $i=CB) or ($a=agentB and $i=CE) then true else if($a=agentE and $i=CE) then true else false endif endif endif
	function knowsSymKey($a in Agent ,$sk in KnowledgeSymKey)=if(($a=agentA and $sk=KAS) or ($a=agentA and $sk=KAB) or ($a=agentB and $sk=KBS) or ($a=agentB and $sk=KAB) or ($a=agentE and $sk=KEA) or ($a=agentE and $sk=KEB) or ($a=agentE and $sk=KES) or ($a=agentS and $sk=KAS) or ($a=agentS and $sk=KBS) or ($a=agentS and $sk=KAB)) then true else false endif
	function mode=chosenMode

	agent Alice:
		r_agentARule[]

	agent Bob:
		r_agentBRule[]

	agent Eve:
		r_agentERule[]

	agent Server:
		r_agentSRule[]