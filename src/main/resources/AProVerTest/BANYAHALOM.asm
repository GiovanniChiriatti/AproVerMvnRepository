asm BANYAHALOM

import CryptoLibraryBANYAHALOM


signature:

definitions:
	domain Level = {1}
	domain FieldPosition = {1:5}
	domain EncField1={1:5}
	domain EncField2={2:5}

	domain KnowledgeNonce = {NA,NB,NB2}
	domain KnowledgeIdentityCertificate = {CA,CB}
	domain KnowledgeSymKey = {KAB,KBS,KNA}


	/*ATTACKER RULES*/
	rule r_message_replay_MA =
		//choose what agets are interested by the message
		let ($b=agentB,$a=agentA) in
		  par 
			//check the reception of the message and the modality of the attack
			if(protocolMessage($a,self)=MA and protocolMessage(self,$b)!=MA and mode=PASSIVE)then
			        //in passsive mode if the attacker knows the decryption key, the message payload is readable and it can be added to the attacker knowledge
			        // the message must be sent unaltered
		          par 
                 	protocolMessage(self,$b):=MA
                 	messageField(self,$b,1,MA):=messageField($a,self,1,MA)
                 	messageField(self,$b,2,MA):=messageField($a,self,2,MA)
                 	knowsIdentityCertificate(self,messageField($a,self,1,MA)):=true
                 	knowsNonce(self,messageField($a,self,2,MA)):=true
		          endpar 
			endif 
			        //check the reception of the message and the modality of the attack
			if(protocolMessage($a,self)=MA and protocolMessage(self,$b)!=MA and mode=ACTIVE)then
		          par 
                 	protocolMessage(self,$b):=MA
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
			if(protocolMessage($a,self)=MB and protocolMessage(self,$b)!=MB and mode=PASSIVE)then
			        //in passsive mode if the attacker knows the decryption key, the message payload is readable and it can be added to the attacker knowledge
			        // the message must be sent unaltered
		          par 
                 	protocolMessage(self,$b):=MB
                 	messageField(self,$b,1,MB):=messageField($a,self,1,MB)
                 	messageField(self,$b,2,MB):=messageField($a,self,2,MB)
                 	messageField(self,$b,3,MB):=messageField($a,self,3,MB)
                 	messageField(self,$b,4,MB):=messageField($a,self,4,MB)
                 	knowsIdentityCertificate(self,messageField($a,self,1,MB)):=true
                 	knowsNonce(self,messageField($a,self,2,MB)):=true
			        if(symDec(MB,1,3,4,self)=true)then
                      par 
                    	knowsOther(self,messageField($a,self,3,MB)):=true
                    	knowsOther(self,messageField($a,self,4,MB)):=true
			            symEnc(MB,1,3,4):=KNA
                      endpar 
			        endif 
		          endpar 
			endif 
			        //check the reception of the message and the modality of the attack
			if(protocolMessage($a,self)=MB and protocolMessage(self,$b)!=MB and mode=ACTIVE)then
		          par 
                 	protocolMessage(self,$b):=MB
                 	messageField(self,$b,1,MB):=messageField($a,self,1,MB)
                 	messageField(self,$b,2,MB):=messageField($a,self,2,MB)
                 	messageField(self,$b,3,MB):=messageField($a,self,3,MB)
                 	messageField(self,$b,4,MB):=messageField($a,self,4,MB)
                 	knowsIdentityCertificate(self,messageField($a,self,1,MB)):=true
                 	knowsNonce(self,messageField($a,self,2,MB)):=true
			        if(symDec(MB,1,3,4,self)=true)then
	   			     par 
                    	knowsOther(self,messageField($a,self,3,MB)):=true
                    	knowsOther(self,messageField($a,self,4,MB)):=true
			        	symEnc(MB,1,3,4):=KBS
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
			         messageField(self,$e,2,MA):=NA
			         internalStateA(self):=END_A
			     endpar
			   else
			       if(receiver=AG_E)then
			         par
			            protocolMessage(self,$e):=MA
			            messageField(self,$e,1,MA):=CA
			            messageField(self,$e,2,MA):=NA
			            internalStateA(self):=END_A
			         endpar
			       endif
			   endif
			endif
		endlet
	rule r_message_MB =
		let ($e=agentE) in
			if(internalStateB(self)=WAITING_MB and protocolMessage($e,self)=MA)then
			   if(receiver!=AG_E)then
			          par
			            knowsIdentityCertificate(self,messageField($e,self,1,MA)):=true
			            knowsNonce(self,messageField($e,self,2,MA)):=true
			            protocolMessage(self,$e):=MB
			            messageField(self,$e,1,MB):=CB
			            messageField(self,$e,2,MB):=NB
			            messageField(self,$e,3,MB):=CA
			            messageField(self,$e,4,MB):=NA
			            symEnc(MB,1,3,4):=KBS
			            internalStateB(self):=WAITING_MD
			          endpar
			   else
			          par
			            knowsIdentityCertificate(self,messageField($e,self,1,MA)):=true
			            knowsNonce(self,messageField($e,self,2,MA)):=true
			            protocolMessage(self,$e):=MB
			            messageField(self,$e,1,MB):=CB
			            messageField(self,$e,2,MB):=NB
			            messageField(self,$e,3,MB):=messageField($e,self,1,MA)
			            messageField(self,$e,4,MB):=messageField($e,self,2,MA)
			            symEnc(MB,1,3,4):=KNA
			            internalStateB(self):=WAITING_MD
			         endpar
			   endif
			endif
		endlet
	rule r_message_MC =
		let ($e=agentB,$t=agentS) in
			if(internalStateE(self)=WAITING_MC and protocolMessage(self,$t)=MB)then
			     par
			            protocolMessage(self,$e):=MC
			            messageField(self,$e,1,MC):=CA
			            messageField(self,$e,2,MC):=KNA
			            messageField(self,$e,3,MC):=NB
			            symEnc(MC,1,2,3):=KBS
			            internalStateE(self):=WAITING_ME
			          endpar
			endif
		endlet
	rule r_message_MD =
		let ($e=agentE) in
			if(internalStateB(self)=WAITING_MD and protocolMessage($e,self)=MC)then
 			        if(symDec(MC,1,2,3,self)=true ) then
			          par
			            knowsSymKey(self,messageField($e,self,1,MC)):=true
			            knowsNonce(self,messageField($e,self,2,MC)):=true
			            protocolMessage(self,$e):=MD
			            messageField(self,$e,1,MD):=CB
			            messageField(self,$e,2,MD):=NB2
			            messageField(self,$e,3,MD):=CA
			            messageField(self,$e,4,MD):=KNA
			            messageField(self,$e,5,MD):=NB
			            symEnc(MD,1,3,5):=KBS
			            internalStateB(self):=CHECK_END_B
			          endpar
			        endif
			endif
		endlet
	rule r_message_ME =
		let ($e=agentB) in
			if(internalStateE(self)=WAITING_ME and protocolMessage($e,self)=MD)then
			          par
			            knowsIdentityCertificate(self,messageField($e,self,1,MD)):=true
			            knowsNonce(self,messageField($e,self,2,MD)):=true
			            protocolMessage(self,$e):=ME
			            messageField(self,$e,1,ME):=CA
			            messageField(self,$e,2,ME):=KNA
			            messageField(self,$e,3,ME):=NB
			            symEnc(ME,1,1,3):=KBS
			            messageField(self,$e,3,ME):=NB
			            symEnc(ME,1,4,4):=KNA
			            internalStateE(self):=END_E
			          endpar
			endif
		endlet
	rule r_check_ME =
		let ($e=agentE) in
			if(internalStateB(self)=CHECK_END_B and protocolMessage($e,self)=ME)then
			        if(symDec(ME,1,1,3,self)= true and symDec(ME,1,4,4,self)= true) then
			            internalStateB(self):=END_B
			        endif
			endif
		endlet

	rule r_agentERule  =
	  par
            r_message_replay_MA[]
            r_message_replay_MB[]
            r_message_MC[]
            r_message_ME[]
	  endpar

	rule r_agentARule  =
            r_message_MA[]

	rule r_agentBRule  =
	  par
            r_message_MB[]
            r_message_MD[]
            r_check_ME[]
	  endpar

	main rule r_Main =
	  par
             program(agentA)
             program(agentB)
             program(agentE)
	  endpar
default init s0:
	function internalStateA($a in  Alice)=IDLE_MA
	function internalStateB($b in  Bob)=WAITING_MB
	function internalStateS($s in  Server)=CHECK_END_S
	function internalStateE($e in  Eve)=WAITING_MC
	function receiver=chosenReceiver
	function knowsNonce($a in Agent, $n in KnowledgeNonce)=if($a=agentA and $n=NA) then true else if($a=agentB and $n=NB) or ($a=agentB and $n=NB2) then true else false endif endif
	function knowsIdentityCertificate($a in Agent, $i in KnowledgeIdentityCertificate)=if($a=agentA and $i=CA) then true else if($a=agentB and $i=CB) then true else false endif endif
	function knowsOther($a in Agent, $ho in KnowledgeOther)=if($a=agentB and $ho=CA) or ($a=agentB and $ho=NA) then true else false endif
	function knowsSymKey($a in Agent ,$sk in KnowledgeSymKey)=if(($a=agentB and $sk=KBS) or ($a=agentB and $sk=KNA) or ($a=agentE and $sk=KNA) or ($a=agentE and $sk=KNA) or ($a=agentS and $sk=KAB) or ($a=agentS and $sk=KBS)) then true else false endif
	function mode=chosenMode

	agent Alice:
		r_agentARule[]

	agent Bob:
		r_agentBRule[]

	agent Eve:
		r_agentERule[]
