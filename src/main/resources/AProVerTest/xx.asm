asm xx

import CryptoLibraryxx


signature:

definitions:
	domain Level = {1}
	domain FieldPosition = {1:7}
	domain EncField1={1:7}
	domain EncField2={2:7}
	domain NumMsg={0:15}

	domain KnowledgeNonce = {NA,NB,NB2}
	domain KnowledgeIdentityCertificate = {CA,CB}
	domain KnowledgeSymKey = {KAB,KAS,KBS,KNA}


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
			            messageField(self,$b,1,MF):=messageField($b,self,4,MD)
			            messageField(self,$b,2,MF):=messageField($b,self,5,MD)
			            symEnc(MF,1,1,2):=KBS
			            messageField(self,$b,3,MF):=messageField($b,self,5,MD)
			            symEnc(MF,1,3,3):=messageField(self,$b,2,MC)
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
			        if(symDec(MF,1,1,2,self)=true)then
                      par 
                    	knowsSymKey(self,messageField($e,self,1,MF)):=true
                    	knowsNonce(self,messageField($e,self,2,MF)):=true
                      endpar 
			        endif 
			        if(symDec(MF,1,2,2,self)=true)then
                    	knowsNonce(self,messageField($e,self,3,MF)):=true
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
	function knowsSymKey($a in Agent ,$sk in KnowledgeSymKey)=if(($a=agentA and $sk=KAS) or ($a=agentB and $sk=KBS) or ($a=agentB and $sk=KNA) or ($a=agentE and $sk=KNA) or ($a=agentE and $sk=KNA) or ($a=agentS and $sk=KAB) or ($a=agentS and $sk=KBS) or ($a=agentS and $sk=KAS)) then true else false endif
	function mode=chosenMode

	agent Alice:
		r_agentARule[]

	agent Bob:
		r_agentBRule[]

	agent Eve:
		r_agentERule[]

	agent Server:
		r_agentSRule[]
