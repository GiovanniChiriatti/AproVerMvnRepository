asm Needham_SchroederNSSYMKASTest

import StandardLibrary
import CTLlibrary


signature:

	enum domain Agenti = {ALICE|BOB|EVE|SERVER}

// 	domain Alice subsetof Agent
// 	domain Bob subsetof Agent
// 	domain Eve subsetof Agent
// 	domain Server subsetof Agent



	enum domain StateAlice = {IDLE_MA | WAITING_MC | CHECK_END_A | END_A}
	enum domain StateBob = {WAITING_MD | CHECK_END_B | END_B}
	enum domain StateServer = {WAITING_MB | CHECK_END_S | END_S}

	enum domain Message = {MA | MB | MC | MD} 
// 	enum domain Knowledge ={CA|CB|CE|KAB|KAS|KBS|KEA|KEB|KES|NA|NB}
	enum domain Knowledge ={CA|CB|CE|KAB|KAS|KBS|KEA|KEB|KES|NA|NB|NULL}


	//DOMAIN OF POSSIBLE RECEIVER
	enum domain Receiver={AG_A|AG_B|AG_E|AG_S}
	///DOMAIN OF THE ATTACKER MODE
	enum domain Modality = {ACTIVE | PASSIVE}
// 	domain KnowledgeNonce subsetof Any
// 	domain KnowledgeIdentityCertificate subsetof Any
// 	domain KnowledgeBitString subsetof Any
// 	domain KnowledgeSymKey subsetof Any
// 	domain KnowledgeAsymPrivKey subsetof Any
// 	domain KnowledgeAsymPubKey subsetof Any
// 	domain KnowledgeSignPrivKey subsetof Any
// 	domain KnowledgeSignPubKey subsetof Any
// 	domain KnowledgeTag subsetof Any
// 	domain KnowledgeDigest subsetof Any
// 	domain KnowledgeHash subsetof Any
// 	domain KnowledgeTimestamp subsetof Any
// 	domain KnowledgeOther subsetof Any


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

	//state of the actor// 	controlled internalStateA: Alice -> StateAlice
	controlled internalStateA: StateAlice
// 	controlled internalStateB: Bob -> StateBob
	controlled internalStateB: StateBob
// 	controlled internalStateS: Server -> StateServer
	controlled internalStateS: StateServer


	//name of the message
	controlled protocolMessage: Prod(NumMsg,Agenti,Agenti)-> Message
	// content of the message and in which field it goes
	controlled messageField: Prod(Agenti,Agenti,FieldPosition,Message)->Knowledge

	//attaker mode
	monitored chosenMode: Modality
	//controlled for saving the attacker modality choice
	controlled mode: Modality

	// FUNCTIONS SELECT THE RECEIVER
	static name:Receiver -> Agenti
	//Receiver chosen
	controlled receiver:Receiver
	//Receiver chosen by user
	monitored chosenReceiver:Receiver

	/*------------------------------------------------------------------- */
	//            Knowledge  management of the principals 
	/*------------------------------------------------------------------- */
	controlled knowsNonce:Prod(Agenti,Knowledge)->Boolean

	controlled knowsIdentityCertificate:Prod(Agenti,Knowledge)->Boolean

	controlled knowsBitString:Prod(Agenti,Knowledge)->Boolean

	controlled knowsSymKey:Prod(Agenti,Knowledge)->Boolean

	controlled knowsAsymPubKey:Prod(Agenti,Knowledge)->Boolean

	controlled knowsAsymPrivKey:Prod(Agenti,Knowledge)->Boolean

	controlled knowsSignPubKey:Prod(Agenti,Knowledge)->Boolean

	controlled knowsSignPrivKey:Prod(Agenti,Knowledge)->Boolean

	controlled knowsTag:Prod(Agenti,Knowledge)->Boolean

	controlled knowsDigest:Prod(Agenti,Knowledge)->Boolean

	controlled knowsHash:Prod(Agenti,Knowledge)->Boolean

	controlled knowsTimestamp:Prod(Agenti,Knowledge)->Boolean

	controlled knowsOther:Prod(Agenti,Knowledge)->Boolean

	/*------------------------------------------------------------------- */
	//                  Cryptographic functions
	/*------------------------------------------------------------------- */
	//hash function applied from the field HashField1 to HashField2, the nesting level is Level
	controlled hash: Prod(Message,Level,HashField1,HashField2)-> Knowledge
	static verifyHash: Prod(Message,Level,HashField1,HashField2,Agenti)-> Boolean

	//sign function applied from the field SignField1 to SignField2, the nesting level is Level
	controlled sign: Prod(Message,Level,SignField1,SignField2)-> Knowledge
	static verifySign: Prod(Message,Level,SignField1,SignField2,Agenti)-> Boolean
	static sign_keyAssociation: Knowledge -> Knowledge

	//asymmetric encryption function applied from the field EncField1 to EncField2
	//the nesting level is Level
	controlled asymEnc: Prod(Message,Level,EncField1,EncField2)-> Knowledge
	static asymDec: Prod(Message,Level,EncField1,EncField2,Agenti)-> Boolean
	static asim_keyAssociation: Knowledge -> Knowledge

	//symmetric encryption function applied from the field EncField1 to EncField2
	//the nesting level is Level
	controlled symEnc: Prod(Message,Level,EncField1,EncField2)-> Knowledge
	static symDec: Prod(Message,Level,EncField1,EncField2,Agenti)-> Boolean
// 	static agentA: Alice
// 	static agentB: Bob
// 	static agentE: Eve
// 	static agentS: Server


	controlled agentA: Agenti 
	controlled agentB: Agenti 
	controlled agentE: Agenti 

	controlled agentS: Agenti 
definitions:
	domain Level = {1:2}
	domain FieldPosition = {1:5}
	domain EncField1={1:5}
	domain EncField2={2:5}
	domain NumMsg={0:15}
	domain SignField1={1}
	domain SignField2={2}
	domain HashField1={1}
	domain HashField2={2}

	function asim_keyAssociation($a in Knowledge)=
	       switch( $a )
	              case NULL: NULL
	              otherwise NULL 
	       endswitch
	function sign_keyAssociation($b in Knowledge)=
	       switch( $b )
	              case NULL: NULL
	              otherwise NULL 
	       endswitch

	function name($a in Receiver)=
			switch( $a )
				case AG_A:agentA
				case AG_E:agentE
				case AG_B:agentB
				case AG_S:agentS
			endswitch

		function verifySign($m in Message,$l in Level,$f1 in SignField1,$f2 in SignField2,$d in Agenti)=
			if(knowsSignPubKey($d,sign_keyAssociation(sign($m,$l,$f1,$f2)))=true)then
				true
			else
				false
			endif

		function symDec($m in Message,$l in Level,$f1 in EncField1,$f2 in EncField2,$d in Agenti)=
			if(knowsSymKey($d,symEnc($m,$l,$f1,$f2))=true)then
				true
			else
				false
			endif

		function asymDec($m in Message,$l in Level,$f1 in EncField1,$f2 in EncField2,$d in Agenti)=
			if(knowsAsymPrivKey($d,asim_keyAssociation(asymEnc($m,$l,$f1,$f2)))=true)then
				true
			else
				false
			endif

		function verifyHash($m in Message,$l in Level,$f1 in HashField1,$f2 in HashField2,$d in Agenti)=
			if(knowsHash($d,hash($m,$l,$f1,$f2))=true)then
				true
			else
				false
			endif


	/*ATTACKER RULES*/
	rule r_message_replay_MA =
		//choose what agets are interested by the message
		let ($x=agentE,$b=agentS,$a=agentA) in
		  par 
			//check the reception of the message and the modality of the attack
			if(protocolMessage(0,$a,$x)=MA and protocolMessage(0,$x,$b)!=MA and mode=PASSIVE)then
			        //in passive mode if the attacker knows the decryption key, the message payload is readable and it can be added to the attacker knowledge
			        // the message must be sent unaltered
		          par 
                 	protocolMessage(0,$x,$b):=MA
                 	messageField($x,$b,1,MA):=messageField($a,$x,1,MA)
                 	messageField($x,$b,2,MA):=messageField($a,$x,2,MA)
                 	messageField($x,$b,3,MA):=messageField($a,$x,3,MA)
                 	knowsIdentityCertificate($x,messageField($a,$x,1,MA)):=true
                 	knowsIdentityCertificate($x,messageField($a,$x,2,MA)):=true
                 	knowsNonce($x,messageField($a,$x,3,MA)):=true
		          endpar 
			endif 
			        //check the reception of the message and the modality of the attack
			if(protocolMessage(0,$a,$x)=MA and protocolMessage(0,$x,$b)!=MA and mode=ACTIVE)then
		          par 
                 	protocolMessage(0,$x,$b):=MA
                 	messageField($x,$b,1,MA):=messageField($a,$x,1,MA)
                 	messageField($x,$b,2,MA):=messageField($a,$x,2,MA)
                 	messageField($x,$b,3,MA):=messageField($a,$x,3,MA)
                 	knowsIdentityCertificate($x,messageField($a,$x,1,MA)):=true
                 	knowsIdentityCertificate($x,messageField($a,$x,2,MA)):=true
                 	knowsNonce($x,messageField($a,$x,3,MA)):=true
		          endpar 
			endif 
		  endpar 
		endlet 
	rule r_message_replay_MB =
		//choose what agets are interested by the message
		let ($x=agentE,$b=agentA,$a=agentS) in
		  par 
			//check the reception of the message and the modality of the attack
			if(protocolMessage(1,$a,$x)=MB and protocolMessage(1,$x,$b)!=MB and mode=PASSIVE)then
			        //in passive mode if the attacker knows the decryption key, the message payload is readable and it can be added to the attacker knowledge
			        // the message must be sent unaltered
		          par 
                 	protocolMessage(1,$x,$b):=MB
                 	messageField($x,$b,1,MB):=messageField($a,$x,1,MB)
                 	messageField($x,$b,2,MB):=messageField($a,$x,2,MB)
                 	messageField($x,$b,3,MB):=messageField($a,$x,3,MB)
                 	messageField($x,$b,4,MB):=messageField($a,$x,4,MB)
                 	messageField($x,$b,5,MB):=messageField($a,$x,5,MB)
			        if(symDec(MB,2,1,5,$x)=true)then
                      par 
			        	knowsNonce($x,messageField($a,$x,1,MB)):=true
			        	knowsSymKey($x,messageField($a,$x,2,MB)):=true
			        	knowsIdentityCertificate($x,messageField($a,$x,3,MB)):=true
			            if(symDec(MB,1,4,5,$x)=true)then
	   			 	       par 
	   			 	          	knowsSymKey($x,messageField($a,$x,4,MB)):=true
	   			 	          	knowsIdentityCertificate($x,messageField($a,$x,5,MB)):=true
	   			 	       endpar 
			            endif 
			            symEnc(MB,2,1,5):=KAS
                      endpar 
			        endif 
		          endpar 
			endif 
			        //check the reception of the message and the modality of the attack
			if(protocolMessage(1,$a,$x)=MB and protocolMessage(1,$x,$b)!=MB and mode=ACTIVE)then
		          par 
                 	protocolMessage(1,$x,$b):=MB
                 	messageField($x,$b,1,MB):=messageField($a,$x,1,MB)
                 	messageField($x,$b,3,MB):=messageField($a,$x,3,MB)
                 	messageField($x,$b,5,MB):=messageField($a,$x,5,MB)
			        if(symDec(MB,2,1,5,$x)=true)then
	   			     par 
			         	messageField($x,$b,2,MB):=KAS
			         	messageField($x,$b,4,MB):=KAS
			        	knowsNonce($x,messageField($a,$x,1,MB)):=true
			        	knowsSymKey($x,messageField($a,$x,2,MB)):=true
			        	knowsIdentityCertificate($x,messageField($a,$x,3,MB)):=true
			            if(symDec(MB,1,4,5,$x)=true)then
	   			 	       par 
	   			 	          	knowsSymKey($x,messageField($a,$x,4,MB)):=true
	   			 	          	knowsIdentityCertificate($x,messageField($a,$x,5,MB)):=true
	   			 	       endpar 
			            endif 
			        	symEnc(MB,2,1,5):=KAS
	   			     endpar 
			        else 
	   			     par 
			         	messageField($x,$b,2,MB):=messageField($a,$x,2,MB)
			         	messageField($x,$b,4,MB):=messageField($a,$x,4,MB)
	   			     endpar 
			        endif 
		          endpar 
			endif 
		  endpar 
		endlet 
	rule r_message_replay_MC =
		//choose what agets are interested by the message
		let ($x=agentE,$b=agentB,$a=agentA) in
		  par 
			//check the reception of the message and the modality of the attack
			if(protocolMessage(2,$a,$x)=MC and protocolMessage(2,$x,$b)!=MC and mode=PASSIVE)then
			        //in passive mode if the attacker knows the decryption key, the message payload is readable and it can be added to the attacker knowledge
			        // the message must be sent unaltered
		          par 
                 	protocolMessage(2,$x,$b):=MC
                 	messageField($x,$b,1,MC):=messageField($a,$x,1,MC)
                 	messageField($x,$b,2,MC):=messageField($a,$x,2,MC)
			        if(symDec(MC,1,1,2,$x)=true)then
                      par 
                    	knowsSymKey($x,messageField($a,$x,1,MC)):=true
                    	knowsIdentityCertificate($x,messageField($a,$x,2,MC)):=true
			            symEnc(MC,1,1,2):=KEB
                      endpar 
			        endif 
		          endpar 
			endif 
			        //check the reception of the message and the modality of the attack
			if(protocolMessage(2,$a,$x)=MC and protocolMessage(2,$x,$b)!=MC and mode=ACTIVE)then
		          par 
                 	protocolMessage(2,$x,$b):=MC
                 	messageField($x,$b,2,MC):=messageField($a,$x,2,MC)
			        if(symDec(MC,1,1,2,$x)=true)then
	   			     par 
			         	messageField($x,$b,1,MC):=KEB
                    	knowsSymKey($x,messageField($a,$x,1,MC)):=true
                    	knowsIdentityCertificate($x,messageField($a,$x,2,MC)):=true
			        	symEnc(MC,1,1,2):=KBS
	   			     endpar 
			        else 
			         	messageField($x,$b,1,MC):=messageField($a,$x,1,MC)
			        endif 
		          endpar 
			endif 
		  endpar 
		endlet 
	rule r_message_replay_MD =
		//choose what agets are interested by the message
		let ($x=agentE,$b=agentA,$a=agentB) in
		  par 
			//check the reception of the message and the modality of the attack
			if(protocolMessage(3,$a,$x)=MD and protocolMessage(3,$x,$b)!=MD and mode=PASSIVE)then
			        //in passive mode if the attacker knows the decryption key, the message payload is readable and it can be added to the attacker knowledge
			        // the message must be sent unaltered
		          par 
                 	protocolMessage(3,$x,$b):=MD
                 	messageField($x,$b,1,MD):=messageField($a,$x,1,MD)
			        if(symDec(MD,1,1,1,$x)=true)then
                      par 
                    	knowsNonce($x,messageField($a,$x,1,MD)):=true
			            symEnc(MD,1,1,1):=messageField($b,$x,1,MC)
                      endpar 
			        endif 
		          endpar 
			endif 
			        //check the reception of the message and the modality of the attack
			if(protocolMessage(3,$a,$x)=MD and protocolMessage(3,$x,$b)!=MD and mode=ACTIVE)then
		          par 
                 	protocolMessage(3,$x,$b):=MD
                 	messageField($x,$b,1,MD):=messageField($a,$x,1,MD)
			        if(symDec(MD,1,1,1,$x)=true)then
	   			     par 
                    	knowsNonce($x,messageField($a,$x,1,MD)):=true
			        	symEnc(MD,1,1,1):=messageField($b,$x,1,MC)
	   			     endpar 
			        endif 
		          endpar 
			endif 
		  endpar 
		endlet 

	/*HONEST AGENT RULES*/	
	rule r_message_MA =
		let ($x=agentA,$e=agentE) in
			if(internalStateA=IDLE_MA)then 
			   if(receiver!=AG_E)then
			     par
			         protocolMessage(0,$x,$e):=MA
			         messageField($x,$e,1,MA):=CA
			         messageField($x,$e,2,MA):=CB
			         messageField($x,$e,3,MA):=NA
			         internalStateA:=WAITING_MC
			     endpar
			   else
			       if(receiver=AG_E)then
			         par
			            protocolMessage(0,$x,$e):=MA
			            messageField($x,$e,1,MA):=CA
			            messageField($x,$e,2,MA):=CB
			            messageField($x,$e,3,MA):=NA
			            internalStateA:=WAITING_MC
			         endpar
			       endif
			   endif
			endif
		endlet
	rule r_message_MB =
		let ($x=agentS,$e=agentE) in
			if(internalStateS=WAITING_MB and protocolMessage(0,$e,$x)=MA)then
			   if(receiver!=AG_E)then
			          par
			            knowsIdentityCertificate($x,messageField($e,$x,1,MA)):=true
			            knowsIdentityCertificate($x,messageField($e,$x,2,MA)):=true
			            knowsNonce($x,messageField($e,$x,3,MA)):=true
			            protocolMessage(1,$x,$e):=MB
			            messageField($x,$e,1,MB):=messageField($e,$x,3,MA)
			            messageField($x,$e,2,MB):=KAB
			            messageField($x,$e,3,MB):=messageField($e,$x,2,MA)
			            messageField($x,$e,4,MB):=KAB
			            messageField($x,$e,5,MB):=messageField($e,$x,1,MA)
			            symEnc(MB,1,4,5):=KBS
			            symEnc(MB,2,1,5):=KAS
			            internalStateS:=END_S
			          endpar
			   else
			          par
			            knowsIdentityCertificate($x,messageField($e,$x,1,MA)):=true
			            knowsIdentityCertificate($x,messageField($e,$x,2,MA)):=true
			            knowsNonce($x,messageField($e,$x,3,MA)):=true
			            protocolMessage(1,$x,$e):=MB
			            messageField($x,$e,1,MB):=messageField($e,$x,3,MA)
			            messageField($x,$e,2,MB):=KAB
			            messageField($x,$e,3,MB):=messageField($e,$x,2,MA)
			            messageField($x,$e,4,MB):=KAB
			            messageField($x,$e,5,MB):=messageField($e,$x,1,MA)
			            symEnc(MB,1,4,5):=KBS
			            symEnc(MB,2,1,5):=KAS
			            internalStateS:=END_S
			         endpar
			   endif
			endif
		endlet
	rule r_message_MC =
		let ($x=agentA,$e=agentE) in
			if(internalStateA=WAITING_MC and protocolMessage(1,$e,$x)=MB)then
			   if(receiver!=AG_E)then
 			        if(symDec(MB,2,1,5,$x)=true ) then
			          par
			            knowsNonce($x,messageField($e,$x,1,MB)):=true
			            knowsSymKey($x,messageField($e,$x,2,MB)):=true
			            knowsIdentityCertificate($x,messageField($e,$x,3,MB)):=true
			            if(symDec(MB,1,4,5,$x)=true)then
	   			 	       par 
	   			 	          knowsSymKey($x,messageField($e,$x,4,MB)):=true
	   			 	          knowsIdentityCertificate($x,messageField($e,$x,5,MB)):=true
	   			 	       endpar 
			            endif 
			            protocolMessage(2,$x,$e):=MC
			            messageField($x,$e,1,MC):=messageField($e,$x,4,MB)
			            messageField($x,$e,2,MC):=messageField($e,$x,5,MB)
			            symEnc(MC,1,1,2):=KBS
			            internalStateA:=CHECK_END_A
			          endpar
			        endif
			   else
 			        if(symDec(MB,2,1,5,$x)=true  and receiver=AG_E) then
			          par
			            knowsNonce($x,messageField($e,$x,1,MB)):=true
			            knowsSymKey($x,messageField($e,$x,2,MB)):=true
			            knowsIdentityCertificate($x,messageField($e,$x,3,MB)):=true
			            if(symDec(MB,1,4,5,$x)=true)then
	   			 	       par 
	   			 	          knowsSymKey($x,messageField($e,$x,4,MB)):=true
	   			 	          knowsIdentityCertificate($x,messageField($e,$x,5,MB)):=true
	   			 	       endpar 
			            endif 
			            protocolMessage(2,$x,$e):=MC
			            messageField($x,$e,1,MC):=messageField($e,$x,4,MB)
			            messageField($x,$e,2,MC):=messageField($e,$x,5,MB)
			            symEnc(MC,1,1,2):=KBS
			            internalStateA:=CHECK_END_A
			         endpar
			        endif
			   endif
			endif
		endlet
	rule r_message_MD =
		let ($x=agentB,$e=agentE) in
			if(internalStateB=WAITING_MD and protocolMessage(2,$e,$x)=MC)then
			   if(receiver!=AG_E)then
 			        if(symDec(MC,1,1,2,$x)=true ) then
			          par
			            knowsSymKey($x,messageField($e,$x,1,MC)):=true
			            knowsIdentityCertificate($x,messageField($e,$x,2,MC)):=true
			            protocolMessage(3,$x,$e):=MD
			            messageField($x,$e,1,MD):=NB
			            symEnc(MD,1,1,1):=messageField($e,$x,1,MC)
			            internalStateB:=END_B
			          endpar
			        endif
			   else
 			        if(symDec(MC,1,1,2,$x)=true  and receiver=AG_E) then
			          par
			            knowsSymKey($x,messageField($e,$x,1,MC)):=true
			            knowsIdentityCertificate($x,messageField($e,$x,2,MC)):=true
			            protocolMessage(3,$x,$e):=MD
			            messageField($x,$e,1,MD):=NB
			            symEnc(MD,1,1,1):=messageField($e,$x,1,MC)
			            internalStateB:=END_B
			         endpar
			        endif
			   endif
			endif
		endlet
	rule r_check_MD =
		let ($x=agentA,$e=agentE) in
			if(internalStateA=CHECK_END_A and protocolMessage(3,$e,$x)=MD)then
			  par
			        internalStateA:=END_A
			        if(symDec(MD,1,1,1,$x)=true)then
                    	knowsNonce($x,messageField($e,$x,1,MD)):=true
			        endif 
			  endpar
			endif
		endlet

	main rule r_Main =
	  par
            r_message_replay_MA[]
            r_message_replay_MB[]
            r_message_replay_MC[]
            r_message_replay_MD[]
            r_message_MA[]
            r_message_MB[]
            r_message_MC[]
            r_message_MD[]
            r_check_MD[]
	  endpar

default init s0:
	function agentA=ALICE 
	function agentB=BOB 
	function agentE=EVE 
	function agentS=SERVER 
	function internalStateA=IDLE_MA
	function internalStateB=WAITING_MD
	function internalStateS=WAITING_MB
	function receiver=chosenReceiver
	function knowsNonce($a in Agenti, $n in Knowledge)=if($a=agentA and $n=NA) then true else if($a=agentB and $n=NB) then true else false endif endif
	function knowsIdentityCertificate($a in Agenti, $i in Knowledge)=if($a=agentA and $i=CA) or ($a=agentA and $i=CB) or ($a=agentA and $i=CE) then true else if($a=agentB and $i=CA) or ($a=agentB and $i=CB) or ($a=agentB and $i=CE) then true else if($a=agentE and $i=CE) then true else false endif endif endif
	function knowsSymKey($a in Agenti ,$sk in Knowledge)=if(($a=agentA and $sk=KAS) or ($a=agentA and $sk=KAB) or ($a=agentB and $sk=KBS) or ($a=agentB and $sk=KEB) or ($a=agentB and $sk=KAB) or ($a=agentE and $sk=KEA) or ($a=agentE and $sk=KEB) or ($a=agentE and $sk=KES) or ($a=agentE and $sk=KBS) or ($a=agentE and $sk=KAS) or ($a=agentS and $sk=KAS) or ($a=agentS and $sk=KBS) or ($a=agentS and $sk=KAB)) then true else false endif
	function mode=chosenMode

