asm Needham_SchroederNSSYMKABTest

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
	controlled chosenMode: Modality
	//controlled for saving the attacker modality choice
	controlled mode: Modality

	// FUNCTIONS SELECT THE RECEIVER
	static name:Receiver -> Agenti
	//Receiver chosen
	controlled receiver:Receiver
	//Receiver chosen by user
	controlled chosenReceiver:Receiver

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
// 	static verifyHash: Prod(Message,Level,HashField1,HashField2,Agent)-> Boolean


	//sign function applied from the field SignField1 to SignField2, the nesting level is Level
	controlled sign: Prod(Message,Level,SignField1,SignField2)-> Knowledge
// 	static verifySign: Prod(Message,Level,SignField1,SignField2,Agent)-> Boolean

// 	static sign_keyAssociation: KnowledgeSignPrivKey -> KnowledgeSignPubKey


	//asymmetric encryption function applied from the field EncField1 to EncField2
	//the nesting level is Level
	controlled asymEnc: Prod(Message,Level,EncField1,EncField2)-> Knowledge
// 	static asymDec: Prod(Message,Level,EncField1,EncField2,Agent)-> Boolean

// 	static asim_keyAssociation: KnowledgeAsymPubKey -> KnowledgeAsymPrivKey


	//symmetric encryption function applied from the field EncField1 to EncField2
	//the nesting level is Level
	controlled symEnc: Prod(Message,Level,EncField1,EncField2)-> Knowledge
// 	static symDec: Prod(Message,Level,EncField1,EncField2,Agent)-> Boolean

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
	domain EncField2={1:5}
	domain NumMsg={0:15}
	domain SignField1={1}
	domain SignField2={1}
	domain HashField1={1}
	domain HashField2={1}

//function asim_keyAssociation($a in Knowledge)=
//       switch( $a )
//              case NULL: NULL
//              otherwise NULL 
//       endswitch
//function sign_keyAssociation($b in Knowledge)=
//       switch( $b )
//              case NULL: NULL
//              otherwise NULL 
//       endswitch

	function name($a in Receiver)=
			switch( $a )
				case AG_A:agentA
				case AG_E:agentE
				case AG_B:agentB
				case AG_S:agentS
			endswitch
//
//		function verifySign($m in Message,$l in Level,$f1 in SignField1,$f2 in SignField2,$d in Agenti)=
//			if(knowsSignPubKey($d,sign_keyAssociation(sign($m,$l,$f1,$f2)))=true)then
//				true
//			else
//				false
//			endif
//
//		function symDec($m in Message,$l in Level,$f1 in EncField1,$f2 in EncField2,$d in Agenti)=
//			if(knowsSymKey($d,symEnc($m,$l,$f1,$f2))=true)then
//				true
//			else
//				false
//			endif
//
//		function asymDec($m in Message,$l in Level,$f1 in EncField1,$f2 in EncField2,$d in Agenti)=
//			if(knowsAsymPrivKey($d,asim_keyAssociation(asymEnc($m,$l,$f1,$f2)))=true)then
//				true
//			else
//				false
//			endif
//
//		function verifyHash($m in Message,$l in Level,$f1 in HashField1,$f2 in HashField2,$d in Agenti)=
//			if(knowsHash($d,hash($m,$l,$f1,$f2))=true)then
//				true
//			else
//				false
//			endif
//

	/*ATTACKER RULES*/
	rule r_message_replay_MA =
		//choose what agets are interested by the message
		let ($x=agentE,$b=agentS,$a=agentA) in
		  par 
			//check the reception of the message and the modality of the attack
			if(protocolMessage(0,ALICE,EVE)=MA and protocolMessage(0,EVE,SERVER)!=MA and mode=PASSIVE)then
			        //in passive mode if the attacker knows the decryption key, the message payload is readable and it can be added to the attacker knowledge
			        // the message must be sent unaltered
		          par 
                 	protocolMessage(0,EVE,SERVER):=MA
                 	messageField(EVE,SERVER,1,MA):=messageField(ALICE,EVE,1,MA)
                 	messageField(EVE,SERVER,2,MA):=messageField(ALICE,EVE,2,MA)
                 	messageField(EVE,SERVER,3,MA):=messageField(ALICE,EVE,3,MA)
                 	knowsIdentityCertificate(EVE,messageField(ALICE,EVE,1,MA)):=true
                 	knowsIdentityCertificate(EVE,messageField(ALICE,EVE,2,MA)):=true
                 	knowsNonce(EVE,messageField(ALICE,EVE,3,MA)):=true
		          endpar 
			endif 
			        //check the reception of the message and the modality of the attack
			if(protocolMessage(0,ALICE,EVE)=MA and protocolMessage(0,EVE,SERVER)!=MA and mode=ACTIVE)then
		          par 
                 	protocolMessage(0,EVE,SERVER):=MA
                 	messageField(EVE,SERVER,1,MA):=messageField(ALICE,EVE,1,MA)
                 	messageField(EVE,SERVER,2,MA):=messageField(ALICE,EVE,2,MA)
                 	messageField(EVE,SERVER,3,MA):=messageField(ALICE,EVE,3,MA)
                 	knowsIdentityCertificate(EVE,messageField(ALICE,EVE,1,MA)):=true
                 	knowsIdentityCertificate(EVE,messageField(ALICE,EVE,2,MA)):=true
                 	knowsNonce(EVE,messageField(ALICE,EVE,3,MA)):=true
		          endpar 
			endif 
		  endpar 
		endlet 
	rule r_message_replay_MB =
		//choose what agets are interested by the message
		let ($x=agentE,$b=agentA,$a=agentS) in
		  par 
			//check the reception of the message and the modality of the attack
			if(protocolMessage(1,SERVER,EVE)=MB and protocolMessage(1,EVE,ALICE)!=MB and mode=PASSIVE)then
			        //in passive mode if the attacker knows the decryption key, the message payload is readable and it can be added to the attacker knowledge
			        // the message must be sent unaltered
		          par 
                 	protocolMessage(1,EVE,ALICE):=MB
                 	messageField(EVE,ALICE,1,MB):=messageField(SERVER,EVE,1,MB)
                 	messageField(EVE,ALICE,2,MB):=messageField(SERVER,EVE,2,MB)
                 	messageField(EVE,ALICE,3,MB):=messageField(SERVER,EVE,3,MB)
                 	messageField(EVE,ALICE,4,MB):=messageField(SERVER,EVE,4,MB)
                 	messageField(EVE,ALICE,5,MB):=messageField(SERVER,EVE,5,MB)
//	        if(symDec(MB,2,1,5,EVE)=true)then
			        if(knowsSymKey(EVE,KAS)=true)then
                      par 
			        	knowsNonce(EVE,messageField(SERVER,EVE,1,MB)):=true
			        	knowsSymKey(EVE,messageField(SERVER,EVE,2,MB)):=true
			        	knowsIdentityCertificate(EVE,messageField(SERVER,EVE,3,MB)):=true
//		            if(symDec(MB,1,4,5,EVE)=true)then
			            if(knowsSymKey(EVE,KBS)=true)then
	   			 	       par 
	   			 	          	knowsSymKey(EVE,messageField(SERVER,EVE,4,MB)):=true
	   			 	          	knowsIdentityCertificate(EVE,messageField(SERVER,EVE,5,MB)):=true
	   			 	       endpar 
			            endif 
			            symEnc(MB,2,1,5):=KAS
                      endpar 
			        endif 
		          endpar 
			endif 
			        //check the reception of the message and the modality of the attack
			if(protocolMessage(1,SERVER,EVE)=MB and protocolMessage(1,EVE,ALICE)!=MB and mode=ACTIVE)then
		          par 
                 	protocolMessage(1,EVE,ALICE):=MB
                 	messageField(EVE,ALICE,1,MB):=messageField(SERVER,EVE,1,MB)
                 	messageField(EVE,ALICE,3,MB):=messageField(SERVER,EVE,3,MB)
                 	messageField(EVE,ALICE,5,MB):=messageField(SERVER,EVE,5,MB)
//			        if(symDec(MB,2,1,5,EVE)=true)then
			            if(knowsSymKey(EVE,KAS)=true)then
	   			     par 
			         	messageField(EVE,ALICE,2,MB):=KAB
			         	messageField(EVE,ALICE,4,MB):=KAB
			        	knowsNonce(EVE,messageField(SERVER,EVE,1,MB)):=true
			        	knowsSymKey(EVE,messageField(SERVER,EVE,2,MB)):=true
			        	knowsIdentityCertificate(EVE,messageField(SERVER,EVE,3,MB)):=true
//		            if(symDec(MB,1,4,5,EVE)=true)then
			            if(knowsSymKey(EVE,KBS)=true)then
	   			 	       par 
	   			 	          	knowsSymKey(EVE,messageField(SERVER,EVE,4,MB)):=true
	   			 	          	knowsIdentityCertificate(EVE,messageField(SERVER,EVE,5,MB)):=true
	   			 	       endpar 
			            endif 
			        	symEnc(MB,2,1,5):=KAS
	   			     endpar 
			        else 
	   			     par 
			         	messageField(EVE,ALICE,2,MB):=messageField(SERVER,EVE,2,MB)
			         	messageField(EVE,ALICE,4,MB):=messageField(SERVER,EVE,4,MB)
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
			if(protocolMessage(2,ALICE,EVE)=MC and protocolMessage(2,EVE,BOB)!=MC and mode=PASSIVE)then
			        //in passive mode if the attacker knows the decryption key, the message payload is readable and it can be added to the attacker knowledge
			        // the message must be sent unaltered
		          par 
                 	protocolMessage(2,EVE,BOB):=MC
                 	messageField(EVE,BOB,1,MC):=messageField(ALICE,EVE,1,MC)
                 	messageField(EVE,BOB,2,MC):=messageField(ALICE,EVE,2,MC)
//	        if(symDec(MC,1,1,2,EVE)=true)then
			        if(knowsSymKey(EVE,KBS)=true)then
                      par 
                    	knowsSymKey(EVE,messageField(ALICE,EVE,1,MC)):=true
                    	knowsIdentityCertificate(EVE,messageField(ALICE,EVE,2,MC)):=true
			            symEnc(MC,1,1,2):=KEB
                      endpar 
			        endif 
		          endpar 
			endif 
			        //check the reception of the message and the modality of the attack
			if(protocolMessage(2,ALICE,EVE)=MC and protocolMessage(2,EVE,BOB)!=MC and mode=ACTIVE)then
		          par 
                 	protocolMessage(2,EVE,BOB):=MC
                 	messageField(EVE,BOB,2,MC):=messageField(ALICE,EVE,2,MC)
//			        if(symDec(MC,1,1,2,EVE)=true)then
			            if(knowsSymKey(EVE,KBS)=true)then
	   			     par 
			         	messageField(EVE,BOB,1,MC):=KEB
                    	knowsSymKey(EVE,messageField(ALICE,EVE,1,MC)):=true
                    	knowsIdentityCertificate(EVE,messageField(ALICE,EVE,2,MC)):=true
			        	symEnc(MC,1,1,2):=KBS
	   			     endpar 
			        else 
			         	messageField(EVE,BOB,1,MC):=messageField(ALICE,EVE,1,MC)
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
			if(protocolMessage(3,BOB,EVE)=MD and protocolMessage(3,EVE,ALICE)!=MD and mode=PASSIVE)then
			        //in passive mode if the attacker knows the decryption key, the message payload is readable and it can be added to the attacker knowledge
			        // the message must be sent unaltered
		          par 
                 	protocolMessage(3,EVE,ALICE):=MD
                 	messageField(EVE,ALICE,1,MD):=messageField(BOB,EVE,1,MD)
//	        if(symDec(MD,1,1,1,EVE)=true)then
			        if(knowsSymKey(EVE,KAB)=true)then
                      par 
                    	knowsNonce(EVE,messageField(BOB,EVE,1,MD)):=true
			            symEnc(MD,1,1,1):=messageField(ALICE,EVE,1,MC)
                      endpar 
			        endif 
		          endpar 
			endif 
			        //check the reception of the message and the modality of the attack
			if(protocolMessage(3,BOB,EVE)=MD and protocolMessage(3,EVE,ALICE)!=MD and mode=ACTIVE)then
		          par 
                 	protocolMessage(3,EVE,ALICE):=MD
                 	messageField(EVE,ALICE,1,MD):=messageField(BOB,EVE,1,MD)
//			        if(symDec(MD,1,1,1,EVE)=true)then
			            if(knowsSymKey(EVE,KAB)=true)then
	   			     par 
                    	knowsNonce(EVE,messageField(BOB,EVE,1,MD)):=true
			        	symEnc(MD,1,1,1):=messageField(ALICE,EVE,1,MC)
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
			         protocolMessage(0,ALICE,EVE):=MA
			         messageField(ALICE,EVE,1,MA):=CA
			         messageField(ALICE,EVE,2,MA):=CB
			         messageField(ALICE,EVE,3,MA):=NA
			         internalStateA:=WAITING_MC
			     endpar
			   else
			       if(receiver=AG_E)then
			         par
			            protocolMessage(0,ALICE,EVE):=MA
			            messageField(ALICE,EVE,1,MA):=CA
			            messageField(ALICE,EVE,2,MA):=CB
			            messageField(ALICE,EVE,3,MA):=NA
			            internalStateA:=WAITING_MC
			         endpar
			       endif
			   endif
			endif
		endlet
	rule r_message_MB =
		let ($x=agentS,$e=agentE) in
			if(internalStateS=WAITING_MB and protocolMessage(0,EVE,SERVER)=MA)then
			   if(receiver!=AG_E)then
			          par
			            knowsIdentityCertificate(SERVER,messageField(EVE,SERVER,1,MA)):=true
			            knowsIdentityCertificate(SERVER,messageField(EVE,SERVER,2,MA)):=true
			            knowsNonce(SERVER,messageField(EVE,SERVER,3,MA)):=true
			            protocolMessage(1,SERVER,EVE):=MB
			            messageField(SERVER,EVE,1,MB):=messageField(EVE,SERVER,3,MA)
			            messageField(SERVER,EVE,2,MB):=KAB
			            messageField(SERVER,EVE,3,MB):=messageField(EVE,SERVER,2,MA)
			            messageField(SERVER,EVE,4,MB):=KAB
			            messageField(SERVER,EVE,5,MB):=messageField(EVE,SERVER,1,MA)
			            symEnc(MB,1,4,5):=KBS
			            symEnc(MB,2,1,5):=KAS
			            internalStateS:=END_S
			          endpar
			   else
			          par
			            knowsIdentityCertificate(SERVER,messageField(EVE,SERVER,1,MA)):=true
			            knowsIdentityCertificate(SERVER,messageField(EVE,SERVER,2,MA)):=true
			            knowsNonce(SERVER,messageField(EVE,SERVER,3,MA)):=true
			            protocolMessage(1,SERVER,EVE):=MB
			            messageField(SERVER,EVE,1,MB):=messageField(EVE,SERVER,3,MA)
			            messageField(SERVER,EVE,2,MB):=KAB
			            messageField(SERVER,EVE,3,MB):=messageField(EVE,SERVER,2,MA)
			            messageField(SERVER,EVE,4,MB):=KAB
			            messageField(SERVER,EVE,5,MB):=messageField(EVE,SERVER,1,MA)
			            symEnc(MB,1,4,5):=KBS
			            symEnc(MB,2,1,5):=KAS
			            internalStateS:=END_S
			         endpar
			   endif
			endif
		endlet
	rule r_message_MC =
		let ($x=agentA,$e=agentE) in
			if(internalStateA=WAITING_MC and protocolMessage(1,EVE,ALICE)=MB)then
			   if(receiver!=AG_E)then
			        if(knowsSymKey(ALICE,KAS)=true ) then
			          par
			            knowsNonce(ALICE,messageField(EVE,ALICE,1,MB)):=true
			            knowsSymKey(ALICE,messageField(EVE,ALICE,2,MB)):=true
			            knowsIdentityCertificate(ALICE,messageField(EVE,ALICE,3,MB)):=true
//		            if(symDec(MB,1,4,5,ALICE)=true)then
			            if(knowsSymKey(ALICE,KBS)=true)then
	   			 	       par 
	   			 	          knowsSymKey(ALICE,messageField(EVE,ALICE,4,MB)):=true
	   			 	          knowsIdentityCertificate(ALICE,messageField(EVE,ALICE,5,MB)):=true
	   			 	       endpar 
			            endif 
			            protocolMessage(2,ALICE,EVE):=MC
			            messageField(ALICE,EVE,1,MC):=messageField(EVE,ALICE,4,MB)
			            messageField(ALICE,EVE,2,MC):=messageField(EVE,ALICE,5,MB)
			            symEnc(MC,1,1,2):=KBS
			            internalStateA:=CHECK_END_A
			          endpar
			        endif
			   else
			        if(knowsSymKey(ALICE,KAS)=true  and receiver=AG_E) then
			          par
			            knowsNonce(ALICE,messageField(EVE,ALICE,1,MB)):=true
			            knowsSymKey(ALICE,messageField(EVE,ALICE,2,MB)):=true
			            knowsIdentityCertificate(ALICE,messageField(EVE,ALICE,3,MB)):=true
//		            if(symDec(MB,1,4,5,ALICE)=true)then
			            if(knowsSymKey(ALICE,KBS)=true)then
	   			 	       par 
	   			 	          knowsSymKey(ALICE,messageField(EVE,ALICE,4,MB)):=true
	   			 	          knowsIdentityCertificate(ALICE,messageField(EVE,ALICE,5,MB)):=true
	   			 	       endpar 
			            endif 
			            protocolMessage(2,ALICE,EVE):=MC
			            messageField(ALICE,EVE,1,MC):=messageField(EVE,ALICE,4,MB)
			            messageField(ALICE,EVE,2,MC):=messageField(EVE,ALICE,5,MB)
			            symEnc(MC,1,1,2):=KBS
			            internalStateA:=CHECK_END_A
			         endpar
			        endif
			   endif
			endif
		endlet
	rule r_message_MD =
		let ($x=agentB,$e=agentE) in
			if(internalStateB=WAITING_MD and protocolMessage(2,EVE,BOB)=MC)then
			   if(receiver!=AG_E)then
			        if(knowsSymKey(BOB,KBS)=true ) then
			          par
			            knowsSymKey(BOB,messageField(EVE,BOB,1,MC)):=true
			            knowsIdentityCertificate(BOB,messageField(EVE,BOB,2,MC)):=true
			            protocolMessage(3,BOB,EVE):=MD
			            messageField(BOB,EVE,1,MD):=NB
			            symEnc(MD,1,1,1):=messageField(EVE,BOB,1,MC)
			            internalStateB:=END_B
			          endpar
			        endif
			   else
			        if(knowsSymKey(BOB,KBS)=true  and receiver=AG_E) then
			          par
			            knowsSymKey(BOB,messageField(EVE,BOB,1,MC)):=true
			            knowsIdentityCertificate(BOB,messageField(EVE,BOB,2,MC)):=true
			            protocolMessage(3,BOB,EVE):=MD
			            messageField(BOB,EVE,1,MD):=NB
			            symEnc(MD,1,1,1):=messageField(EVE,BOB,1,MC)
			            internalStateB:=END_B
			         endpar
			        endif
			   endif
			endif
		endlet
	rule r_check_MD =
		let ($x=agentA,$e=agentE) in
			if(internalStateA=CHECK_END_A and protocolMessage(3,EVE,ALICE)=MD)then
			  par
			        internalStateA:=END_A
//		        if(symDec(MD,1,1,1,ALICE)=true)then
			        if(knowsSymKey(ALICE,KAB)=true)then
                    	knowsNonce(ALICE,messageField(EVE,ALICE,1,MD)):=true
			        endif 
			  endpar
			endif
		endlet

// properties TAB=0 COL=0
  CTLSPEC ef(knowsNonce(EVE,NB))
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
	function receiver=AG_E
	function knowsNonce($a in Agenti, $n in Knowledge)=if($a=agentA and $n=NA) then true else if($a=agentB and $n=NB) then true else false endif endif
	function knowsIdentityCertificate($a in Agenti, $i in Knowledge)=if($a=agentA and $i=CA) or ($a=agentA and $i=CB) or ($a=agentA and $i=CE) then true else if($a=agentB and $i=CA) or ($a=agentB and $i=CB) or ($a=agentB and $i=CE) then true else if($a=agentE and $i=CE) then true else false endif endif endif
	function knowsSymKey($a in Agenti ,$sk in Knowledge)=if(($a=agentA and $sk=KAS) or ($a=agentA and $sk=KAB) or ($a=agentB and $sk=KBS) or ($a=agentB and $sk=KEB) or ($a=agentB and $sk=KAB) or ($a=agentE and $sk=KEA) or ($a=agentE and $sk=KEB) or ($a=agentE and $sk=KES) or ($a=agentE and $sk=KAB) or ($a=agentS and $sk=KAS) or ($a=agentS and $sk=KBS) or ($a=agentS and $sk=KAB)) then true else false endif
	function mode=PASSIVE

