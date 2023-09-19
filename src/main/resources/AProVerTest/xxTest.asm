asm xxTest

import StandardLibrary
import CTLlibrary


signature:

	enum domain Agenti = {ALICE|BOB|EVE|SERVER}

// 	domain Alice subsetof Agent
// 	domain Bob subsetof Agent
// 	domain Eve subsetof Agent
// 	domain Server subsetof Agent



	enum domain StateAlice = {IDLE_MA | CHECK_END_A | END_A}
	enum domain StateBob = {WAITING_MB | WAITING_MD | CHECK_END_B | END_B}
	enum domain StateEve = {WAITING_MC | WAITING_MF | CHECK_END_E | END_E}
	enum domain StateServer = {WAITING_ME | CHECK_END_S | END_S}

	enum domain Message = {MA | MB | MC | MD | ME | MF} 
// 	enum domain Knowledge ={CA|CB|KAB|KAS|KBS|KNA|NA|NB|NB2}
	enum domain Knowledge ={CA|CB|KAB|KAS|KBS|KNA|NA|NB|NB2|NULL}


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
// 	controlled internalStateE: Eve -> StateEve
	controlled internalStateE: StateEve
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
	domain Level = {1}
	domain FieldPosition = {1:7}
	domain EncField1={1:7}
	domain EncField2={1:7}
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
		let ($x=agentE,$b=agentB,$a=agentA) in
		  par 
			//check the reception of the message and the modality of the attack
			if(protocolMessage(0,ALICE,EVE)=MA and protocolMessage(0,EVE,BOB)!=MA and mode=PASSIVE)then
			        //in passive mode if the attacker knows the decryption key, the message payload is readable and it can be added to the attacker knowledge
			        // the message must be sent unaltered
		          par 
                 	protocolMessage(0,EVE,BOB):=MA
                 	messageField(EVE,BOB,1,MA):=messageField(ALICE,EVE,1,MA)
                 	messageField(EVE,BOB,2,MA):=messageField(ALICE,EVE,2,MA)
                 	knowsIdentityCertificate(EVE,messageField(ALICE,EVE,1,MA)):=true
                 	knowsNonce(EVE,messageField(ALICE,EVE,2,MA)):=true
		          endpar 
			endif 
			        //check the reception of the message and the modality of the attack
			if(protocolMessage(0,ALICE,EVE)=MA and protocolMessage(0,EVE,BOB)!=MA and mode=ACTIVE)then
		          par 
                 	protocolMessage(0,EVE,BOB):=MA
                 	messageField(EVE,BOB,1,MA):=messageField(ALICE,EVE,1,MA)
                 	messageField(EVE,BOB,2,MA):=messageField(ALICE,EVE,2,MA)
                 	knowsIdentityCertificate(EVE,messageField(ALICE,EVE,1,MA)):=true
                 	knowsNonce(EVE,messageField(ALICE,EVE,2,MA)):=true
		          endpar 
			endif 
		  endpar 
		endlet 
	rule r_message_replay_MB =
		//choose what agets are interested by the message
		let ($x=agentE,$b=agentS,$a=agentB) in
		  par 
			//check the reception of the message and the modality of the attack
			if(protocolMessage(1,BOB,EVE)=MB and protocolMessage(1,EVE,SERVER)!=MB and mode=PASSIVE)then
			        //in passive mode if the attacker knows the decryption key, the message payload is readable and it can be added to the attacker knowledge
			        // the message must be sent unaltered
		          par 
                 	protocolMessage(1,EVE,SERVER):=MB
                 	messageField(EVE,SERVER,1,MB):=messageField(BOB,EVE,1,MB)
                 	messageField(EVE,SERVER,2,MB):=messageField(BOB,EVE,2,MB)
                 	messageField(EVE,SERVER,3,MB):=messageField(BOB,EVE,3,MB)
                 	messageField(EVE,SERVER,4,MB):=messageField(BOB,EVE,4,MB)
                 	knowsIdentityCertificate(EVE,messageField(BOB,EVE,1,MB)):=true
                 	knowsNonce(EVE,messageField(BOB,EVE,2,MB)):=true
//	        if(symDec(MB,1,3,4,EVE)=true)then
			        if(knowsSymKey(EVE,KBS)=true)then
                      par 
                    	knowsIdentityCertificate(EVE,messageField(BOB,EVE,3,MB)):=true
                    	knowsNonce(EVE,messageField(BOB,EVE,4,MB)):=true
			            symEnc(MB,1,3,4):=KBS
                      endpar 
			        endif 
		          endpar 
			endif 
			        //check the reception of the message and the modality of the attack
			if(protocolMessage(1,BOB,EVE)=MB and protocolMessage(1,EVE,SERVER)!=MB and mode=ACTIVE)then
		          par 
                 	protocolMessage(1,EVE,SERVER):=MB
                 	messageField(EVE,SERVER,1,MB):=messageField(BOB,EVE,1,MB)
                 	messageField(EVE,SERVER,2,MB):=messageField(BOB,EVE,2,MB)
                 	messageField(EVE,SERVER,3,MB):=messageField(BOB,EVE,3,MB)
                 	messageField(EVE,SERVER,4,MB):=messageField(BOB,EVE,4,MB)
                 	knowsIdentityCertificate(EVE,messageField(BOB,EVE,1,MB)):=true
                 	knowsNonce(EVE,messageField(BOB,EVE,2,MB)):=true
//			        if(symDec(MB,1,3,4,EVE)=true)then
			            if(knowsSymKey(EVE,KBS)=true)then
	   			     par 
                    	knowsIdentityCertificate(EVE,messageField(BOB,EVE,3,MB)):=true
                    	knowsNonce(EVE,messageField(BOB,EVE,4,MB)):=true
			        	symEnc(MB,1,3,4):=KBS
	   			     endpar 
			        endif 
		          endpar 
			endif 
		  endpar 
		endlet 
	rule r_message_replay_ME =
		//choose what agets are interested by the message
		let ($x=agentE,$b=agentA,$a=agentS) in
		  par 
			//check the reception of the message and the modality of the attack
			if(protocolMessage(4,SERVER,EVE)=ME and protocolMessage(4,EVE,ALICE)!=ME and mode=PASSIVE)then
			        //in passive mode if the attacker knows the decryption key, the message payload is readable and it can be added to the attacker knowledge
			        // the message must be sent unaltered
			          par
			            knowsIdentityCertificate(EVE,messageField(agentB,EVE,1,MD)):=true
			            knowsNonce(EVE,messageField(agentB,EVE,2,MD)):=true
                 	protocolMessage(4,EVE,ALICE):=ME
                 	messageField(EVE,ALICE,1,ME):=messageField(SERVER,EVE,1,ME)
                 	messageField(EVE,ALICE,2,ME):=messageField(SERVER,EVE,2,ME)
                 	messageField(EVE,ALICE,3,ME):=messageField(SERVER,EVE,3,ME)
                 	messageField(EVE,ALICE,4,ME):=messageField(SERVER,EVE,4,ME)
                 	messageField(EVE,ALICE,5,ME):=messageField(SERVER,EVE,5,ME)
                 	messageField(EVE,ALICE,6,ME):=messageField(SERVER,EVE,6,ME)
                 	messageField(EVE,ALICE,7,ME):=messageField(SERVER,EVE,7,ME)
                 	knowsNonce(EVE,messageField(SERVER,EVE,1,ME)):=true
//	        if(symDec(ME,1,2,4,EVE)=true)then
			        if(knowsSymKey(EVE,KAS)=true)then
                      par 
                    	knowsIdentityCertificate(EVE,messageField(SERVER,EVE,2,ME)):=true
                    	knowsSymKey(EVE,messageField(SERVER,EVE,3,ME)):=true
                    	knowsNonce(EVE,messageField(SERVER,EVE,4,ME)):=true
			            symEnc(ME,1,2,4):=KAS
                      endpar 
			        endif 
//	        if(symDec(ME,1,5,7,EVE)=true)then
			        if(knowsSymKey(EVE,KBS)=true)then
                      par 
                    	knowsIdentityCertificate(EVE,messageField(SERVER,EVE,5,ME)):=true
                    	knowsSymKey(EVE,messageField(SERVER,EVE,6,ME)):=true
                    	knowsNonce(EVE,messageField(SERVER,EVE,7,ME)):=true
			            symEnc(ME,1,5,7):=KBS
                      endpar 
			        endif 
		          endpar 
			endif 
			        //check the reception of the message and the modality of the attack
			if(protocolMessage(4,SERVER,EVE)=ME and protocolMessage(4,EVE,ALICE)!=ME and mode=ACTIVE)then
			          par
			            knowsIdentityCertificate(EVE,messageField(agentB,EVE,1,MD)):=true
			            knowsNonce(EVE,messageField(agentB,EVE,2,MD)):=true
                 	protocolMessage(4,EVE,ALICE):=ME
                 	messageField(EVE,ALICE,1,ME):=messageField(SERVER,EVE,1,ME)
                 	messageField(EVE,ALICE,2,ME):=messageField(SERVER,EVE,2,ME)
                 	messageField(EVE,ALICE,4,ME):=messageField(SERVER,EVE,4,ME)
                 	messageField(EVE,ALICE,5,ME):=messageField(SERVER,EVE,5,ME)
                 	messageField(EVE,ALICE,7,ME):=messageField(SERVER,EVE,7,ME)
                 	knowsNonce(EVE,messageField(SERVER,EVE,1,ME)):=true
//			        if(symDec(ME,1,2,4,EVE)=true)then
			            if(knowsSymKey(EVE,KAS)=true)then
	   			     par 
			         	messageField(EVE,ALICE,3,ME):=KNA
                    	knowsIdentityCertificate(EVE,messageField(SERVER,EVE,2,ME)):=true
                    	knowsSymKey(EVE,messageField(SERVER,EVE,3,ME)):=true
                    	knowsNonce(EVE,messageField(SERVER,EVE,4,ME)):=true
			        	symEnc(ME,1,2,4):=KAS
	   			     endpar 
			        else 
			         	messageField(EVE,ALICE,3,ME):=messageField(SERVER,EVE,3,ME)
			        endif 
//			        if(symDec(ME,1,5,7,EVE)=true)then
			            if(knowsSymKey(EVE,KBS)=true)then
	   			     par 
			         	messageField(EVE,ALICE,6,ME):=KNA
                    	knowsIdentityCertificate(EVE,messageField(SERVER,EVE,5,ME)):=true
                    	knowsSymKey(EVE,messageField(SERVER,EVE,6,ME)):=true
                    	knowsNonce(EVE,messageField(SERVER,EVE,7,ME)):=true
			        	symEnc(ME,1,5,7):=KBS
	   			     endpar 
			        else 
			         	messageField(EVE,ALICE,6,ME):=messageField(SERVER,EVE,6,ME)
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
			         messageField(ALICE,EVE,2,MA):=NA
			         internalStateA:=CHECK_END_A
			     endpar
			   else
			       if(receiver=AG_E)then
			         par
			            protocolMessage(0,ALICE,EVE):=MA
			            messageField(ALICE,EVE,1,MA):=CA
			            messageField(ALICE,EVE,2,MA):=NA
			            internalStateA:=CHECK_END_A
			         endpar
			       endif
			   endif
			endif
		endlet
	rule r_message_MB =
		let ($x=agentB,$e=agentE) in
			if(internalStateB=WAITING_MB and protocolMessage(0,EVE,BOB)=MA)then
			   if(receiver!=AG_E)then
			          par
			            knowsIdentityCertificate(BOB,messageField(EVE,BOB,1,MA)):=true
			            knowsNonce(BOB,messageField(EVE,BOB,2,MA)):=true
			            protocolMessage(1,BOB,EVE):=MB
			            messageField(BOB,EVE,1,MB):=CB
			            messageField(BOB,EVE,2,MB):=NB
			            messageField(BOB,EVE,3,MB):=messageField(EVE,BOB,1,MA)
			            messageField(BOB,EVE,4,MB):=messageField(EVE,BOB,2,MA)
			            symEnc(MB,1,3,4):=KBS
			            internalStateB:=WAITING_MD
			          endpar
			   else
			          par
			            knowsIdentityCertificate(BOB,messageField(EVE,BOB,1,MA)):=true
			            knowsNonce(BOB,messageField(EVE,BOB,2,MA)):=true
			            protocolMessage(1,BOB,EVE):=MB
			            messageField(BOB,EVE,1,MB):=CB
			            messageField(BOB,EVE,2,MB):=NB
			            messageField(BOB,EVE,3,MB):=messageField(EVE,BOB,1,MA)
			            messageField(BOB,EVE,4,MB):=messageField(EVE,BOB,2,MA)
			            symEnc(MB,1,3,4):=KBS
			            internalStateB:=WAITING_MD
			         endpar
			   endif
			endif
		endlet
	rule r_message_MC =
		let ($x=agentE,$b=agentB,$t=agentS) in
			if(internalStateE=WAITING_MC and protocolMessage(1,EVE,SERVER)=MB)then
			     par
			            protocolMessage(2,EVE,BOB):=MC
			            messageField(EVE,BOB,1,MC):=messageField(agentA,EVE,1,MA)
			            messageField(EVE,BOB,2,MC):=KNA
			            messageField(EVE,BOB,3,MC):=messageField(BOB,EVE,2,MB)
			            internalStateE:=WAITING_MF
			          endpar
			   endif
		endlet
	rule r_message_MD =
		let ($x=agentB,$e=agentE) in
			if(internalStateB=WAITING_MD and protocolMessage(2,EVE,BOB)=MC)then
			          par
			            knowsSymKey(BOB,messageField(EVE,BOB,2,MC)):=true
			            knowsNonce(BOB,messageField(EVE,BOB,3,MC)):=true
			            protocolMessage(3,BOB,EVE):=MD
			            messageField(BOB,EVE,1,MD):=CB
			            messageField(BOB,EVE,2,MD):=NB2
			            messageField(BOB,EVE,3,MD):=messageField(EVE,BOB,1,MC)
			            messageField(BOB,EVE,4,MD):=messageField(EVE,BOB,2,MC)
			            messageField(BOB,EVE,5,MD):=messageField(EVE,BOB,3,MC)
			            symEnc(MD,1,3,5):=KBS
			            internalStateB:=CHECK_END_B
			          endpar
			   endif
		endlet
	rule r_message_ME =
		let ($x=agentS,$e=agentE,$f=agentB) in
			if(internalStateS=WAITING_ME and protocolMessage(3,BOB,EVE)=MD)then
			   if(receiver!=AG_E)then
			    par
			            knowsIdentityCertificate(SERVER,messageField(EVE,SERVER,1,MB)):=true
			            knowsNonce(SERVER,messageField(EVE,SERVER,2,MB)):=true
			        if(knowsSymKey(SERVER,KBS)=true ) then
			          par
			            knowsIdentityCertificate(SERVER,messageField(EVE,SERVER,3,MB)):=true
			            knowsNonce(SERVER,messageField(EVE,SERVER,4,MB)):=true
			            protocolMessage(4,SERVER,EVE):=ME
			            messageField(SERVER,EVE,1,ME):=messageField(EVE,SERVER,2,MB)
			            messageField(SERVER,EVE,2,ME):=messageField(EVE,SERVER,1,MB)
			            messageField(SERVER,EVE,3,ME):=KAB
			            messageField(SERVER,EVE,4,ME):=messageField(EVE,SERVER,4,MB)
			            symEnc(ME,1,2,4):=KAS
			            messageField(SERVER,EVE,5,ME):=messageField(EVE,SERVER,3,MB)
			            messageField(SERVER,EVE,6,ME):=KAB
			            messageField(SERVER,EVE,7,ME):=messageField(EVE,SERVER,2,MB)
			            symEnc(ME,1,5,7):=KBS
			            internalStateS:=END_S
			          endpar
			        endif
			    endpar
			   else
			    par
			            knowsIdentityCertificate(SERVER,messageField(EVE,SERVER,1,MB)):=true
			            knowsNonce(SERVER,messageField(EVE,SERVER,2,MB)):=true
			        if(knowsSymKey(SERVER,KBS)=true  and receiver=AG_E) then
			          par
			            knowsIdentityCertificate(SERVER,messageField(EVE,SERVER,3,MB)):=true
			            knowsNonce(SERVER,messageField(EVE,SERVER,4,MB)):=true
			            protocolMessage(4,SERVER,EVE):=ME
			            messageField(SERVER,EVE,1,ME):=messageField(EVE,SERVER,2,MB)
			            messageField(SERVER,EVE,2,ME):=messageField(EVE,SERVER,1,MB)
			            messageField(SERVER,EVE,3,ME):=KAB
			            messageField(SERVER,EVE,4,ME):=messageField(EVE,SERVER,4,MB)
			            symEnc(ME,1,2,4):=KAS
			            messageField(SERVER,EVE,5,ME):=messageField(EVE,SERVER,3,MB)
			            messageField(SERVER,EVE,6,ME):=KAB
			            messageField(SERVER,EVE,7,ME):=messageField(EVE,SERVER,2,MB)
			            symEnc(ME,1,5,7):=KBS
			            internalStateS:=END_S
			         endpar
			        endif
			    endpar
			   endif
			endif
		endlet
	rule r_message_MF =
		let ($x=agentE,$b=agentB,$t=agentA) in
			if(internalStateE=WAITING_MF and protocolMessage(4,EVE,ALICE)=ME)then
			     par
			            protocolMessage(5,EVE,BOB):=MF
			            messageField(EVE,BOB,1,MF):=messageField(BOB,EVE,3,MD)
			            messageField(EVE,BOB,2,MF):=messageField(BOB,EVE,4,MD)
			            messageField(EVE,BOB,3,MF):=messageField(BOB,EVE,5,MD)
			            symEnc(MF,1,1,3):=KBS
			            messageField(EVE,BOB,4,MF):=messageField(BOB,EVE,5,MD)
			            symEnc(MF,1,4,4):=messageField(EVE,BOB,2,MC)
			            internalStateE:=END_E
			          endpar
			   endif
		endlet
	rule r_check_ME =
		let ($x=agentA,$e=agentE ,$t=agentB) in
			if(internalStateA=CHECK_END_A and protocolMessage(4,EVE,ALICE)=ME and protocolMessage(5,$e,$t)=MF)then
			  par
			        internalStateA:=END_A
                 	knowsNonce(ALICE,messageField(EVE,ALICE,1,ME)):=true
//		        if(symDec(ME,1,2,4,ALICE)=true)then
			        if(knowsSymKey(ALICE,KAS)=true)then
                      par 
                    	knowsIdentityCertificate(ALICE,messageField(EVE,ALICE,2,ME)):=true
                    	knowsSymKey(ALICE,messageField(EVE,ALICE,3,ME)):=true
                    	knowsNonce(ALICE,messageField(EVE,ALICE,4,ME)):=true
                      endpar 
			        endif 
//		        if(symDec(ME,1,5,7,ALICE)=true)then
			        if(knowsSymKey(ALICE,KBS)=true)then
                      par 
                    	knowsIdentityCertificate(ALICE,messageField(EVE,ALICE,5,ME)):=true
                    	knowsSymKey(ALICE,messageField(EVE,ALICE,6,ME)):=true
                    	knowsNonce(ALICE,messageField(EVE,ALICE,7,ME)):=true
                      endpar 
			        endif 
			  endpar
			endif
		endlet
	rule r_check_MF =
		let ($x=agentB,$e=agentE) in
			if(internalStateB=CHECK_END_B and protocolMessage(5,EVE,BOB)=MF)then
			  par
			        internalStateB:=END_B
//		        if(symDec(MF,1,1,3,BOB)=true)then
			        if(knowsSymKey(BOB,KBS)=true)then
                      par 
                    	knowsIdentityCertificate(BOB,messageField(EVE,BOB,1,MF)):=true
                    	knowsSymKey(BOB,messageField(EVE,BOB,2,MF)):=true
                    	knowsNonce(BOB,messageField(EVE,BOB,3,MF)):=true
                      endpar 
			        endif 
//		        if(symDec(MF,1,3,3,BOB)=true)then
			        if(knowsSymKey(BOB,KNA)=true)then
                    	knowsNonce(BOB,messageField(EVE,BOB,4,MF)):=true
			        endif 
			  endpar
			endif
		endlet

// properties TAB=0 COL=0
  CTLSPEC ef(knowsNonce(EVE,NB))
// properties TAB=0 COL=1
  CTLSPEC not(ef(knowsNonce(EVE,NB)))
// properties TAB=0 COL=2
  CTLSPEC ef(knowsSymKey(BOB,KNA))
// properties TAB=1 COL=0
  CTLSPEC not(ef(messageField(ALICE,EVE,1,MA)!=messageField(EVE,BOB,1,MA)))
// properties TAB=2 COL=0
  CTLSPEC ef(knowsSymKey(BOB,KBS) and knowsSymKey(SERVER,KBS)) implies ag(not(knowsSymKey(EVE,KBS)))
	main rule r_Main =
	  par
            r_message_replay_MA[]
            r_message_replay_MB[]
            r_message_replay_ME[]
            r_message_MA[]
            r_message_MB[]
            r_message_MC[]
            r_message_MD[]
            r_message_ME[]
            r_message_MF[]
            r_check_ME[]
            r_check_MF[]
	  endpar

default init s0:
	function agentA=ALICE 
	function agentB=BOB 
	function agentE=EVE 
	function agentS=SERVER 
	function internalStateA=IDLE_MA
	function internalStateB=WAITING_MB
	function internalStateS=WAITING_ME
	function internalStateE=WAITING_MC
	function receiver=AG_E
	function knowsNonce($a in Agenti, $n in Knowledge)=if($a=agentA and $n=NA) then true else if($a=agentB and $n=NB) or ($a=agentB and $n=NB2) then true else false endif endif
	function knowsIdentityCertificate($a in Agenti, $i in Knowledge)=if($a=agentA and $i=CA) then true else if($a=agentB and $i=CB) then true else false endif endif
	function knowsSymKey($a in Agenti ,$sk in Knowledge)=if(($a=agentA and $sk=KAS) or ($a=agentB and $sk=KBS) or ($a=agentE and $sk=KNA) or ($a=agentS and $sk=KAB) or ($a=agentS and $sk=KBS) or ($a=agentS and $sk=KAS)) then true else false endif
	function mode=PASSIVE

