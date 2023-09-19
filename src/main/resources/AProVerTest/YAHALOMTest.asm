asm YAHALOMTest

import StandardLibrary
import CTLlibrary


signature:

	enum domain Agenti = {ALICE|BOB|EVE|SERVER}

// 	domain Alice subsetof Agent
// 	domain Bob subsetof Agent
// 	domain Eve subsetof Agent
// 	domain Server subsetof Agent



	enum domain StateAlice = {IDLE_REQCOM | WAITING_FRWVRNB | CHECK_END_A | END_A}
	enum domain StateBob = {WAITING_ENCKBS | CHECK_END_B | END_B}
	enum domain StateServer = {WAITING_GENKEYSES | CHECK_END_S | END_S}

	enum domain Message = {REQCOM | ENCKBS | GENKEYSES | FRWVRNB} 
// 	enum domain Knowledge ={CA|CB|KAB|KAS|KBS|KES|NA|NB}
	enum domain Knowledge ={CA|CB|KAB|KAS|KBS|KES|NA|NB|NULL}


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
	domain Level = {1}
	domain FieldPosition = {1:6}
	domain EncField1={1:6}
	domain EncField2={1:6}
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
	rule r_message_replay_REQCOM =
		//choose what agets are interested by the message
		let ($x=agentE,$b=agentB,$a=agentA) in
		  par 
			//check the reception of the message and the modality of the attack
			if(protocolMessage(0,ALICE,EVE)=REQCOM and protocolMessage(0,EVE,BOB)!=REQCOM and mode=PASSIVE)then
			        //in passive mode if the attacker knows the decryption key, the message payload is readable and it can be added to the attacker knowledge
			        // the message must be sent unaltered
		          par 
                 	protocolMessage(0,EVE,BOB):=REQCOM
                 	messageField(EVE,BOB,1,REQCOM):=messageField(ALICE,EVE,1,REQCOM)
                 	messageField(EVE,BOB,2,REQCOM):=messageField(ALICE,EVE,2,REQCOM)
                 	knowsIdentityCertificate(EVE,messageField(ALICE,EVE,1,REQCOM)):=true
                 	knowsNonce(EVE,messageField(ALICE,EVE,2,REQCOM)):=true
		          endpar 
			endif 
			        //check the reception of the message and the modality of the attack
			if(protocolMessage(0,ALICE,EVE)=REQCOM and protocolMessage(0,EVE,BOB)!=REQCOM and mode=ACTIVE)then
		          par 
                 	protocolMessage(0,EVE,BOB):=REQCOM
                 	messageField(EVE,BOB,1,REQCOM):=messageField(ALICE,EVE,1,REQCOM)
                 	messageField(EVE,BOB,2,REQCOM):=messageField(ALICE,EVE,2,REQCOM)
                 	knowsIdentityCertificate(EVE,messageField(ALICE,EVE,1,REQCOM)):=true
                 	knowsNonce(EVE,messageField(ALICE,EVE,2,REQCOM)):=true
		          endpar 
			endif 
		  endpar 
		endlet 
	rule r_message_replay_ENCKBS =
		//choose what agets are interested by the message
		let ($x=agentE,$b=agentS,$a=agentB) in
		  par 
			//check the reception of the message and the modality of the attack
			if(protocolMessage(1,BOB,EVE)=ENCKBS and protocolMessage(1,EVE,SERVER)!=ENCKBS and mode=PASSIVE)then
			        //in passive mode if the attacker knows the decryption key, the message payload is readable and it can be added to the attacker knowledge
			        // the message must be sent unaltered
		          par 
                 	protocolMessage(1,EVE,SERVER):=ENCKBS
                 	messageField(EVE,SERVER,1,ENCKBS):=messageField(BOB,EVE,1,ENCKBS)
                 	messageField(EVE,SERVER,2,ENCKBS):=messageField(BOB,EVE,2,ENCKBS)
                 	messageField(EVE,SERVER,3,ENCKBS):=messageField(BOB,EVE,3,ENCKBS)
                 	messageField(EVE,SERVER,4,ENCKBS):=messageField(BOB,EVE,4,ENCKBS)
                 	knowsIdentityCertificate(EVE,messageField(BOB,EVE,1,ENCKBS)):=true
//	        if(symDec(ENCKBS,1,2,4,EVE)=true)then
			        if(knowsSymKey(EVE,KBS)=true)then
                      par 
                    	knowsIdentityCertificate(EVE,messageField(BOB,EVE,2,ENCKBS)):=true
                    	knowsNonce(EVE,messageField(BOB,EVE,3,ENCKBS)):=true
                    	knowsNonce(EVE,messageField(BOB,EVE,4,ENCKBS)):=true
			            symEnc(ENCKBS,1,2,4):=KBS
                      endpar 
			        endif 
		          endpar 
			endif 
			        //check the reception of the message and the modality of the attack
			if(protocolMessage(1,BOB,EVE)=ENCKBS and protocolMessage(1,EVE,SERVER)!=ENCKBS and mode=ACTIVE)then
		          par 
                 	protocolMessage(1,EVE,SERVER):=ENCKBS
                 	messageField(EVE,SERVER,1,ENCKBS):=messageField(BOB,EVE,1,ENCKBS)
                 	messageField(EVE,SERVER,2,ENCKBS):=messageField(BOB,EVE,2,ENCKBS)
                 	messageField(EVE,SERVER,3,ENCKBS):=messageField(BOB,EVE,3,ENCKBS)
                 	messageField(EVE,SERVER,4,ENCKBS):=messageField(BOB,EVE,4,ENCKBS)
                 	knowsIdentityCertificate(EVE,messageField(BOB,EVE,1,ENCKBS)):=true
//			        if(symDec(ENCKBS,1,2,4,EVE)=true)then
			            if(knowsSymKey(EVE,KBS)=true)then
	   			     par 
                    	knowsIdentityCertificate(EVE,messageField(BOB,EVE,2,ENCKBS)):=true
                    	knowsNonce(EVE,messageField(BOB,EVE,3,ENCKBS)):=true
                    	knowsNonce(EVE,messageField(BOB,EVE,4,ENCKBS)):=true
			        	symEnc(ENCKBS,1,2,4):=KBS
	   			     endpar 
			        endif 
		          endpar 
			endif 
		  endpar 
		endlet 
	rule r_message_replay_GENKEYSES =
		//choose what agets are interested by the message
		let ($x=agentE,$b=agentA,$a=agentS) in
		  par 
			//check the reception of the message and the modality of the attack
			if(protocolMessage(2,SERVER,EVE)=GENKEYSES and protocolMessage(2,EVE,ALICE)!=GENKEYSES and mode=PASSIVE)then
			        //in passive mode if the attacker knows the decryption key, the message payload is readable and it can be added to the attacker knowledge
			        // the message must be sent unaltered
		          par 
                 	protocolMessage(2,EVE,ALICE):=GENKEYSES
                 	messageField(EVE,ALICE,1,GENKEYSES):=messageField(SERVER,EVE,1,GENKEYSES)
                 	messageField(EVE,ALICE,2,GENKEYSES):=messageField(SERVER,EVE,2,GENKEYSES)
                 	messageField(EVE,ALICE,3,GENKEYSES):=messageField(SERVER,EVE,3,GENKEYSES)
                 	messageField(EVE,ALICE,4,GENKEYSES):=messageField(SERVER,EVE,4,GENKEYSES)
                 	messageField(EVE,ALICE,5,GENKEYSES):=messageField(SERVER,EVE,5,GENKEYSES)
                 	messageField(EVE,ALICE,6,GENKEYSES):=messageField(SERVER,EVE,6,GENKEYSES)
//	        if(symDec(GENKEYSES,1,1,4,EVE)=true)then
			        if(knowsSymKey(EVE,KAS)=true)then
                      par 
                    	knowsIdentityCertificate(EVE,messageField(SERVER,EVE,1,GENKEYSES)):=true
                    	knowsSymKey(EVE,messageField(SERVER,EVE,2,GENKEYSES)):=true
                    	knowsNonce(EVE,messageField(SERVER,EVE,3,GENKEYSES)):=true
                    	knowsNonce(EVE,messageField(SERVER,EVE,4,GENKEYSES)):=true
			            symEnc(GENKEYSES,1,1,4):=KAS
                      endpar 
			        endif 
//	        if(symDec(GENKEYSES,1,5,6,EVE)=true)then
			        if(knowsSymKey(EVE,KBS)=true)then
                      par 
                    	knowsIdentityCertificate(EVE,messageField(SERVER,EVE,5,GENKEYSES)):=true
                    	knowsSymKey(EVE,messageField(SERVER,EVE,6,GENKEYSES)):=true
			            symEnc(GENKEYSES,1,5,6):=KBS
                      endpar 
			        endif 
		          endpar 
			endif 
			        //check the reception of the message and the modality of the attack
			if(protocolMessage(2,SERVER,EVE)=GENKEYSES and protocolMessage(2,EVE,ALICE)!=GENKEYSES and mode=ACTIVE)then
		          par 
                 	protocolMessage(2,EVE,ALICE):=GENKEYSES
                 	messageField(EVE,ALICE,1,GENKEYSES):=messageField(SERVER,EVE,1,GENKEYSES)
                 	messageField(EVE,ALICE,3,GENKEYSES):=messageField(SERVER,EVE,3,GENKEYSES)
                 	messageField(EVE,ALICE,4,GENKEYSES):=messageField(SERVER,EVE,4,GENKEYSES)
                 	messageField(EVE,ALICE,5,GENKEYSES):=messageField(SERVER,EVE,5,GENKEYSES)
//			        if(symDec(GENKEYSES,1,1,4,EVE)=true)then
			            if(knowsSymKey(EVE,KAS)=true)then
	   			     par 
			         	messageField(EVE,ALICE,2,GENKEYSES):=KES
                    	knowsIdentityCertificate(EVE,messageField(SERVER,EVE,1,GENKEYSES)):=true
                    	knowsSymKey(EVE,messageField(SERVER,EVE,2,GENKEYSES)):=true
                    	knowsNonce(EVE,messageField(SERVER,EVE,3,GENKEYSES)):=true
                    	knowsNonce(EVE,messageField(SERVER,EVE,4,GENKEYSES)):=true
			        	symEnc(GENKEYSES,1,1,4):=KAS
	   			     endpar 
			        else 
			         	messageField(EVE,ALICE,2,GENKEYSES):=messageField(SERVER,EVE,2,GENKEYSES)
			        endif 
//			        if(symDec(GENKEYSES,1,5,6,EVE)=true)then
			            if(knowsSymKey(EVE,KBS)=true)then
	   			     par 
			         	messageField(EVE,ALICE,6,GENKEYSES):=KES
                    	knowsIdentityCertificate(EVE,messageField(SERVER,EVE,5,GENKEYSES)):=true
                    	knowsSymKey(EVE,messageField(SERVER,EVE,6,GENKEYSES)):=true
			        	symEnc(GENKEYSES,1,5,6):=KBS
	   			     endpar 
			        else 
			         	messageField(EVE,ALICE,6,GENKEYSES):=messageField(SERVER,EVE,6,GENKEYSES)
			        endif 
		          endpar 
			endif 
		  endpar 
		endlet 
	rule r_message_replay_FRWVRNB =
		//choose what agets are interested by the message
		let ($x=agentE,$b=agentB,$a=agentA) in
		  par 
			//check the reception of the message and the modality of the attack
			if(protocolMessage(3,ALICE,EVE)=FRWVRNB and protocolMessage(3,EVE,BOB)!=FRWVRNB and mode=PASSIVE)then
			        //in passive mode if the attacker knows the decryption key, the message payload is readable and it can be added to the attacker knowledge
			        // the message must be sent unaltered
		          par 
                 	protocolMessage(3,EVE,BOB):=FRWVRNB
                 	messageField(EVE,BOB,1,FRWVRNB):=messageField(ALICE,EVE,1,FRWVRNB)
                 	messageField(EVE,BOB,2,FRWVRNB):=messageField(ALICE,EVE,2,FRWVRNB)
                 	messageField(EVE,BOB,3,FRWVRNB):=messageField(ALICE,EVE,3,FRWVRNB)
//	        if(symDec(FRWVRNB,1,1,2,EVE)=true)then
			        if(knowsSymKey(EVE,KBS)=true)then
                      par 
                    	knowsIdentityCertificate(EVE,messageField(ALICE,EVE,1,FRWVRNB)):=true
                    	knowsSymKey(EVE,messageField(ALICE,EVE,2,FRWVRNB)):=true
			            symEnc(FRWVRNB,1,1,2):=KBS
                      endpar 
			        endif 
//	        if(symDec(FRWVRNB,1,3,3,EVE)=true)then
			        if(knowsSymKey(EVE,KAB)=true)then
                      par 
                    	knowsNonce(EVE,messageField(ALICE,EVE,3,FRWVRNB)):=true
			            symEnc(FRWVRNB,1,3,3):=messageField(BOB,EVE,6,GENKEYSES)
                      endpar 
			        endif 
		          endpar 
			endif 
			        //check the reception of the message and the modality of the attack
			if(protocolMessage(3,ALICE,EVE)=FRWVRNB and protocolMessage(3,EVE,BOB)!=FRWVRNB and mode=ACTIVE)then
		          par 
                 	protocolMessage(3,EVE,BOB):=FRWVRNB
                 	messageField(EVE,BOB,1,FRWVRNB):=messageField(ALICE,EVE,1,FRWVRNB)
                 	messageField(EVE,BOB,3,FRWVRNB):=messageField(ALICE,EVE,3,FRWVRNB)
//			        if(symDec(FRWVRNB,1,1,2,EVE)=true)then
			            if(knowsSymKey(EVE,KBS)=true)then
	   			     par 
			         	messageField(EVE,BOB,2,FRWVRNB):=KES
                    	knowsIdentityCertificate(EVE,messageField(ALICE,EVE,1,FRWVRNB)):=true
                    	knowsSymKey(EVE,messageField(ALICE,EVE,2,FRWVRNB)):=true
			        	symEnc(FRWVRNB,1,1,2):=KBS
	   			     endpar 
			        else 
			         	messageField(EVE,BOB,2,FRWVRNB):=messageField(ALICE,EVE,2,FRWVRNB)
			        endif 
//			        if(symDec(FRWVRNB,1,3,3,EVE)=true)then
			            if(knowsSymKey(EVE,KAB)=true)then
	   			     par 
                    	knowsNonce(EVE,messageField(ALICE,EVE,3,FRWVRNB)):=true
			        	symEnc(FRWVRNB,1,3,3):=KES
	   			     endpar 
			        endif 
		          endpar 
			endif 
		  endpar 
		endlet 

	/*HONEST AGENT RULES*/	
	rule r_message_REQCOM =
		let ($x=agentA,$e=agentE) in
			if(internalStateA=IDLE_REQCOM)then 
			   if(receiver!=AG_E)then
			     par
			         protocolMessage(0,ALICE,EVE):=REQCOM
			         messageField(ALICE,EVE,1,REQCOM):=CA
			         messageField(ALICE,EVE,2,REQCOM):=NA
			         internalStateA:=WAITING_FRWVRNB
			     endpar
			   else
			       if(receiver=AG_E)then
			         par
			            protocolMessage(0,ALICE,EVE):=REQCOM
			            messageField(ALICE,EVE,1,REQCOM):=CA
			            messageField(ALICE,EVE,2,REQCOM):=NA
			            internalStateA:=WAITING_FRWVRNB
			         endpar
			       endif
			   endif
			endif
		endlet
	rule r_message_ENCKBS =
		let ($x=agentB,$e=agentE) in
			if(internalStateB=WAITING_ENCKBS and protocolMessage(0,EVE,BOB)=REQCOM)then
			   if(receiver!=AG_E)then
			          par
			            knowsIdentityCertificate(BOB,messageField(EVE,BOB,1,REQCOM)):=true
			            knowsNonce(BOB,messageField(EVE,BOB,2,REQCOM)):=true
			            protocolMessage(1,BOB,EVE):=ENCKBS
			            messageField(BOB,EVE,1,ENCKBS):=CB
			            messageField(BOB,EVE,2,ENCKBS):=messageField(EVE,BOB,1,REQCOM)
			            messageField(BOB,EVE,3,ENCKBS):=messageField(EVE,BOB,2,REQCOM)
			            messageField(BOB,EVE,4,ENCKBS):=NB
			            symEnc(ENCKBS,1,2,4):=KBS
			            internalStateB:=CHECK_END_B
			          endpar
			   else
			          par
			            knowsIdentityCertificate(BOB,messageField(EVE,BOB,1,REQCOM)):=true
			            knowsNonce(BOB,messageField(EVE,BOB,2,REQCOM)):=true
			            protocolMessage(1,BOB,EVE):=ENCKBS
			            messageField(BOB,EVE,1,ENCKBS):=CB
			            messageField(BOB,EVE,2,ENCKBS):=messageField(EVE,BOB,1,REQCOM)
			            messageField(BOB,EVE,3,ENCKBS):=messageField(EVE,BOB,2,REQCOM)
			            messageField(BOB,EVE,4,ENCKBS):=NB
			            symEnc(ENCKBS,1,2,4):=KBS
			            internalStateB:=CHECK_END_B
			         endpar
			   endif
			endif
		endlet
	rule r_message_GENKEYSES =
		let ($x=agentS,$e=agentE) in
			if(internalStateS=WAITING_GENKEYSES and protocolMessage(1,EVE,SERVER)=ENCKBS)then
			   if(receiver!=AG_E)then
			    par
			            knowsIdentityCertificate(SERVER,messageField(EVE,SERVER,1,ENCKBS)):=true
			        if(knowsSymKey(SERVER,KBS)=true ) then
			          par
			            knowsIdentityCertificate(SERVER,messageField(EVE,SERVER,2,ENCKBS)):=true
			            knowsNonce(SERVER,messageField(EVE,SERVER,3,ENCKBS)):=true
			            knowsNonce(SERVER,messageField(EVE,SERVER,4,ENCKBS)):=true
			            protocolMessage(2,SERVER,EVE):=GENKEYSES
			            messageField(SERVER,EVE,1,GENKEYSES):=messageField(EVE,SERVER,1,ENCKBS)
			            messageField(SERVER,EVE,2,GENKEYSES):=KAB
			            messageField(SERVER,EVE,3,GENKEYSES):=messageField(EVE,SERVER,3,ENCKBS)
			            messageField(SERVER,EVE,4,GENKEYSES):=messageField(EVE,SERVER,4,ENCKBS)
			            symEnc(GENKEYSES,1,1,4):=KAS
			            messageField(SERVER,EVE,5,GENKEYSES):=messageField(EVE,SERVER,2,ENCKBS)
			            messageField(SERVER,EVE,6,GENKEYSES):=KAB
			            symEnc(GENKEYSES,1,5,6):=KBS
			            internalStateS:=END_S
			          endpar
			        endif
			    endpar
			   else
			    par
			            knowsIdentityCertificate(SERVER,messageField(EVE,SERVER,1,ENCKBS)):=true
			        if(knowsSymKey(SERVER,KBS)=true  and receiver=AG_E) then
			          par
			            knowsIdentityCertificate(SERVER,messageField(EVE,SERVER,2,ENCKBS)):=true
			            knowsNonce(SERVER,messageField(EVE,SERVER,3,ENCKBS)):=true
			            knowsNonce(SERVER,messageField(EVE,SERVER,4,ENCKBS)):=true
			            protocolMessage(2,SERVER,EVE):=GENKEYSES
			            messageField(SERVER,EVE,1,GENKEYSES):=messageField(EVE,SERVER,1,ENCKBS)
			            messageField(SERVER,EVE,2,GENKEYSES):=KAB
			            messageField(SERVER,EVE,3,GENKEYSES):=messageField(EVE,SERVER,3,ENCKBS)
			            messageField(SERVER,EVE,4,GENKEYSES):=messageField(EVE,SERVER,4,ENCKBS)
			            symEnc(GENKEYSES,1,1,4):=KAS
			            messageField(SERVER,EVE,5,GENKEYSES):=messageField(EVE,SERVER,2,ENCKBS)
			            messageField(SERVER,EVE,6,GENKEYSES):=KAB
			            symEnc(GENKEYSES,1,5,6):=KBS
			            internalStateS:=END_S
			         endpar
			        endif
			    endpar
			   endif
			endif
		endlet
	rule r_message_FRWVRNB =
		let ($x=agentA,$e=agentE) in
			if(internalStateA=WAITING_FRWVRNB and protocolMessage(2,EVE,ALICE)=GENKEYSES)then
			   if(receiver!=AG_E)then
			        if(knowsSymKey(ALICE,KAS)=true ) then
			          par
			            knowsIdentityCertificate(ALICE,messageField(EVE,ALICE,1,GENKEYSES)):=true
			            knowsSymKey(ALICE,messageField(EVE,ALICE,2,GENKEYSES)):=true
			            knowsNonce(ALICE,messageField(EVE,ALICE,3,GENKEYSES)):=true
			            knowsNonce(ALICE,messageField(EVE,ALICE,4,GENKEYSES)):=true
			            protocolMessage(3,ALICE,EVE):=FRWVRNB
			            messageField(ALICE,EVE,1,FRWVRNB):=messageField(EVE,ALICE,5,GENKEYSES)
			            messageField(ALICE,EVE,2,FRWVRNB):=messageField(EVE,ALICE,6,GENKEYSES)
			            symEnc(FRWVRNB,1,1,2):=KBS
			            messageField(ALICE,EVE,3,FRWVRNB):=messageField(EVE,ALICE,4,GENKEYSES)
			            symEnc(FRWVRNB,1,3,3):=messageField(EVE,ALICE,6,GENKEYSES)
			            internalStateA:=END_A
			          endpar
			        endif
			   else
			        if(knowsSymKey(ALICE,KAS)=true  and receiver=AG_E) then
			          par
			            knowsIdentityCertificate(ALICE,messageField(EVE,ALICE,1,GENKEYSES)):=true
			            knowsSymKey(ALICE,messageField(EVE,ALICE,2,GENKEYSES)):=true
			            knowsNonce(ALICE,messageField(EVE,ALICE,3,GENKEYSES)):=true
			            knowsNonce(ALICE,messageField(EVE,ALICE,4,GENKEYSES)):=true
			            protocolMessage(3,ALICE,EVE):=FRWVRNB
			            messageField(ALICE,EVE,1,FRWVRNB):=messageField(EVE,ALICE,5,GENKEYSES)
			            messageField(ALICE,EVE,2,FRWVRNB):=messageField(EVE,ALICE,6,GENKEYSES)
			            symEnc(FRWVRNB,1,1,2):=KBS
			            messageField(ALICE,EVE,3,FRWVRNB):=messageField(EVE,ALICE,4,GENKEYSES)
			            symEnc(FRWVRNB,1,3,3):=messageField(EVE,ALICE,6,GENKEYSES)
			            internalStateA:=END_A
			         endpar
			        endif
			   endif
			endif
		endlet
	rule r_check_FRWVRNB =
		let ($x=agentB,$e=agentE) in
			if(internalStateB=CHECK_END_B and protocolMessage(3,EVE,BOB)=FRWVRNB)then
			  par
			        internalStateB:=END_B
//		        if(symDec(FRWVRNB,1,1,2,BOB)=true)then
			        if(knowsSymKey(BOB,KBS)=true)then
                      par 
                    	knowsIdentityCertificate(BOB,messageField(EVE,BOB,1,FRWVRNB)):=true
                    	knowsSymKey(BOB,messageField(EVE,BOB,2,FRWVRNB)):=true
                      endpar 
			        endif 
//		        if(symDec(FRWVRNB,1,3,3,BOB)=true)then
			        if(knowsSymKey(BOB,KAB)=true)then
                    	knowsNonce(BOB,messageField(EVE,BOB,3,FRWVRNB)):=true
			        endif 
			  endpar
			endif
		endlet

// properties TAB=0 COL=0
  CTLSPEC ef(knowsNonce(BOB,NB))
	main rule r_Main =
	  par
            r_message_replay_REQCOM[]
            r_message_replay_ENCKBS[]
            r_message_replay_GENKEYSES[]
            r_message_replay_FRWVRNB[]
            r_message_REQCOM[]
            r_message_ENCKBS[]
            r_message_GENKEYSES[]
            r_message_FRWVRNB[]
            r_check_FRWVRNB[]
	  endpar

default init s0:
	function agentA=ALICE 
	function agentB=BOB 
	function agentE=EVE 
	function agentS=SERVER 
	function internalStateA=IDLE_REQCOM
	function internalStateB=WAITING_ENCKBS
	function internalStateS=WAITING_GENKEYSES
	function receiver=AG_E
	function knowsNonce($a in Agenti, $n in Knowledge)=if($a=agentA and $n=NA) then true else if($a=agentB and $n=NB) then true else false endif endif
	function knowsIdentityCertificate($a in Agenti, $i in Knowledge)=if($a=agentA and $i=CA) then true else if($a=agentB and $i=CA) or ($a=agentB and $i=CB) then true else if($a=agentS and $i=CB) then true else false endif endif endif
	function knowsSymKey($a in Agenti ,$sk in Knowledge)=if(($a=agentA and $sk=KAS) or ($a=agentB and $sk=KBS) or ($a=agentE and $sk=KES) or ($a=agentS and $sk=KAB) or ($a=agentS and $sk=KBS) or ($a=agentS and $sk=KAS)) then true else false endif
	function mode=PASSIVE

