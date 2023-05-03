asm Needham_SchroederXTest

import StandardLibrary
import CTLlibrary


signature:

	enum domain Agenti = {ALICE|BOB|EVE}

// 	domain Alice subsetof Agent
// 	domain Bob subsetof Agent
// 	domain Eve subsetof Agent



	enum domain StateAlice = {IDLE_NAK | WAITING_NK | CHECK_END_A | END_A}
	enum domain StateBob = {WAITING_NNK | CHECK_END_B | END_B}

	enum domain Message = {NAK | NNK | NK} 
// 	enum domain Knowledge ={ID_A|ID_B|ID_E|NA|NB|NE|PRIVKA|PRIVKB|PRIVKE|PUBKA|PUBKB|PUBKE}
	enum domain Knowledge ={ID_A|ID_B|ID_E|NA|NB|NE|PRIVKA|PRIVKB|PRIVKE|PUBKA|PUBKB|PUBKE|NULL}


	//DOMAIN OF POSSIBLE RECEIVER
	enum domain Receiver={AG_A|AG_B|AG_E}
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


	controlled agentA: Agenti 
	controlled agentB: Agenti 
	controlled agentE: Agenti 

definitions:
	domain Level = {1}
	domain FieldPosition = {1:2}
	domain EncField1={1}
	domain EncField2={2}
	domain NumMsg={0:15}
	domain SignField1={1}
	domain SignField2={2}
	domain HashField1={1}
	domain HashField2={2}

	function asim_keyAssociation($a in Knowledge)=
	       switch( $a )
	              case PUBKA: PRIVKA
	              case PUBKB: PRIVKB
	              case PUBKE: PRIVKE
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
	rule r_message_replay_NAK =
		//choose what agets are interested by the message
		let ($x=agentE,$b=agentB,$a=agentA) in
		  par 
			//check the reception of the message and the modality of the attack
			if(protocolMessage(0,$a,$x)=NAK and protocolMessage(0,$x,$b)!=NAK and mode=PASSIVE)then
			        //in passive mode if the attacker knows the decryption key, the message payload is readable and it can be added to the attacker knowledge
			        // the message must be sent unaltered
		          par 
                 	protocolMessage(0,$x,$b):=NAK
                 	messageField($x,$b,1,NAK):=messageField($a,$x,1,NAK)
                 	messageField($x,$b,2,NAK):=messageField($a,$x,2,NAK)
			        if(asymDec(NAK,1,1,2,$x)=true)then
                      par 
                    	knowsNonce($x,messageField($a,$x,1,NAK)):=true
                    	knowsIdentityCertificate($x,messageField($a,$x,2,NAK)):=true
			            asymEnc(NAK,1,1,2):=PUBKB
                      endpar 
			        endif 
		          endpar 
			endif 
			        //check the reception of the message and the modality of the attack
			if(protocolMessage(0,$a,$x)=NAK and protocolMessage(0,$x,$b)!=NAK and mode=ACTIVE)then
		          par 
                 	protocolMessage(0,$x,$b):=NAK
                 	messageField($x,$b,1,NAK):=messageField($a,$x,1,NAK)
                 	messageField($x,$b,2,NAK):=messageField($a,$x,2,NAK)
			        if(asymDec(NAK,1,1,2,$x)=true)then
	   			     par 
                    	knowsNonce($x,messageField($a,$x,1,NAK)):=true
                    	knowsIdentityCertificate($x,messageField($a,$x,2,NAK)):=true
			        	asymEnc(NAK,1,1,2):=PUBKB
	   			     endpar 
			        endif 
		          endpar 
			endif 
		  endpar 
		endlet 
	rule r_message_replay_NNK =
		//choose what agets are interested by the message
		let ($x=agentE,$b=agentA,$a=agentB) in
		  par 
			//check the reception of the message and the modality of the attack
			if(protocolMessage(1,$a,$x)=NNK and protocolMessage(1,$x,$b)!=NNK and mode=PASSIVE)then
			        //in passive mode if the attacker knows the decryption key, the message payload is readable and it can be added to the attacker knowledge
			        // the message must be sent unaltered
		          par 
                 	protocolMessage(1,$x,$b):=NNK
                 	messageField($x,$b,1,NNK):=messageField($a,$x,1,NNK)
                 	messageField($x,$b,2,NNK):=messageField($a,$x,2,NNK)
			        if(asymDec(NNK,1,1,2,$x)=true)then
                      par 
                    	knowsNonce($x,messageField($a,$x,1,NNK)):=true
                    	knowsNonce($x,messageField($a,$x,2,NNK)):=true
			            asymEnc(NNK,1,1,2):=PUBKA
                      endpar 
			        endif 
		          endpar 
			endif 
			        //check the reception of the message and the modality of the attack
			if(protocolMessage(1,$a,$x)=NNK and protocolMessage(1,$x,$b)!=NNK and mode=ACTIVE)then
		          par 
                 	protocolMessage(1,$x,$b):=NNK
                 	messageField($x,$b,1,NNK):=messageField($a,$x,1,NNK)
                 	messageField($x,$b,2,NNK):=messageField($a,$x,2,NNK)
			        if(asymDec(NNK,1,1,2,$x)=true)then
	   			     par 
                    	knowsNonce($x,messageField($a,$x,1,NNK)):=true
                    	knowsNonce($x,messageField($a,$x,2,NNK)):=true
			        	asymEnc(NNK,1,1,2):=PUBKA
	   			     endpar 
			        endif 
		          endpar 
			endif 
		  endpar 
		endlet 
	rule r_message_replay_NK =
		//choose what agets are interested by the message
		let ($x=agentE,$b=agentB,$a=agentA) in
		  par 
			//check the reception of the message and the modality of the attack
			if(protocolMessage(2,$a,$x)=NK and protocolMessage(2,$x,$b)!=NK and mode=PASSIVE)then
			        //in passive mode if the attacker knows the decryption key, the message payload is readable and it can be added to the attacker knowledge
			        // the message must be sent unaltered
		          par 
                 	protocolMessage(2,$x,$b):=NK
                 	messageField($x,$b,1,NK):=messageField($a,$x,1,NK)
			        if(asymDec(NK,1,1,1,$x)=true)then
                      par 
                    	knowsNonce($x,messageField($a,$x,1,NK)):=true
			            asymEnc(NK,1,1,1):=PUBKB
                      endpar 
			        endif 
		          endpar 
			endif 
			        //check the reception of the message and the modality of the attack
			if(protocolMessage(2,$a,$x)=NK and protocolMessage(2,$x,$b)!=NK and mode=ACTIVE)then
		          par 
                 	protocolMessage(2,$x,$b):=NK
                 	messageField($x,$b,1,NK):=messageField($a,$x,1,NK)
			        if(asymDec(NK,1,1,1,$x)=true)then
	   			     par 
                    	knowsNonce($x,messageField($a,$x,1,NK)):=true
			        	asymEnc(NK,1,1,1):=PUBKB
	   			     endpar 
			        endif 
		          endpar 
			endif 
		  endpar 
		endlet 

	/*HONEST AGENT RULES*/	
	rule r_message_NAK =
		let ($x=agentA,$e=agentE) in
			if(internalStateA=IDLE_NAK)then 
			   if(receiver!=AG_E)then
			     par
			         protocolMessage(0,$x,$e):=NAK
			         messageField($x,$e,1,NAK):=NA
			         messageField($x,$e,2,NAK):=ID_A
			         asymEnc(NAK,1,1,2):=PUBKB
			         internalStateA:=WAITING_NK
			     endpar
			   else
			       if(receiver=AG_E)then
			         par
			            protocolMessage(0,$x,$e):=NAK
			            messageField($x,$e,1,NAK):=NA
			            messageField($x,$e,2,NAK):=ID_A
			            asymEnc(NAK,1,1,2):=PUBKE
			            internalStateA:=WAITING_NK
			         endpar
			       endif
			   endif
			endif
		endlet
	rule r_message_NNK =
		let ($x=agentB,$e=agentE) in
			if(internalStateB=WAITING_NNK and protocolMessage(0,$e,$x)=NAK)then
			   if(receiver!=AG_E)then
 			        if(asymDec(NAK,1,1,2,$x)=true ) then
			          par
			            knowsNonce($x,messageField($e,$x,1,NAK)):=true
			            knowsIdentityCertificate($x,messageField($e,$x,2,NAK)):=true
			            protocolMessage(1,$x,$e):=NNK
			            messageField($x,$e,1,NNK):=messageField($e,$x,1,NAK)
			            messageField($x,$e,2,NNK):=NB
			            asymEnc(NNK,1,1,2):=PUBKA
			            internalStateB:=CHECK_END_B
			          endpar
			        endif
			   else
 			        if(asymDec(NAK,1,1,2,$x)=true  and receiver=AG_E) then
			          par
			            knowsNonce($x,messageField($e,$x,1,NAK)):=true
			            knowsIdentityCertificate($x,messageField($e,$x,2,NAK)):=true
			            protocolMessage(1,$x,$e):=NNK
			            messageField($x,$e,1,NNK):=messageField($e,$x,1,NAK)
			            messageField($x,$e,2,NNK):=NB
			            asymEnc(NNK,1,1,2):=PUBKA
			            internalStateB:=CHECK_END_B
			         endpar
			        endif
			   endif
			endif
		endlet
	rule r_message_NK =
		let ($x=agentA,$e=agentE) in
			if(internalStateA=WAITING_NK and protocolMessage(1,$e,$x)=NNK)then
			   if(receiver!=AG_E)then
 			        if(asymDec(NNK,1,1,2,$x)=true ) then
			          par
			            knowsNonce($x,messageField($e,$x,1,NNK)):=true
			            knowsNonce($x,messageField($e,$x,2,NNK)):=true
			            protocolMessage(2,$x,$e):=NK
			            messageField($x,$e,1,NK):=messageField($e,$x,2,NNK)
			            asymEnc(NK,1,1,1):=PUBKB
			            internalStateA:=END_A
			          endpar
			        endif
			   else
 			        if(asymDec(NNK,1,1,2,$x)=true  and receiver=AG_E) then
			          par
			            knowsNonce($x,messageField($e,$x,1,NNK)):=true
			            knowsNonce($x,messageField($e,$x,2,NNK)):=true
			            protocolMessage(2,$x,$e):=NK
			            messageField($x,$e,1,NK):=messageField($e,$x,2,NNK)
			            asymEnc(NK,1,1,1):=PUBKE
			            internalStateA:=END_A
			         endpar
			        endif
			   endif
			endif
		endlet
	rule r_check_NK =
		let ($x=agentB,$e=agentE) in
			if(internalStateB=CHECK_END_B and protocolMessage(2,$e,$x)=NK)then
			  par
			        internalStateB:=END_B
			        if(asymDec(NK,1,1,1,$x)=true)then
                    	knowsNonce($x,messageField($e,$x,1,NK)):=true
			        endif 
			  endpar
			endif
		endlet

	main rule r_Main =
	  par
            r_message_replay_NAK[]
            r_message_replay_NNK[]
            r_message_replay_NK[]
            r_message_NAK[]
            r_message_NNK[]
            r_message_NK[]
            r_check_NK[]
	  endpar

default init s0:
	function agentA=ALICE 
	function agentB=BOB 
	function agentE=EVE 
	function internalStateA=IDLE_NAK
	function internalStateB=WAITING_NNK
	function receiver=chosenReceiver
	function knowsNonce($a in Agenti, $n in Knowledge)=if($a=agentA and $n=NA) then true else if($a=agentB and $n=NB) or ($a=agentB and $n=NA) then true else if($a=agentE and $n=NE) then true else false endif endif endif
	function knowsIdentityCertificate($a in Agenti, $i in Knowledge)=if($a=agentA and $i=ID_A) then true else if($a=agentB and $i=ID_B) then true else if($a=agentE and $i=ID_E) then true else false endif endif endif
	function knowsAsymPrivKey($a in Agenti ,$k in Knowledge)=if(($a=agentA and $k=PRIVKA) or ($a=agentB and $k=PRIVKB) or ($a=agentE and $k=PRIVKE)) then true else false endif
	function knowsAsymPubKey($a in Agenti ,$pk in Knowledge)=true
	function mode=chosenMode

