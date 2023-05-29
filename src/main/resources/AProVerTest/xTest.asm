asm xTest

import StandardLibrary
import CTLlibrary


signature:

domain Agenti subsetof Agent
//  	domain Alice subsetof Agenti
//  	domain Eve subsetof Agenti

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

//	controlled knowsBitString:Prod(Agenti,Knowledge)->Boolean

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
// 	static verifyHash: Prod(Message,Level,HashField1,HashField2,Agenti)-> Boolean


	//sign function applied from the field SignField1 to SignField2, the nesting level is Level
	controlled sign: Prod(Message,Level,SignField1,SignField2)-> Knowledge
// 	static verifySign: Prod(Message,Level,SignField1,SignField2,Agenti)-> Boolean

// 	static sign_keyAssociation: KnowledgeSignPrivKey -> KnowledgeSignPubKey


	//asymmetric encryption function applied from the field EncField1 to EncField2
	//the nesting level is Level
	controlled asymEnc: Prod(Message,Level,EncField1,EncField2)-> Knowledge
// 	static asymDec: Prod(Message,Level,EncField1,EncField2,Agenti)-> Boolean

// 	static asim_keyAssociation: KnowledgeAsymPubKey -> KnowledgeAsymPrivKey


	//symmetric encryption function applied from the field EncField1 to EncField2
	//the nesting level is Level
	controlled symEnc: Prod(Message,Level,EncField1,EncField2)-> Knowledge
// 	static symDec: Prod(Message,Level,EncField1,EncField2,Agenti)-> Boolean

// 	static agentA: Alice
// 	static agentB: Bob
// 	static agentE: Eve
// 	static agentS: Server


	static agentA: Agenti 
	static agentB: Agenti 
	static agentE: Agenti 
	static agentS: Agenti 

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
				 otherwise agentA
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
			if(protocolMessage(0,$a,self)=MA and protocolMessage(0,self,$b)!=MA and mode=PASSIVE)then
			        //in passive mode if the attacker knows the decryption key, the message payload is readable and it can be added to the attacker knowledge
			        // the message must be sent unaltered
		          par 
                 	protocolMessage(0,self,$b):=MA
                 	messageField(self,$b,1,MA):=messageField($a,self,1,MA)
                 	messageField(self,$b,2,MA):=messageField($a,self,2,MA)
                 	messageField(self,$b,3,MA):=messageField($a,self,3,MA)
                 	knowsIdentityCertificate(self,messageField($a,self,1,MA)):=true
                 	knowsIdentityCertificate(self,messageField($a,self,2,MA)):=true
                 	knowsNonce(self,messageField($a,self,3,MA)):=true
		          endpar 
			endif 
			        //check the reception of the message and the modality of the attack
			if(protocolMessage(0,$a,self)=MA and protocolMessage(0,self,$b)!=MA and mode=ACTIVE)then
		          par 
                 	protocolMessage(0,self,$b):=MA
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
	

	/*HONEST AGENT RULES*/	
	rule r_message_MA =
		let ($x=agentA,$e=agentE) in
			if(internalStateA=IDLE_MA)then 
			   if(receiver!=AG_E)then
			     par
			         protocolMessage(0,self,$e):=MA
			         messageField(self,$e,1,MA):=CA
			         messageField(self,$e,2,MA):=CB
			         messageField(self,$e,3,MA):=NA
			         internalStateA:=WAITING_MC
			     endpar
			   else
			       if(receiver=AG_E)then
			         par
			            protocolMessage(0,self,$e):=MA
			            messageField(self,$e,1,MA):=CA
			            messageField(self,$e,2,MA):=CB
			            messageField(self,$e,3,MA):=NA
			            internalStateA:=WAITING_MC
			         endpar
			       endif
			   endif
			endif
		endlet


// properties TAB=0 COL=0

  
  	rule r_agentERule  =
            r_message_replay_MA[]

	rule r_agentARule  =
            r_message_MA[]

CTLSPEC ef(knowsNonce(agentE,NB))
	main rule r_Main =
	  par
             program(agentA)
             program(agentE)
	  endpar
  


default init s0:

	function internalStateA=IDLE_MA
	function internalStateB=WAITING_MD
	function internalStateS=WAITING_MB
	function receiver=AG_E
	function knowsNonce($a in Agenti, $n in Knowledge)=if($a=agentA and $n=NA) then true else if($a=agentB and $n=NB) then true else false endif endif
	function knowsIdentityCertificate($a in Agenti, $i in Knowledge)=if($a=agentA and $i=CA) or ($a=agentA and $i=CB) or ($a=agentA and $i=CE) then true else if($a=agentB and $i=CA) or ($a=agentB and $i=CB) or ($a=agentB and $i=CE) then true else if($a=agentE and $i=CE) then true else false endif endif endif
	function knowsSymKey($a in Agenti ,$sk in Knowledge)=if(($a=agentA and $sk=KAS) or ($a=agentA and $sk=KAB) or ($a=agentB and $sk=KBS) or ($a=agentB and $sk=KEB) or ($a=agentB and $sk=KAB) or ($a=agentE and $sk=KEA) or ($a=agentE and $sk=KEB) or ($a=agentE and $sk=KES) or ($a=agentS and $sk=KAS) or ($a=agentS and $sk=KBS) or ($a=agentS and $sk=KAB)) then true else false endif
	function mode=PASSIVE
	agent Agenti:
		r_agentARule[]

	agent Agenti:
		r_agentERule[]



