package org.unimi.model;
import java.io.*;
import java.util.ArrayList;
import java.util.Map;
import java.util.TreeMap;

public class WriteCryptoLibrary {
	private Boolean actorServer,actorAlice,actorBob;
	private SecurityKey securityKey;
	private String[] signature = new String[50];
	private String[] stateActor = new String[4];
	private int indSignature,levelMsg,levelTot;
	private Messages messages;
	private SecurityKey alice;
	private SecurityKey bob;
	private SecurityKey eve;
	private SecurityKey server;
	private Map<String, String> map = new TreeMap<String, String>();
	private Map<String, String> mapMsg = new TreeMap<String, String>();
	private int numMap = 0, fieldPosition=0,fieldPositionMsg=0,numEncField=0,numSignField =0,numSymField =0,numHashField =0,numEncSignHashMsg=0;
	private SecurityKey KeyActorFrom;
	private SecurityKey KeyActorTo;	
	private BufferedWriter b;
	private FileWriter w;
	private String acronym;
	String[] changNumMSG = new String[15];

	private String toolEve;
	public WriteCryptoLibrary(Boolean actorServer, Messages messages,SecurityKey alice,SecurityKey bob,SecurityKey eve,SecurityKey server,String toolEve,String acronym) 
			  throws IOException {
		 		this.acronym=acronym;
				this.actorServer = actorServer;
				this.messages = messages;
				this.alice = alice;
				this.bob = bob;
				this.eve = eve;
				this.server = server;
				this.toolEve = toolEve;
				indSignature=0;
				changNumMSG[0]="MA";
				changNumMSG[1]="MB";
				changNumMSG[2]="MC";
				changNumMSG[3]="MD";
				changNumMSG[4]="ME";
				changNumMSG[5]="MF";
				changNumMSG[6]="MG";
				changNumMSG[7]="MH";
				changNumMSG[8]="MI";
				changNumMSG[9]="ML";
				changNumMSG[10]="MM";
				changNumMSG[11]="MN";
				changNumMSG[12]="MO";
				changNumMSG[13]="MP";
				changNumMSG[14]="MQ";
				int i=0;
				actorAlice = false;
				actorBob = false;
				for(Message e: messages.getListMessages()) {
					if (e.getNameMess()!=null && !e.getNameMess().isEmpty()
						&& !e.getNameMess().isBlank() && !e.getNameMess().equals("")) {
						changNumMSG[i]= e.getNameMess();
						if (e.getActorTo().toUpperCase().contains("A") || e.getActorfrom().toUpperCase().contains("A")) {
							actorAlice=true;
						}
						if (e.getActorTo().toUpperCase().contains("B") || e.getActorfrom().toUpperCase().contains("B")) {
							actorBob=true;
						}
						}
					i++;
					}

			    
			    w=new FileWriter("src/main/resources/AProVerTest/CryptoLibrary"+acronym+".asm");

			    
			    b=new BufferedWriter (w);
			    System.out.println("finee");
			    
			  }
	//Scrittura prime info file asm
	public boolean writeFile() throws IOException {
		 
	    // scrittura info iniziali del file asm
 	    System.out.println("writeOpen");
	    writeOpen(b);
	    
	    // scrittura info domain Agent_x
 	    System.out.println("writeAgent " + actorServer);
	     
	    writeAgent(actorServer, b);
	    
	    
	    System.out.println("writeAlice " + alice);
	    //vengono memorizzate in una tabella l'elenco knows sia dalle SecurityKey che dai messaggi per ogni singolo attore
	    storeKnows(alice);
	    
	    System.out.println("writeBob " + bob);
	    storeKnows(bob);
	    
	    System.out.println("writeEve " + eve);
	    storeKnows(eve);
	     
	    if (server != null || actorServer) {
	    	System.out.println("writeServer " + server);
	    	storeKnows(server);
	    }
    
	     
	    System.out.println("writeMessaget");
	    writeMessage(b);
	    
	    String payloadXXX = "";
	    System.out.println("altro");
	    numMap = 0;
	    
	    for(String s : mapMsg.keySet()) {
	    	if (numMap ==0 ) {
	    		payloadXXX = "	enum domain Knowledge ={" + s;
	    		numMap++;
	    	}else {
	    		payloadXXX = payloadXXX + "|" + s;
	    		numMap++;
	    	}
	    }
	    for(String s : map.keySet()) {
	    	if (numMap ==0 ) {
	    		payloadXXX = "	enum domain Knowledge ={" + s;
	    		numMap++;
	    	}else {
	    		payloadXXX = payloadXXX + "|" + s;
	    		numMap++;
	    	}
	    }
	    if (!payloadXXX.isEmpty()) {
	    	payloadXXX = payloadXXX + "}\n";
	    	b.write(payloadXXX);
	    }
	    b.write("\n");
	    writeEndSignature(b);
	    writeDefinitions(b);				
/*
	    for (String s : signature) {
	    	if (s!=null)   	b.write(s);
	    }
	    
	    
	    b.write("	controlled knownAsimPubKey: Agent −> Powerset(AsimPubKeyType)\n");
	    b.write("	controlled knownAsimPrivKey: Agent −> Powerset(AsimPrivKeyType)\n");
	    b.write("	controlled knownSimmKey: Agent −> Powerset(SimmKeyType)\n");
	    b.write("	controlled knownPayload: Agent −> Powerset(PayloadType)\n");
	    b.write("	domain State subsetof Any\n");
	    b.write("	controlled internalState: Agent −> State\n");
*/			    
	    b.flush();
	    b.close();
	    return true;
	}

	//Scrittura prime info file asm
	private void writeOpen(BufferedWriter b) throws IOException {
		b.write("module CryptoLibrary"+acronym+"\n");
		b.write("\n");
		b.write("import ../StandardLibrary\n");
		b.write("export *\n");
		b.write("\n");
		b.write("signature:\n");
	}
	//Scrittura Signature Domini Agent
	private void writeAgent(Boolean actorServer, BufferedWriter b) throws IOException {
		b.write("\n");
		b.write("	domain Alice subsetof Agent\n");
	    
	    
	    signature[indSignature]="	static agentA: Agent_A\n";
	    indSignature++;
	    b.write("	domain Bob subsetof Agent\n");
	    signature[indSignature]="	static agentB: Agent_B\n";
	    indSignature++;
	   	
	    b.write("	domain Eve subsetof Agent\n");
	   	signature[indSignature]="	static agentE: Agent_E\n";
	    indSignature++;

	    if (actorServer) {
	    	b.write("	domain Server subsetof Agent\n");
		    signature[indSignature]="	static agentS: Agent_S\n";
		    indSignature++;
	    }
	}

	//memorizza elenco knows sia dalle SecurityKey che dai messaggi 
		private void storeKnows(SecurityKey actor){
			
			System.out.println("a");
 			for(int i = 0; i <actor.getNonce().size(); i++) {
 				map.put(actor.getNonce().get(i).toUpperCase(), actor.getNonce().get(i));
 		       }
 			System.out.println("b");
			for(int i = 0; i <actor.getBitstring().size(); i++) {
				map.put(actor.getBitstring().get(i).toUpperCase(), actor.getBitstring().get(i));
		       }
			System.out.println("c");
			for(int i = 0; i <actor.getHashKey().size(); i++) {
				map.put(actor.getHashKey().get(i).toUpperCase(), actor.getHashKey().get(i));
		       }
			System.out.println("d");
 			for(int i = 0; i <actor.getDigest().size(); i++) {
 				map.put(actor.getDigest().get(i).toUpperCase(), actor.getDigest().get(i));
 		       }
 			System.out.println("e");
 			for(int i = 0; i <actor.getIdCertificate().size(); i++) {
 				map.put(actor.getIdCertificate().get(i).toUpperCase(), actor.getIdCertificate().get(i));
 		       }
 			System.out.println("f");
			for(int i = 0; i <actor.getAsymmetricPrivateKey().size(); i++) {
				map.put(actor.getAsymmetricPrivateKey().get(i).toUpperCase(), actor.getAsymmetricPrivateKey().get(i));
		       }
			System.out.println("g");
			for(int i = 0; i <actor.getAsymmetricPublicKey().size(); i++) {
				map.put(actor.getAsymmetricPublicKey().get(i).toUpperCase(), actor.getAsymmetricPublicKey().get(i));
		       }
			System.out.println("h");
			for(int i = 0; i <actor.getSymmetricKey().size(); i++) {
				map.put(actor.getSymmetricKey().get(i).toUpperCase(), actor.getSymmetricKey().get(i));
		       }
			System.out.println("i");
			for(int i = 0; i <actor.getSignaturePubKey().size(); i++) {
				map.put(actor.getSignaturePubKey().get(i).toUpperCase(), actor.getSignaturePubKey().get(i));
		       }
			System.out.println("l");
			for(int i = 0; i <actor.getSignaturePrivKey().size(); i++) {
				map.put(actor.getSignaturePrivKey().get(i).toUpperCase(), actor.getSignaturePrivKey().get(i));
		       }
//			for(int i = 0; i <actor.getTag().size(); i++) {
//				map.put(actor.getTag().get(i).toUpperCase(), actor.getTag().get(i));
//		       }
//			for(int i = 0; i <actor.getTimestamp().size(); i++) {
//				map.put(actor.getTimestamp().get(i).toUpperCase(), actor.getTimestamp().get(i));
//		       }
			System.out.println("m");
		}
		//Scrittura Signature Domini and state Agent 
		private void writeMessage(BufferedWriter b) throws IOException {
			b.write("\n");
			String messageXXX = "";		
			int numPayloadSection = 0;
			fieldPosition=0;
			levelTot=0;
			numEncField=0;
			numSignField =0;
			numHashField =0;

			for (int i = 0; i < 15; i++) {
				Message message = messages.getMessage(i);
				if (message.getActorfrom() == null || message.getActorfrom().isEmpty()) {
					if (i > 0) {
						messageXXX = messageXXX + "} \n";
						break;
					}
				}
				levelMsg=0;
				fieldPositionMsg=0;
				for (int numMsg = 0; numMsg < 15; numMsg++) {
					if (message.getSecurityFunctionsPartMessage(numMsg) != null
							&& !message.getSecurityFunctionsPartMessage(numMsg).isEmpty()) {
//						System.out.println("getSecurityFunctionsPartMessage mes:"+ numMsg + " valore: "+ message.getSecurityFunctionsPartMessage(numMsg));
						numEncSignHashMsg=0;
						storeMessage(message, numMsg);
						System.out.println("numEncSignHashMsg entro da findTypeKey numEncSignHashMsg: "+ numEncSignHashMsg);
						findTypeKey(message, numMsg);
						System.out.println("numEncSignHashMsg uscito da findTypeKey numEncSignHashMsg: "+ numEncSignHashMsg);
					}
				}
				if (levelMsg > levelTot) {
					levelTot=levelMsg;
				}
				if (fieldPositionMsg > fieldPosition) {
					fieldPosition=fieldPositionMsg;
				}
				// si inseriscono nella tabella di appoggio le informazioni sugli stati degli attori
				loadStateActor(i,message.getActorfrom(),message.getActorTo());
				// signature[indSignature]="	protocolMessage(" + defAgent(message.getActorfrom()) + ","+ defAgent (message.getActorTo())  + "):=M"+ i+"\n";
			   // indSignature++;
				if (i==0) {
		    		messageXXX= messageXXX + "	enum domain Message = {"+ changNumMSG[i];
		    	} else {
		    		messageXXX= messageXXX + " | "+ changNumMSG[i];
		    	}
		    }
			
			if (messageXXX.isEmpty()) {
		    	return;}
			b.write("\n");
	//		System.out.println("loadStateActor -0- " + stateActor[0] );
			if (stateActor[0] !=null) {
				b.write("	enum domain StateAlice = {"+stateActor[0]+" | END_A}\n");
			}
	//		System.out.println("loadStateActor -1- " + stateActor[0] );
			if (stateActor[1] !=null) {
				b.write("	enum domain StateBob = {"+stateActor[1]+" | END_B}\n");
			}
	//		System.out.println("loadStateActor -2- " + stateActor[2] );
			if (stateActor[2] !=null) {
				b.write("	enum domain StateEve = {"+stateActor[2]+" | END_E}\n");
			}
	//		System.out.println("loadStateActor -3- " + stateActor[3] );
			if (stateActor[3] !=null) {
				b.write("	enum domain StateServer = {"+stateActor[3]+" | END_S}\n");
			}
			
		    b.write("\n");
		    b.write(messageXXX);
		    b.write("\n");
		    
	}
	private void writeEndSignature(BufferedWriter b) throws IOException {
		b.write("	//DOMAIN OF POSSIBLE RECEIVER\n"); 
		if (stateActor[0] !=null && stateActor[0].contains("IDLE")){
			if (server != null || actorServer) {
				b.write("	enum domain Receiver={AG_A|AG_B|AG_E|AG_S}\n");
			} else {
				b.write("	enum domain Receiver={AG_A|AG_B|AG_E}\n");
			}
		}
		if (stateActor[1] !=null && stateActor[1].contains("IDLE")){
			if (server != null || actorServer) {
				b.write("	enum domain Receiver={AG_A|AG_E|AG_S}\n");
			} else {
				b.write("	enum domain Receiver={AG_A|AG_E}\n");
			}
		}
		if (stateActor[2] !=null && stateActor[2].contains("IDLE")){
			if (server != null || actorServer) {
				b.write("	enum domain Receiver={AG_A|AG_B|AG_S}\n");
			} else {
				b.write("	enum domain Receiver={AG_A|AG_B}\n");
			}
		}
		if (stateActor[3] !=null && stateActor[3].contains("IDLE")){
				b.write("	enum domain Receiver={AG_B|AG_E|AG_S}\n");
		}
		
	    b.write("	///DOMAIN OF THE ATTACKER MODE\n"); 
	    b.write("	enum domain Modality = {ACTIVE | PASSIVE}\n");
	    b.write("\n");
	    
	    b.write("	domain KnowledgeNonce subsetof Any\n");
	    b.write("	domain KnowledgeIdentityCertificate subsetof Any\n");
	    b.write("	domain KnowledgeBitString subsetof Any\n");
	    b.write("	domain KnowledgeSymKey subsetof Any\n");
	    b.write("	domain KnowledgeAsymPrivKey subsetof Any\n");
	    b.write("	domain KnowledgeAsymPubKey subsetof Any\n");
	    // Queste non trovate
	    b.write("	domain KnowledgeSignPrivKey subsetof Any\n");
	    b.write("	domain KnowledgeSignPubKey subsetof Any\n");
	    //
	    b.write("	domain KnowledgeTag subsetof Any\n");
	    
	    //Queste aggiunte io 
	    b.write("	domain KnowledgeDigest subsetof Any\n");
	    b.write("	domain KnowledgeHash subsetof Any\n");
	    b.write("	domain KnowledgeTimestamp subsetof Any\n");
	    b.write("	domain KnowledgeOther subsetof Any\n");
	    b.write("\n");
	    
	    b.write("	//range on which apply the cryptographic function\n");
	    b.write("	domain  FieldPosition subsetof Integer\n");
	    b.write("	domain  Level subsetof Integer\n");
	    b.write("	domain  EncField1 subsetof Integer\n");
	    b.write("	domain  EncField2 subsetof Integer\n");
	    b.write("	domain  SignField1 subsetof Integer\n");
	    b.write("	domain  SignField2 subsetof Integer\n");
	    b.write("	domain  HashField1 subsetof Integer\n");
	    b.write("	domain  HashField2 subsetof Integer\n");
	    
	    b.write("\n");
	    b.write("	//state of the actor\n");
	    if (actorAlice) { b.write("	controlled internalStateA: Alice -> StateAlice\n");}
	    if (actorBob) {b.write("	controlled internalStateB: Bob -> StateBob\n");}
	    if (toolEve.contains("Eve Doesn't Create Messages")){
	    	b.write("	controlled internalStateE: Eve -> StateEve\n");
	    }
	    if (server != null || actorServer) {
	    	b.write("	controlled internalStateS: Server -> StateServer\n");
	    }
	    
	    b.write("\n");
	    b.write("	//name of the message\n");
	    b.write("	controlled protocolMessage: Prod(Agent,Agent)-> Message\n");
	    b.write("	// content of the message and in which field it goes\n");
	    b.write("	controlled messageField: Prod(Agent,Agent,FieldPosition,Message)->Knowledge\n");
	    b.write("\n");
	    b.write("	//attaker mode\n");
	    b.write("	monitored chosenMode: Modality\n");
		b.write("	//controlled for saving the attacker modality choice\n");
		b.write("	controlled mode: Modality\n");
		b.write("\n");
		b.write("	// FUNCTIONS SELECT THE RECEIVER\n");
		b.write("	static name:Receiver -> Agent\n");
		b.write("	//Receiver chosen\n");
		b.write("	controlled receiver:Receiver\n");
		b.write("	//Receiver chosen by user\n");
		b.write("	monitored chosenReceiver:Receiver\n");	
		
		b.write("\n");
		b.write("	/*------------------------------------------------------------------- */\n");
		b.write("	//            Knowledge  management of the principals \n");
		b.write("	/*------------------------------------------------------------------- */\n");
		b.write("	controlled knowsNonce:Prod(Agent,KnowledgeNonce)->Boolean\n");
		b.write("\n");
		b.write("	controlled knowsIdentityCertificate:Prod(Agent,KnowledgeIdentityCertificate)->Boolean\n");
		b.write("\n");
		b.write("	controlled knowsBitString:Prod(Agent,KnowledgeBitString)->Boolean\n");
		b.write("\n");
		b.write("	controlled knowsSymKey:Prod(Agent,KnowledgeSymKey)->Boolean\n");
		b.write("\n");
		b.write("	controlled knowsAsymPubKey:Prod(Agent,KnowledgeAsymPubKey)->Boolean\n");
		b.write("\n");
		b.write("	controlled knowsAsymPrivKey:Prod(Agent,KnowledgeAsymPrivKey)->Boolean\n");
		b.write("\n");
		b.write("	controlled knowsSignPubKey:Prod(Agent,KnowledgeSignPubKey)->Boolean\n");
		b.write("\n");
		b.write("	controlled knowsSignPrivKey:Prod(Agent,KnowledgeSignPrivKey)->Boolean\n");
		b.write("\n");
		b.write("	controlled knowsTag:Prod(Agent,KnowledgeTag)->Boolean\n");
		//Queste aggiunte io 
		b.write("\n");
		b.write("	controlled knowsDigest:Prod(Agent,KnowledgeDigest)->Boolean\n");
		b.write("\n");
		b.write("	controlled knowsHash:Prod(Agent,KnowledgeHash)->Boolean\n");
		b.write("\n");
		b.write("	controlled knowsTimestamp:Prod(Agent,KnowledgeTimestamp)->Boolean\n");
		b.write("\n");
		b.write("	controlled knowsOther:Prod(Agent,KnowledgeOther)->Boolean\n");

		b.write("\n");
		b.write("	/*------------------------------------------------------------------- */\n");
		b.write("	//                  Cryptographic functions\n");
		b.write("	/*------------------------------------------------------------------- */\n");
		b.write("	//hash function applied from the field HashField1 to HashField2, the nesting level is Level\n");
		b.write("	static hash: Prod(Message,Level,HashField1,HashField2)-> KnowledgeTag\n");
		b.write("	static verifyHash: Prod(Message,Level,HashField1,HashField2,KnowledgeTag)-> Boolean\n");
		b.write("\n");
		b.write("	//sign function applied from the field SignField1 to SignField2, the nesting level is Level\n");
		b.write("	controlled sign: Prod(Message,Level,SignField1,SignField2)-> KnowledgeSignPrivKey\n");
		b.write("	static verifySign: Prod(Message,Level,SignField1,SignField2,Agent)-> Boolean\n");
		b.write("	static sign_keyAssociation: KnowledgeSignPrivKey -> KnowledgeSignPubKey\n");
		b.write("\n");
		b.write("	//asymmetric encryption function applied from the field EncField1 to EncField2\n");
		b.write("	//the nesting level is Level\n");
		b.write("	controlled asymEnc: Prod(Message,Level,EncField1,EncField2)-> KnowledgeAsymPubKey\n");
		b.write("	static asymDec: Prod(Message,Level,EncField1,EncField2,Agent)-> Boolean\n");
		b.write("	static asim_keyAssociation: KnowledgeAsymPubKey -> KnowledgeAsymPrivKey\n");
		b.write("\n");
		b.write("	//symmetric encryption function applied from the field EncField1 to EncField2\n");
		b.write("	//the nesting level is Level\n");
		b.write("	controlled symEnc: Prod(Message,Level,EncField1,EncField2)-> KnowledgeSymKey\n");
		b.write("	static symDec: Prod(Message,Level,EncField1,EncField2,Agent)-> Boolean\n");
		b.write("\n");
		b.write("	static diffieHellman:Prod(KnowledgeAsymPubKey,KnowledgeAsymPrivKey)->KnowledgeSymKey\n");
		b.write("\n");
		b.write("	static agentA: Alice\n");
		b.write("	static agentB: Bob\n");
		b.write("	static agentE: Eve\n");
		if (server != null || actorServer) {
			b.write("	static agentS: Server\n");
		}
	}
	
	private void writeDefinitions(BufferedWriter b) throws IOException {
		b.write("\n");
		b.write("definitions:\n");
		b.write("	function name($a in Receiver)=\n");
		b.write("			switch( $a )\n");
		b.write("				case AG_A:agentA\n");
		b.write("				case AG_E:agentE\n");
		b.write("				case AG_B:agentB\n");
		if (server != null || actorServer) {
			b.write("				case AG_S:agentS\n");		
		}
		b.write("			endswitch\n");
		b.write("\n");	
		b.write("		function verifySign($m in Message,$l in Level,$f1 in SignField1,$f2 in SignField2,$d in Agent)=\n");
		b.write("			if(knowsSignPubKey($d,sign_keyAssociation(sign($m,$l,$f1,$f2)))=true)then\n");
		b.write("				true\n");
		b.write("			else\n");
		b.write("				false\n");
		b.write("			endif\n");
		b.write("\n");	
		b.write("		function symDec($m in Message,$l in Level,$f1 in EncField1,$f2 in EncField2,$d in Agent)=\n");
		b.write("			if(knowsSymKey($d,symEnc($m,$l,$f1,$f2))=true)then\n");
		b.write("				true\n");
		b.write("			else\n");
		b.write("				false\n");
		b.write("			endif\n");
		b.write("\n");		
		b.write("		function asymDec($m in Message,$l in Level,$f1 in EncField1,$f2 in EncField2,$d in Agent)=\n");
		b.write("			if(knowsAsymPrivKey($d,asim_keyAssociation(asymEnc($m,$l,$f1,$f2)))=true)then\n");
		b.write("				true\n");
		b.write("			else\n");
		b.write("				false\n");
		b.write("			endif\n");
		b.write("\n");	

	}
	
	private void loadStateActor(int i, String actorFrom, String actorTo) {
		int indActorFrom, indActorTo;
		indActorFrom=0;
		indActorTo=0;
	//	System.out.println(actorFrom + " - " + actorTo);
		switch(actorFrom) {
		  case "Alice":
			  indActorFrom=0;
			  break;
		  case "Bob":
			  indActorFrom=1;
			  break;
		  case "Eve":
			  indActorFrom=2;
			  break;
		  case "Server":
			  indActorFrom=3;
			  break;
		}
		
		switch(actorTo) {
		  case "Alice":
			  indActorTo=0;
			  break;
		  case "Bob":
			  indActorTo=1;
			  break;
		  case "Eve":
			  indActorTo=2;
			  break;
		  case "Server":
			  indActorTo=3;
			  break;
		}
		
	//	System.out.println(indActorFrom + " - " + indActorTo);
		if (i==0) {
			stateActor[indActorFrom]="IDLE_"+changNumMSG[i];
		} else {
			if (stateActor[indActorFrom] == null) {
				stateActor[indActorFrom]="SEND_"+changNumMSG[i];
			} else {
				stateActor[indActorFrom]=stateActor[indActorFrom] + " | SEND_"+changNumMSG[i];
			}
		}
		if (stateActor[indActorTo] == null) {
			stateActor[indActorTo]="WAITING_"+changNumMSG[i];
		} else {
			stateActor[indActorTo]=stateActor[indActorTo] + " | WAITING_"+changNumMSG[i];
		}
		
	}
	
	private void storeMessage(Message message, int numMsg) {
		for (int j = 0; j < 15; j++) {
			if (message.getListPartMessage(numMsg, j) != null && !message.getListPartMessage(numMsg, j).isEmpty()) {
 				System.out.println("getListPartMessage riga: "+ j + " Valore: " + message.getListPartMessage(numMsg, j));
				if (!message.getListPartMessage(numMsg, j).toUpperCase().contains("PAYLOAD")) {
					numEncSignHashMsg++;
					fieldPositionMsg++;
					if (!map.containsKey(message.getListPartMessage(numMsg, j).toUpperCase())) {
						mapMsg.put(message.getListPartMessage(numMsg, j).toUpperCase(), message.getListPartMessage(numMsg, j));
					}
				} else {
					numEncSignHashMsg=numEncSignHashMsg+countFields(message.getListPartMessage(numMsg, j));
					levelMsg++;
				}
			}
		}
	}
	private String defAgent(String agent) {
		switch(agent) {
		  case "Alice":
			  return "agentA";
		  case "Bob":
			  return "agentB";
		  case "Eve":
			  return "agentE";
		  case "Server":
			  return "agentS";
		}
		return "Errore";
	}

	// determina quali algoritmi crittografici sono stati usati prima di inviare il messaggio
	private void findTypeKey(Message message, int numMsg ) {
		System.out.println("numEncSignHashMsg entro da findTypeKey "+ numEncSignHashMsg + " numMsg " + numMsg);
		String keyUsed=null;
		String partMsg = message.getSecurityFunctionsPartMessage(numMsg);
		
		if (!partMsg.substring(partMsg.length()-3).equals(" - ")) {
			System.out.println("numEncSignHashMsg esco perchè non c'è operazione "+ numEncSignHashMsg);
//			System.out.println(" --> "+ partMsg.substring(partMsg.length()-3));
			return;
		}
		keyUsed= partMsg.substring(0,partMsg.length()-3);
		keyUsed = keyUsed.substring(keyUsed.lastIndexOf(" - ")+3);
 		System.out.println(" trovata chiave --> "+ keyUsed);
		String operation = null;
		String actorFrom = message.getActorfrom();
		String actorTo = message.getActorTo();
		System.out.println("numEncSignHashMsg Attore actorFrom"+ actorFrom);
		
		switch (actorFrom) {
		case "Alice":
			KeyActorFrom = alice;
			break;
		case "Bob":
			KeyActorFrom = bob;
			break;
		case "Eve":
			KeyActorFrom = eve;
			break;
		case "Server":
			KeyActorFrom = server;
			break;
		default:
			KeyActorFrom = null;
		}
		
		System.out.println("numEncSignHashMsg Attore actorTo"+ actorTo);

		switch (actorTo) {
		case "Alice":
			KeyActorTo = alice;
			break;
		case "Bob":
			KeyActorTo = bob;
			break;
		case "Eve":
			KeyActorTo = eve;
			break;
		case "Server":
			KeyActorTo = server;
			break;
		default:
			KeyActorTo = null;
		}
		if (KeyActorFrom !=null) {
			operation= KeyActorFrom.searchEle(keyUsed);
			System.out.println("cerco operation per actorFrom"+ operation + " numMsg " + numMsg + " KayUsed " + keyUsed );

//			System.out.println("operation " + operation);
			if (operation == null) {
				if (KeyActorTo !=null) {
					System.out.println("cerco operation per actorTo numMsg " + numMsg + " KayUsed " + keyUsed );

					operation= KeyActorTo.searchEle(keyUsed);
					System.out.println("operation to " + operation);
				}
			}
		}

		
		
		if (operation != null) {
			System.out.println(" Operatio " + operation);
			switch (operation) {
			case "Asymmetric Public Key":
				System.out.println("Asymmetric Public Key -  numEncSignHashMsg " + numEncSignHashMsg + " numEncField "+ numEncField );
				if (numEncSignHashMsg>numEncField) {
					System.out.println("numEncField = numEncSignHashMsg");
					numEncField = numEncSignHashMsg;
				}
				break;
			case "Symmetric Key":
				System.out.println("Symmetric Key -  numEncSignHashMsg " + numEncSignHashMsg + " numSymField "+ numSymField );
				if (numEncSignHashMsg>numSymField) {
					System.out.println("numSymField = numEncSignHashMsg");
					numSymField = numEncSignHashMsg;
				}
				break;	
			case "Signature Pub Key":
				if (numEncSignHashMsg>numSignField) {
					numSignField = numEncSignHashMsg;
				}
				break;	
			case "Hash":
				if (numEncSignHashMsg>numHashField) {
					numHashField = numEncSignHashMsg;
				}
				break;		
			default:
				return;
			}
		}
		return;
	}
	public int countFields(String field) {
		int numFieldCount=0;
		char[] string = field.toCharArray();
		char cPrec=' ';
		for (char c : string){
		    if ((c==',' || c=='}') && cPrec!='}') {
		    	numFieldCount++;
		    }
		    cPrec = c;
		}
		return numFieldCount;
	}
	public int getNumEleMsg () {
		return fieldPosition;
	}
	public int getLevelTot () {
		return levelTot;
	}
	public int getNumSignField () {
		return numSignField;
	}
	public int getNumEncField () {
		return numEncField;
	}
	public int getNumSymField () {
		return numSymField;
	}
	public int getNumHashField () {
		return numHashField;
	}

}
