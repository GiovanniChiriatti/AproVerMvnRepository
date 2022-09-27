package org.unimi.model;
import java.io.*;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.Map;
import java.util.TreeMap;

import javafx.scene.image.Image;

public class WriteASM {
	
	private Boolean actorServer;
	private String[] ruleR_Agent = new String[50];
	private String[] stateActor = new String[4];
	private int  levelTot;
	private int fieldPosition;
	private int numEncField;
	private int numSymField;
	private int numSignField;
	private int numHashField;
	private int indRuleR_Agent;
	private int countIf;
	private SecurityKey KeyActorFrom;
	private SecurityKey KeyActorTo;	
	private Messages messages;
	private SecurityKey alice;
	private SecurityKey bob;
	private SecurityKey eve;
	private SecurityKey server;
	private Map<String, String> map = new TreeMap<String, String>();
	private String toolEve;
	String actorStartProtocol="";
	String actorReceiveProtocol="";
	public WriteASM(Boolean actorServer, Messages messages,SecurityKey alice,SecurityKey bob,SecurityKey eve,SecurityKey server,String toolEve, int fieldPosition, int levelTot,int numEncField,int numSignField,int numSymField,int numHashField) 
			  throws IOException {
				this.actorServer = actorServer;
				this.messages = messages;
				this.alice = alice;
				this.bob = bob;
				this.eve = eve;
				this.server = server;
				this.toolEve = toolEve;
				this.fieldPosition=fieldPosition;
				this.levelTot=levelTot;
				this.numEncField=numEncField;
				this.numSignField=numSignField;
				this.numSymField=numSymField;
				this.numHashField=numHashField;
				
				
				indRuleR_Agent=0;
//				System.out.println("-------WriteASM---------");
			    FileWriter w;
			    w=new FileWriter("src/main/resources/AProVerFile/protocolInfo.asm");

			    BufferedWriter b;
			    b=new BufferedWriter (w);
			    // scrittura info iniziali del file asm
			    writeOpen(b);

			    // scrittura delle Knowledge
			    writeKnowledge(b);
			    b.flush();
			    
			  }
	//Scrittura prime info file asm
	private void writeOpen(BufferedWriter b) throws IOException {
		b.write("asm XXX\n");
		b.write("\n");
		b.write("import CryptoLibraryXXX\n");
		b.write("\n");
		b.write("\n");
		b.write("signature:\n");
		b.write("\n");
		b.write("definitions:\n");
		if (levelTot > 0) {
			levelTot++;
			b.write("	domain Level = {1:"+ levelTot  + "}\n");
		} else {
			b.write("	domain Level = {1}\n");
		}
		if (fieldPosition>1 ) {
			b.write("	domain FieldPosition = {1:"+ fieldPosition + "}\n");
		} else {
			b.write("	domain FieldPosition = {1}\n");
		}
		if (numEncField>0) {
			if (numEncField==2) {
				b.write("	domain EncField1={1}\n");
				b.write("	domain EncField2={2}\n");
			} else {
				b.write("	domain EncField1={1:"+ numEncField +"}\n");
				b.write("	domain EncField2={2:"+ numEncField +"}\n");
		
			}
		}
		if (numSignField > 0) {
			if (numSignField == 2) {
				b.write("	domain SignField1={1}\n");
				b.write("	domain SignField2={2}\n");
			} else {
				b.write("	domain SignField1={1:" + numSignField + "}\n");
				b.write("	domain SignField2={2:" + numSignField + "}\n");
			}
		}
		if (numHashField > 0) {
			if (numHashField == 2) {
				b.write("	domain HashField1={1}\n");
				b.write("	domain HashField2={2}\n");
			} else {
				b.write("	domain HashField1={1}\n");
				b.write("	domain HashField2={2}\n");
			}
		}
	}
	//Scrittura prime info file asm
	private void writeKnowledge(BufferedWriter b) throws IOException {
		String[] elencoAsymPrivPub = new String[60];
		String[] elencoSignPrivPub = new String[60];
		b.write("\n");
		writeKnowledgeNonce(b);
		writeKnowledgeIdentityCertificate(b);
		writeKnowledgeBitString(b);
		writeKnowledgeSymKey(b);
		elencoAsymPrivPub = writeKnowledgeAsymPrivEPubKey(b);
		elencoSignPrivPub = writeKnowledgeSignPrivePubKey(b);
		writeKnowledgeTag(b);
		writeKnowledgeDigest(b);
		writeKnowledgeHash(b);
		writeKnowledgeTimestamp(b);
		b.write("\n");
		if (!elencoAsymPrivPub[0].isEmpty()) {
			b.write("	function asim_keyAssociation($a in KnowledgeAsymPubKey)=\n");
			b.write("	       switch( $a )\n");
			for (String s : elencoAsymPrivPub) {
				if (s.isEmpty()) break;
				b.write("	              case " + s + "\n");
			}
			b.write("	       endswitch\n");
		}
		
		if (!elencoSignPrivPub[0].isEmpty()) {
			b.write("	function sign_keyAssociation($b in KnowledgeSignPrivKey)=\n");
			b.write("	       switch( $b )\n");
			for (String s : elencoSignPrivPub) {
				if (s.isEmpty()) break;
				b.write("	              case " + s + "\n");
			}
			b.write("	       endswitch\n");
		}
		
		writeMessageAttacker(b);
		writeMessageHonest(b);
		
		writeRuleR_Agent(b);
		writeDefaultInitS0(b);
	}
	//Scrittura delle informazioni legate alla Knowledge Nonce
	private void writeKnowledgeNonce(BufferedWriter b) throws IOException {
		
		if (alice != null) {
			for (int i = 0; i < alice.getNonce().size(); i++) {
				map.put(alice.getNonce().get(i).toUpperCase(), alice.getNonce().get(i));
			}
		}
		if (bob != null) {
			for (int i = 0; i < bob.getNonce().size(); i++) {
				map.put(bob.getNonce().get(i).toUpperCase(), bob.getNonce().get(i));
			}
		}
		if (eve != null) {
			for (int i = 0; i < eve.getNonce().size(); i++) {
				map.put(eve.getNonce().get(i).toUpperCase(), eve.getNonce().get(i));
			}
		}
		
		if (server != null) {			
			for (int i = 0; i < server.getNonce().size(); i++) {
				map.put(server.getNonce().get(i).toUpperCase(), server.getNonce().get(i));
			}
		}
	    int numeMap = 0;

	    for(String s : map.keySet()) {
	    	if (numeMap ==0 ) {
	    		b.write("	domain KnowledgeNonce = {" + s);
	    		numeMap++;
	    	}else {
	    		b.write( "," + s);
	    		numeMap++;
	    	}
	    	//map.remove(s);
	    }
	    if (numeMap !=0 ) { 
	    	b.write( "}\n");
	    }
        Iterator<Map.Entry<String, String>> it = map.entrySet().iterator();
        while (it.hasNext()) {        
            if (it.next().getKey().startsWith("")){
                it.remove();
            }
        }
	}
	//Scrittura delle informazioni legate alla Knowledge Certificato ID
	private void writeKnowledgeIdentityCertificate(BufferedWriter b) throws IOException {
		if (alice != null) {
			for (int i = 0; i < alice.getIdCertificate().size(); i++) {
				map.put(alice.getIdCertificate().get(i).toUpperCase(), alice.getIdCertificate().get(i));
			}
		}
		if (bob != null) {
			for (int i = 0; i < bob.getIdCertificate().size(); i++) {
				map.put(bob.getIdCertificate().get(i).toUpperCase(), bob.getIdCertificate().get(i));
			}
		}
		if (eve != null) {
			for (int i = 0; i < eve.getIdCertificate().size(); i++) {
				map.put(eve.getIdCertificate().get(i).toUpperCase(), eve.getIdCertificate().get(i));
			}
		}
		
		if (server != null) {
			for (int i = 0; i < server.getIdCertificate().size(); i++) {
				map.put(server.getIdCertificate().get(i).toUpperCase(), server.getIdCertificate().get(i));
			}
		}
	    int numeMap = 0;

	    for(String s : map.keySet()) {
	    	if (numeMap ==0 ) {
	    		b.write("	domain KnowledgeIdentityCertificate = {" + s);
	    		numeMap++;
	    	}else {
	    		b.write( "," + s);
	    		numeMap++;
	    	}
	    }
	    if (numeMap !=0 ) { 
	    	b.write( "}\n");
	    }
        Iterator<Map.Entry<String, String>> it = map.entrySet().iterator();
        while (it.hasNext()) {
            if (it.next().getKey().startsWith("")){
                it.remove();
            }
        }
	}
	//Scrittura delle informazioni legate alla Knowledge Bit String
	private void writeKnowledgeBitString(BufferedWriter b) throws IOException {
		if (alice != null) {
			for (int i = 0; i < alice.getBitstring().size(); i++) {
				map.put(alice.getBitstring().get(i).toUpperCase(), alice.getBitstring().get(i));
			}
		}
		if (bob != null) {
			for (int i = 0; i < bob.getBitstring().size(); i++) {
				map.put(bob.getBitstring().get(i).toUpperCase(), bob.getBitstring().get(i));
			}
		}
		if (eve != null) {
			for (int i = 0; i < eve.getBitstring().size(); i++) {
				map.put(eve.getBitstring().get(i).toUpperCase(), eve.getBitstring().get(i));
			}
		}
		
		if (server != null) {
			for (int i = 0; i < server.getBitstring().size(); i++) {
				map.put(server.getBitstring().get(i).toUpperCase(), server.getBitstring().get(i));
			}
		}
	    int numeMap = 0;

	    for(String s : map.keySet()) {
	    	if (numeMap ==0 ) {
	    		b.write("	domain KnowledgeBitString = {" + s);
	    		numeMap++;
	    	}else {
	    		b.write( "," + s);
	    		numeMap++;
	    	}
	    }
	    if (numeMap !=0 ) { 
	    	b.write( "}\n");
	    }
        Iterator<Map.Entry<String, String>> it = map.entrySet().iterator();
        while (it.hasNext()) {
            if (it.next().getKey().startsWith("")){
                it.remove();
            }
        }
	}
	//Scrittura delle informazioni legate alla Knowledge chiave simmetrica
	private void writeKnowledgeSymKey(BufferedWriter b) throws IOException {
		if (alice != null) {
			for (int i = 0; i < alice.getSymmetricKey().size(); i++) {
				map.put(alice.getSymmetricKey().get(i).toUpperCase(), alice.getSymmetricKey().get(i));
			}
		}
		if (bob != null) {
			for (int i = 0; i < bob.getSymmetricKey().size(); i++) {
				map.put(bob.getSymmetricKey().get(i).toUpperCase(), bob.getSymmetricKey().get(i));
			}
		}
		if (eve != null) {
			for (int i = 0; i < eve.getSymmetricKey().size(); i++) {
				map.put(eve.getSymmetricKey().get(i).toUpperCase(), eve.getSymmetricKey().get(i));
			}
		}
		
		if (server != null) {
			for (int i = 0; i < server.getSymmetricKey().size(); i++) {
				map.put(server.getSymmetricKey().get(i).toUpperCase(), server.getSymmetricKey().get(i));
			}
		}
	    int numeMap = 0;

	    for(String s : map.keySet()) {
	    	if (numeMap ==0 ) {
	    		b.write("	domain KnowledgeSymKey = {" + s);
	    		numeMap++;
	    	}else {
	    		b.write( "," + s);
	    		numeMap++;
	    	}
	    }
	    if (numeMap !=0 ) { 
	    	b.write( "}\n");
	    }
        Iterator<Map.Entry<String, String>> it = map.entrySet().iterator();
        while (it.hasNext()) {
            if (it.next().getKey().startsWith("")){
                it.remove();
            }
        }
        
	}
	//Scrittura delle info sulle chiavi asimmetriche
	private String[] writeKnowledgeAsymPrivEPubKey(BufferedWriter b) throws IOException {
		String[] elencoPrivPub = new String[60];
		for (int i=0; i<60;i++) {
			elencoPrivPub[i]="";
		}
		if (alice != null) { 
			for (int i = 0; i < alice.getAsymmetricPrivateKey().size(); i++) {
				map.put(alice.getAsymmetricPrivateKey().get(i).toUpperCase() + " -> "  + alice.getAsymmetricPublicKey().get(i).toUpperCase(), alice.getAsymmetricPrivateKey().get(i));
			}
		}
		if (bob != null) {
			for (int i = 0; i < bob.getAsymmetricPrivateKey().size(); i++) {
				map.put(bob.getAsymmetricPrivateKey().get(i).toUpperCase() + " -> "  + bob.getAsymmetricPublicKey().get(i).toUpperCase(), bob.getAsymmetricPrivateKey().get(i));
			}
		}
		if (eve != null) {
			for (int i = 0; i < eve.getAsymmetricPrivateKey().size(); i++) {
				map.put(eve.getAsymmetricPrivateKey().get(i).toUpperCase() + " -> "  + eve.getAsymmetricPublicKey().get(i).toUpperCase(), alice.getAsymmetricPrivateKey().get(i));
			}
		}
		
		if (server != null) {
			for (int i = 0; i < server.getAsymmetricPrivateKey().size(); i++) {
				map.put(server.getAsymmetricPrivateKey().get(i).toUpperCase() + " -> "  + server.getAsymmetricPublicKey().get(i).toUpperCase(), alice.getAsymmetricPrivateKey().get(i));
			}
		}
	    int numeMap = 0;
	    
	    for(String s : map.keySet()) {
	    	if (numeMap ==0 ) {
	    		b.write("	domain KnowledgeAsymPrivKey = {" + s.substring(0, s.lastIndexOf(" -> ")));
	    		elencoPrivPub[numeMap] = s.replace(" -> ", ": ");
	    		numeMap++;
	    	}else {
	    		b.write( "," + s.substring(0, s.lastIndexOf(" -> ")));
	    		elencoPrivPub[numeMap] = s.replace(" -> ", ": ");
	    		numeMap++;
	    	}
	    }
	    if (numeMap !=0 ) { 
	    	b.write( "}\n");
	    }
	    numeMap = 0;
	    for(String s : map.keySet()) {
	    	if (numeMap ==0 ) {
	    		b.write("	domain KnowledgeAsymPubKey = {" + s.substring(s.lastIndexOf(" -> ")+4, s.length()));
	    		numeMap++;
	    	}else {
	    		b.write( "," + s.substring(s.lastIndexOf(" -> ")+4, s.length()));
	    		numeMap++;
	    	}
	    }
	    if (numeMap !=0 ) { 
	    	b.write( "}\n");
	    }
        Iterator<Map.Entry<String, String>> it = map.entrySet().iterator();
        while (it.hasNext()) {
            if (it.next().getKey().startsWith("")){
                it.remove();
            }
        }
		return elencoPrivPub;
	}
	//Scrittura delle info sulle chiavi per la firma
	private String[] writeKnowledgeSignPrivePubKey(BufferedWriter b) throws IOException {
		String[] elencoPrivPub = new String[60];
		for (int i=0; i<60;i++) {
			elencoPrivPub[i]="";
		}
		if (alice != null) {
			for (int i = 0; i < alice.getSignaturePrivKey().size(); i++) {
				map.put(alice.getSignaturePrivKey().get(i).toUpperCase() + " -> "  + alice.getSignaturePubKey().get(i).toUpperCase(), alice.getSignaturePrivKey().get(i));
			}
		}
		if (bob != null) {
			for (int i = 0; i < bob.getSignaturePrivKey().size(); i++) {
				map.put(bob.getSignaturePrivKey().get(i).toUpperCase() + " -> "  + bob.getSignaturePubKey().get(i).toUpperCase(), bob.getSignaturePrivKey().get(i));
			}
		}
		if (eve != null) {
			for (int i = 0; i < eve.getSignaturePrivKey().size(); i++) {
				map.put(eve.getSignaturePrivKey().get(i).toUpperCase() + " -> "  + eve.getSignaturePubKey().get(i).toUpperCase(), alice.getSignaturePrivKey().get(i));
			}
		}
		
		if (server != null) {
			for (int i = 0; i < server.getSignaturePrivKey().size(); i++) {
				map.put(server.getSignaturePrivKey().get(i).toUpperCase() + " -> "  + server.getSignaturePubKey().get(i).toUpperCase(), alice.getSignaturePrivKey().get(i));
			}
		}
	    int numeMap = 0;
	    
	    for(String s : map.keySet()) {
	    	if (numeMap ==0 ) {
	    		b.write("	domain KnowledgeSignPrivKey = {" + s.substring(0, s.lastIndexOf(" -> ")));
	    		elencoPrivPub[numeMap] = s.replace(" -> ", ": ");
	    		numeMap++;
	    	}else {
	    		b.write( "," + s.substring(0, s.lastIndexOf(" -> ")));
	    		elencoPrivPub[numeMap] = s.replace(" -> ", ": ");
	    		numeMap++;
	    	}
	    }
	    if (numeMap !=0 ) { 
	    	b.write( "}\n");
	    }
	    numeMap = 0;
	    for(String s : map.keySet()) {
	    	if (numeMap ==0 ) {
	    		b.write("	domain KnowledgeSignPubKey = {" + s.substring(s.lastIndexOf(" -> ")+4, s.length()));
	    		numeMap++;
	    	}else {
	    		b.write( "," + s.substring(s.lastIndexOf(" -> ")+4, s.length()));
	    		numeMap++;
	    	}
	    }
	    if (numeMap !=0 ) { 
	    	b.write( "}\n");
	    }
        Iterator<Map.Entry<String, String>> it = map.entrySet().iterator();
        while (it.hasNext()) {
            if (it.next().getKey().startsWith("")){
                it.remove();
            }
        }
		return elencoPrivPub;
	}
	//Scrittura delle informazioni legate alla Knowledge Tag
	private void writeKnowledgeTag(BufferedWriter b) throws IOException {
		if (alice != null) {
			for (int i = 0; i < alice.getTag().size(); i++) {
				map.put(alice.getTag().get(i).toUpperCase(), alice.getTag().get(i));
			}
		}
		if (bob != null) {
			for (int i = 0; i < bob.getTag().size(); i++) {
				map.put(bob.getTag().get(i).toUpperCase(), bob.getTag().get(i));
			}
		}
		if (eve != null) {
			for (int i = 0; i < eve.getTag().size(); i++) {
				map.put(eve.getTag().get(i).toUpperCase(), eve.getTag().get(i));
			}
		}
		
		if (server != null) {
			for (int i = 0; i < server.getTag().size(); i++) {
				map.put(server.getTag().get(i).toUpperCase(), server.getTag().get(i));
			}
		}
	    int numeMap = 0;

	    for(String s : map.keySet()) {
	    	if (numeMap ==0 ) {
	    		b.write("	domain KnowledgeTag = {" + s);
	    		numeMap++;
	    	}else {
	    		b.write( "," + s);
	    		numeMap++;
	    	}
	    }
	    if (numeMap !=0 ) { 
	    	b.write( "}\n");
	    }
        Iterator<Map.Entry<String, String>> it = map.entrySet().iterator();
        while (it.hasNext()) {
            if (it.next().getKey().startsWith("")){
                it.remove();
            }
        }
        
	}
	//Scrittura delle informazioni legate alla Knowledge Digest
	private void writeKnowledgeDigest(BufferedWriter b) throws IOException {
		if (alice != null) {
			for (int i = 0; i < alice.getDigest().size(); i++) {
				map.put(alice.getDigest().get(i).toUpperCase(), alice.getDigest().get(i));
			}
		}
		if (bob != null) {
			for (int i = 0; i < bob.getDigest().size(); i++) {
				map.put(bob.getDigest().get(i).toUpperCase(), bob.getDigest().get(i));
			}
		}
		if (eve != null) {
			for (int i = 0; i < eve.getDigest().size(); i++) {
				map.put(eve.getDigest().get(i).toUpperCase(), eve.getDigest().get(i));
			}
		}
		
		if (server != null) {
			for (int i = 0; i < server.getDigest().size(); i++) {
				map.put(server.getDigest().get(i).toUpperCase(), server.getDigest().get(i));
			}
		}
	    int numeMap = 0;

	    for(String s : map.keySet()) {
	    	if (numeMap ==0 ) {
	    		b.write("	domain KnowledgeDigest = {" + s);
	    		numeMap++;
	    	}else {
	    		b.write( "," + s);
	    		numeMap++;
	    	}
	    }
	    if (numeMap !=0 ) { 
	    	b.write( "}\n");
	    }
        Iterator<Map.Entry<String, String>> it = map.entrySet().iterator();
        while (it.hasNext()) {
            if (it.next().getKey().startsWith("")){
                it.remove();
            }
        }
	}
	//Scrittura delle informazioni legate alla Knowledge Hash
	private void writeKnowledgeHash(BufferedWriter b) throws IOException {
		if (alice != null) {
			for (int i = 0; i < alice.getHashKey().size(); i++) {
				map.put(alice.getHashKey().get(i).toUpperCase(), alice.getHashKey().get(i));
			}
		}
		if (bob != null) {
			for (int i = 0; i < bob.getHashKey().size(); i++) {
				map.put(bob.getHashKey().get(i).toUpperCase(), bob.getHashKey().get(i));
			}
		}
		if (eve != null) {
			for (int i = 0; i < eve.getHashKey().size(); i++) {
				map.put(eve.getHashKey().get(i).toUpperCase(), eve.getHashKey().get(i));
			}
		}
		
		if (server != null) {
			for (int i = 0; i < server.getHashKey().size(); i++) {
				map.put(server.getHashKey().get(i).toUpperCase(), server.getHashKey().get(i));
			}
		}
	    int numeMap = 0;

	    for(String s : map.keySet()) {
	    	if (numeMap ==0 ) {
	    		b.write("	domain KnowledgeHashKey = {" + s);
	    		numeMap++;
	    	}else {
	    		b.write( "," + s);
	    		numeMap++;
	    	}
	    }
	    if (numeMap !=0 ) { 
	    	b.write( "}\n");
	    }
        Iterator<Map.Entry<String, String>> it = map.entrySet().iterator();
        while (it.hasNext()) {
            if (it.next().getKey().startsWith("")){
                it.remove();
            }
        }
	}
	//Scrittura delle informazioni legate alla Knowledge Timestamp
	private void writeKnowledgeTimestamp(BufferedWriter b) throws IOException {
		if (alice != null) {
			for (int i = 0; i < alice.getTimestamp().size(); i++) {
				map.put(alice.getTimestamp().get(i).toUpperCase(), alice.getTimestamp().get(i));
			}
		}
		if (bob != null) {
			for (int i = 0; i < bob.getTimestamp().size(); i++) {
				map.put(bob.getTimestamp().get(i).toUpperCase(), bob.getTimestamp().get(i));
			}
		}
		if (eve != null) {
			for (int i = 0; i < eve.getHashKey().size(); i++) {
				map.put(eve.getTimestamp().get(i).toUpperCase(), eve.getTimestamp().get(i));
			}
		}
		
		if (server != null) {
			for (int i = 0; i < server.getDigest().size(); i++) {
				map.put(server.getTimestamp().get(i).toUpperCase(), server.getTimestamp().get(i));
			}
		}
	    int numeMap = 0;

	    for(String s : map.keySet()) {
	    	if (numeMap ==0 ) {
	    		b.write("	domain KnowledgeTimestamp = {" + s);
	    		numeMap++;
	    	}else {
	    		b.write( "," + s);
	    		numeMap++;
	    	}
	    }
	    if (numeMap !=0 ) { 
	    	b.write("}\n");
	    }
        Iterator<Map.Entry<String, String>> it = map.entrySet().iterator();
        while (it.hasNext()) {
            if (it.next().getKey().startsWith("")){
                it.remove();
            }
        }
	}
	//Scrittura delle informazioni legate ai messaggi scambiati prendendo in cosniderazione un eventuale attacco
	private void writeMessageAttacker(BufferedWriter b) throws IOException {
		b.write("\n");
		b.write("	/*ATTACKER RULES*/\n");
		for (int i = 0; i < 15; i++) {
			Message message = messages.getMessage(i);
			if (message.getActorfrom() == null || message.getActorfrom().isEmpty()) {
				if (i > 0) {
					break;
				}
			}
			b.write("	rule r_message_replay_M"+ i +" =\n");
			ruleR_Agent[indRuleR_Agent]= "E r_message_replay_M"+ i+"[]";
			indRuleR_Agent++;
			b.write("		//choose what agets are interested by the message\n");
			b.write("		let ($b=agent" + message.getActorTo().substring(0,1).toUpperCase() + ",$a=agent" + message.getActorfrom().substring(0,1).toUpperCase() + ") in\n");
			b.write("			//check the reception of the message and the modality of the attack\n");
			b.write("			if(protocolMessage($a ,self)=M"+ i +" and protocolMessage(self,$b)!=M"+ i + " and mode=PASSIVE)then\n");
			b.write("			        //in passsive mode if the attacker knows the decryption key, the message payload is readable and it can be added to the attacker knowledge\n");
			b.write("			        // the message must be sent unaltered\n");
			
			String keyUsed = findKey(message.getPayload());
			String operation=null;
			if (keyUsed != null) {
				operation = findOperation(keyUsed,message.getActorfrom(),message.getActorTo());
			} else {
				b.write("PAYLOAD KEY DECODING ERROR");
				return;
			}
			String[] msgEncField1EncField2 = new String[15];
			String[] msgField = new String[15];
			String levelEncField1EncField2 = calcLevelEncField1EncField2(message, msgEncField1EncField2, msgField);
			b.write("			        if("+operation+"(M"+ i+","+ levelEncField1EncField2 +",self)=true)then\n");
			b.write("			                par\n");
			String[] linesKnowledge = writeKnowledge(message,i,msgField,"$a");
			String spaces="";
			printKnowledge(b,"Know",linesKnowledge,spaces);
			printKnowledge(b,"Prot",linesKnowledge,spaces);
			printKnowledge(b,"Mess",linesKnowledge,spaces);
			b.write("			                endpar\n");
			b.write("			        else\n");
			b.write("			                par\n");
			printKnowledge(b,"Prot",linesKnowledge,spaces);
			printKnowledge(b,"Mess",linesKnowledge,spaces);
			b.write("			                endpar\n");
			b.write("			        endif\n");
			b.write("			else\n");
			b.write("			        //check the reception of the message and the modality of the attack\n");
			b.write("			        if(protocolMessage($a ,self)=M"+ i +" and protocolMessage(self,$b)!=M"+ i + " and mode=ACTIVE)then\n");
			b.write("			                 // in the active mode the attacker can forge the message with all his knowledge\n");
			b.write("			                 if("+operation+"(M"+ i+","+ levelEncField1EncField2 +",self)=true)then\n");
			b.write("			                          par\n");
			spaces="         ";
			printKnowledge(b,"Know",linesKnowledge,spaces);
			printKnowledge(b,"Prot",linesKnowledge,spaces);
			printKnowledge(b,"Mess",linesKnowledge,spaces);			
			b.write("			                               "+reversOperation(operation)+"(M"+ i+","+ levelEncField1EncField2 +"):=" + keyUsed +"\n");
			b.write("			                          endpar\n");			
			b.write("			                 else\n");
			b.write("			                          par\n");			
			printKnowledge(b,"Prot",linesKnowledge,spaces);
			printKnowledge(b,"Mess",linesKnowledge,spaces);				
			b.write("			                          endpar\n");
			b.write("			                 endif\n");
			b.write("			        endif\n");
			b.write("			endif\n");
			b.write("		endlet\n");
		}
	}
	// determina quale chiave è stata usata prima di inviare il messaggio
	private String findKey(String partMsg) {
		String keyUsed=null;
		
		if (!partMsg.substring(partMsg.length()-1).equals("-")) {
//			System.out.println(" --> "+ partMsg.substring(partMsg.length()-3));
			return keyUsed;
		}
		keyUsed= partMsg.substring(0,partMsg.length()-1);
		keyUsed = keyUsed.substring(keyUsed.lastIndexOf("-")+1);
		return keyUsed;
	}
	// determina quale algoritmo crittografico è stato usato prima di inviare il messaggio
	private String findOperation(String keyUsed, String actorFrom,String actorTo ) {
		String operation = null;
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
//			System.out.println("operation " + operation);
			if (operation == null) {
				if (KeyActorTo !=null) {
					operation= KeyActorTo.searchEle(keyUsed);
//					System.out.println("operation to " + operation);
				}
			}
		}

		
		
		if (operation != null) {
			switch (operation) {
			case "Asymmetric Public Key":
				return "asymDec";
			case "Asymmetric Private Key":
				return "asymEnc";
			case "Symmetric Key":
				return "symDec";	
			case "Signature Pub Key":
				return "verifySign";	
			case "Signature Priv Key":
				return "sign";	
			case "Hash":
				return "hash";	
			default:
				return  null;
			}
		}
		return null;
	}
	// inverte decodicifa e codifica nell'operazione del messaggio
	private String reversOperation(String operation) {
		
		if (operation != null) {
			switch (operation) {
			case "asymDec":
				return "asymEnc";
			case "asymEnc":
				return "asymDec";
			case "symDec":
				return "symEnc";	
			case "verifySign":
				return "sign";	
			case "sign":
				return "verifySign";	
			case "hash":
				return "hash";	
			default:
				return  null;
			}
		}
		return null;
	}
	// routin che server per determinare di quanti field si compone il messaggio e quanti livelli di cripr/encript ci sono
	private String calcLevelEncField1EncField2(Message message, String[] msgEncField1EncField2, String[] msgField) {
		int encField1, encField2, level;
		encField1=0;
		encField2=0;
		level=0;
		String calcLevelEncField1EncField2 = null;
		System.out.println(" messaggio payload " + message.getPayload());
		for (int numMsg = 0; numMsg < 15; numMsg++) {
			msgEncField1EncField2[numMsg] = "";
			System.out.println(" Leggo riga numero : " + numMsg);
			System.out.println(" messaggio SecurityFunctionsPartMessage" + message.getSecurityFunctionsPartMessage(numMsg));
			if (message.getSecurityFunctionsPartMessage(numMsg)!= null && message.getSecurityFunctionsPartMessage(numMsg).length() > 3  && message.getSecurityFunctionsPartMessage(numMsg).substring(message.getSecurityFunctionsPartMessage(numMsg).length()-3).equals(" - ")	
				&&	((message.getListPartMessage(numMsg, 0)!=null && message.getListPartMessage(numMsg, 0).toUpperCase().contains("PAYLOADFIELD"))|| numMsg==0||level==0))
			{ 
//			   System.out.println(" AGGIUNGO 1 AL LIVEL in quanto il message.getSecurityFunctionsPartMessage(numMsg) continen alla fine  --- ");
			   level++;
			}
			if (message.getSecurityFunctionsPartMessage(numMsg) != null
					&& !message.getSecurityFunctionsPartMessage(numMsg).isEmpty()) {
				for (int j = 0; j < 15; j++) {
					if (message.getListPartMessage(numMsg, j) != null
							&& !message.getListPartMessage(numMsg, j).isEmpty()) {
						System.out.println("          Leggo colonna numero : " + j);
						System.out.println("          messaggio " + message.getListPartMessage(numMsg, j));
			//			if (message.getListPartMessage(numMsg, j).length() > 3  && message.getListPartMessage(numMsg, j).substring(message.getListPartMessage(numMsg, j).length()-3).equals(" - ")
			// 					&& message.getListPartMessage(numMsg, j).toUpperCase().contains("PAYLOADFIELD")) 
			//			if (message.getSecurityFunctionsPartMessage(numMsg).length() > 3  && message.getSecurityFunctionsPartMessage(numMsg).substring(message.getSecurityFunctionsPartMessage(numMsg).length()-3).equals(" - "))	
			//				{ 
			//				   System.out.println(" AGGIUNGO 1 AL LIVEL in quanto il message.getSecurityFunctionsPartMessage(numMsg) continen alla fine  --- ");
			//				   level++;
			//				}
						if (message.getListPartMessage(numMsg, j).toUpperCase().contains("(PAYLOADFIELD2)")) {	
			//				System.out.println("ho trovato payload 2 ed imposto ad 1 encField1 ");
							encField1 = 1;
						} else {
							if (message.getListPartMessage(numMsg, j).toUpperCase().contains("(PAYLOADFIELD)")) {
			//					System.out.println("ho trovato payload 1 ed imposto ad "+encField1 +" encField2 ");
								encField2 = encField1;
							} else {
//								System.out.println(" Entro per il field " + encField1 + " - " + encField2);
								if (encField1 == 0) {
									encField1 = encField2 + 1;
									encField2 = encField1;
									msgField[encField2]  = message.getListPartMessage(numMsg, j).toUpperCase();
								} else {
									encField2++;
									msgField[encField2]  = message.getListPartMessage(numMsg, j).toUpperCase();
									if (j == 0) {
										encField1 = encField2;		
									}
								}
							}
						}
					}
				}
				if (encField2==0) {
					encField2=encField1;
				}
				msgEncField1EncField2[numMsg] = level+","+encField1+","+encField2;
				
				//
				System.out.println(" risultato " +numMsg + " " + msgEncField1EncField2[numMsg]);
				for(int i=0; i<15; i++) {
					if (msgField[i] != null) {
						System.out.println(" Campo " + i + " Valore: " + msgField[i]);
					}
				}
				
			//
			}
		}

		return level+","+encField1+","+encField2;
	}
	// routin che server per determinare di quanti field si compone il messaggio e quanti livelli di cripr/encript ci sono
	private String[] writeKnowledge(Message message,int numMessage, String[] msgField,String typeActor) throws IOException {
		String[] linesKnowledge = new String[50];
		linesKnowledge[0]="Prot                                              protocolMessage(self,$b):= M"+numMessage+"\n";
		Boolean flgAtorTo = true;
		int numRighe = 1;
		for (int i = 0; i < 15; i++) {
			if (msgField[i] != null) {
				String typeFieldActorFrom = KeyActorFrom.searchEle(msgField[i]);
				System.out.println(" Campo " + msgField[i] + " Tipo Campo " + typeFieldActorFrom);
				if (typeFieldActorFrom == null) {
					flgAtorTo = false;
					typeFieldActorFrom = KeyActorTo.searchEle(msgField[i]);
						if (typeFieldActorFrom == null) {	
								flgAtorTo = true;
								typeFieldActorFrom = "Other";
						}
				}
				
				switch (typeFieldActorFrom) {
				case "Asymmetric Public Key":
					typeFieldActorFrom = "knowsAsymPubKey";
					break;
				case "Asymmetric Private Key":
					typeFieldActorFrom = "knowsAsymPrivKey";
					break;
				case "Symmetric Key":
					typeFieldActorFrom = "knowsSymKey";
					break;
				case "Signature Pub Key":
					typeFieldActorFrom = "knowsSignPubKey";
					break;
				case "Signature Priv Key":
					typeFieldActorFrom = "knowsSignPrivKey";
					break;
				case "Hash":
					typeFieldActorFrom = "knowsHash";
					break;
				case "Nonce":
					typeFieldActorFrom = "knowsNonce";
					break;
				case "Identity Certificate":
					typeFieldActorFrom = "knowsIdentityCertificate";
					break;
				case "Bitstring":
					typeFieldActorFrom = "knowsBitString";
					break;
				case "Tag":
					typeFieldActorFrom = "knowsTag";
					break;
				case "Timestamp":
					typeFieldActorFrom = "knowsTimestamp";
					break;
				case "Digest":
					typeFieldActorFrom = "knowsDigest";
					break;
				case "Other":
					typeFieldActorFrom = "knowsOther";
					break;
				default:
					typeFieldActorFrom = null;
				}
				linesKnowledge[numRighe] = "Know                                              " + typeFieldActorFrom
						+ "(self,messageField("+ typeActor+",self," + i + ",M" + numMessage + ")):=true\n";
				numRighe++;

				linesKnowledge[numRighe] = "Mess                                              messageField(self,$b," + i
						+ ",M" + numMessage + "):=messageField(typeActor"+",self," + i + ",M" + numMessage + ")\n";
				numRighe++;
			}
		}
		return linesKnowledge;
	}
	private void printKnowledge(BufferedWriter b, String type,String[]linesKnowledge,String spaces ) throws IOException {
		for (int i=0; i<50;i++) {
			if (linesKnowledge[i] != null && linesKnowledge[i].startsWith(type)) {
				b.write(spaces+linesKnowledge[i].substring(4));
			}
		}
	}
	//Scrittura delle informazioni legate ai messaggi scambiati prendendo in cosniderazione un eventuale attacco
	private void writeMessageHonest(BufferedWriter b) throws IOException {
		boolean endMessage = false;
		b.write("\n");
		b.write("	/*HONEST AGENT RULES*/	\n");
		String operationPrev="";
		String levelEncField1EncField2Prev="";
		
		for (int i = 0; i < 15; i++) {
			Message message = messages.getMessage(i);
			if (message.getActorfrom() == null || message.getActorfrom().isEmpty()) {
				if (i > 0) {
					break;
				}
			}
			String[] msgEncField1EncField2 = new String[15];
			String[] msgField = new String[15];
			String levelEncField1EncField2 = calcLevelEncField1EncField2(message, msgEncField1EncField2, msgField);
			b.write("	rule r_message_M"+ i +" =\n");
			ruleR_Agent[indRuleR_Agent]= message.getActorfrom().toUpperCase().substring(0, 1)+" r_message_M"+ i+"[]";
			indRuleR_Agent++;
			b.write("		let ($e=agentE) in\n");
			String keyUsed = findKey(message.getPayload());
			String operation="";
			if (keyUsed != null) {
				operation = findOperation(keyUsed,message.getActorfrom(),message.getActorTo());				
			} else {
				b.write("PAYLOAD KEY DECODING ERROR");
				return;
			}
			if(i==0) {
				actorStartProtocol = message.getActorfrom();
				actorReceiveProtocol = message.getActorTo();
				b.write("			if(internalState"+message.getActorfrom().substring(0, 1)+"(self)=IDLE_M"+ i + ")then)\n");
				b.write("			        if(receiver=AG_"+message.getActorTo().substring(0, 1)+")then\n");
				b.write("			                par\n");
				b.write("			                       protocolMessage(self,$e):=M"+i+"\n");
				for (int k = 0; k < 15; k++) {
					if (msgField[k] != null) {
						b.write("			                       messageField(self,$e,"+k+",M"+i+"):="+msgField[k].toUpperCase()+"\n");						
					}
				}
				b.write("			                       "+reversOperation(operation)+"(M"+ i+","+ levelEncField1EncField2 +"):=" + keyUsed +"\n");

				int j = i+1;
				b.write("			                       internalState"+message.getActorfrom().substring(0, 1)+"(self):=WAITING_M"+j+"\n");					
				b.write("			                endpar\n");
				b.write("			        else\n");
				b.write("			                if(receiver=AG_E)then\n");
				b.write("			                        par\n");
				b.write("			                              protocolMessage(self,$e):=M"+i+"\n");
				for (int k = 0; k < 15; k++) {
					if (msgField[k] != null) {
						b.write("			                              messageField(self,$e,"+k+",M"+i+"):="+changValueEve(msgField[k]).toUpperCase()+"\n");						
					}
				}
				b.write("			                              "+reversOperation(operation)+"(M"+ i+","+ levelEncField1EncField2 +"):=" + changValueEve(keyUsed).toUpperCase() +"\n");
				b.write("			                              internalState"+message.getActorfrom().substring(0, 1)+"(self):=WAITING_M"+j+"\n");					
				b.write("			                        endpar\n");
				b.write("			                endif\n");				
				b.write("			        endif\n");	
				b.write("			endif\n");

				
				
			} else {
				int j = i-1;
				b.write("			if(internalState"+message.getActorfrom().substring(0, 1)+"(self)=WAITING_M"+ j + " and protocolMessage($e,self)=M"+ j +")then\n");
				if (actorStartProtocol.equals(message.getActorTo())){
								Message messagePrev = messages.getMessage(i-1);
								String[] msgEncField1EncField2Prev = new String[15];
								String[] msgFieldPrev = new String[15];
								levelEncField1EncField2Prev = calcLevelEncField1EncField2(messagePrev, msgEncField1EncField2Prev, msgFieldPrev);
								b.write("			        if("+operationPrev+"(M"+ j+","+ levelEncField1EncField2Prev +",self)=true)then\n");
								String[] linesKnowledgePrev = writeKnowledge(messagePrev,j,msgFieldPrev,"$e");
								String spaces="";
								printKnowledge(b,"Know",linesKnowledgePrev,spaces);
								b.write("			                      protocolMessage(self,$e):=M"+ i +"\n");
								for (int k = 0; k < 15; k++) {
									if (msgField[k] != null) {
										b.write("			                      messageField(self,$e,"+k+",M"+i+"):="+msgField[k].toUpperCase()+"\n");						
									}
								}
								b.write("			                      "+reversOperation(operation)+"(M"+ i+","+ levelEncField1EncField2 +"):=" + keyUsed +"\n");
								j=i+1;
								if (messages.getMessage(i+1).getActorfrom()!=null && !messages.getMessage(i+1).getActorfrom().isEmpty()) {
								       b.write("			                      internalState"+message.getActorfrom().substring(0, 1)+"(self):=WAITING_M"+j+"\n");					
								} else {
								       b.write("			                      internalState"+message.getActorfrom().substring(0, 1)+"(self):=END_"+message.getActorfrom().substring(0, 1)+"\n");								
								}
								b.write("			                endpar\n");	
								b.write("			        endif\n");	
								b.write("			endif\n");
				} else {
					b.write("			        if(receiver=AG_"+message.getActorTo().substring(0, 1)+")then\n");
					Message messagePrev = messages.getMessage(i-1);
					String[] msgEncField1EncField2Prev = new String[15];
					String[] msgFieldPrev = new String[15];
					levelEncField1EncField2Prev = calcLevelEncField1EncField2(messagePrev, msgEncField1EncField2Prev, msgFieldPrev);
					b.write("			           if("+operationPrev+"(M"+ j+","+ levelEncField1EncField2Prev +",self)=true)then\n");
					b.write("			                par\n");
					String[] linesKnowledgePrev = writeKnowledge(messagePrev,j,msgFieldPrev,"$e");
					String spaces="";
					printKnowledge(b,"Know",linesKnowledgePrev,spaces);
					b.write("			                      protocolMessage(self,$e):=M"+ i +"\n");
					for (int k = 0; k < 15; k++) {
						if (msgField[k] != null) {
							b.write("			                      messageField(self,$e,"+k+",M"+i+"):="+msgField[k].toUpperCase()+"\n");						
						}
					}
					b.write("			                      "+reversOperation(operation)+"(M"+ i+","+ levelEncField1EncField2 +"):=" + keyUsed +"\n");
					j=i+1;
					if (messages.getMessage(i+1).getActorfrom()!=null && !messages.getMessage(i+1).getActorfrom().isEmpty()) {
					       b.write("			                      internalState"+message.getActorfrom().substring(0, 1)+"(self):=WAITING_M"+j+"\n");					
					} else {
					       b.write("			                      internalState"+message.getActorfrom().substring(0, 1)+"(self):=END_"+message.getActorfrom().substring(0, 1)+"\n");								
					}
					b.write("			                endpar\n");	
					b.write("			        endif\n");	
					b.write("			else\n");
					msgFieldPrev = new String[15];
					j=i-1;
					levelEncField1EncField2Prev = calcLevelEncField1EncField2(messagePrev, msgEncField1EncField2Prev, msgFieldPrev);
					b.write("			           if("+operationPrev+"(M"+ j+","+ levelEncField1EncField2Prev +",self)=true)then\n");
					b.write("			                par\n");
					linesKnowledgePrev = writeKnowledge(messagePrev,j,msgFieldPrev,"$e");
					spaces="";
					printKnowledge(b,"Know",linesKnowledgePrev,spaces);
					b.write("			                      protocolMessage(self,$e):=M"+ i +"\n");
					for (int k = 0; k < 15; k++) {
						if (msgField[k] != null) {
							b.write("			                      messageField(self,$e,"+k+",M"+i+"):="+msgField[k].toUpperCase()+"\n");						
						}
					}
					b.write("			                      "+reversOperation(operation)+"(M"+ i+","+ levelEncField1EncField2 +"):=" + changValueEve(keyUsed).toUpperCase() +"\n");
					j=i+1;
					if (messages.getMessage(i+1).getActorfrom()!=null && !messages.getMessage(i+1).getActorfrom().isEmpty()) {
						   endMessage = false;
						   b.write("			                      internalState"+message.getActorfrom().substring(0, 1)+"(self):=WAITING_M"+j+"\n");					
					} else {
						   endMessage = true;
					       b.write("			                      internalState"+message.getActorfrom().substring(0, 1)+"(self):=END_"+message.getActorfrom().substring(0, 1)+"\n");								
					}
					b.write("			                endpar\n");	
					b.write("				  endif\n");	
					b.write("				endif\n");
					b.write("			endif\n");
					b.write("		endlet\n");
					if (endMessage) {
						b.write("	rule r_check_M" + i + " =\n");
						ruleR_Agent[indRuleR_Agent] = message.getActorTo().toUpperCase().substring(0, 1) + " r_check_M"
								+ i+"[]";
						indRuleR_Agent++;
						b.write("		let ($e=agentE) in\n");
						b.write("			if(internalState" + message.getActorTo().substring(0, 1)
								+ "(self)=WAITING_M" + i + " and protocolMessage($e,self)=M" + i + ")then\n");
						b.write("			        if(" + operation + "(M" + i + "," + levelEncField1EncField2
								+ ",self)=true)then\n");
						b.write("			                      internalState" + message.getActorTo().substring(0, 1)
								+ "(self):=END_" + message.getActorTo().substring(0, 1) + "\n");
						b.write("			        endif\n");
						b.write("			endif\n");
						b.write("		endlet\n");
					}
				}
			}
			operationPrev=operation;
	 	}
	}
	
	private String changValueEve(String value){
		System.out.println("cerco il valore : " + value);
		String valueOutput = value;
		String typeFieldActorFrom = KeyActorFrom.searchEle(value);
		System.out.println("tipo : " + eve +  " ------ " + typeFieldActorFrom);


		boolean found=false;
		if (typeFieldActorFrom != null) {
			found=true;
			switch (typeFieldActorFrom) {
			case "Asymmetric Public Key":
				if (eve.getAsymmetricPublicKey().get(0) != null)
					valueOutput = eve.getAsymmetricPublicKey().get(0);
				break;
			case "Asymmetric Private Key":
				if (eve.getAsymmetricPrivateKey().get(0) != null)
					valueOutput = eve.getAsymmetricPrivateKey().get(0);
				break;
			case "Symmetric Key":
				if (eve.getSymmetricKey().get(0) != null)
					valueOutput = eve.getSymmetricKey().get(0);
				break;
			case "Signature Pub Key":
				if (eve.getSignaturePubKey().get(0) != null)
					valueOutput = eve.getSignaturePubKey().get(0);
				break;
			case "Signature Priv Key":
				if (eve.getSignaturePrivKey().get(0) != null)
					valueOutput = eve.getSignaturePrivKey().get(0);
				break;
			case "Hash":
				if (eve.getHashKey().get(0) != null)
					valueOutput = eve.getHashKey().get(0);
				break;
			default:
				found = false;
				break;
			}
		}
		if (!found) {
			typeFieldActorFrom = KeyActorTo.searchEle(value);
			if (typeFieldActorFrom != null) {
				switch (typeFieldActorFrom) {
				case "Asymmetric Public Key":
					if (eve.getAsymmetricPublicKey().get(0) != null)
						valueOutput = eve.getAsymmetricPublicKey().get(0);
					break;
				case "Asymmetric Private Key":
					if (eve.getAsymmetricPrivateKey().get(0) != null)
						valueOutput = eve.getAsymmetricPrivateKey().get(0);
					break;
				case "Symmetric Key":
					if (eve.getSymmetricKey().get(0) != null)
						valueOutput = eve.getSymmetricKey().get(0);
					break;
				case "Signature Pub Key":
					if (eve.getSignaturePubKey().get(0) != null)
						valueOutput = eve.getSignaturePubKey().get(0);
					break;
				case "Signature Priv Key":
					if (eve.getSignaturePrivKey().get(0) != null)
						valueOutput = eve.getSignaturePrivKey().get(0);
					break;
				case "Hash":
					if (eve.getHashKey().get(0) != null)
						valueOutput = eve.getHashKey().get(0);
					break;
				default:
					break;
				}
			}
		}
		
		return valueOutput;
	}
	
	// dalla tabella si estraggono i messaggi divisi per i vari agenti e si scrivono le rispettive rule
	// per distinguere tra i messaggi a quale agent vanno agganciati si vede il primo carattere della stringa.
	private void writeRuleR_Agent(BufferedWriter b) throws IOException {
		System.out.println("----writeRuleR_Agent---");
		b.write("\n");
		boolean firtE=true;
		for ( int i=0 ; i < indRuleR_Agent; i++) {
			if (ruleR_Agent[i].substring(0, 1).equals("E")) {
				if (firtE) {
					b.write("	rule r_agentERule  =");
					b.write("\n");
					b.write("	  par\n");
					b.write("            " + ruleR_Agent[i].substring(2, ruleR_Agent[i].length()));
					b.write("\n");
					firtE = false;
				} else {
					b.write("            " + ruleR_Agent[i].substring(2, ruleR_Agent[i].length()));
					b.write("\n");
				}
			}
		}
		if (!firtE) {
			b.write("	  endpar\n");
			b.write("\n");
		}
		
		boolean firtA = true;
		for (int i = 0; i < indRuleR_Agent; i++) {
			if (ruleR_Agent[i].substring(0, 1).equals("A")) {
				if (firtA) {
					b.write("	rule r_agentARule  =");
					b.write("\n");
					b.write("	  par\n");
					b.write("            " + ruleR_Agent[i].substring(2, ruleR_Agent[i].length()));
					b.write("\n");
					firtA = false;
				} else {
					b.write("            " + ruleR_Agent[i].substring(2, ruleR_Agent[i].length()));
					b.write("\n");
				}
			}
		}
		if (!firtA) {
			b.write("	  endpar\n");
			b.write("\n");
		}
		boolean firtB = true;
		for (int i = 0; i < indRuleR_Agent; i++) {
			if (ruleR_Agent[i].substring(0, 1).equals("B")) {
				if (firtB) {
					b.write("	rule r_agentBRule  =");
					b.write("\n");
					b.write("	  par\n");
					b.write("            " + ruleR_Agent[i].substring(2, ruleR_Agent[i].length()));
					b.write("\n");
					firtB = false;
				} else {
					b.write("            " + ruleR_Agent[i].substring(2, ruleR_Agent[i].length()));
					b.write("\n");
				}
			}
		}
		if (!firtB) {
			b.write("	  endpar\n");
			b.write("\n");
		}
		boolean firtS = true;
		for (int i = 0; i < indRuleR_Agent; i++) {
			if (ruleR_Agent[i].substring(0, 1).equals("S")) {
				if (firtS) {
					b.write("	rule r_agentSRule  =");
					b.write("\n");
					b.write("	  par\n");
					b.write("            " + ruleR_Agent[i].substring(2, ruleR_Agent[i].length()));
					b.write("\n");
					firtS = false;
				} else {
					b.write("            " + ruleR_Agent[i].substring(2, ruleR_Agent[i].length()));
					b.write("\n");
				}
			}
		}
		if (!firtS) {
			b.write("	  endpar\n");
			b.write("\n");
		}
		b.write("	main rule r_Main =\n");
		b.write("	  par\n");
		if (!firtA) {
			b.write("             program(agentA)\n");
		}		
		if (!firtB) {
			b.write("             program(agentB)\n");
		}	
		if (!firtS) {
			b.write("             program(agentS)\n");
		}	
		if (!firtE) {
			b.write("             program(agentE)\n");
		}	
		b.write("	  endpar\n");		
	}
	private void writeDefaultInitS0(BufferedWriter b) throws IOException {
		b.write("default init s0:\n");
		b.write("	function internalState"+actorStartProtocol.substring(0, 1)+"($a in "+actorStartProtocol+")=IDLE_M0\n");				
		b.write("	function internalState"+actorReceiveProtocol.substring(0, 1)+"($b in "+actorReceiveProtocol+")=WAITING_M0\n");				
		b.write("	function receiver=chosenReceiver\n");
		boolean found = false;
		
		
		// Scrittura dello stato S0 per la KnowledgeNonce
		countIf=0;
		found = writeDefaultInitS0Nonce(b, alice, "Alice", found);
		found = writeDefaultInitS0Nonce(b, bob, "Bob", found);
		found = writeDefaultInitS0Nonce(b, eve, "Eve", found);
		if (actorServer) {
			found = writeDefaultInitS0Nonce(b, server, "Server", found);
		}
		
		if (countIf>0) {
			b.write(" false");
			for (int i = 0; i < countIf; i++) {
				b.write(" endif");
			}
			b.write("\n");
		}
		
		// Scrittura dello stato S0 per la knowsIdentityCertificate
		countIf=0;
		found = false;
		found = writeDefaultInitS0IDCer(b, alice, "Alice", found);
		found = writeDefaultInitS0IDCer(b, bob, "Bob", found);
		found = writeDefaultInitS0IDCer(b, eve, "Eve", found);
		if (actorServer) {
			found = writeDefaultInitS0IDCer(b, server, "Server", found);
		}
		
		if (countIf>0) {
			b.write(" false");
			for (int i = 0; i < countIf; i++) {
				b.write(" endif");
			}
			b.write("\n");
		}
		
		// Scrittura dello stato S0 per la knowsBitString
		countIf=0;
		found = false;
		found = writeDefaultInitS0BitSt(b, alice, "Alice", found);
		found = writeDefaultInitS0BitSt(b, bob, "Bob", found);
		found = writeDefaultInitS0BitSt(b, eve, "Eve", found);
		if (actorServer) {
			found = writeDefaultInitS0BitSt(b, server, "Server", found);
		}
		
		if (countIf>0) {
			b.write(" false");
			for (int i = 0; i < countIf; i++) {
				b.write(" endif");
			}
			b.write("\n");
		}
		
		// Scrittura dello stato S0 per la KnowledgeTag
		countIf=0;
		found = false;
		found = writeDefaultInitS0Tag(b, alice, "Alice", found);
		found = writeDefaultInitS0Tag(b, bob, "Bob", found);
		found = writeDefaultInitS0Tag(b, eve, "Eve", found);
		if (actorServer) {
			found = writeDefaultInitS0Tag(b, server, "Server", found);
		}
		
		if (countIf>0) {
			b.write(" false");
			for (int i = 0; i < countIf; i++) {
				b.write(" endif");
			}
			b.write("\n");
		}
	
		// Scrittura dello stato S0 per la KnowledgeDigest
		countIf=0;
		found = false;
		found = writeDefaultInitS0Dig(b, alice, "Alice", found);
		found = writeDefaultInitS0Dig(b, bob, "Bob", found);
		found = writeDefaultInitS0Dig(b, eve, "Eve", found);
		if (actorServer) {
			found = writeDefaultInitS0Dig(b, server, "Server", found);
		}
		
		if (countIf>0) {
			b.write(" false");
			for (int i = 0; i < countIf; i++) {
				b.write(" endif");
			}
			b.write("\n");
		}
		
		// Scrittura dello stato S0 per la KnowledgeTimestamp
		countIf=0;
		found = false;
		found = writeDefaultInitS0Tim(b, alice, "Alice", found);
		found = writeDefaultInitS0Tim(b, bob, "Bob", found);
		found = writeDefaultInitS0Tim(b, eve, "Eve", found);
		if (actorServer) {
			found = writeDefaultInitS0Tim(b, server, "Server", found);
		}
		
		if (countIf>0) {
			b.write(" false");
			for (int i = 0; i < countIf; i++) {
				b.write(" endif");
			}
			b.write("\n");
		}			

		// Scrittura dello stato S0 per la knowsAsymPrivKey e knowsAsymPubKey
		countIf=0;
		found = false;
		found = writeDefaultInitS0AsPr(b, alice, "Alice", found);
		found = writeDefaultInitS0AsPr(b, bob, "Bob", found);
		found = writeDefaultInitS0AsPr(b, eve, "Eve", found);
		if (actorServer) {
			found = writeDefaultInitS0AsPr(b, server, "Server", found);
		}
		
		if (countIf>0) {
			b.write(") then true else false endif\n");
			b.write("	function knowsAsymPubKey($a in Agent ,$pk in KnowledgeAsymPubKey)=true\n");
		}
		
		// Scrittura dello stato S0 per la KnowledgeSymKey
		countIf=0;
		found = false;
		found = writeDefaultInitS0SymK(b, alice, "Alice", found);
		found = writeDefaultInitS0SymK(b, bob, "Bob", found);
		found = writeDefaultInitS0SymK(b, eve, "Eve", found);
		if (actorServer) {
			found = writeDefaultInitS0SymK(b, server, "Server", found);
		}
		
		if (countIf>0) {
			b.write(") then true else false endif\n");;
		}
		
		
		// Scrittura dello stato S0 per la knowsSignPubKey e knowsSignPrivKey
		countIf=0;
		found = false;
		found = writeDefaultInitS0SiPu(b, alice, "Alice", found);
		found = writeDefaultInitS0SiPu(b, bob, "Bob", found);
		found = writeDefaultInitS0SiPu(b, eve, "Eve", found);
		if (actorServer) {
			found = writeDefaultInitS0SiPu(b, server, "Server", found);
		}
		
		if (countIf>0) {
			b.write(") then true else false endif\n");
			b.write("	function knowsSignPrivKey($a in Agent ,$spr in KnowledgeSignPrivKey)=true\n");
		}
		b.write("	function mode=chosenMode\n");
		b.write("\n");
		b.write("	agent Alice:\n");
		b.write("		r_agentARule[]\n");
		b.write("\n");
		b.write("	agent Bob:\n");
		b.write("		r_agentBRule[]\n");
		b.write("\n");
		b.write("	agent Eve:\n");
		b.write("		r_agentERule[]\n");
		if (actorServer) {
			b.write("\n");
			b.write("	agent Server:\n");
			b.write("		r_agentSRule[]\n");
		}
	/*	 
	function mode=chosenMode
	
	agent Alice:
		r_agentARule[]

	agent Bob:
		r_agentBRule[]
		
	agent Eve:
	r_agentERule[]

		 
		 
		domain KnowledgeHash subsetof Any

	*/	
				
	}
// Scrittura dello stato S0 per la KnowledgeNonce
	private boolean writeDefaultInitS0Nonce(BufferedWriter b, SecurityKey KeyActor, String agent, boolean foundIn)
			throws IOException {
		boolean found = foundIn;
		boolean first = true;
		for (String ele : KeyActor.getNonce()) {
			if (!found) {
				b.write("	function knowsNonce($a in Agent, $n in KnowledgeNonce)=if($a=agent" + agent.substring(0, 1)
						+ " and $n=" + ele.toUpperCase() + ")");
				countIf++;
				found = true;
			} else {
				if (first) {
					b.write(" if($a=agent" + agent.substring(0, 1) + " and $n=" + ele.toUpperCase() + ")");
					countIf++;
				} else {
					b.write(" or ($a=agent" + agent.substring(0, 1) + " and $n=" + ele.toUpperCase() + ")");
				}
			}
			first = false;
		}
		if (countIf > 0) {
			b.write(" then true else");
		}
		return found;
	}
	// Scrittura dello stato S0 per la knowsIdentityCertificate
		private boolean writeDefaultInitS0IDCer(BufferedWriter b, SecurityKey KeyActor, String agent, boolean foundIn)
				throws IOException {
			boolean found = foundIn;
			boolean first = true;
			for (String ele : KeyActor.getIdCertificate()) {
				if (!found) {
					b.write("	function knowsIdentityCertificate($a in Agent, $i in KnowledgeIdentityCertificate)=if($a=agent" + agent.substring(0, 1)
							+ " and $i=" + ele.toUpperCase() + ")");
					countIf++;
					found = true;
				} else {
					if (first) {
						b.write(" if($a=agent" + agent.substring(0, 1) + " and $i=" + ele.toUpperCase() + ")");
						countIf++;
					} else {
						b.write(" or ($a=agent" + agent.substring(0, 1) + " and $i=" + ele.toUpperCase() + ")");
					}
				}
				first = false;
			}
			if (countIf > 0) {
				b.write(" then true else");
			}
			return found;
		}
		// Scrittura dello stato S0 per la knowsBitString
		private boolean writeDefaultInitS0BitSt(BufferedWriter b, SecurityKey KeyActor, String agent, boolean foundIn)
				throws IOException {
			boolean found = foundIn;
			boolean first = true;
			for (String ele : KeyActor.getBitstring()) {
				if (!found) {
					b.write("	function knowsBitString($a in Agent, $bs in KnowledgeBitString)=if($a=agent" + agent.substring(0, 1)
							+ " and $bs=" + ele.toUpperCase() + ")");
					countIf++;
					found = true;
				} else {
					if (first) {
						b.write(" if($a=agent" + agent.substring(0, 1) + " and $bs=" + ele.toUpperCase() + ")");
						countIf++;
					} else {
						b.write(" or ($a=agent" + agent.substring(0, 1) + " and $bs=" + ele.toUpperCase() + ")");
					}
				}
				first = false;
			}
			if (countIf > 0) {
				b.write(" then true else");
			}
			return found;
		}
		// Scrittura dello stato S0 per la knowsBitString
		private boolean writeDefaultInitS0Tag(BufferedWriter b, SecurityKey KeyActor, String agent, boolean foundIn)
				throws IOException {
			boolean found = foundIn;
			boolean first = true;
			for (String ele : KeyActor.getTag()) {
				if (!found) {
					b.write("	function knowsTag($a in Agent, $tg in KnowledgeTag)=if($a=agent" + agent.substring(0, 1)
							+ " and $tg=" + ele.toUpperCase() + ")");
					countIf++;
					found = true;
				} else {
					if (first) {
						b.write(" if($a=agent" + agent.substring(0, 1) + " and $tg=" + ele.toUpperCase() + ")");
						countIf++;
					} else {
						b.write(" or ($a=agent" + agent.substring(0, 1) + " and $tg=" + ele.toUpperCase() + ")");
					}
				}
				first = false;
			}
			if (countIf > 0) {
				b.write(" then true else");
			}
			return found;
		}
		
		// Scrittura dello stato S0 per la knowsDigest
		private boolean writeDefaultInitS0Dig(BufferedWriter b, SecurityKey KeyActor, String agent, boolean foundIn)
				throws IOException {
			boolean found = foundIn;
			boolean first = true;
			for (String ele : KeyActor.getDigest()) {
				if (!found) {
					b.write("	function knowsDigest($a in Agent, $dg in KnowledgeDigest)=if($a=agent" + agent.substring(0, 1)
							+ " and $dg=" + ele.toUpperCase() + ")");
					countIf++;
					found = true;
				} else {
					if (first) {
						b.write(" if($a=agent" + agent.substring(0, 1) + " and $dg=" + ele.toUpperCase() + ")");
						countIf++;
					} else {
						b.write(" or ($a=agent" + agent.substring(0, 1) + " and $dg=" + ele.toUpperCase() + ")");
					}
				}
				first = false;
			}
			if (countIf > 0) {
				b.write(" then true else");
			}
			return found;
		}
		
		// Scrittura dello stato S0 per la knowsTimestamp
		private boolean writeDefaultInitS0Tim(BufferedWriter b, SecurityKey KeyActor, String agent, boolean foundIn)
				throws IOException {
			boolean found = foundIn;
			boolean first = true;
			for (String ele : KeyActor.getTimestamp()) {
				if (!found) {
					b.write("	function knowsTimestamp($a in Agent, $tm in KnowledgeTimestamp)=if($a=agent" + agent.substring(0, 1)
							+ " and $tm=" + ele.toUpperCase() + ")");
					countIf++;
					found = true;
				} else {
					if (first) {
						b.write(" if($a=agent" + agent.substring(0, 1) + " and $tm=" + ele.toUpperCase() + ")");
						countIf++;
					} else {
						b.write(" or ($a=agent" + agent.substring(0, 1) + " and $tm=" + ele.toUpperCase() + ")");
					}
				}
				first = false;
			}
			if (countIf > 0) {
				b.write(" then true else");
			}
			return found;
		}
		
		// Scrittura dello stato S0 per la knowsAsymPrivKey
		private boolean writeDefaultInitS0AsPr(BufferedWriter b, SecurityKey KeyActor, String agent, boolean foundIn)
				throws IOException {
			boolean found = foundIn;
			for (String ele : KeyActor.getAsymmetricPrivateKey()) {
				if (!found) {
					b.write("	function knowsAsymPrivKey($a in Agent ,$k in KnowledgeAsymPrivKey)=if(($a=agent" + agent.substring(0, 1)
							+ " and $k=" + ele.toUpperCase() + ")");
					countIf++;
					found = true;
				} else {
						b.write(" or ($a=agent" + agent.substring(0, 1) + " and $k=" + ele.toUpperCase() + ")");
					}
			}

			return found;
		}		

		// Scrittura dello stato S0 per la knowsSymKey
		private boolean writeDefaultInitS0SymK(BufferedWriter b, SecurityKey KeyActor, String agent, boolean foundIn)
				throws IOException {
			boolean found = foundIn;
			for (String ele : KeyActor.getSymmetricKey()) {
				if (!found) {
					b.write("	function knowsSymKey($a in Agent ,$sk in KnowledgeSymKey)=if(($a=agent" + agent.substring(0, 1)
							+ " and $sk=" + ele.toUpperCase() + ")");
					countIf++;
					found = true;
				} else {
						b.write(" or ($a=agent" + agent.substring(0, 1) + " and $sk=" + ele.toUpperCase() + ")");
					}
			}

			return found;
		}		
		
		// Scrittura dello stato S0 per la knowsSignPubKey
		private boolean writeDefaultInitS0SiPu(BufferedWriter b, SecurityKey KeyActor, String agent, boolean foundIn)
				throws IOException {
			boolean found = foundIn;
			for (String ele : KeyActor.getSymmetricKey()) {
				if (!found) {
					b.write("	function knowsSignPubKey($a in Agent ,$spu in KnowledgeSignPubKey)=if(($a=agent" + agent.substring(0, 1)
							+ " and $spu=" + ele.toUpperCase() + ")");
					countIf++;
					found = true;
				} else {
						b.write(" or ($a=agent" + agent.substring(0, 1) + " and $spu=" + ele.toUpperCase() + ")");
					}
			}

			return found;
		}		

		
}
