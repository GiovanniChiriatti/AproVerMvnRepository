package org.unimi.model;
import java.io.*;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.Iterator;
import java.util.Map;
import java.util.TreeMap;

import javafx.scene.image.Image;

public class WriteASM {
	
	private Boolean actorServer;
	private String[] ruleR_Agent = new String[150];
	private String[] operationMessage = new String[150];
	private Map<String, String> otherElement = new HashMap<String, String>();
	private Map<String, String> attackerElement = new HashMap<String, String>();
	private Map<String, String> honestElement = new HashMap<String, String>();
	private Map<String, Integer> honestLevelElement;
	private int  levelTot;
	private int fieldPosition;
	private int numEncField;
	private int numSymField;
	private int numSignField;
	private int numHashField;
	private int indRuleR_Agent;
	private int countIf;
	private int numRuleE;
	private int numRuleB;
	private int numRuleS;
	private int numRuleA;
	private int numOperationMessage;
	private SecurityKey KeyActorFrom;
	private SecurityKey KeyActorTo;	
	private Messages messages;
	private SecurityKey alice;
	private SecurityKey bob;
	private SecurityKey eve;
	private SecurityKey server;
	private Map<String, String> map = new TreeMap<String, String>();
	private String toolEve;
	private String nameFile;
	private String acronym;
	private String actorStartProtocol="";
	private String actorReceiveProtocol="";
	private BufferedWriter b;
	String[] changNumMSG = new String[15];
	
	public WriteASM(Boolean actorServer, Messages messages,SecurityKey alice,SecurityKey bob,SecurityKey eve,SecurityKey server,String toolEve, int fieldPosition, int levelTot,int numEncField,int numSignField,
			int numSymField,int numHashField, String nameFile,String acronym) 
			  throws IOException {
		System.out.println("WriteASM");
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
				this.nameFile=nameFile;
				this.acronym=acronym;
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
				for(Message e: messages.getListMessages()) {
					if (e.getNameMess()!=null && !e.getNameMess().isEmpty()
						&& !e.getNameMess().isBlank() && !e.getNameMess().equals("")) {
						changNumMSG[i]= e.getNameMess();
						}
					i++;
					}
				indRuleR_Agent=0;
//				System.out.println("-------WriteASM---------");
			    FileWriter w;
			    w=new FileWriter("src/main/resources/AProVerTest/"+ nameFile+".asm");

			   
			    b=new BufferedWriter (w);

			    
			  }
	//Scrittura prime info file asm
		public boolean writeFile() throws IOException {
			if (!initialControl()){
				b.write("errore dati incompleti");
				b.flush();
			    b.close();
				return false;
			}
		    // scrittura info iniziali del file asm
		    writeOpen(b);
		    // scrittura delle Knowledge
		    writeKnowledge(b);
		    b.flush();
		    b.close();
			
			return true;
		}
	private boolean initialControl() {
		if (alice == null) return false;
		if (bob == null) return false;
		if (eve == null) return false;
		if (messages == null) return false;
		if (alice.getAsymmetricPrivateKey().size()> 0 && !(eve.getAsymmetricPrivateKey().size() > 0)) return false;
		if (alice.getAsymmetricPublicKey().size()> 0 && !(eve.getAsymmetricPublicKey().size() > 0)) return false;
		
	 	if (alice.getSignaturePrivKey().size()> 0 && !(eve.getSignaturePrivKey().size() > 0)) return false;
	 	if (alice.getSignaturePubKey().size()> 0 && !(eve.getSignaturePubKey().size() > 0)) return false;
	 	if (alice.getSymmetricKey().size()> 0 && !(eve.getSymmetricKey().size() > 0)) return false;

		
		
		return true;
	}
	//Scrittura prime info file asm
	private void writeOpen(BufferedWriter b) throws IOException {
		b.write("asm "+nameFile+"\n");
		b.write("\n");
		b.write("import CryptoLibrary"+acronym+"\n");
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
		int numEncSymField = numSymField;
		if (numEncField>numSymField) {
			numEncSymField = numEncField; 
		}
		if (numEncSymField>0) {
			if (numEncSymField<3) {
				b.write("	domain EncField1={1}\n");
				b.write("	domain EncField2={2}\n");
			} else {
	//			b.write("	domain EncField1={1:"+ numEncSymField +"}\n");
	//			b.write("	domain EncField2={2:"+ numEncSymField +"}\n");
				b.write("	domain EncField1={1:"+ fieldPosition +"}\n");
				b.write("	domain EncField2={2:"+ fieldPosition +"}\n");

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
				map.put(alice.getAsymmetricPublicKey().get(i).toUpperCase() + " -> "  + alice.getAsymmetricPrivateKey().get(i).toUpperCase(), alice.getAsymmetricPublicKey().get(i));
			}
		}
		if (bob != null) {
			for (int i = 0; i < bob.getAsymmetricPrivateKey().size(); i++) {
				map.put(bob.getAsymmetricPublicKey().get(i).toUpperCase() + " -> "  + bob.getAsymmetricPrivateKey().get(i).toUpperCase(), bob.getAsymmetricPublicKey().get(i));
			}
		}
		if (eve != null) {
			for (int i = 0; i < eve.getAsymmetricPrivateKey().size(); i++) {
				map.put(eve.getAsymmetricPublicKey().get(i).toUpperCase() + " -> "  + eve.getAsymmetricPrivateKey().get(i).toUpperCase(),alice.getAsymmetricPublicKey().get(i));
			}
		}
		
		if (server != null) {
			for (int i = 0; i < server.getAsymmetricPrivateKey().size(); i++) {
				map.put(server.getAsymmetricPublicKey().get(i).toUpperCase() + " -> "  + server.getAsymmetricPrivateKey().get(i).toUpperCase(),server.getAsymmetricPublicKey().get(i));
			}
		}
	    int numeMap = 0;
	    
	    for(String s : map.keySet()) {
	    	if (numeMap ==0 ) {
	    		b.write("	domain KnowledgeAsymPubKey = {" + s.substring(0, s.lastIndexOf(" -> ")));
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
	    		b.write("	domain KnowledgeAsymPrivKey = {" + s.substring(s.lastIndexOf(" -> ")+4, s.length()));
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
		// si leggono tutti i messaggi del protocollo
		for (int i = 0; i < 15; i++) {
			Message message = messages.getMessage(i);
			if (message.getActorfrom() == null || message.getActorfrom().isEmpty()) {
				if (i > 0) {
					break;
				}
			}
			// per ogni messaggio si scrivono l'istruzione Rule e la Let
			b.write("	rule r_message_replay_" + changNumMSG[i] + " =\n");
			ruleR_Agent[indRuleR_Agent] = "E r_message_replay_" + changNumMSG[i] + "[]";
			indRuleR_Agent++;
			b.write("		//choose what agets are interested by the message\n");
			b.write("		let ($b=agent" + message.getActorTo().substring(0, 1).toUpperCase() + ",$a=agent"
				+ message.getActorfrom().substring(0, 1).toUpperCase() + ") in\n");
			b.write("		  par \n");
//			if (messages.getMessage(i).getPayload().contains("-")) {b.write("		  par \n");}
			// si iniziano a scrivere le istruzoni per la modalità passiva
			writeMessageAttackerPassive(b,message,i);
			// si iniziano a scrivere le istruzoni per la modalità attiva
			writeMessageAttackerActive(b,message,i);
//			if (messages.getMessage(i).getPayload().contains("-")) {b.write("		  endpar \n");}
			b.write("		  endpar \n");
			b.write("		endlet \n");
		}
	}

	// Scrittura delle informazioni legate ai messaggi scambiati prendendo in
	// cosniderazione un eventuale attacco quando EVE è passivo
	private void writeMessageAttackerPassive(BufferedWriter b, Message message, int i) throws IOException {
		b.write("			//check the reception of the message and the modality of the attack\n");
		b.write("			if(protocolMessage($a,self)=" + changNumMSG[i] + " and protocolMessage(self,$b)!="
				+ changNumMSG[i] + " and mode=PASSIVE)then\n");
		b.write("			        //in passsive mode if the attacker knows the decryption key, the message payload is readable and it can be added to the attacker knowledge\n");
		b.write("			        // the message must be sent unaltered\n");
		b.write("		          par \n");
		//
		// per ogni messaggio
		// dal payload si estraggono tutti i filed e si scrivono a prescindere
		findActorFromTo(message.getActorfrom(), message.getActorTo());
		String[] msgFieldTot = FindField(messages.getMessage(i).getPayload());
		String[] linesKnowledge = writeKnowledge(message, i, msgFieldTot, "$a");

		String spaces = "                            ";
		printKnowledge(b, "Prot", linesKnowledge, spaces);
		if (i==0) {printKnowledge(b, "Mess", linesKnowledge, spaces);}
		//
		// si divide il payload in messaggi separati (se necessario)
		String[] listSubPayload = findMsg(message);
		// per ogni messaggio si estraggono le operazioni
		int totOpz = 0;
		for (int j = 0; j < 15; j++) {
			if (listSubPayload[j] == null || listSubPayload[j].isEmpty()) {
				break;
			}
			// per ogni sottomessaggio si scrivono le istruzioni di Encode
			String keyUsed = findKey(listSubPayload[j]);
			String operation = "";
			if (keyUsed != null) {
				totOpz++;
				operation = findOperation(keyUsed, message.getActorfrom(), message.getActorTo());
				String[] msgEncField1EncField2 = new String[15];
				String[] msgField = new String[15];
				// determino i dati per la scrittura del tipo di crittografia ha il messaggio
				String levelEncField1EncField2 = calcLevelEncField1EncField2(listSubPayload[j], msgEncField1EncField2,
						msgField, msgFieldTot);
				if (reversOperation(operation).equals("symEnc")) {
					b.write("                            	" + reversOperation(operation) + "(" + changNumMSG[i] + ","
							+ levelEncField1EncField2 + "):="
							+ findKeyEle(keyUsed, message.getActorfrom(), message.getActorTo(), true) + "\n");
				} else {
					b.write("                            	" + reversOperation(operation) + "(" + changNumMSG[i] + ","
							+ levelEncField1EncField2 + "):="
							+ findKeyEle(keyUsed, message.getActorfrom(), message.getActorTo(), false) + "\n");
				}
			} else {
				// se nel sottomessaggio non c'è una funzione di crittografia si scrive la konw
				String[] msgEncField1EncField2 = new String[15];
				String[] msgField = new String[15];
				// determino i dati per la scrittura del tipo di crittografia ha il messaggio
				String levelEncField1EncField2 = calcLevelEncField1EncField2(listSubPayload[j], msgEncField1EncField2,
						msgField, msgFieldTot);
				// determino i campi del messaggio e la posizione
				String[] msgFieldDet = detField(msgField, msgFieldTot);
				findActorFromTo(message.getActorfrom(), message.getActorTo());
				linesKnowledge = writeKnowledge(message, i, msgFieldDet, "$a");
				spaces = "                            ";
				printKnowledge(b, "Know", linesKnowledge, spaces);
				if (i!=0) {printKnowledge(b, "Mess", linesKnowledge, spaces);}
			}
		}
		b.write("		          endpar \n");
		b.write("			endif \n");
		// Si rileggono i sottomessaggi per verificare se l'attore riesce a
		// decodificarli e in questo caso si aggiorna la knowlege
		boolean firstOp = true;
		for (int j = 0; j < 15; j++) {
			if (listSubPayload[j] == null || listSubPayload[j].isEmpty()) {
				break;
			}
			String keyUsed = findKey(listSubPayload[j]);
			String operation = "";
			if (keyUsed != null) {
				operation = findOperation(keyUsed, message.getActorfrom(), message.getActorTo());
				String[] msgEncField1EncField2 = new String[15];
				String[] msgField = new String[15];
				// determino i dati per la scrittura del tipo di crittografia ha il messaggio
				String levelEncField1EncField2 = calcLevelEncField1EncField2(listSubPayload[j], msgEncField1EncField2,
						msgField, msgFieldTot);
				String[] msgFieldDet = detField(msgField, msgFieldTot);
				if (operation != null && !operation.isEmpty()) {
					if (firstOp) {
						b.write("			if(protocolMessage($a,self)=" + changNumMSG[i]
							+ " and protocolMessage(self,$b)!=" + changNumMSG[i] + " and mode=PASSIVE)then\n");
						firstOp = false;
						if(totOpz>1) {b.write("			  par \n");}
					}
					b.write("			        if(" + operation + "(" + changNumMSG[i] + "," + levelEncField1EncField2
							+ ",self)=true)then\n");
					linesKnowledge = writeKnowledge(message, i, msgFieldDet, "$a");
					if (countMsgFieldDet(msgFieldDet) > 1 || i!=0) {
						b.write("			  		  par \n");
					}
					spaces = "                            ";
					printKnowledge(b, "Know", linesKnowledge, spaces);
					if (i!=0) {printKnowledge(b, "Mess", linesKnowledge, spaces);}
					if (countMsgFieldDet(msgFieldDet) > 1 || i!=0) {
						b.write("			  		  endpar \n");
					}
					if (i!=0) {
						b.write("				    else \n");
						if (countMsgFieldDet(msgFieldDet) > 1) {
							b.write("			  		  par \n");
						}
						printKnowledge(b, "Mes3", linesKnowledge, spaces);
						if (countMsgFieldDet(msgFieldDet) > 1) {
							b.write("			  		  endpar \n");
						}
					}
					b.write("					endif \n");
					
				}
			}

		}
		if (!firstOp ) {
			if(totOpz>1) {
				b.write("			  endpar \n");
			}
			b.write("			endif \n");
		}

	}
	// Scrittura delle informazioni legate ai messaggi scambiati prendendo in
	// cosniderazione un eventuale attacco quando EVE è attivo
	private void writeMessageAttackerActive(BufferedWriter b, Message message, int i) throws IOException {
		b.write("			        //check the reception of the message and the modality of the attack\n");
		b.write("			if(protocolMessage($a,self)=" + changNumMSG[i]
				+ " and protocolMessage(self,$b)!=" + changNumMSG[i] + " and mode=ACTIVE)then\n");
		b.write("		          par \n");
		//
		// per ogni messaggio
		// dal payload si estraggono tutti i filed e si scrivono a prescindere
		findActorFromTo(message.getActorfrom(), message.getActorTo());
		String[] msgFieldTot = FindField(messages.getMessage(i).getPayload());
		String[] linesKnowledge = writeKnowledge(message, i, msgFieldTot, "$a");

		String spaces = "                            ";
		printKnowledge(b, "Prot", linesKnowledge, spaces);
		if (i==0) {printKnowledge(b, "Mes2", linesKnowledge, spaces);}
		//
		// si divide il payload in messaggi separati (se necessario)
		String[] listSubPayload = findMsg(message);
		// per ogni messaggio si estraggono le operazioni
		int totOpz = 0;
		for (int j = 0; j < 15; j++) {
			if (listSubPayload[j] == null || listSubPayload[j].isEmpty()) {
				break;
			}
			// per ogni sottomessaggio si scrivono le istruzioni di Encode
			String keyUsed = findKey(listSubPayload[j]);
			String operation = "";
			if (keyUsed != null) {
				totOpz++;
				operation = findOperation(keyUsed, message.getActorfrom(), message.getActorTo());
				String[] msgEncField1EncField2 = new String[15];
				String[] msgField = new String[15];
				// determino i dati per la scrittura del tipo di crittografia ha il messaggio
				String levelEncField1EncField2 = calcLevelEncField1EncField2(listSubPayload[j], msgEncField1EncField2,
						msgField, msgFieldTot);
				if (reversOperation(operation).equals("symEnc")) {
					b.write("                            	" + reversOperation(operation) + "(" + changNumMSG[i] + ","
							+ levelEncField1EncField2 + "):="
							+ findKeyEle(keyUsed, message.getActorfrom(), message.getActorTo(), true) + "\n");
				} else {
					b.write("                            	" + reversOperation(operation) + "(" + changNumMSG[i] + ","
							+ levelEncField1EncField2 + "):="
							+ findKeyEle(keyUsed, message.getActorfrom(), message.getActorTo(), false) + "\n");
				}
			} else {
				// se nel sottomessaggio non c'è una funzione di crittografia si scrive la konw
				String[] msgEncField1EncField2 = new String[15];
				String[] msgField = new String[15];
				// determino i dati per la scrittura del tipo di crittografia ha il messaggio
				String levelEncField1EncField2 = calcLevelEncField1EncField2(listSubPayload[j], msgEncField1EncField2,
						msgField, msgFieldTot);
				// determino i campi del messaggio e la posizione
				String[] msgFieldDet = detField(msgField, msgFieldTot);
				findActorFromTo(message.getActorfrom(), message.getActorTo());
				linesKnowledge = writeKnowledge(message, i, msgFieldDet, "$a");
				spaces = "                            ";
				printKnowledge(b, "Know", linesKnowledge, spaces);
				if (i!=0) {printKnowledge(b, "Mes2", linesKnowledge, spaces);}
			}
		}
		b.write("		          endpar \n");
		b.write("			endif \n");
		// Si rileggono i sottomessaggi per verificare se l'attore riesce a
		// decodificarli e in questo caso si aggiorna la knowlege
		boolean firstOp = true;
		for (int j = 0; j < 15; j++) {
			if (listSubPayload[j] == null || listSubPayload[j].isEmpty()) {
				break;
			}
			String keyUsed = findKey(listSubPayload[j]);
			String operation = "";
			if (keyUsed != null) {
				operation = findOperation(keyUsed, message.getActorfrom(), message.getActorTo());
				String[] msgEncField1EncField2 = new String[15];
				String[] msgField = new String[15];
				// determino i dati per la scrittura del tipo di crittografia ha il messaggio
				String levelEncField1EncField2 = calcLevelEncField1EncField2(listSubPayload[j], msgEncField1EncField2,
						msgField, msgFieldTot);
				String[] msgFieldDet = detField(msgField, msgFieldTot);
				if (operation != null && !operation.isEmpty()) {
					if (firstOp) {
						b.write("			if(protocolMessage($a,self)=" + changNumMSG[i]
								+ " and protocolMessage(self,$b)!=" + changNumMSG[i] + " and mode=ACTIVE)then\n");
						firstOp = false;
						if(totOpz>1) {b.write("			  par \n");}
					}
					b.write("			        if(" + operation + "(" + changNumMSG[i] + "," + levelEncField1EncField2
							+ ",self)=true)then\n");
					linesKnowledge = writeKnowledge(message, i, msgFieldDet, "$a");
					if (countMsgFieldDet(msgFieldDet) > 1 || i!=0) {
						b.write("			  		  par \n");
					}
					spaces = "                            ";
					printKnowledge(b, "Know", linesKnowledge, spaces);
					if (i!=0) {printKnowledge(b, "Mes2", linesKnowledge, spaces);}
					if (countMsgFieldDet(msgFieldDet) > 1 || i!=0) {
						b.write("			  		  endpar \n");
					}
					if (i!=0) {
						b.write("				    else \n");
						if (countMsgFieldDet(msgFieldDet) > 1) {
							b.write("			  		  par \n");
						}
						printKnowledge(b, "Mes3", linesKnowledge, spaces);
						if (countMsgFieldDet(msgFieldDet) > 1) {
							b.write("			  		  endpar \n");
						}
					}					
					b.write("					endif \n");
				}
			}

		}
		if (!firstOp ) {
			if(totOpz>1) {
				b.write("			  endpar \n");
			}
			b.write("			endif \n");
		}
	}
	// determina l'elenco dei messaggi che compongono il payload
	private String[] findMsg(Message message) {
		String partMsg = message.getPayload();
		int numBrackets = 0;
		char[] string = partMsg.toCharArray();
		String subPayload = "";
		int i = 0;
		String[] listSubPayload = new String[15];
		boolean primo = true;
		for (char c : string) {
			if (c == '{') {
				if (!primo) {
					if (numBrackets == 0) {
						listSubPayload[i] = subPayload;
						i++;
						numBrackets = 0;
						subPayload = "";
					}

				}
				numBrackets++;
			}
			if (c == '}') {
				numBrackets--;
			}
			primo = false;
			subPayload = subPayload + c;

		}
		listSubPayload[i] = subPayload;
		for (int j = 0; j < 15; j++) {
			if (listSubPayload[j] == null) {
				break;
			}
			if (listSubPayload[j].substring(listSubPayload[j].length() - 1).equals(",")) {
				listSubPayload[j] = listSubPayload[j].substring(0, listSubPayload[j].length() - 1);
			}
//			System.out.println("listSubPayload[j] " + listSubPayload[j]);
		}

		return listSubPayload;

	}

	// determina quale chiave è stata usata prima di inviare il messaggio
	private String findKey(String partMsg) {

		String keyUsed = null;

		if (!partMsg.substring(partMsg.length() - 1).equals("-")) {
			return keyUsed;
		}

		keyUsed = partMsg.substring(0, partMsg.length() - 1);
		keyUsed = keyUsed.substring(keyUsed.lastIndexOf("-") + 1);
		return keyUsed;
	}

	// determina quale algoritmo crittografico è stato usato prima di inviare il
	// messaggio
	private String findOperation(String keyUsed, String actorFrom, String actorTo) {
		String operation = null;
		findActorFromTo(actorFrom, actorTo);
		if (KeyActorFrom != null) {
			operation = KeyActorFrom.searchEle(keyUsed);
//				System.out.println("operation " + operation);
			if (operation == null) {
				if (KeyActorTo != null) {
					operation = KeyActorTo.searchEle(keyUsed);
//						System.out.println("operation to " + operation);
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
				return null;
			}
		}
		return null;
	}

	// determina quale SecurityKey appartiene all'cator from e all'actor to
	private void findActorFromTo(String actorFrom, String actorTo) {

		
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
	}
	// routin che estrae tutti i campi dal payload
	private String[] FindField(String messagePayload) {
		
		String[] msgField = new String[15];
		String fieldMsg = "";
		boolean dash = false;
		int numField=0;
		int counter = 0;
		for (int i = 0; i < messagePayload.length(); i++) {
	//		System.out.println("---> leggo carattere i " + i + " -->" + messagePart.charAt(i));
			if (messagePayload.charAt(i) == '-') {
				counter++;
	//			System.out.println("conto trattino " + counter);
			}
			if (messagePayload.charAt(i) != '-' && messagePayload.charAt(i) != ' ' && messagePayload.charAt(i) != ','
					&& messagePayload.charAt(i) != '}' && messagePayload.charAt(i) != '{') {
				fieldMsg = fieldMsg + messagePayload.charAt(i);
	//			System.out.println("memorizzo parte della stringa " + fieldMsg.toString());
			}
			if (fieldMsg != null && !fieldMsg.isEmpty()
					&& (messagePayload.charAt(i) == ',' || messagePayload.charAt(i) == '}')) {
				msgField[numField+1] = fieldMsg.toUpperCase();
	//			System.out.println("archivio stringa " + (encField2+1) + " - " + msgField[encField2+1].toString());
				fieldMsg = "";
				numField++;
			}
			if (messagePayload.charAt(i) == '-') {
				if (!dash) {
	//				System.out.println("metto dash a true in quanto si tratta primo trattino");
					dash = true;
				} else {
	//				System.out.println(
	//						"trovo secondo trattino e torno indietro " + messagePart.charAt(i) + " OPZ: " + fieldMsg);
					dash = false;
					fieldMsg = "";
					boolean first = false;
					int countDash = 0;
					int count = 0;
					int countField = 0;

				}
			}

		}

		return msgField;

	}
	// determina i campi di output del sottomessaggio (si dividono i messaggi del payload)
	private String[] detField (String[] msgField, String[] msgFieldTot) {
/*		System.out.println("*---------- msg msgField ---------*");
		for (String e : msgField){System.out.println("    " + e);}
		System.out.println("*---------- msg msgFieldTot ---------*");
		for (String e : msgFieldTot){System.out.println("    " + e);}
*/		
		String[] msgFieldDet = new String[15];
		int i=1;
		int start =0;
		int end = 0;
		boolean find = false;
		for (int j=1; j<15 ; j++) {
//			System.out.println("leggo msgField con indice " + i + " " + msgField[i] + " e msgFieldTot " + j + " " + msgFieldTot[j]);
			if (msgField[i] == null) {System.out.println("esco per msgField[i] " + msgField[i]); break;}
			if (msgFieldTot[j] != null && !msgFieldTot[j].isEmpty() ) {
				if (msgField[i].equals(msgFieldTot[j]) && !find ) {
//					System.out.println("memorizzo start " + j); 
					start = j;
				}
				if (msgField[i].equals(msgFieldTot[j])) {
//					System.out.println("memorizzo end  " + j); 
					find = true;
					end = j;
					i++;
				} else {
//					System.out.println("rimetto tutto apposto  i lo rimetto a 1"); 
					find = false;
					i = 1;
				}
				if (i > 14) {
//					System.out.println("esco per i " + i);
					break;
				}
			}
		}
		
//		System.out.println("determinate posizioni partenza:" + start + " Fine " + end);
		for (int k=start ; k<end+1 ; k++) {msgFieldDet[k] = msgFieldTot[k];}
//		System.out.println("*---------- msg msgFieldDet ---------*");
//		for (String e : msgFieldDet){System.out.println("    " + e);}

		return msgFieldDet;
	}
	// routin che server per determinare di quanti field si compone il messaggio e
	// quanti livelli di cripr/encript ci sono
	private String calcLevelEncField1EncField2(String messagePart, String[] msgEncField1EncField2, String[] msgField,String[] msgFieldTot) {
		int encField1, encField2, level, numMsgP;
		encField1 = 1;
		encField2 = 0;
		numMsgP = 0;
		level = 0;
		String calcLevelEncField1EncField2 = null;
		String fieldMsg = "";
		boolean dash = false;
//	 	System.out.println("analizzo la stringa " + messagePart.toString() + " lunghezza " + messagePart.length());
		int counter = 0;
		for (int i = 0; i < messagePart.length(); i++) {
	//		System.out.println("---> leggo carattere i " + i + " -->" + messagePart.charAt(i));
			if (messagePart.charAt(i) == '-') {
				counter++;
	//			System.out.println("conto trattino " + counter);
			}
			if (messagePart.charAt(i) != '-' && messagePart.charAt(i) != ' ' && messagePart.charAt(i) != ','
					&& messagePart.charAt(i) != '}' && messagePart.charAt(i) != '{') {
				fieldMsg = fieldMsg + messagePart.charAt(i);
	//			System.out.println("memorizzo parte della stringa " + fieldMsg.toString());
			}
			if (fieldMsg != null && !fieldMsg.isEmpty()
					&& (messagePart.charAt(i) == ',' || messagePart.charAt(i) == '}')) {
				msgField[encField2+1] = fieldMsg.toUpperCase();
	//			System.out.println("archivio stringa " + (encField2+1) + " - " + msgField[encField2+1].toString());
				fieldMsg = "";
				encField2++;
			}
			if (messagePart.charAt(i) == '-') {
				if (!dash) {
	//				System.out.println("metto dash a true in quanto si tratta primo trattino");
					dash = true;
				} else {
	//				System.out.println(
	//						"trovo secondo trattino e torno indietro " + messagePart.charAt(i) + " OPZ: " + fieldMsg);
					dash = false;
					fieldMsg = "";
					boolean first = false;
					int countDash = 0;
					int count = 0;
					int countField = 0;
					for (int j = i; j > -1; j--) {
	//					System.out.println("leggo carattere in posizione " + j + " - " + messagePart.charAt(j));
						if (messagePart.charAt(j) == '-') {
							countDash++;
	//						System.out.println("trovo trattino " + messagePart.charAt(j));
						}
						if (messagePart.charAt(j) == '}') {
							count++;
							first = true;
	//						System.out.println("trovo parentesi } e metto first a true " + messagePart.charAt(j));
						}
						if ((messagePart.charAt(j) == '}' || messagePart.charAt(j) == ',')
								&& (messagePart.charAt(j - 1) != '}' && messagePart.charAt(j - 1) != '-'
										&& messagePart.charAt(j - 1) != ',' && messagePart.charAt(j - 1) != ' ')) {
							countField++;
						}
						if (messagePart.charAt(j) == '{') {
							count--;
	//						System.out.println("trovo parentesi { " + messagePart.charAt(j));
						}
						if (count == 0 && first) {
							level = countDash / 2;
	//						System.out.println("calcolo level " + countDash);
							break;
						}
					}
					encField1 = encField2 - countField + 1;
					boolean trovaSequenza = false;
					int j = encField1;
					int appoField1 =encField1;
					int appoField2 =encField2;
					// cerca la sequenza dei field trovati all'interno dei field del payload
/*					System.out.println("verifico i campi del messaggio con quelli del payload da " + encField1 + " a " + encField2);
 					System.out.println("Campi del messaggio : ");
					for (int k=encField1 ; k<encField2+1; k++){
						System.out.println("  " + msgField[k]);
					}
					System.out.println("Campi del payload : ");
					for (int k=0 ; k<15; k++){
						if (msgFieldTot[k] != null && !msgFieldTot[k].isEmpty()) {
							System.out.println("  " + msgFieldTot[k]);
						}
					}
*/
					for (int k = 0; k < 15; k++) {
//						System.out.println("cerco  " + msgField[j] + " e lo confronto con " + msgFieldTot[k]);
						
						if (msgFieldTot[k] != null && !msgFieldTot[k].isEmpty()) {
							if (msgField[j].equals(msgFieldTot[k]) && !trovaSequenza) {
//								System.out.println("trovato prima volta in posizione  " + k);
								appoField1 = k;
							}
							if (msgField[j].equals(msgFieldTot[k])) {
//								System.out.println("metto a true l'inizio sequenza e memorizzo anche appoField2  " + k);
								trovaSequenza = true;
								j++;
								appoField2 = k;
							} else {
//							 	System.out.println("metto a false l'inizio sequenza e riposizione j  a " + encField1);
								trovaSequenza = false;
								j = encField1;
							}
//							System.out.println("verifico se j è arrivato a encField2 " + j + " " +encField2);
							if (j > encField2) {
								break;
							}
						}
					}
					msgEncField1EncField2[numMsgP] = level + "," + appoField1 + "," + appoField2;
//					System.out.println("msgEncField1EncField2[numMsgP] " + msgEncField1EncField2[numMsgP]);
					numMsgP++;
				}
			}

		}
		
		
/*		if (!(numMsgP > 0)) {

			System.out.println("*------------- non c'è chiave -------* " + "field1 " + " Field 2 " + encField2);
			encField1 = 1;
			boolean trovaSequenza = false;
			int j = encField1;
			int appoField1 = encField1;
			int appoField2 = encField2;
			// cerca la sequenza dei field trovati all'interno dei field del payload
			System.out.println(
					"verifico i campi del messaggio con quelli del payload da " + encField1 + " a " + encField2);
			System.out.println("Campi del messaggio : ");
			for (int k = encField1; k < encField2 + 1; k++) {
				System.out.println("  " + msgField[k]);
			}
			System.out.println("Campi del payload : ");
			for (int k = 0; k < 15; k++) {
				if (msgFieldTot[k] != null && !msgFieldTot[k].isEmpty()) {
					System.out.println("  " + msgFieldTot[k]);
				}
			}
			for (int k = 0; k < 15; k++) {
				System.out.println("cerco  " + msgField[j] + " e lo confronto con " + msgFieldTot[k]);

				if (msgFieldTot[k] != null && !msgFieldTot[k].isEmpty()) {
					if (msgField[j].equals(msgFieldTot[k]) && !trovaSequenza) {
						System.out.println("trovato prima volta in posizione  " + k);
						appoField1 = k;
					}
					if (msgField[j].equals(msgFieldTot[k])) {
						System.out.println("metto a true l'inizio sequenza e memorizzo anche appoField2  " + k);
						trovaSequenza = true;
						j++;
						appoField2 = k;
					} else {
						System.out.println("metto a false l'inizio sequenza e riposizione j  a " + encField1);
						trovaSequenza = false;
						j = encField1;
					}
					System.out.println("verifico se j è arrivato a encField2 " + j + " " + encField2);
					if (j > encField2) {
						break;
					}
				}
			}
		}
*/
		if (numMsgP > 0) {
			return msgEncField1EncField2[numMsgP - 1];
		}
		return null;
	}
	
	// determina le operazioni (crittografiche) all'interno del messaggio e scrive sul file di output
	private void determinesOperation (BufferedWriter b,int m, Message message, String messagePart,  String agent, String space,boolean receiverAG_B) 
			throws IOException {
		int encField1, encField2, level, numMsgP;
		encField1 = 1;
		encField2 = 0;
		numMsgP = 0;
		level = 0;
		String[] msgEncField1EncField2 = new String[15];
		String[] keyFieldMsg = new String[15];
		String calcLevelEncField1EncField2 = null;
		String fieldMsg = "";
		String keyMsg = "";
//		int numOperationMessage=0;
		// pulisce la tabella delle operazioni.
//		for (String eleOperationMessage : operationMessage) {
//			eleOperationMessage="";
//		}

		boolean dash = false;
//		System.out.println("determinesOperation analizzo la stringa " + messagePart.toString() + " lunghezza " + messagePart.length());
		int counter = 0;
		
		for (int i = 0; i < messagePart.length(); i++) {
//			System.out.println("determinesOperation ---> leggo carattere i " + i + " -->" + messagePart.charAt(i));
			if (messagePart.charAt(i) == '-') {
				counter++;
//				System.out.println("conto trattino " + counter);
			}
			if (messagePart.charAt(i) != '-' && messagePart.charAt(i) != ' ' && messagePart.charAt(i) != ','
					&& messagePart.charAt(i) != '}' && messagePart.charAt(i) != '{') {
				fieldMsg = fieldMsg + messagePart.charAt(i);
//				System.out.println("determinesOperation memorizzo parte della stringa " + fieldMsg.toString());
			}
			if (fieldMsg != null && !fieldMsg.isEmpty()
					&& (messagePart.charAt(i) == ',' || messagePart.charAt(i) == '}')) {
				fieldMsg = "";
				encField2++;
			}
			if (messagePart.charAt(i) != '-' && messagePart.charAt(i) != ' ' && dash) {
				keyMsg = keyMsg + messagePart.charAt(i);
			}
			if (messagePart.charAt(i) == '-') {
				if (!dash) {
//					System.out.println("determinesOperation metto dash a true in quanto si tratta primo trattino");
					keyMsg = "";
					dash = true;
				} else {
//					System.out.println(
//							"determinesOperation trovo secondo trattino e torno indietro " + messagePart.charAt(i) + " OPZ: " + fieldMsg + " keyMsg: " + keyMsg);
					dash = false;
					fieldMsg = "";
					 
					boolean first = false;
					int countDash = 0;
					int count = 0;
					int countField = 0;
					for (int j = i; j > -1; j--) {
//						System.out.println("determinesOperation leggo carattere in posizione " + j + " - " + messagePart.charAt(j));
						if (messagePart.charAt(j) == '-') {
							countDash++;
//							System.out.println("determinesOperation trovo trattino " + messagePart.charAt(j));
						}
						if (messagePart.charAt(j) == '}') {
							count++;
							first = true;
//							System.out.println("determinesOperation trovo parentesi } e metto first a true " + messagePart.charAt(j));
						}
						if ((messagePart.charAt(j) == '}' || messagePart.charAt(j) == ',')
								&& (messagePart.charAt(j - 1) != '}' && messagePart.charAt(j - 1) != '-'
										&& messagePart.charAt(j - 1) != ',' && messagePart.charAt(j - 1) != ' ')) {
							countField++;
						}
						if (messagePart.charAt(j) == '{') {
							count--;
//							System.out.println("determinesOperation trovo parentesi { " + messagePart.charAt(j));
						}
						if (count == 0 && first) {
							level = countDash / 2;
//							System.out.println("determinesOperation calcolo level " + countDash);
							break;
						}
					}
					encField1 = encField2 - countField + 1;
					msgEncField1EncField2[numMsgP] = level + "," + encField1 + "," + encField2;
					keyFieldMsg[numMsgP] = keyMsg;
//					System.out.println("determinesOperation msgEncField1EncField2[numMsgP] " + msgEncField1EncField2[numMsgP] + " keyFieldMsg[numMsgP] " + keyFieldMsg[numMsgP]);
					keyMsg="";
					numMsgP++;
				}
			}

		}
		for (int k=0 ; k<numMsgP ;  k++) {
			String operationMsg = findOperation(keyFieldMsg[k], message.getActorfrom(), message.getActorTo());
			String changValueEve;
			if (receiverAG_B) {
				changValueEve = findValueHonest(
						findKeyEle(keyFieldMsg[k], message.getActorfrom(), message.getActorTo(), false),
						message.getActorTo()).replace("($e", "(self");
			} else {
//			 	System.out.println ("findValueHonest2 " + findValueHonest(
//			 			findKeyEle(keyUsedMsg, message.getActorfrom(), message.getActorTo(), false),
//			 			message.getActorTo()));
				changValueEve = changValueEve(keyFieldMsg[k], message.getActorfrom(), true).replace("($e",
						"(self");
			}
			changValueEve = changValueEve.replace(",self", ",$e");	
			changValueEve = changValueEve.replace("($b", "(self");
			if (k < numMsgP-1) {
				b.write("			                      " + operationMsg + "(" + changNumMSG[m] + ","+ msgEncField1EncField2[k] + "):="+ changValueEve+"\n");	
				operationMessage[numOperationMessage] = reversOperation(operationMsg) + "(" + changNumMSG[m] + ","+ msgEncField1EncField2[k] + ",self):= true";
				numOperationMessage++;
			} else {
				b.write("			                      " + reversOperation(operationMsg) + "(" + changNumMSG[m] + ","+ msgEncField1EncField2[k] + "):="+ changValueEve+"\n");
				operationMessage[numOperationMessage] = operationMsg + "(" + changNumMSG[m] + ","+ msgEncField1EncField2[k] + ",self):= true";		
				numOperationMessage++;
			}
		}
	}


	// routin che server per determinare di quanti field si compone il messaggio e
	// quanti livelli di cripr/encript ci sono
	private String[] writeKnowledge(Message message, int numMessage, String[] msgField, String typeActor)
			throws IOException {
		System.out.println(" entro in  writeKnowledge");
		String[] linesKnowledge = new String[50];
		linesKnowledge[0] = "Prot	protocolMessage(self,$b):=" + changNumMSG[numMessage] + "\n";
		Boolean flgAtorTo = true;
		int numRighe = 1;
		for (int i = 0; i < 15; i++) {
			System.out.println(" writeKnowledge i: " + i);
			if (msgField[i] != null) {
				String typeFieldActorFrom = KeyActorFrom.searchEle(msgField[i]);
 						System.out.println("writeKnowledge Campo " + msgField[i] + " Tipo Campo " + typeFieldActorFrom);
				if (typeFieldActorFrom == null) {
					flgAtorTo = false;
					typeFieldActorFrom = KeyActorTo.searchEle(msgField[i]);
					if (typeFieldActorFrom == null) {
						typeFieldActorFrom = "Other";
						otherElement.put(message.getActorfrom().substring(0, 1) + " " + msgField[i].toUpperCase(),
								message.getActorfrom().substring(0, 1) + " " + msgField[i].toUpperCase());
					}
				}
				String eleEve = null;
				switch (typeFieldActorFrom) {
				case "Asymmetric Public Key":
					typeFieldActorFrom = "knowsAsymPubKey";
					eleEve = eve.getAsymmetricPublicKey().get(0);
					if (flgAtorTo) {
						attackerElement.put(message.getActorTo().substring(0, 1) + " " + msgField[i].toUpperCase(),
								"messageField($b,self," + i + "," + changNumMSG[numMessage] + ")");
					}
					break;
				case "Asymmetric Private Key":
					typeFieldActorFrom = "knowsAsymPrivKey";
					eleEve = eve.getAsymmetricPrivateKey().get(0);
					if (flgAtorTo) {
						attackerElement.put(message.getActorTo().substring(0, 1) + " " + msgField[i].toUpperCase(),
								"messageField($b,self," + i + "," + changNumMSG[numMessage] + ")");
					}
					break;
				case "Symmetric Key":
					typeFieldActorFrom = "knowsSymKey";
					eleEve = eve.getSymmetricKey().get(0);
					if (flgAtorTo) {
						attackerElement.put(message.getActorTo().substring(0, 1) + " " + msgField[i].toUpperCase(),
								"messageField($b,self," + i + "," + changNumMSG[numMessage] + ")");
					}
					break;
				case "Signature Pub Key":
					typeFieldActorFrom = "knowsSignPubKey";
					eleEve = eve.getSignaturePubKey().get(0);
					if (flgAtorTo) {
						attackerElement.put(message.getActorTo().substring(0, 1) + " " + msgField[i].toUpperCase(),
								"messageField($b,self," + i + "," + changNumMSG[numMessage] + ")");
					}
					break;
				case "Signature Priv Key":
					typeFieldActorFrom = "knowsSignPrivKey";
					eleEve = eve.getSignaturePrivKey().get(0);
					if (flgAtorTo) {
						attackerElement.put(message.getActorTo().substring(0, 1) + " " + msgField[i].toUpperCase(),
								"messageField($b,self," + i + "," + changNumMSG[numMessage] + ")");
					}
					break;
				case "Hash":
					typeFieldActorFrom = "knowsHash";
					eleEve = eve.getHashKey().get(0);
					if (flgAtorTo) {
						attackerElement.put(message.getActorTo().substring(0, 1) + " " + msgField[i].toUpperCase(),
								"messageField($b,self," + i + "," + changNumMSG[numMessage] + ")\n");
					}
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
				linesKnowledge[numRighe] = "Know	" + typeFieldActorFrom + "(self,messageField("
						+ typeActor + ",self," + i + "," + changNumMSG[numMessage] + ")):=true\n";
				numRighe++;
				linesKnowledge[numRighe] = "Kno3	" + typeFieldActorFrom + "(self,messageField(" + typeActor
						+ ",self," + i + "," + changNumMSG[0] + ")):=true\n";
				numRighe++;

				linesKnowledge[numRighe] = "Mess	messageField(self,$b," + i + ","
						+ changNumMSG[numMessage] + "):=messageField(" + typeActor + ",self," + i + ","
						+ changNumMSG[numMessage] + ")\n";
				numRighe++;
				if (eleEve != null) {
					linesKnowledge[numRighe] = "Mes2	messageField(self,$b," + i + ","
							+ changNumMSG[numMessage] + "):=" + eleEve + "\n";
					numRighe++;
					linesKnowledge[numRighe] = "Mes3	messageField(self,$b," + i + "," + changNumMSG[0]
							+ "):=messageField(" + typeActor + ",self," + i + "," + changNumMSG[numMessage] + ")\n";
					numRighe++;
				} else {
					linesKnowledge[numRighe] = "Mes2	messageField(self,$b," + i + ","
							+ changNumMSG[numMessage] + "):=messageField(" + typeActor + ",self," + i + ","
							+ changNumMSG[numMessage] + ")\n";
					numRighe++;
					linesKnowledge[numRighe] = "Mes3	messageField(self,$b," + i + "," + changNumMSG[0]
							+ "):=messageField(" + typeActor + ",self," + i + "," + changNumMSG[numMessage] + ")\n";
					numRighe++;
				}
			}
		}
		return linesKnowledge;
	}
	// conta quanti campi contiene il sottomessaggio
	private int countMsgFieldDet( String[] msgField) {
		int tot = 0;
		for (int i = 0; i < 15; i++) {
			if (msgField[i] != null) { tot++;}
		}
		return tot;
	}

	// stampa le informazioni registrate nelle fasi precedenti delle Know, field e
	// mess
	private void printKnowledge(BufferedWriter b, String type, String[] linesKnowledge, String spaces)
			throws IOException {
		for (int i = 0; i < 50; i++) {
			if (linesKnowledge[i] != null && linesKnowledge[i].startsWith(type)) {
				b.write(spaces + linesKnowledge[i].substring(4));
			}
		}
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
				return null;
			}
		}
		return null;
	}

	private String findKeyEle(String keyUsed, String actorfrom, String actorTo, boolean reverse) {
		for (Map.Entry<String, String> entry : attackerElement.entrySet()) {
			if (entry.getKey().equals(actorfrom.substring(0, 1) + " " + keyUsed.toUpperCase())) {
				return entry.getValue();
			}
		}
		if (reverse) {
			if (eve.getSymmetricKey().get(0) != null) {
				keyUsed = eve.getSymmetricKey().get(0);
			}
			for (String e : eve.getSymmetricKey()) {
				if (actorTo.contains("Alice") && alice.searchSym(e)) {
					keyUsed = e;
					break;
				}
				if (actorTo.contains("Bob") && bob.searchSym(e)) {
					keyUsed = e;
					break;
				}
				if (actorTo.contains("Server") && server.searchSym(e)) {
					keyUsed = e;

				}
			}
		}
		return keyUsed;
	}

	// Scrittura delle informazioni legate ai messaggi scambiati prendendo in
	// cosniderazione un eventuale attacco
	private void writeMessageHonest(BufferedWriter b) throws IOException {
		boolean endMessage = false;
		b.write("\n");
		b.write("	/*HONEST AGENT RULES*/	\n");
		System.out.println("/*HONEST AGENT RULES*/");
		String operationPrev = "";
		String levelEncField1EncField2Prev = "";
		boolean flgBob = false;
		boolean flgAlice = false;
		boolean flgServer = false;

		for (int i = 0; i < 15; i++) {
			Message message = messages.getMessage(i);
//			System.out.println("-------> " + message);
//			System.out.println("messaggio numero " + i + " actorfrom " + message.getActorfrom());
			if (message.getActorfrom() == null || message.getActorfrom().isEmpty()) {
				if (i > 0) {
					break;
				}
			}
			switch (message.getActorfrom()) {
			case "Alice":
				flgAlice = true;
				break;
			case "Bob":
				flgBob = true;
				break;
			case "Server":
				flgServer = true;
				break;
			}

			String[] msgFieldTot = FindField(messages.getMessage(i).getPayload()); 
			b.write("	rule r_message_" + changNumMSG[i] + " =\n");
			ruleR_Agent[indRuleR_Agent] = message.getActorfrom().toUpperCase().substring(0, 1) + " r_message_"
					+ changNumMSG[i] + "[]";
//			System.out.println("ruleR_Agent[indRuleR_Agent] " + ruleR_Agent[indRuleR_Agent] + " indRuleR_Agent " + indRuleR_Agent);
			indRuleR_Agent++;
			b.write("		let ($e=agentE) in\n");

			String[] listSubPayload = findMsg(message);

			if (i == 0) {
				for (int j = 0; j < 15; j++) {
					if (listSubPayload[j] == null || listSubPayload[j].isEmpty()) {break;}
					System.out.println("1-Leggo messaggio "+ j + " " +listSubPayload[j] + " MSG "+ i);
					String keyUsed = findKey(listSubPayload[j]);
					String operation = "";
					if (keyUsed != null) {
						operation = findOperation(keyUsed, message.getActorfrom(), message.getActorTo());
					} else {
						findActorFromTo(message.getActorfrom(), message.getActorTo());
					}
					String[] msgEncField1EncField2 = new String[15];
					String[] msgField = new String[15];
					String levelEncField1EncField2 = calcLevelEncField1EncField2(listSubPayload[j],
							msgEncField1EncField2, msgField,msgFieldTot);
					String[] msgFieldDet = detField(msgField,msgFieldTot);
//					System.out.println("primo messaggio " + changNumMSG[i] + "  " + listSubPayload[j]);
					actorStartProtocol = message.getActorfrom();
					actorReceiveProtocol = message.getActorTo();
					b.write("			if(internalState" + message.getActorfrom().substring(0, 1) + "(self)=IDLE_"
							+ changNumMSG[i] + ")then \n");
					b.write("			        if(receiver=AG_" + message.getActorTo().substring(0, 1) + ")then\n");
					b.write("			                par\n");
					b.write("			                       protocolMessage(self,$e):=" + changNumMSG[i] + "\n");
					for (int k = 0; k < 15; k++) {
						if (msgFieldDet[k] != null) {
// 							System.out.println("Leggo campi numero " + k + " valore msgFieldDet[k]  " + msgFieldDet[k] );
							b.write("			                       messageField(self,$e," + k + "," + changNumMSG[i]
									+ "):=" + findValueHonest(msgFieldDet[k].toUpperCase(), message.getActorfrom())
									+ "\n");
// 							System.out.println("registro in  honestElement " + message.getActorTo().substring(0, 1)+ " "+ msgFieldDet[k].toUpperCase() + " , messageField($e,self,"+k+","+changNumMSG[i]+")");
							honestElement.put(message.getActorTo().substring(0, 1) + " " + msgFieldDet[k].toUpperCase(),
									"messageField($e,self," + k + "," + changNumMSG[i] + ")");
						}
					}
//					System.out.println("operation " + operation);
					if (operation != null && !operation.isEmpty()) {
// 						System.out.println("scrivo operazione su file ricercando se gia registrato findValueHonest"); 
						b.write("			                       " + reversOperation(operation) + "(" + changNumMSG[i]
								+ "," + levelEncField1EncField2 + "):="
								+ findValueHonest(
										findKeyEle(keyUsed, message.getActorfrom(), message.getActorTo(), false),
										message.getActorTo())
								+ "\n");
					}
					int z = i + 1;
//					System.out.println("operation " + operation);
//					System.out.println("messages.getMessage(i + 1) " + messages.getMessage(i + 1).getActorTo());
					if (messages.getMessage(i + 1).getActorTo()!=null && !messages.getMessage(i + 1).getActorTo().isEmpty()) { 
						b.write("			                       internalState"
							+ messages.getMessage(i + 1).getActorTo().substring(0, 1) + "(agent"+ messages.getMessage(i + 1).getActorTo().substring(0, 1) +"):=WAITING_"
							+ changNumMSG[z] + "\n");
					}  
					b.write("			                endpar\n");
					b.write("			        else\n");
					b.write("			                if(receiver=AG_E)then\n");
					b.write("			                        par\n");
					b.write("			                              protocolMessage(self,$e):=" + changNumMSG[i]
							+ "\n");
//					System.out.println("leggo Field");
					for (int k = 0; k < 15; k++) {
						if (msgFieldDet[k] != null) {
//							System.out.println("leggo Field " + k + " - " + msgFieldDet[k]);
							b.write("			                              messageField(self,$e," + k + ","
									+ changNumMSG[i] + "):=" + changValueEve(msgFieldDet[k], message.getActorfrom(), true)
									+ "\n");
							honestElement.put(
									"E" + " " + changValueEve(msgFieldDet[k], message.getActorfrom(), false).toUpperCase(),
									"messageField($e,self," + k + "," + changNumMSG[i] + ")");
						}
					}
					if (operation != null && !operation.isEmpty()) {
						b.write("			                              " + reversOperation(operation) + "("
								+ changNumMSG[i] + "," + levelEncField1EncField2 + "):="
								+ changValueEve(keyUsed, message.getActorfrom(), true).toUpperCase() + "\n");
					}
//					System.out.println("scrivo finale");
					if (messages.getMessage(i + 1).getActorTo()!=null && !messages.getMessage(i + 1).getActorTo().isEmpty()) { 
						b.write("			                              internalState"
								+ messages.getMessage(i + 1).getActorTo().substring(0, 1) + "(agent"+ messages.getMessage(i + 1).getActorTo().substring(0, 1)+ "):=WAITING_"
								+ changNumMSG[z] + "\n");
					}
					b.write("			                        endpar\n");
					b.write("			                endif\n");
					b.write("			        endif\n");
					b.write("			endif\n");
					b.write("		endlet\n");
				}
			} else {
//				System.out.println("non sono sul primo messaggio ma su " + i + " changNumMSG[i] " + changNumMSG[i]);
				int z = i - 1;
				b.write("			if(internalState" + message.getActorfrom().substring(0, 1) + "(self)=WAITING_"
						+ changNumMSG[i-1] + " and protocolMessage($e,self)=" + changNumMSG[i-1] + ")then\n");
//					System.out.println("verifico se l'actorTo è quello che ha fatto partire il protocollo actorStartProtocol "+ actorStartProtocol + " message.getActorTo() " + message.getActorTo()); 
				if (actorStartProtocol.equals(message.getActorTo())) {
//						System.out.println("l'attore risulta uguale a quello cha ha avviato il protocollo allora guardo il messaggio precedente per vedere i campi che ha ricevuto l'attore e registrarli");
					Message messagePrev = messages.getMessage(z);
					String[] msgFieldTotPrev = FindField(messages.getMessage(i-1).getPayload());
//					System.out.println("message.getPayload() " + message.getPayload());
					String[] listSubPayloadPrev = findMsg(messagePrev);
					boolean fistOperation = true;   
					String[] msgFieldPrev = new String[15];
					for (int f = 0; f < 15; f++) {
						if (listSubPayloadPrev[f] == null || listSubPayloadPrev[f].isEmpty()) {
							break;
						}
//						System.out.println("listSubPayloadPrev[f] " + listSubPayloadPrev[f]);
						String[] msgEncField1EncField2Prev = new String[15];
						levelEncField1EncField2Prev = calcLevelEncField1EncField2(listSubPayloadPrev[f],
								msgEncField1EncField2Prev, msgFieldPrev,msgFieldTotPrev);
						String[] msgFieldDetPrev = detField(msgFieldPrev,msgFieldTotPrev);
//						System.out.println("Cerco la chiave dal messaggio " + listSubPayload[f]);
						String keyUsedPrev = findKey(listSubPayloadPrev[f]);
//						System.out.println("chiave trovata " + keyUsedPrev);
						operationPrev = "";
						if (keyUsedPrev != null) {
							operationPrev = findOperation(keyUsedPrev, message.getActorfrom(), message.getActorTo());
//							System.out.println("operazione trovata " + operationPrev);
						}
						if (operationPrev != null && !operationPrev.isEmpty()) {
//								System.out.println("se in precedenza c'era opz allora la scrivo con IF" );
							if (fistOperation) {
								b.write(" 			        if(" + operationPrev + "(" + changNumMSG[i-1] + ","
										+ levelEncField1EncField2Prev + ",self)=true ");
								fistOperation = false;
							} else {
								b.write(" and " + operationPrev + "(" + changNumMSG[i-1] + ","
										+ levelEncField1EncField2Prev + ",self)=true ");
							}
						}
					}
					if (!fistOperation) {
						b.write(") then\n");
					}
					String[] msgFieldDetPrev = detField(msgFieldPrev,msgFieldTotPrev);
					b.write("			                par\n");
					String[] linesKnowledgePrev = writeKnowledge(messagePrev,z,msgFieldPrev,"$e");
					String spaces= "					";
					printKnowledge(b,"Kno3",linesKnowledgePrev,spaces);
					b.write("	 		                      protocolMessage(self,$e):="+ changNumMSG[i] +"\n");
					listSubPayload = findMsg(message);
					for (int j = 0; j < 15; j++) {
						if (listSubPayload[j] == null || listSubPayload[j].isEmpty()) {
							break;
						}
						System.out.println("2-Leggo messaggio "+ j + " " +listSubPayload[j] + " MSG "+ i);
						String[] msgEncField1EncField2 = new String[15];
						String[] msgField = new String[15];
						String levelEncField1EncField2 = calcLevelEncField1EncField2(listSubPayload[j],
								msgEncField1EncField2, msgField,msgFieldTot);
						String[] msgFieldDet = detField(msgField,msgFieldTot);
						String keyUsed = findKey(listSubPayload[j]);
						String operation = "";
						if (keyUsed != null) {
							operation = findOperation(keyUsed, message.getActorfrom(), message.getActorTo());
						}
						for (int k = 0; k < 15; k++) {
							if (msgFieldDet[k] != null) {
//								System.out.println("scrivo i messageField ");
								b.write("			                      messageField(self,$e," + k + ","
										+ changNumMSG[i] + "):="
										+ changValueEve(msgFieldDet[k], message.getActorfrom(), true) + "\n");
//								System.out.println("registro i messaggi si a come attore ricevente E che come " + message.getActorTo().substring(0, 1));
								honestElement.put(
										"E" + " "
												+ changValueEve(msgFieldDet[k], message.getActorfrom(), false)
														.toUpperCase(),
										"messageField($e,self," + k + "," + changNumMSG[i] + ")");
								honestElement.put(
										message.getActorTo().substring(0, 1) + " " + msgFieldDet[k].toUpperCase(),
										"messageField($e,self," + k + "," + changNumMSG[i] + ")");
							}
						}
						if (operation != null && !operation.isEmpty()) {
							if (reversOperation(operation).equals("symEnc")) {
//								System.out.println("l'operazione  è symEnc allora scivo la reverse utilizzando la findkeyele con true " + operation);
								b.write(" 			                      " + reversOperation(operation) + "("
										+ changNumMSG[i] + "," + levelEncField1EncField2 + "):="
										+ findKeyEle(keyUsed, message.getActorfrom(), message.getActorTo(), true)
												.replace("$b", "$e")
										+ "\n");
//								System.out.println("l'operazione scritta è : " + reversOperation(operation) + "("
//										+ changNumMSG[i] + "," + levelEncField1EncField2 + "):="
//										+ findKeyEle(keyUsed, message.getActorfrom(), message.getActorTo(),
//												true).replace("$b", "$e"));
							} else {
//								System.out.println("l'operazione  NON è symEnc allora scivo la reverse utilizzando la findkeyele con false " + operation);
								b.write(" 			                      " + reversOperation(operation) + "("
										+ changNumMSG[i] + "," + levelEncField1EncField2 + "):="
										+ findKeyEle(keyUsed, message.getActorfrom(), message.getActorTo(), false)
												.replace("$b", "$e")
										+ "\n");
//								System.out.println("l'operazione scritta è :: " + changNumMSG[i] + "," + levelEncField1EncField2 + "):="
//											+ findKeyEle(keyUsed, message.getActorfrom(), message.getActorTo(),
//												false).replace("$b", "$e"));
							}
						}

					}
					if (messages.getMessage(i + 1).getActorfrom() != null
							&& !messages.getMessage(i + 1).getActorfrom().isEmpty()) {
						b.write("			                      internalState"
								+ messages.getMessage(i + 1).getActorTo().substring(0, 1) + "(agent"+ messages.getMessage(i + 1).getActorTo().substring(0, 1) + "):=WAITING_"
								+ changNumMSG[i + 1] + "\n");
					} else {
						b.write("			                      internalState"
								+ message.getActorfrom().substring(0, 1) + "(agent"+ message.getActorfrom().substring(0, 1) +"):=END_"
								+ message.getActorfrom().substring(0, 1) + "\n");
					}
					b.write("			                endpar\n");
					if (!fistOperation) {
						b.write("			        endif\n");
					}
					b.write("			endif\n");
					b.write("		endlet\n");
				} else {
					b.write("			     if(receiver=AG_"+message.getActorTo().substring(0, 1)+")then\n");
					Message messagePrev = messages.getMessage(i-1);
//					System.out.println("Sono nel terzo gruppo message.getPayload() " + message.getPayload());
					String[] listSubPayloadPrev = findMsg(messagePrev);
					String[] msgFieldTotPrev = FindField(messages.getMessage(i-1).getPayload());
					boolean fistOperation = true;
					String[] msgFieldPrev = new String[15];
					for (int f = 0; f < 15; f++) {
						if (listSubPayloadPrev[f] == null || listSubPayloadPrev[f].isEmpty()) {
							break;
						}
//						System.out.println("listSubPayloadPrev[f] " + listSubPayloadPrev[f]);
						String[] msgEncField1EncField2Prev = new String[15];
						levelEncField1EncField2Prev = calcLevelEncField1EncField2(listSubPayloadPrev[f],
								msgEncField1EncField2Prev, msgFieldPrev,msgFieldTotPrev);
						String[] msgFieldDetPrev = detField(msgFieldPrev,msgFieldTotPrev);
//						System.out.println("Cerco la chiave dal messaggio " + listSubPayload[f]);
						String keyUsedPrev = findKey(listSubPayloadPrev[f]);
//						System.out.println("chiave trovata " + keyUsedPrev);
						operationPrev = "";
						if (keyUsedPrev != null) {
							operationPrev = findOperation(keyUsedPrev, message.getActorfrom(), message.getActorTo());
//							System.out.println("operazione trovata " + operationPrev);
						}
						if (operationPrev != null && !operationPrev.isEmpty()) {
//							System.out.println("se in precedenza c'era opz allora la scrivo con IF" );
							if (fistOperation) {
								b.write(" 			        if(" + operationPrev + "(" + changNumMSG[i-1] + ","
									+ levelEncField1EncField2Prev + ",self)=true ");
								fistOperation = false;
							} else {
								b.write(" and " + operationPrev + "(" + changNumMSG[i-1] + ","
									+ levelEncField1EncField2Prev + ",self)=true ");
							}
						}
					}
					if (!fistOperation) {
						b.write(") then\n");
					}
					b.write("			                par\n");
					String[] msgFieldDetPrev = detField(msgFieldPrev,msgFieldTotPrev);
					String[] linesKnowledgePrev = writeKnowledge(messagePrev,(i-1),msgFieldPrev,"$e");
					String spaces="                            	        ";
					printKnowledge(b,"Kno3",linesKnowledgePrev,spaces);
					b.write("			                      protocolMessage(self,$e):="+ changNumMSG[i] +"\n");
					listSubPayload = findMsg(message);
					numOperationMessage=0;
					// pulisce la tabella delle operazioni.
					for (String eleOperationMessage : operationMessage) {
						eleOperationMessage="";
					}
					for (int j = 0; j < 15; j++) {
						if (listSubPayload[j] == null || listSubPayload[j].isEmpty()) {
							break;
						}
						System.out.println("3-Leggo messaggio "+ j + " " +listSubPayload[j]+ " MSG "+ i);
						String[] msgEncField1EncField2 = new String[15];
						String[] msgField = new String[15];
						String levelEncField1EncField2 = calcLevelEncField1EncField2(listSubPayload[j],
								msgEncField1EncField2, msgField,msgFieldTot);
						String[] msgFieldDet = detField(msgField,msgFieldTot); 
						String keyUsed = findKey(listSubPayload[j]);
						String operation = "";
						if (keyUsed != null) {
							operation = findOperation(keyUsed, message.getActorfrom(), message.getActorTo());
						}
						for (int k = 0; k < 15; k++) {
							if (msgFieldDet[k] != null) {
								b.write("			                      messageField(self,$e,"+k+","+changNumMSG[i]+"):="+findValueHonest(msgFieldDet[k].toUpperCase(),message.getActorfrom())+"\n");															
								honestElement.put(message.getActorTo().substring(0, 1)+ " "+ msgFieldDet[k].toUpperCase(),"messageField($e,self,"+k+","+changNumMSG[i]+")");											    
							}
						}
						determinesOperation (b, i, message, listSubPayload[j], message.getActorfrom(), "",true);
					}
					if (messages.getMessage(i+1).getActorfrom()!=null && !messages.getMessage(i+1).getActorfrom().isEmpty()) {
					      b.write("			                      internalState"+messages.getMessage(i+1).getActorTo().substring(0, 1)+"(agent" +messages.getMessage(i+1).getActorTo().substring(0, 1) +"):=WAITING_"+changNumMSG[i+1]+"\n");					
					} else {
					      b.write("			                      internalState"+message.getActorfrom().substring(0, 1)+"(agent"+message.getActorfrom().substring(0, 1) + "):=END_"+message.getActorfrom().substring(0, 1)+"\n");								
					}
					b.write("			                endpar\n");
					if (!fistOperation) {
						b.write("			        endif\n");
					}
					b.write("			else\n");
					messagePrev = messages.getMessage(i-1);
//					System.out.println("Sono nel quarto gruppo message.getPayload() " + message.getPayload());
					listSubPayloadPrev = findMsg(messagePrev);
					fistOperation = true;
					msgFieldPrev = new String[15];
					for (int f = 0; f < 15; f++) {
						if (listSubPayloadPrev[f] == null || listSubPayloadPrev[f].isEmpty()) {
							break;
						}
//						System.out.println("listSubPayloadPrev[f] " + listSubPayloadPrev[f]);
						String[] msgEncField1EncField2Prev = new String[15];
						levelEncField1EncField2Prev = calcLevelEncField1EncField2(listSubPayloadPrev[f],
								msgEncField1EncField2Prev, msgFieldPrev,msgFieldTotPrev);
						msgFieldDetPrev = detField(msgFieldPrev,msgFieldTotPrev);
//						System.out.println("Cerco la chiave dal messaggio " + listSubPayload[f]);
						String keyUsedPrev = findKey(listSubPayloadPrev[f]);
//						System.out.println("chiave trovata " + keyUsedPrev);
						operationPrev = "";
						if (keyUsedPrev != null) {
							operationPrev = findOperation(keyUsedPrev, message.getActorfrom(), message.getActorTo());
//							System.out.println("operazione trovata " + operationPrev);
						}
						if (operationPrev != null && !operationPrev.isEmpty()) {
//							System.out.println("se in precedenza c'era opz allora la scrivo con IF" );
							if (fistOperation) {
								b.write(" 			        if(" + operationPrev + "(" + changNumMSG[i-1] + ","
									+ levelEncField1EncField2Prev + ",self)=true ");
								fistOperation = false;
							} else {
								b.write(" and " + operationPrev + "(" + changNumMSG[i-1] + ","
									+ levelEncField1EncField2Prev + ",self)=true ");
							}
						}
					}
					if (!fistOperation) {
						b.write(") then\n");
					}
					b.write("			                par\n");
					linesKnowledgePrev = writeKnowledge(messagePrev,(i-1),msgFieldPrev,"$e");
					spaces="                            	        ";
					printKnowledge(b,"Kno3",linesKnowledgePrev,spaces);
					b.write("			                      protocolMessage(self,$e):="+ changNumMSG[i] +"\n");
					numOperationMessage=0;
					// pulisce la tabella delle operazioni.
					for (String eleOperationMessage : operationMessage) {
						eleOperationMessage="";
					}

					listSubPayload = findMsg(message);
					for (int j = 0; j < 15; j++) {
						if (listSubPayload[j] == null || listSubPayload[j].isEmpty()) {
							break;
						}
						System.out.println("4-Leggo messaggio "+ j + " " +listSubPayload[j]+ " MSG "+ i);
						String[] msgEncField1EncField2 = new String[15];
						String[] msgField = new String[15];
						String levelEncField1EncField2 = calcLevelEncField1EncField2(listSubPayload[j],
								msgEncField1EncField2, msgField,msgFieldTot);
						String[] msgFieldDet = detField(msgField,msgFieldTot);
						String keyUsed = findKey(listSubPayload[j]);
						String operation = "";
						if (keyUsed != null) {
							operation = findOperation(keyUsed, message.getActorfrom(), message.getActorTo());
						}
						for (int k = 0; k < 15; k++) {
							if (msgFieldDet[k] != null) {
								b.write("			                      messageField(self,$e,"+k+","+changNumMSG[i]+"):="+changValueEve(msgFieldDet[k], message.getActorfrom(),true)+"\n");						
								honestElement.put("E"+ " "+ changValueEve(msgFieldDet[k], message.getActorfrom(),false).toUpperCase(),"messageField($e,self,"+k+","+changNumMSG[i]+")");
							}
						}
						determinesOperation (b, i, message, listSubPayload[j], message.getActorfrom(), "",false);
					}
				
					if (messages.getMessage(i+1).getActorfrom()!=null && !messages.getMessage(i+1).getActorfrom().isEmpty()) {
						   endMessage = false;
						   b.write("			                      internalState"+messages.getMessage(i+1).getActorTo().substring(0, 1)+"(agent"+ messages.getMessage(i+1).getActorTo().substring(0, 1)+"):=WAITING_"+changNumMSG[i+1]+"\n");					
					} else {
						   endMessage = true;
					       b.write("			                      internalState"+message.getActorfrom().substring(0, 1)+"(agent" + message.getActorfrom().substring(0, 1) + "):=END_"+message.getActorfrom().substring(0, 1)+"\n");								
					}
					b.write("			                endpar\n");
					if (!fistOperation) {
						b.write("			        endif\n");
					}
					b.write("				endif\n");
					b.write("			endif\n");
					b.write("		endlet\n");
//					System.out.println("determinesOperation d OUT" + endMessage);
					if (endMessage) {
//						System.out.println("determinesOperation d1 OUT");
//						System.out.println("determinesOperation d1 OUT" + changNumMSG[i]);
						b.write("	rule r_check_" + changNumMSG[i] + " =\n");
//						System.out.println("determinesOperation d2 OUT " + i + " - " + indRuleR_Agent);
//						System.out.println("determinesOperation d2 OUT " +message.getActorTo());
						ruleR_Agent[indRuleR_Agent] = message.getActorTo().toUpperCase().substring(0, 1) + " r_check_"
								+ changNumMSG[i]+"[]";
//						System.out.println("determinesOperation d3 OUT");
						indRuleR_Agent++;
						b.write("		let ($e=agentE) in\n");
						b.write("			if(internalState" + message.getActorTo().substring(0, 1)
								+ "(self)=WAITING_" + changNumMSG[i] + " and protocolMessage($e,self)=" + changNumMSG[i] + ")then\n");
//						b.write("			        if(" + operation + "(" + changNumMSG[i] + "," + levelEncField1EncField2
//								+ ",self)=true)then\n");
//						System.out.println("determinesOperation d4 OUT");
 						b.write("			        if(");
 						boolean flgPrimo = true;
						for (String eleOperationMessage : operationMessage) {
							if (eleOperationMessage != null) {
								if (flgPrimo) {
			 						b.write(eleOperationMessage.replace(":", ""));
									flgPrimo= false;
								} else {
									b.write(" and " + eleOperationMessage.replace(":", ""));
								}
							}
						}
 					    b.write(") then\n");
						if ((message.getActorTo().substring(0, 1).equals("A") && message.getActorfrom().substring(0, 1).equals("B") && flgServer) || (message.getActorTo().substring(0, 1).equals("A") && message.getActorfrom().substring(0, 1).equals("S") && flgBob )
								|| (message.getActorTo().substring(0, 1).equals("B") && message.getActorfrom().substring(0, 1).equals("A") && flgServer )||  (message.getActorTo().substring(0, 1).equals("B") && message.getActorfrom().substring(0, 1).equals("S") && flgAlice )
								|| (message.getActorTo().substring(0, 1).equals("S") && message.getActorfrom().substring(0, 1).equals("A") && flgBob )|| (message.getActorTo().substring(0, 1).equals("S") && message.getActorfrom().substring(0, 1).equals("B") && flgAlice )) {
							b.write("			             par\n");
						}
						b.write("			                      internalState" + message.getActorTo().substring(0, 1)
								+ "(agent"+message.getActorTo().substring(0, 1)+"):=END_" + message.getActorTo().substring(0, 1) + "\n");
						
						if (message.getActorTo().substring(0, 1).equals("A") && message.getActorfrom().substring(0, 1).equals("B") && flgServer ) {
							b.write("			                      internalStateS(agentS):=END_S\n");
						}
						if (message.getActorTo().substring(0, 1).equals("A") && message.getActorfrom().substring(0, 1).equals("S") && flgBob ) {
							b.write("			                      internalStateB(agentB):=END_B\n");
						}
						if (message.getActorTo().substring(0, 1).equals("B") && message.getActorfrom().substring(0, 1).equals("A") && flgServer ) {
							b.write("			                      internalStateS(agentS):=END_S\n");
						}
						if (message.getActorTo().substring(0, 1).equals("B") && message.getActorfrom().substring(0, 1).equals("S") && flgAlice ) {
							b.write("			                      internalStateA(agentA):=END_A\n");
						}	
						if (message.getActorTo().substring(0, 1).equals("S") && message.getActorfrom().substring(0, 1).equals("A") && flgBob ) {
							b.write("			                      internalStateB(agentB):=END_B\n");
						}
						if (message.getActorTo().substring(0, 1).equals("S") && message.getActorfrom().substring(0, 1).equals("B") && flgAlice ) {
							b.write("			                      internalStateA(agentA):=END_A\n");
						}
						if ((message.getActorTo().substring(0, 1).equals("A") && message.getActorfrom().substring(0, 1).equals("B") && flgServer) || (message.getActorTo().substring(0, 1).equals("A") && message.getActorfrom().substring(0, 1).equals("S") && flgBob )
								|| (message.getActorTo().substring(0, 1).equals("B") && message.getActorfrom().substring(0, 1).equals("A") && flgServer )||  (message.getActorTo().substring(0, 1).equals("B") && message.getActorfrom().substring(0, 1).equals("S") && flgAlice )
								|| (message.getActorTo().substring(0, 1).equals("S") && message.getActorfrom().substring(0, 1).equals("A") && flgBob )|| (message.getActorTo().substring(0, 1).equals("S") && message.getActorfrom().substring(0, 1).equals("B") && flgAlice )) {
							b.write("			            endpar\n");
						}
						b.write("			        endif\n");
						b.write("			endif\n");
						b.write("		endlet\n");
					}
				}
			}

		}
	}

	// quando ad operare è l'EVE si deve effettuare il reverse delle chiavi e dei
	// field
	private String findValueHonest(String value, String actorFrom) {
//			System.out.println(" cerco su map.entry se ho gia registrato l'elemento " + actorFrom.toUpperCase().substring(0,1) + " "+ value.toUpperCase());
		for (Map.Entry<String, String> entry : honestElement.entrySet()) {
			if (entry.getKey().equals(actorFrom.toUpperCase().substring(0, 1) + " " + value.toUpperCase())) {
//		    		System.out.println(" trovato elemento " + entry.getValue());
				return entry.getValue();
			}
		}
//			System.out.println(" NON trovato elemento e quindi restituisco " + value);
		return value;
	}

	// quando ad operare è l'EVE si deve effettuare il reverse delle chiavi e dei
	// field
	private String changValueEve(String value, String actorFrom, boolean verifyElement) {

		String valueOutput = value;
		String typeFieldActorFrom = KeyActorFrom.searchEle(value);
//			System.out.println("tipo : " + eve +  " ------ " + typeFieldActorFrom);

		boolean found = false;
		if (typeFieldActorFrom != null) {
			found = true;
			switch (typeFieldActorFrom) {
			case "Asymmetric Public Key":
				if (eve.getAsymmetricPublicKey().get(0) != null)
					valueOutput = eve.getAsymmetricPublicKey().get(0);
				break;
			case "Asymmetric Private Key":
				// if (eve.getAsymmetricPrivateKey().get(0) != null)
				// valueOutput = eve.getAsymmetricPrivateKey().get(0);
				break;
			case "Symmetric Key":
				if (eve.getSymmetricKey().get(0) != null) {
					valueOutput = eve.getSymmetricKey().get(0);
					for (String e : eve.getSymmetricKey()) {
//						System.out.println("Verifico Alice " + (actorFrom.contains("Alice") && alice.searchSym(e)));
//						System.out.println("Verifico Bob " + (actorFrom.contains("Bob") && alice.searchSym(e)));

						if (actorFrom.contains("Alice") && alice.searchSym(e)) {
							valueOutput = e;
							break;
						}
						if (actorFrom.contains("Bob") && bob.searchSym(e)) {
							valueOutput = e;
							break;
						}
						if (actorFrom.contains("Server") && server.searchSym(e)) {
							valueOutput = e;
							break;
						}
					}
				}

				break;
			case "Signature Pub Key":
				// if (eve.getSignaturePubKey().get(0) != null)
				// valueOutput = eve.getSignaturePrivKey().get(0);
				break;
			case "Signature Priv Key":
				// if (eve.getSignaturePrivKey().get(0) != null)
				// valueOutput = eve.getSignaturePrivKey().get(0);
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
					// if (eve.getAsymmetricPrivateKey().get(0) != null)
					// valueOutput = eve.getAsymmetricPrivateKey().get(0);
					break;
				case "Symmetric Key":
					if (eve.getSymmetricKey().get(0) != null) {
						valueOutput = eve.getSymmetricKey().get(0);

						for (String e : eve.getSymmetricKey()) {
							if (actorFrom.contains("Alice") && alice.searchSym(e)) {
								valueOutput = e;
								break;
							}
							if (actorFrom.contains("Bob") && bob.searchSym(e)) {
								valueOutput = e;
								break;
							}
							if (actorFrom.contains("Server") && server.searchSym(e)) {
								valueOutput = e;
								break;
							}
						}
					}
					break;
				case "Signature Pub Key":
					// if (eve.getSignaturePubKey().get(0) != null)
					// valueOutput = eve.getSignaturePubKey().get(0);
					break;
				case "Signature Priv Key":
					// if (eve.getSignaturePrivKey().get(0) != null)
					// valueOutput = eve.getSignaturePrivKey().get(0);
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
//			System.out.println("cerco il valore : " + value + " Actor-from E ma reale: " + actorFrom);
		if (verifyElement) {
//				System.out.println("Cerco se l'elemento " + value +" è gia stato ricevuto da " + actorFrom);
			for (Map.Entry<String, String> entry : honestElement.entrySet()) {
//			    	System.out.println("   verifico:  "+ entry.getKey());
				if (entry.getKey().equals("E " + valueOutput.toUpperCase())) {
//			        	System.out.println("trovato elemento "+ entry.getValue());
					return entry.getValue();
				}
			}
		}
		return valueOutput.toUpperCase();
	}
	// dalla tabella si estraggono i messaggi divisi per i vari agenti e si scrivono le rispettive rule
	// per distinguere tra i messaggi a quale agent vanno agganciati si vede il primo carattere della stringa.
	private void writeRuleR_Agent(BufferedWriter b) throws IOException {
//		System.out.println("----writeRuleR_Agent---");
		b.write("\n");
		boolean firtE=true;
 
		numRuleE=0;
		numRuleB=0;
		numRuleS=0;
		numRuleA =0;
		for ( int i=0 ; i < indRuleR_Agent; i++) {
			if (ruleR_Agent[i].substring(0, 1).equals("A")) {numRuleA++;}
			if (ruleR_Agent[i].substring(0, 1).equals("E")) {numRuleE++;}
			if (ruleR_Agent[i].substring(0, 1).equals("S")) {numRuleS++;}
			if (ruleR_Agent[i].substring(0, 1).equals("B")) {numRuleB++;}
		}
		for ( int i=0 ; i < indRuleR_Agent; i++) {
			if (ruleR_Agent[i].substring(0, 1).equals("E")) {
				if (firtE) {
					b.write("	rule r_agentERule  =");
					b.write("\n");
					if (numRuleE>1) {b.write("	  par\n");}
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
			if (numRuleE>1) {b.write("	  endpar\n");}
			b.write("\n");
		}
		
		boolean firtA = true;
		for (int i = 0; i < indRuleR_Agent; i++) {
			if (ruleR_Agent[i].substring(0, 1).equals("A")) {
				if (firtA) {
					b.write("	rule r_agentARule  =");
					b.write("\n");
					if (numRuleA>1) {b.write("	  par\n");}
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
			if (numRuleA>1) {b.write("	  endpar\n");}
			b.write("\n");
		}
		boolean firtB = true;
		for (int i = 0; i < indRuleR_Agent; i++) {
			if (ruleR_Agent[i].substring(0, 1).equals("B")) {
				if (firtB) {
					b.write("	rule r_agentBRule  =");
					b.write("\n");
					if (numRuleB>1) {b.write("	  par\n");}
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
			if (numRuleB>1) {b.write("	  endpar\n");}
			b.write("\n");
		}
		boolean firtS = true;
		for (int i = 0; i < indRuleR_Agent; i++) {
			if (ruleR_Agent[i].substring(0, 1).equals("S")) {
				if (firtS) {
					b.write("	rule r_agentSRule  =");
					b.write("\n");
					if (numRuleS>1) {b.write("	  par\n");}
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
			if (numRuleS>1) {b.write("	  endpar\n");}
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

		b.write("	function internalState" + actorStartProtocol.substring(0, 1) + "($a in " + actorStartProtocol
				+ ")=IDLE_" + changNumMSG[0] + "\n");

		b.write("	function internalState" + actorReceiveProtocol.substring(0, 1) + "($b in " + actorReceiveProtocol
				+ ")=WAITING_" + changNumMSG[0] + "\n");

		b.write("	function receiver=chosenReceiver\n");
		boolean found = false;

		// Scrittura dello stato S0 per la KnowledgeNonce
		countIf = 0;
		found = writeDefaultInitS0Nonce(b, alice, "Alice", found);

		found = writeDefaultInitS0Nonce(b, bob, "Bob", found);

		found = writeDefaultInitS0Nonce(b, eve, "Eve", found);

		if (actorServer) {

			found = writeDefaultInitS0Nonce(b, server, "Server", found);
		}

		if (countIf > 0) {
			b.write(" false");
			for (int i = 0; i < countIf; i++) {
				b.write(" endif");
			}
			b.write("\n");
		}

		// Scrittura dello stato S0 per la knowsIdentityCertificate
		countIf = 0;
		found = false;
		found = writeDefaultInitS0IDCer(b, alice, "Alice", found);
		found = writeDefaultInitS0IDCer(b, bob, "Bob", found);
		found = writeDefaultInitS0IDCer(b, eve, "Eve", found);
		if (actorServer) {
			found = writeDefaultInitS0IDCer(b, server, "Server", found);
		}

		if (countIf > 0) {
			b.write(" false");
			for (int i = 0; i < countIf; i++) {
				b.write(" endif");
			}
			b.write("\n");
		}

		// Scrittura dello stato S0 per la knowsBitString
		countIf = 0;
		found = false;
		found = writeDefaultInitS0BitSt(b, alice, "Alice", found);
		found = writeDefaultInitS0BitSt(b, bob, "Bob", found);
		found = writeDefaultInitS0BitSt(b, eve, "Eve", found);
		if (actorServer) {
			found = writeDefaultInitS0BitSt(b, server, "Server", found);
		}

		if (countIf > 0) {
			b.write(" false");
			for (int i = 0; i < countIf; i++) {
				b.write(" endif");
			}
			b.write("\n");
		}

		// Scrittura dello stato S0 per la KnowledgeTag
		countIf = 0;
		found = false;
		found = writeDefaultInitS0Tag(b, alice, "Alice", found);
		found = writeDefaultInitS0Tag(b, bob, "Bob", found);
		found = writeDefaultInitS0Tag(b, eve, "Eve", found);
		if (actorServer) {
			found = writeDefaultInitS0Tag(b, server, "Server", found);
		}

		if (countIf > 0) {
			b.write(" false");
			for (int i = 0; i < countIf; i++) {
				b.write(" endif");
			}
			b.write("\n");
		}

		// Scrittura dello stato S0 per la KnowledgeDigest
		countIf = 0;
		found = false;
		found = writeDefaultInitS0Dig(b, alice, "Alice", found);
		found = writeDefaultInitS0Dig(b, bob, "Bob", found);
		found = writeDefaultInitS0Dig(b, eve, "Eve", found);
		if (actorServer) {
			found = writeDefaultInitS0Dig(b, server, "Server", found);
		}

		if (countIf > 0) {
			b.write(" false");
			for (int i = 0; i < countIf; i++) {
				b.write(" endif");
			}
			b.write("\n");
		}

		// Scrittura dello stato S0 per la KnowledgeOther
		countIf = 0;
		found = false;
		found = writeDefaultInitS0Hot(b, alice, "Alice", found);

		found = writeDefaultInitS0Hot(b, bob, "Bob", found);

		found = writeDefaultInitS0Hot(b, eve, "Eve", found);

		if (actorServer) {

			found = writeDefaultInitS0Hot(b, server, "Server", found);

		}

		if (countIf > 0) {
			b.write(" false");
			for (int i = 0; i < countIf; i++) {
				b.write(" endif");
			}
			b.write("\n");
		}

		// Scrittura dello stato S0 per la KnowledgeTimestamp
		countIf = 0;
		found = false;
		found = writeDefaultInitS0Tim(b, alice, "Alice", found);
		found = writeDefaultInitS0Tim(b, bob, "Bob", found);
		found = writeDefaultInitS0Tim(b, eve, "Eve", found);
		if (actorServer) {
			found = writeDefaultInitS0Tim(b, server, "Server", found);
		}

		if (countIf > 0) {
			b.write(" false");
			for (int i = 0; i < countIf; i++) {
				b.write(" endif");
			}
			b.write("\n");
		}

		// Scrittura dello stato S0 per la knowsAsymPrivKey e knowsAsymPubKey
		countIf = 0;
		found = false;
		found = writeDefaultInitS0AsPr(b, alice, "Alice", found);
		found = writeDefaultInitS0AsPr(b, bob, "Bob", found);
		found = writeDefaultInitS0AsPr(b, eve, "Eve", found);
		if (actorServer) {
			found = writeDefaultInitS0AsPr(b, server, "Server", found);
		}

		if (countIf > 0) {
			b.write(") then true else false endif\n");
			b.write("	function knowsAsymPubKey($a in Agent ,$pk in KnowledgeAsymPubKey)=true\n");
		}

		// Scrittura dello stato S0 per la KnowledgeSymKey
		countIf = 0;
		found = false;
		found = writeDefaultInitS0SymK(b, alice, "Alice", found);
		found = writeDefaultInitS0SymK(b, bob, "Bob", found);
		found = writeDefaultInitS0SymK(b, eve, "Eve", found);
		if (actorServer) {
			found = writeDefaultInitS0SymK(b, server, "Server", found);
		}

		if (countIf > 0) {
			b.write(") then true else false endif\n");
			;
		}

		// Scrittura dello stato S0 per la knowsSignPubKey e knowsSignPrivKey
		countIf = 0;
		found = false;
		found = writeDefaultInitS0SiPu(b, alice, "Alice", found);
		found = writeDefaultInitS0SiPu(b, bob, "Bob", found);
		found = writeDefaultInitS0SiPu(b, eve, "Eve", found);
		if (actorServer) {
			found = writeDefaultInitS0SiPu(b, server, "Server", found);
		}

		if (countIf > 0) {
			b.write(") then true else false endif\n");
			b.write("	function knowsSignPrivKey($a in Agent ,$spr in KnowledgeSignPrivKey)=true\n");
		}
		b.write("	function mode=chosenMode\n");
		b.write("\n");
		if (numRuleA > 0) {
			b.write("	agent Alice:\n");
			b.write("		r_agentARule[]\n");
			b.write("\n");
		}

		if (numRuleB > 0) {
			b.write("	agent Bob:\n");
			b.write("		r_agentBRule[]\n");
			b.write("\n");
		}
		if (numRuleE > 0) {
			b.write("	agent Eve:\n");
			b.write("		r_agentERule[]\n");
		}
		if (numRuleS > 0) {
			if (actorServer) {
				b.write("\n");
				b.write("	agent Server:\n");
				b.write("		r_agentSRule[]\n");
			}
		}
		/*
		 * function mode=chosenMode
		 * 
		 * agent Alice: r_agentARule[]
		 * 
		 * agent Bob: r_agentBRule[]
		 * 
		 * agent Eve: r_agentERule[]
		 * 
		 * 
		 * 
		 * domain KnowledgeHash subsetof Any
		 * 
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
		if (countIf > 0 && !first) {
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
				b.write("	function knowsIdentityCertificate($a in Agent, $i in KnowledgeIdentityCertificate)=if($a=agent"
						+ agent.substring(0, 1) + " and $i=" + ele.toUpperCase() + ")");
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
		if (countIf > 0 && !first) {
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
				b.write("	function knowsBitString($a in Agent, $bs in KnowledgeBitString)=if($a=agent"
						+ agent.substring(0, 1) + " and $bs=" + ele.toUpperCase() + ")");
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
		if (countIf > 0 && !first) {
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
		if (countIf > 0 && !first) {
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
				b.write("	function knowsDigest($a in Agent, $dg in KnowledgeDigest)=if($a=agent"
						+ agent.substring(0, 1) + " and $dg=" + ele.toUpperCase() + ")");
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
		if (countIf > 0 && !first) {
			b.write(" then true else");
		}
		return found;
	}

	// Scrittura dello stato S0 per la knowsOther
	private boolean writeDefaultInitS0Hot(BufferedWriter b, SecurityKey KeyActor, String agent, boolean foundIn)
			throws IOException {
		boolean found = foundIn;
		boolean first = true;
		for (String ele : otherElement.keySet()) {
			if (agent.substring(0, 1).equals(ele.substring(0, 1))) {
				if (!found) {
					b.write("	function knowsOther($a in Agent, $ho in KnowledgeOther)=if($a=agent"
							+ ele.substring(0, 1) + " and $ho=" + ele.substring(2).toUpperCase() + ")");
					countIf++;
					found = true;
				} else {
					if (first) {
						b.write(" if($a=agent" + ele.substring(0, 1) + " and $ho=" + ele.substring(2) + ")");
						countIf++;
					} else {
						b.write(" or ($a=agent" + ele.substring(0, 1) + " and $ho=" + ele.substring(2) + ")");
					}
				}
				first = false;
			}
		}
		if (countIf > 0 && !first) {
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
				b.write("	function knowsTimestamp($a in Agent, $tm in KnowledgeTimestamp)=if($a=agent"
						+ agent.substring(0, 1) + " and $tm=" + ele.toUpperCase() + ")");
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
				b.write("	function knowsAsymPrivKey($a in Agent ,$k in KnowledgeAsymPrivKey)=if(($a=agent"
						+ agent.substring(0, 1) + " and $k=" + ele.toUpperCase() + ")");
				countIf++;
				found = true;
			} else {
				b.write(" or ($a=agent" + agent.substring(0, 1) + " and $k=" + ele.toUpperCase() + ")");
			}
		}
		for (String ele : KeyActor.getKnowAcq()) {
			if (ele.contains("Asymmetric Private Key")) {
				if (!found) {
					b.write("	function knowsAsymPrivKey($a in Agent ,$k in KnowledgeSymKey)=if(($a=agent"
							+ agent.substring(0, 1) + " and $k=" + ele.substring(0, ele.indexOf(" - ")).toUpperCase()
							+ ")");
					countIf++;
					found = true;
				} else {
					b.write(" or ($a=agent" + agent.substring(0, 1) + " and $k="
							+ ele.substring(0, ele.indexOf(" - ")).toUpperCase() + ")");
				}
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
				b.write("	function knowsSymKey($a in Agent ,$sk in KnowledgeSymKey)=if(($a=agent"
						+ agent.substring(0, 1) + " and $sk=" + ele.toUpperCase() + ")");
				countIf++;
				found = true;
			} else {
				b.write(" or ($a=agent" + agent.substring(0, 1) + " and $sk=" + ele.toUpperCase() + ")");
			}
		}
		for (String ele : KeyActor.getKnowAcq()) {
			if (ele.contains("Symmetric Key")) {
				if (!found) {
					b.write("	function knowsSymKey($a in Agent ,$sk in KnowledgeSymKey)=if(($a=agent"
							+ agent.substring(0, 1) + " and $sk=" + ele.substring(0, ele.indexOf(" - ")).toUpperCase()
							+ ")");
					countIf++;
					found = true;
				} else {
					b.write(" or ($a=agent" + agent.substring(0, 1) + " and $sk="
							+ ele.substring(0, ele.indexOf(" - ")).toUpperCase() + ")");
				}
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
				b.write("	function knowsSignPubKey($a in Agent ,$spu in KnowledgeSignPubKey)=if(($a=agent"
						+ agent.substring(0, 1) + " and $spu=" + ele.toUpperCase() + ")");
				countIf++;
				found = true;
			} else {
				b.write(" or ($a=agent" + agent.substring(0, 1) + " and $spu=" + ele.toUpperCase() + ")");
			}
		}
		for (String ele : KeyActor.getKnowAcq()) {
			if (ele.contains("Signature Pub Key")) {
				if (!found) {
					b.write("	function knowsSymKey($a in Agent ,$spu in KnowledgeSymKey)=if(($a=agent"
							+ agent.substring(0, 1) + " and $spu=" + ele.substring(0, ele.indexOf(" - ")).toUpperCase()
							+ ")");
					countIf++;
					found = true;
				} else {
					b.write(" or ($a=agent" + agent.substring(0, 1) + " and $spu="
							+ ele.substring(0, ele.indexOf(" - ")).toUpperCase() + ")");
				}
			}
		}

		return found;
	}
}
