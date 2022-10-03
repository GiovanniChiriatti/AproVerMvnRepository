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
	private String[] ruleR_Agent = new String[50];
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
				changNumMSG[0]="A";
				changNumMSG[1]="B";
				changNumMSG[2]="C";
				changNumMSG[3]="D";
				changNumMSG[4]="E";
				changNumMSG[5]="F";
				changNumMSG[6]="G";
				changNumMSG[7]="H";
				changNumMSG[8]="I";
				changNumMSG[9]="L";
				changNumMSG[10]="M";
				changNumMSG[11]="N";
				changNumMSG[12]="O";
				changNumMSG[13]="P";
				changNumMSG[14]="Q";
				indRuleR_Agent=0;
//				System.out.println("-------WriteASM---------");
			    FileWriter w;
			    w=new FileWriter("src/main/resources/AProVerFile/"+ nameFile+".asm");

			   
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
		if (alice.getAsymmetricPrivateKey().size()> 0 && !(eve.getAsymmetricPrivateKey().size() > 0)) return false;
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
		if (numEncField>0) {
			if (numEncField<3) {
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
		for (int i = 0; i < 15; i++) {
			Message message = messages.getMessage(i);
			if (message.getActorfrom() == null || message.getActorfrom().isEmpty()) {
				if (i > 0) {
					break;
				}
			}
			b.write("	rule r_message_replay_M"+ changNumMSG[i] +" =\n");
			ruleR_Agent[indRuleR_Agent]= "E r_message_replay_M"+ changNumMSG[i]+"[]";
			indRuleR_Agent++;
			b.write("		//choose what agets are interested by the message\n");
			b.write("		let ($b=agent" + message.getActorTo().substring(0,1).toUpperCase() + ",$a=agent" + message.getActorfrom().substring(0,1).toUpperCase() + ") in\n");
			b.write("			//check the reception of the message and the modality of the attack\n");
			b.write("			if(protocolMessage($a,self)=M"+ changNumMSG[i] +" and protocolMessage(self,$b)!=M"+ changNumMSG[i] + " and mode=PASSIVE)then\n");
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
			b.write("			        if("+operation+"(M"+ changNumMSG[i]+","+ levelEncField1EncField2 +",self)=true)then\n");
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
			b.write("			        if(protocolMessage($a,self)=M"+ changNumMSG[i] +" and protocolMessage(self,$b)!=M"+ changNumMSG[i] + " and mode=ACTIVE)then\n");
			b.write("			                 // in the active mode the attacker can forge the message with all his knowledge\n");
			b.write("			                 if("+operation+"(M"+ changNumMSG[i]+","+ levelEncField1EncField2 +",self)=true)then\n");
			b.write("			                          par\n");
			spaces="         ";
			printKnowledge(b,"Know",linesKnowledge,spaces);
			printKnowledge(b,"Prot",linesKnowledge,spaces);
			printKnowledge(b,"Mes2",linesKnowledge,spaces);
			if (reversOperation(operation).equals("symEnc")) {
					b.write("			                               "+reversOperation(operation)+"(M"+ changNumMSG[i]+","+ levelEncField1EncField2 +"):=" + findKeyEle(keyUsed,message.getActorfrom(),message.getActorTo(), true)+"\n");
			} else {
				b.write("			                               "+reversOperation(operation)+"(M"+ changNumMSG[i]+","+ levelEncField1EncField2 +"):=" + findKeyEle(keyUsed,message.getActorfrom(),message.getActorTo(), false)+"\n");
				
			}
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
	// verifica se tra gli elementi arrivati all'interno dei messaggi precedenti contiene la chiave usata nel messaggio attuale
	private String findKeyEle(String keyUsed, String actorfrom, String actorTo,boolean reverse) {
		    for (Map.Entry<String, String> entry : attackerElement.entrySet()) {
		        if (entry.getKey().equals(actorfrom.substring(0,1)+ " " + keyUsed.toUpperCase() )) {
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
//		System.out.println(" messaggio payload " + message.getPayload());
		for (int numMsg = 0; numMsg < 15; numMsg++) {
			msgEncField1EncField2[numMsg] = "";
//			System.out.println(" Leggo riga numero : " + numMsg);
//			System.out.println(" messaggio SecurityFunctionsPartMessage" + message.getSecurityFunctionsPartMessage(numMsg));
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
//				System.out.println(" risultato " +numMsg + " " + msgEncField1EncField2[numMsg]);
//				for(int i=0; i<15; i++) {
//					if (msgField[i] != null) {
//						System.out.println(" Campo " + i + " Valore: " + msgField[i]);
//					}
//				}
				
			//
			}
		}

		return level+","+encField1+","+encField2;
	}
	// routin che server per determinare di quanti field si compone il messaggio e quanti livelli di cripr/encript ci sono
	private String[] writeKnowledge(Message message,int numMessage, String[] msgField,String typeActor) throws IOException {
		String[] linesKnowledge = new String[50];
		linesKnowledge[0]="Prot                                              protocolMessage(self,$b):=M"+changNumMSG[numMessage]+"\n";
		Boolean flgAtorTo = true;
		int numRighe = 1;
		for (int i = 0; i < 15; i++) {
			if (msgField[i] != null) {
				String typeFieldActorFrom = KeyActorFrom.searchEle(msgField[i]);
//				System.out.println(" Campo " + msgField[i] + " Tipo Campo " + typeFieldActorFrom);
				if (typeFieldActorFrom == null) {
					flgAtorTo = false;
					typeFieldActorFrom = KeyActorTo.searchEle(msgField[i]);
						if (typeFieldActorFrom == null) {	
								typeFieldActorFrom = "Other";
								otherElement.put(message.getActorfrom().substring(0,1) + " "+ msgField[i].toUpperCase(),message.getActorfrom().substring(0,1) + " "+ msgField[i].toUpperCase() );
						}
				}
				String eleEve=null;
				switch (typeFieldActorFrom) {
				case "Asymmetric Public Key":
					typeFieldActorFrom = "knowsAsymPubKey";
					eleEve = eve.getAsymmetricPublicKey().get(0);
					if (flgAtorTo) { attackerElement.put(message.getActorTo().substring(0, 1) + " " + msgField[i].toUpperCase(), "messageField($b,self," + i + ",M" + changNumMSG[numMessage] + ")");}
					break;
				case "Asymmetric Private Key":
					typeFieldActorFrom = "knowsAsymPrivKey";
					eleEve = eve.getAsymmetricPrivateKey().get(0);
					if (flgAtorTo) { attackerElement.put(message.getActorTo().substring(0, 1) + " " + msgField[i].toUpperCase(), "messageField($b,self," + i + ",M" + changNumMSG[numMessage] + ")");}
					break;
				case "Symmetric Key":
					typeFieldActorFrom = "knowsSymKey";
					eleEve = eve.getSymmetricKey().get(0);
					if (flgAtorTo) { attackerElement.put(message.getActorTo().substring(0, 1) + " " + msgField[i].toUpperCase(), "messageField($b,self," + i + ",M" + changNumMSG[numMessage] + ")");}
					break;
				case "Signature Pub Key":
					typeFieldActorFrom = "knowsSignPubKey";
					eleEve = eve.getSignaturePubKey().get(0);
					if (flgAtorTo) { attackerElement.put(message.getActorTo().substring(0, 1) + " " + msgField[i].toUpperCase(), "messageField($b,self," + i + ",M" + changNumMSG[numMessage] + ")");}
					break;
				case "Signature Priv Key":
					typeFieldActorFrom = "knowsSignPrivKey";
					eleEve = eve.getSignaturePrivKey().get(0);
					if (flgAtorTo) { attackerElement.put(message.getActorTo().substring(0, 1) + " " + msgField[i].toUpperCase(), "messageField($b,self," + i + ",M" + changNumMSG[numMessage] + ")");}
					break;
				case "Hash":
					typeFieldActorFrom = "knowsHash";
					eleEve = eve.getHashKey().get(0);
					if (flgAtorTo) { attackerElement.put(message.getActorTo().substring(0, 1) + " " + msgField[i].toUpperCase(), "messageField($b,self," + i + ",M" + changNumMSG[numMessage] + ")\n");}
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
						+ "(self,messageField("+ typeActor+",self," + i + ",M" + changNumMSG[numMessage] + ")):=true\n";
				numRighe++;

				linesKnowledge[numRighe] = "Mess                                              messageField(self,$b," + i
						+ ",M" + changNumMSG[numMessage] + "):=messageField("+typeActor +",self," + i + ",M" + changNumMSG[numMessage] + ")\n";
				numRighe++;
				if (eleEve != null) {
					linesKnowledge[numRighe] = "Mes2                                              messageField(self,$b,"
							+ i + ",M" + changNumMSG[numMessage] + "):=" + eleEve + "\n";
					numRighe++;
				} else {
					linesKnowledge[numRighe] = "Mes2                                              messageField(self,$b,"
							+ i + ",M" + changNumMSG[numMessage] + "):=messageField(" + typeActor + ",self," + i + ",M" + changNumMSG[numMessage]
							+ ")\n";
					numRighe++;
				}
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
			b.write("	rule r_message_M"+ changNumMSG[i] +" =\n");
			ruleR_Agent[indRuleR_Agent]= message.getActorfrom().toUpperCase().substring(0, 1)+" r_message_M"+ changNumMSG[i]+"[]";
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
				b.write("			if(internalState"+message.getActorfrom().substring(0, 1)+"(self)=IDLE_M"+ changNumMSG[i] + ")then \n");
				b.write("			        if(receiver=AG_"+message.getActorTo().substring(0, 1)+")then\n");
				b.write("			                par\n");
				b.write("			                       protocolMessage(self,$e):=M"+changNumMSG[i]+"\n");
				for (int k = 0; k < 15; k++) {
					if (msgField[k] != null) {
						b.write("			                       messageField(self,$e,"+k+",M"+changNumMSG[i]+"):="+findValueHonest(msgField[k].toUpperCase(),message.getActorfrom())+"\n");						
						honestElement.put(message.getActorTo().substring(0, 1)+ " "+ msgField[k].toUpperCase(),"messageField($e,self,"+k+",M"+changNumMSG[i]+")");					
					}
				}
				b.write("			                       "+reversOperation(operation)+"(M"+ changNumMSG[i]+","+ levelEncField1EncField2 +"):=" + findValueHonest(findKeyEle(keyUsed,message.getActorfrom(),message.getActorTo(),false),message.getActorTo()) +"\n");
				int j = i+1;
				b.write("			                       internalState"+message.getActorfrom().substring(0, 1)+"(self):=WAITING_M"+changNumMSG[j]+"\n");					
				b.write("			                endpar\n");
				b.write("			        else\n");
				b.write("			                if(receiver=AG_E)then\n");
				b.write("			                        par\n");
				b.write("			                              protocolMessage(self,$e):=M"+changNumMSG[i]+"\n");
				for (int k = 0; k < 15; k++) {
					if (msgField[k] != null) {
						b.write("			                              messageField(self,$e,"+k+",M"+changNumMSG[i]+"):="+changValueEve(msgField[k], message.getActorfrom(),true)+"\n");				
						honestElement.put("E"+ " "+ changValueEve(msgField[k], message.getActorfrom(),false).toUpperCase(),"messageField($e,self,"+k+",M"+changNumMSG[i]+")");
					}
				}
				b.write("			                              "+reversOperation(operation)+"(M"+ changNumMSG[i]+","+ levelEncField1EncField2 +"):=" + changValueEve(keyUsed,message.getActorfrom(),true).toUpperCase() +"\n");
				b.write("			                              internalState"+message.getActorfrom().substring(0, 1)+"(self):=WAITING_M"+changNumMSG[j]+"\n");					
				b.write("			                        endpar\n");
				b.write("			                endif\n");				
				b.write("			        endif\n");	
				b.write("			endif\n");
				b.write("		endlet\n");
				
				
			} else {
				int j = i-1;
				b.write("			if(internalState"+message.getActorfrom().substring(0, 1)+"(self)=WAITING_M"+ changNumMSG[j] + " and protocolMessage($e,self)=M"+ changNumMSG[j] +")then\n");
				if (actorStartProtocol.equals(message.getActorTo())){
								Message messagePrev = messages.getMessage(i-1);
								String[] msgEncField1EncField2Prev = new String[15];
								String[] msgFieldPrev = new String[15];
								levelEncField1EncField2Prev = calcLevelEncField1EncField2(messagePrev, msgEncField1EncField2Prev, msgFieldPrev);
								b.write("			        if("+operationPrev+"(M"+ changNumMSG[j]+","+ levelEncField1EncField2Prev +",self)=true)then\n");
								b.write("			                par\n");
								String[] linesKnowledgePrev = writeKnowledge(messagePrev,j,msgFieldPrev,"$e");
								String spaces="";
								printKnowledge(b,"Know",linesKnowledgePrev,spaces);
								b.write("			                      protocolMessage(self,$e):=M"+ changNumMSG[i] +"\n");
								for (int k = 0; k < 15; k++) {
									if (msgField[k] != null) {
										b.write("			                      messageField(self,$e,"+k+",M"+changNumMSG[i]+"):="+changValueEve(msgField[k], message.getActorfrom(),true)+"\n");															
										honestElement.put("E"+ " "+ changValueEve(msgField[k], message.getActorfrom(),false).toUpperCase(),"messageField($e,self,"+k+",M"+changNumMSG[i]+")");
										honestElement.put(message.getActorTo().substring(0, 1)+ " "+ msgField[k].toUpperCase(),"messageField($e,self,"+k+",M"+changNumMSG[i]+")");					
									}
								}
								if (reversOperation(operation).equals("symEnc")) {
									b.write("			                      "+reversOperation(operation)+"(M"+ changNumMSG[i]+","+ levelEncField1EncField2 +"):=" + findKeyEle(keyUsed,message.getActorfrom(),message.getActorTo(),true).replace("$b", "$e") +"\n");
								} else {
									b.write("			                      "+reversOperation(operation)+"(M"+ changNumMSG[i]+","+ levelEncField1EncField2 +"):=" + findKeyEle(keyUsed,message.getActorfrom(),message.getActorTo(),false).replace("$b", "$e") +"\n");									
								}
									j=i+1;
								if (messages.getMessage(i+1).getActorfrom()!=null && !messages.getMessage(i+1).getActorfrom().isEmpty()) {
								       b.write("			                      internalState"+message.getActorfrom().substring(0, 1)+"(self):=WAITING_M"+changNumMSG[j]+"\n");					
								} else {
								       b.write("			                      internalState"+message.getActorfrom().substring(0, 1)+"(self):=END_"+message.getActorfrom().substring(0, 1)+"\n");								
								}
								b.write("			                endpar\n");	
								b.write("			        endif\n");	
								b.write("			endif\n");
								b.write("	endlet\n");
				} else {
					b.write("			        if(receiver=AG_"+message.getActorTo().substring(0, 1)+")then\n");
					Message messagePrev = messages.getMessage(i-1);
					String[] msgEncField1EncField2Prev = new String[15];
					String[] msgFieldPrev = new String[15];
					levelEncField1EncField2Prev = calcLevelEncField1EncField2(messagePrev, msgEncField1EncField2Prev, msgFieldPrev);
					b.write("			           if("+operationPrev+"(M"+ changNumMSG[j]+","+ levelEncField1EncField2Prev +",self)=true)then\n");
					b.write("			                par\n");
					String[] linesKnowledgePrev = writeKnowledge(messagePrev,j,msgFieldPrev,"$e");
					String spaces="";
					printKnowledge(b,"Know",linesKnowledgePrev,spaces);
					b.write("			                      protocolMessage(self,$e):=M"+ changNumMSG[i] +"\n");
					for (int k = 0; k < 15; k++) {
						if (msgField[k] != null) {
			//				b.write("			                      messageField(self,$e,"+k+",M"+i+"):="+msgField[k].toUpperCase()+"\n");						
							b.write("			                      messageField(self,$e,"+k+",M"+changNumMSG[i]+"):="+findValueHonest(msgField[k].toUpperCase(),message.getActorfrom())+"\n");															
							honestElement.put(message.getActorTo().substring(0, 1)+ " "+ msgField[k].toUpperCase(),"messageField($e,self,"+k+",M"+changNumMSG[i]+")");					
						}
					}
			//		b.write("			                      "+reversOperation(operation)+"(M"+ i+","+ levelEncField1EncField2 +"):=" + findValueHonest(findKeyEle(keyUsed,message.getActorfrom(),message.getActorTo(),false),message.getActorTo()) +"\n");
					determinesOperation ( b, message, i, message.getActorfrom(), "",true);
					j=i+1;
					if (messages.getMessage(i+1).getActorfrom()!=null && !messages.getMessage(i+1).getActorfrom().isEmpty()) {
					       b.write("			                      internalState"+message.getActorfrom().substring(0, 1)+"(self):=WAITING_M"+changNumMSG[j]+"\n");					
					} else {
					       b.write("			                      internalState"+message.getActorfrom().substring(0, 1)+"(self):=END_"+message.getActorfrom().substring(0, 1)+"\n");								
					}
					b.write("			                endpar\n");	
					b.write("			        endif\n");	
					b.write("			else\n");
					msgFieldPrev = new String[15];
					j=i-1; 
					levelEncField1EncField2Prev = calcLevelEncField1EncField2(messagePrev, msgEncField1EncField2Prev, msgFieldPrev);
					b.write("			           if("+operationPrev+"(M"+ changNumMSG[j]+","+ levelEncField1EncField2Prev +",self)=true)then\n");
					b.write("			                par\n");
					linesKnowledgePrev = writeKnowledge(messagePrev,j,msgFieldPrev,"$e");
					spaces="";
					printKnowledge(b,"Know",linesKnowledgePrev,spaces);
					b.write("			                      protocolMessage(self,$e):=M"+ changNumMSG[i] +"\n");
					for (int k = 0; k < 15; k++) {
						if (msgField[k] != null) {
							b.write("			                      messageField(self,$e,"+k+",M"+changNumMSG[i]+"):="+changValueEve(msgField[k], message.getActorfrom(),true)+"\n");						
							honestElement.put("E"+ " "+ changValueEve(msgField[k], message.getActorfrom(),false).toUpperCase(),"messageField($e,self,"+k+",M"+changNumMSG[i]+")");
						}
					}
	//				b.write("			                      "+reversOperation(operation)+"(M"+ i+","+ levelEncField1EncField2 +"):=" + changValueEve(keyUsed,message.getActorfrom(),true) +"\n");
					determinesOperation ( b, message, i, message.getActorfrom(), "",false);
					j=i+1;
					if (messages.getMessage(i+1).getActorfrom()!=null && !messages.getMessage(i+1).getActorfrom().isEmpty()) {
						   endMessage = false;
						   b.write("			                      internalState"+message.getActorfrom().substring(0, 1)+"(self):=WAITING_M"+changNumMSG[j]+"\n");					
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
						b.write("	rule r_check_M" + changNumMSG[i] + " =\n");
						ruleR_Agent[indRuleR_Agent] = message.getActorTo().toUpperCase().substring(0, 1) + " r_check_M"
								+ changNumMSG[i]+"[]";
						indRuleR_Agent++;
						b.write("		let ($e=agentE) in\n");
						b.write("			if(internalState" + message.getActorTo().substring(0, 1)
								+ "(self)=WAITING_M" + changNumMSG[i] + " and protocolMessage($e,self)=M" + changNumMSG[i] + ")then\n");
						b.write("			        if(" + operation + "(M" + changNumMSG[i] + "," + levelEncField1EncField2
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
// quando ad operare è l'EVE si deve effettuare il reverse delle chiavi e dei field	
	private String changValueEve(String value, String actorFrom,boolean verifyElement){

		
		String valueOutput = value;
		String typeFieldActorFrom = KeyActorFrom.searchEle(value);
//		System.out.println("tipo : " + eve +  " ------ " + typeFieldActorFrom);


		boolean found=false;
		if (typeFieldActorFrom != null) {
			found=true;
			switch (typeFieldActorFrom) {
			case "Asymmetric Public Key":
				if (eve.getAsymmetricPublicKey().get(0) != null)
					valueOutput = eve.getAsymmetricPublicKey().get(0);
				break;
			case "Asymmetric Private Key":
	//			if (eve.getAsymmetricPrivateKey().get(0) != null)
	//				valueOutput = eve.getAsymmetricPrivateKey().get(0);
				break;
			case "Symmetric Key":
				if (eve.getSymmetricKey().get(0) != null) {
					valueOutput = eve.getSymmetricKey().get(0);
				}
				for (String e : eve.getSymmetricKey()) {
//					System.out.println("Verifico Alice " + (actorFrom.contains("Alice") && alice.searchSym(e)));
//					System.out.println("Verifico Bob " + (actorFrom.contains("Bob") && alice.searchSym(e)));

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
	
				break;
			case "Signature Pub Key":
		//		if (eve.getSignaturePubKey().get(0) != null)
		//			valueOutput = eve.getSignaturePrivKey().get(0);
				break;
			case "Signature Priv Key":
		//		if (eve.getSignaturePrivKey().get(0) != null)
		//			valueOutput = eve.getSignaturePrivKey().get(0);
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
		//			if (eve.getAsymmetricPrivateKey().get(0) != null)
		//				valueOutput = eve.getAsymmetricPrivateKey().get(0);
					break;
				case "Symmetric Key":
					if (eve.getSymmetricKey().get(0) != null) {
						valueOutput = eve.getSymmetricKey().get(0);
					}
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
					break;
				case "Signature Pub Key":
		//			if (eve.getSignaturePubKey().get(0) != null)
		//				valueOutput = eve.getSignaturePubKey().get(0);
					break;
				case "Signature Priv Key":
		//			if (eve.getSignaturePrivKey().get(0) != null)
		//				valueOutput = eve.getSignaturePrivKey().get(0);
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
//		System.out.println("cerco il valore : " + value + " Actor-from E ma reale: " + actorFrom);
		if (verifyElement) {
//			System.out.println("Cerco se l'elemento " + value +" è gia stato ricevuto da " + actorFrom);
		    for (Map.Entry<String, String> entry : honestElement.entrySet()) {
//		    	System.out.println("   verifico:  "+ entry.getKey());
		        if (entry.getKey().equals("E " + valueOutput.toUpperCase() )) {
//		        	System.out.println("trovato elemento "+ entry.getValue());
		        	return entry.getValue();
		        }
		    }
		}
		return valueOutput.toUpperCase();
	}
	
	// quando ad operare è l'EVE si deve effettuare il reverse delle chiavi e dei field	
		private String findValueHonest(String value, String actorFrom){
//			System.out.println("Cerco se l'elemento " + value +" è gia stato ricevuto da-> " + actorFrom);
		    for (Map.Entry<String, String> entry : honestElement.entrySet()) {
//		    	System.out.println("   verifico->:  "+ entry.getKey());
		    	if (entry.getKey().equals(actorFrom.toUpperCase().substring(0,1) + " "+ value.toUpperCase() )) {
//		        	System.out.println("trovato elemento-> "+ entry.getValue());
		        	return entry.getValue();
		        }
		    }
		    return value;
		}

	// dalla tabella si estraggono i messaggi divisi per i vari agenti e si scrivono le rispettive rule
	// per distinguere tra i messaggi a quale agent vanno agganciati si vede il primo carattere della stringa.
	private void writeRuleR_Agent(BufferedWriter b) throws IOException {
//		System.out.println("----writeRuleR_Agent---");
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
		b.write("	function internalState"+actorStartProtocol.substring(0, 1)+"($a in "+actorStartProtocol+")=IDLE_MA\n");				
		b.write("	function internalState"+actorReceiveProtocol.substring(0, 1)+"($b in "+actorReceiveProtocol+")=WAITING_MA\n");				
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
		// Scrittura dello stato S0 per la KnowledgeOther
				countIf=0;
				found = false;
				found = writeDefaultInitS0Hot(b, alice, "Alice", found);
				found = writeDefaultInitS0Hot(b, bob, "Bob", found);
				found = writeDefaultInitS0Hot(b, eve, "Eve", found);
				if (actorServer) {
					found = writeDefaultInitS0Hot(b, server, "Server", found);
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
		// determina le operazioni (crittografiche) all'interno del messaggio e scrive sul file di output
		private void determinesOperation (BufferedWriter b, Message message,int i,  String agent, String space,boolean receiverAG_B) 
				throws IOException {
			System.out.println("entro");
			//honestLevelElement = new HashMap<String, Integer>();
			int eleNum=0,levela=0,levelb=0;
			int elePartenza=0; 
			int eleArrivo=0;
			int ultimoEle=0;
			String keyUsedMsg;
			for (int numMsg = 0; numMsg < 15; numMsg++) {
				keyUsedMsg = null;
				if (message.getSecurityFunctionsPartMessage(numMsg) != null
						&& !message.getSecurityFunctionsPartMessage(numMsg).isEmpty()) {

//					System.out.println(
//							numMsg + " ho trovato securityfunction " + message.getSecurityFunctionsPartMessage(numMsg));
					if (message.getSecurityFunctionsPartMessage(numMsg)
							.substring(message.getSecurityFunctionsPartMessage(numMsg).length() - 2).equals("- ")) {

						keyUsedMsg = message.getSecurityFunctionsPartMessage(numMsg).substring(0,
								message.getSecurityFunctionsPartMessage(numMsg).length() - 3);
						keyUsedMsg = keyUsedMsg.substring(keyUsedMsg.lastIndexOf("-") + 2);
//						System.out.println("   " + numMsg + " trovata chiave :" + keyUsedMsg);
						
					}

					for (int j = 0; j < 15; j++) {
						if (message.getListPartMessage(numMsg, j) != null
								&& !message.getListPartMessage(numMsg, j).isEmpty()) {
							if (message.getListPartMessage(numMsg, j).toUpperCase().contains("(PAYLOADFIELD2)")) {
	//							System.out.println(numMsg + " " + j + " ho trovato PAYLOADFIELD2 "
	//									+ message.getListPartMessage(numMsg, j).toUpperCase());
								levelb++;
								levela=levelb;
								elePartenza=1;
	//							System.out.println("PAYALOAD2"+ message.getListPartMessage(numMsg, j).toUpperCase());
							} else {
								if (message.getListPartMessage(numMsg, j).toUpperCase().contains("(PAYLOADFIELD)")) {
	//								System.out.println("PAYALOAD1"+ message.getListPartMessage(numMsg, j).toUpperCase());
									levela++;
									elePartenza=ultimoEle;
									if (levela>levelb) {levelb=levela;};
								} else {
									eleNum++;
									if (j==0) {
										elePartenza=eleNum;
										levela=1;
								//		System.out.println("-----> rimetto a 1 ");
										if (levela>levelb) {levelb=levela;};
									}
									
					//				if (!honestLevelElement.containsKey(message.getListPartMessage(numMsg, j).toUpperCase())) {
					//					eleNum++;
					//					honestLevelElement.put(message.getListPartMessage(numMsg, j).toUpperCase(),eleNum);
					//				}
								//	System.out.println(numMsg + " " + j + " Entro per il field "
								//			+ message.getListPartMessage(numMsg, j).toUpperCase());
								}
							}
						}
					}
					eleArrivo=eleNum;
					ultimoEle=eleNum;
					System.out.println("messaggio " + message.getSecurityFunctionsPartMessage(numMsg)+ " livello " + levela + " ele Partenza "+ elePartenza + " ele Arrivo " + eleArrivo);
					if (keyUsedMsg != null) {
						String operationMsg = findOperation(keyUsedMsg, message.getActorfrom(), message.getActorTo());
						int numMsgNext = numMsg + 1;
						String changValueEve;
						if (receiverAG_B) {
							changValueEve = findValueHonest(
									findKeyEle(keyUsedMsg, message.getActorfrom(), message.getActorTo(), false),
									message.getActorTo()).replace("($e", "(self");
						} else {
							changValueEve = changValueEve(keyUsedMsg, message.getActorfrom(), true).replace("($e",
									"(self");
						}
						changValueEve.replace(",self", ",$e");					
						if (numMsgNext < 15 && message.getSecurityFunctionsPartMessage(numMsgNext) != null
								&& !message.getSecurityFunctionsPartMessage(numMsgNext).isEmpty()) {
							b.write("			                      " + operationMsg + "(M" + changNumMSG[i] + ","+ levela +"," + elePartenza+"," + eleArrivo + "):="+ changValueEve+"\n");
						} else {
							b.write("			                      " + reversOperation(operationMsg) + "(M" + changNumMSG[i] + ","+ levela +"," + elePartenza+"," + eleArrivo + "):="+ changValueEve+"\n");
							
						}
					}
				}
			}
		   // for (Map.Entry<String, Integer> entry : honestLevelElement.entrySet()) {
 		   // 	System.out.println("   dati in tabella :  "+ entry.getKey() + " - " +entry.getValue());
		   //     }

			
		}
}
