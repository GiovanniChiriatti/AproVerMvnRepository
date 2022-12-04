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
	private Map<String, String> keychangEve = new HashMap<String, String>();
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
	private int encField2Old;
	private int numOperationMessage;
	private SecurityKey KeyActorFrom;
	private SecurityKey KeyActorTo;	
	private Messages messages;
	private SecurityKey aliceStart;
	private SecurityKey bobStart;
	private SecurityKey eveStart;
	private SecurityKey serverStart;
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
	private boolean debug;
	
	public WriteASM(Boolean actorServer, Messages messages,SecurityKey aliceStart,SecurityKey bobStart,SecurityKey eveStart,SecurityKey serverStart,String toolEve, int fieldPosition, int levelTot,int numEncField,int numSignField,
			int numSymField,int numHashField, String nameFile,String acronym) 
			  throws IOException {
		System.out.println("WriteASM");
				this.actorServer = actorServer;
				this.messages = messages;
				this.aliceStart = aliceStart;
				this.bobStart = bobStart;
				this.eveStart = eveStart;
				this.serverStart = serverStart;
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
				debug=false;
				
				if (debug) {System.out.println("WriteASM ---> 000");}
				
				// Carico le conoscenze attuali 
				loadKnowActual();
				
				if (debug) {System.out.println("WriteASM ---> 001");}
				
				indRuleR_Agent=0;

			    FileWriter w;
			    w=new FileWriter("src/main/resources/AProVerTest/"+ nameFile+".asm");

			   
			    b=new BufferedWriter (w);

			    
			  }
	//Carico le conoscenze attuali che possono essere modificate durante l'esecuzione del protocollo
	private void loadKnowActual() {
		// Carico le conoscenze attuali 
		alice = new SecurityKey();
		if (aliceStart!=null) {
		loadKnowActor(alice,aliceStart);
		} else {
			alice = null;
		}
		
		bob = new SecurityKey();
		if (bobStart!=null) {
			loadKnowActor(bob,bobStart);
		} else {
			bob = null;
		}
		
		eve = new SecurityKey();
		if (eveStart!=null) {
			loadKnowActor(eve,eveStart);								
		} else {
			eve = null;
		}				
		server = new SecurityKey();
		if (serverStart!=null) {
			loadKnowActor(server,serverStart);
		} else {
			server = null;
		}
	}
	private void loadKnowActor(SecurityKey arrived, SecurityKey start) {
		if (debug) {System.out.println("WriteASM ---> 002");}
		for (String e : start.getAsymmetricPublicKey()) {
			arrived.addAsymmetricPublicKey(e);
		}

		for (String e : start.getAsymmetricPrivateKey()) {
			arrived.addAsymmetricPrivateKey(e);
		}

		for (String e : start.getSymmetricKey()) {
			arrived.addSymmetricKey(e);
		}

		for (String e : start.getHashKey()) {
			arrived.addHashKey(e);
		}	

		for (String e : start.getBitstring()) {
			arrived.addBitstring(e);
		}		

		for (String e : start.getIdCertificate()) {
			arrived.addIdCertificate(e);
		}	

		for (String e : start.getNonce()) {
			arrived.addNonce(e);
		}

		for (String e : start.getSignaturePubKey()) {
			arrived.addSignaturePubKey(e);
		}	

		for (String e : start.getSignaturePrivKey()) {
			arrived.addSignaturePrivKey(e);
		}	

		for (String e : start.getTag()) {
			arrived.addTag(e);
		}			
		for (String e : start.getTimestamp()) {
			arrived.addTimestamp(e);
		}	

		for (String e : start.getDigest()) {
			arrived.addDigest(e);
		}	

		for (String e : start.getKnowAcq()) {
			arrived.addKnowAcq(e.substring(0, e.indexOf(" - ")),
					e.substring(e.indexOf(" - ")+3));
		}	
		
		if (debug) {System.out.println("WriteASM ---> 003");}
	}
	//Scrittura prime info file asm
		public boolean writeFile() throws IOException {
			if (debug) {System.out.println("WriteASM ---> 004");}
			if (!initialControl()){
				b.write("errore dati incompleti");
				b.flush();
			    b.close();
				return false;
			}
		    // scrittura info iniziali del file asm
		    writeOpen(b);
		    // scrittura delle Knowledge
		    writeKnowledgeASM(b);
		    b.flush();
		    b.close();
		    if (debug) {System.out.println("WriteASM ---> 005");}
			return true;
		}
	private boolean initialControl() {
		if (debug) {System.out.println("WriteASM ---> 006");}
		if (alice == null) return false;
		if (bob == null) return false;
		if (eve == null) return false;
		if (messages == null) return false;
		if (alice.getAsymmetricPrivateKey().size()> 0 && !(eve.getAsymmetricPrivateKey().size() > 0)) return false;
		if (alice.getAsymmetricPublicKey().size()> 0 && !(eve.getAsymmetricPublicKey().size() > 0)) return false;
		
	 	if (alice.getSignaturePrivKey().size()> 0 && !(eve.getSignaturePrivKey().size() > 0)) return false;
	 	if (alice.getSignaturePubKey().size()> 0 && !(eve.getSignaturePubKey().size() > 0)) return false;
	 	if (alice.getSymmetricKey().size()> 0 && !(eve.getSymmetricKey().size() > 0)) return false;

		
	 	if (debug) {System.out.println("WriteASM ---> 007");}
		return true;
	}
	//Scrittura prime info file asm
	private void writeOpen(BufferedWriter b) throws IOException {
		if (debug) {System.out.println("WriteASM ---> 008");}
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
		if (debug) {System.out.println("WriteASM ---> 009");}
	}
	//Scrittura prime info file asm
	private void writeKnowledgeASM(BufferedWriter b) throws IOException {
		if (debug) {System.out.println("WriteASM ---> 010");}
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
        if (debug) {System.out.println("WriteASM ---> 011");}
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
		String[] linesKnowledge = writeKnowledge(message, i, msgFieldTot, "$a",false);

		String spaces = "                            ";
		printKnowledge(b, "Prot", linesKnowledge, spaces);
		printKnowledge(b, "Mess", linesKnowledge, spaces);
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
/*				operation = findOperation(keyUsed, message.getActorfrom(), message.getActorTo());
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
*/
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
				linesKnowledge = writeKnowledge(message, i, msgFieldDet, "$a",false);
				spaces = "                            ";
				printKnowledge(b, "Know", linesKnowledge, spaces);
			}
		}
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
					b.write("			        if(" + operation + "(" + changNumMSG[i] + "," + levelEncField1EncField2
							+ ",self)=true)then\n");
					linesKnowledge = writeKnowledge(message, i, msgFieldDet, "$a",false);
					b.write("	   			 par \n");
					spaces = "				";
					printKnowledge(b, "Know", linesKnowledge, spaces);
					spaces = "					";
//---				if (reversOperation(operation).equals("symEnc")) {
//---							b.write("					" + reversOperation(operation) + "(" + changNumMSG[i] + ","
//---							+ levelEncField1EncField2 + "):="
//---							+ findKeyEle(keyUsed, message.getActorfrom(), message.getActorTo(), true) + "\n");
//---				} else {
						b.write("					" + reversOperation(operation) + "(" + changNumMSG[i] + ","
								+ levelEncField1EncField2 + "):="
								+ findKeyEle(keyUsed, message.getActorfrom(), message.getActorTo(), false) + "\n");
//---				}

					b.write("	   			 endpar \n");
					b.write("			        endif \n");
					
				}
			}

		}
		if (!firstOp ) {
			if(totOpz>1) {
				b.write("			  endpar \n");
			}
			b.write("			endif \n");
		}
		b.write("		          endpar \n");
		b.write("			endif \n");

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
		String[] linesKnowledge = writeKnowledge(message, i, msgFieldTot, "$a",false);

		String spaces = "                            ";
		printKnowledge(b, "Prot", linesKnowledge, spaces);
		printKnowledge(b, "Mes2", linesKnowledge, spaces);
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
/*				operation = findOperation(keyUsed, message.getActorfrom(), message.getActorTo());
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
*/
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
				linesKnowledge = writeKnowledge(message, i, msgFieldDet, "$a",false);
				spaces = "                            ";
				printKnowledge(b, "Know", linesKnowledge, spaces);
				printKnowledge(b, "Mes4", linesKnowledge, spaces);
			}
		}

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
				b.write("			        if(" + operation + "(" + changNumMSG[i] + "," + levelEncField1EncField2
						+ ",self)=true)then\n");
				
				b.write("	   			 par \n");
				String eleEve = findKeyEve(keyUsed);
				debug=true;
				if (debug && eleEve !=null) {System.out.println("eleEve " + eleEve + " parte finale " + eleEve.substring(eleEve.indexOf(" - ")+3) +
						" Parte iniziale  " + eleEve.substring(0,eleEve.indexOf(" - ")) + " actor To " + message.getActorTo());
				}
				debug=false;
				if (eleEve != null) {
					if (eleEve.substring(eleEve.indexOf(" - ")+3).contains(message.getActorTo())) {
						eleEve = null;
					} else {
						eleEve = eleEve.substring(0,eleEve.indexOf(" - "));
					}
				}
					
				linesKnowledge = writeKnowledge(message, i, msgFieldDet, "$a", true);
				spaces = " 				";
				printKnowledge(b, "Know", linesKnowledge, spaces);
				printKnowledge(b, "Mes4", linesKnowledge, spaces);
				operation = findOperation(keyUsed, message.getActorfrom(), message.getActorTo());
				if (eleEve != null) {
					b.write("					" + reversOperation(operation) + "(" + changNumMSG[i] + ","
							+ levelEncField1EncField2 + "):="
							+ eleEve + "\n");
				} else {
					b.write("					" + reversOperation(operation) + "(" + changNumMSG[i] + ","
							+ levelEncField1EncField2 + "):="
							+ findKeyEle(keyUsed, message.getActorfrom(), message.getActorTo(), false) + "\n");
				}
				b.write("	   			 endpar \n");
				int totCountLinesKnowledgeMes5 = countLinesKnowledge("Mes5", linesKnowledge);
				if (totCountLinesKnowledgeMes5 > 0) {
					b.write("				else \n");
					if (totCountLinesKnowledgeMes5 > 1) {
						b.write("			  		  par \n");
					}
					spaces = " 				";
					printKnowledge(b, "Mes5", linesKnowledge, spaces);
					if (totCountLinesKnowledgeMes5 > 1) {
						b.write("			  		  endpar \n");
					}
				}
				b.write("			        endif \n");
			}
			
		}


		b.write("		          endpar \n");
		b.write("			endif \n");
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
			if (operation == null) {
				if (KeyActorTo != null) {
					operation = KeyActorTo.searchEle(keyUsed);
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
			if (messagePayload.charAt(i) == '-') {
				counter++;
			}
			if (messagePayload.charAt(i) != '-' && messagePayload.charAt(i) != ' ' && messagePayload.charAt(i) != ','
					&& messagePayload.charAt(i) != '}' && messagePayload.charAt(i) != '{') {
				fieldMsg = fieldMsg + messagePayload.charAt(i);
			}
			if (fieldMsg != null && !fieldMsg.isEmpty()
					&& (messagePayload.charAt(i) == ',' || messagePayload.charAt(i) == '}')) {
				msgField[numField+1] = fieldMsg.toUpperCase();
				fieldMsg = "";
				numField++;
			}
			if (messagePayload.charAt(i) == '-') {
				if (!dash) {
					dash = true;
				} else {
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
		String[] msgFieldDet = new String[15];
		int i=1;
		int start =0;
		int end = 0;
		boolean find = false;
		for (int j=1; j<15 ; j++) {
			if (msgField[i] == null) {break;}
			if (msgFieldTot[j] != null && !msgFieldTot[j].isEmpty() ) {
				if (msgField[i].equals(msgFieldTot[j]) && !find ) {
					start = j;
				}
				if (msgField[i].equals(msgFieldTot[j])) {
					find = true;
					end = j;
					i++;
				} else {
					find = false;
					i = 1;
				}
				if (i > 14) {
					break;
				}
			}
		}
		
		for (int k=start ; k<end+1 ; k++) {msgFieldDet[k] = msgFieldTot[k];}

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
		int counter = 0;
		for (int i = 0; i < messagePart.length(); i++) {
			if (messagePart.charAt(i) == '-') {
				counter++;
			}
			if (messagePart.charAt(i) != '-' && messagePart.charAt(i) != ' ' && messagePart.charAt(i) != ','
					&& messagePart.charAt(i) != '}' && messagePart.charAt(i) != '{') {
				fieldMsg = fieldMsg + messagePart.charAt(i);
			}
			if (fieldMsg != null && !fieldMsg.isEmpty()
					&& (messagePart.charAt(i) == ',' || messagePart.charAt(i) == '}')) {
				msgField[encField2+1] = fieldMsg.toUpperCase();
				fieldMsg = "";
				encField2++;
			}
			if (messagePart.charAt(i) == '-') {
				if (!dash) {
					dash = true;
				} else {
					dash = false;
					fieldMsg = "";
					boolean first = false;
					int countDash = 0;
					int count = 0;
					int countField = 0;
					for (int j = i; j > -1; j--) {
						if (messagePart.charAt(j) == '-') {
							countDash++;
						}
						if (messagePart.charAt(j) == '}') {
							count++;
							first = true;
						}
						if ((messagePart.charAt(j) == '}' || messagePart.charAt(j) == ',')
								&& (messagePart.charAt(j - 1) != '}' && messagePart.charAt(j - 1) != '-'
										&& messagePart.charAt(j - 1) != ',' && messagePart.charAt(j - 1) != ' ')) {
							countField++;
						}
						if (messagePart.charAt(j) == '{') {
							count--;
						}
						if (count == 0 && first) {
							level = countDash / 2;
							break;
						}
					}
					encField1 = encField2 - countField + 1;
					boolean trovaSequenza = false;
					int j = encField1;
					int appoField1 =encField1;
					int appoField2 =encField2;
					// cerca la sequenza dei field trovati all'interno dei field del payload
					for (int k = 0; k < 15; k++) {
						
						if (msgFieldTot[k] != null && !msgFieldTot[k].isEmpty()) {
							if (msgField[j].equals(msgFieldTot[k]) && !trovaSequenza) {
								appoField1 = k;
							}
							if (msgField[j].equals(msgFieldTot[k])) {
								trovaSequenza = true;
								j++;
								appoField2 = k;
							} else {
								trovaSequenza = false;
								j = encField1;
							}
							if (j > encField2) {
								break;
							}
						}
					}
					msgEncField1EncField2[numMsgP] = level + "," + appoField1 + "," + appoField2;
					numMsgP++;
				}
			}

		}
		
		
		if (numMsgP > 0) {
			return msgEncField1EncField2[numMsgP - 1];
		}
		return null;
	}
	
	// determina le operazioni (crittografiche) all'interno del messaggio e scrive sul file di output
	private void determinesOperation (BufferedWriter b,int m,int s, Message message, String messagePart,  String agent, String space,boolean receiverAG_B) 
			throws IOException {
		int encField1, encField2, level, numMsgP;
		encField1 = 1;
		encField2 =0;
		if (s != 0 ) {encField2 = encField2Old;};
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
 		int counter = 0;
		
		for (int i = 0; i < messagePart.length(); i++) {
			if (messagePart.charAt(i) == '-') {
				counter++;
			}
			if (messagePart.charAt(i) != '-' && messagePart.charAt(i) != ' ' && messagePart.charAt(i) != ','
					&& messagePart.charAt(i) != '}' && messagePart.charAt(i) != '{') {
				fieldMsg = fieldMsg + messagePart.charAt(i);
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
					keyMsg = "";
					dash = true;
				} else {
					dash = false;
					fieldMsg = "";
					 
					boolean first = false;
					int countDash = 0;
					int count = 0;
					int countField = 0;
					for (int j = i; j > -1; j--) {
						if (messagePart.charAt(j) == '-') {
							countDash++;
						}
						if (messagePart.charAt(j) == '}') {
							count++;
							first = true;
						}
						if ((messagePart.charAt(j) == '}' || messagePart.charAt(j) == ',')
								&& (messagePart.charAt(j - 1) != '}' && messagePart.charAt(j - 1) != '-'
										&& messagePart.charAt(j - 1) != ',' && messagePart.charAt(j - 1) != ' ')) {
							countField++;
						}
						if (messagePart.charAt(j) == '{') {
							count--;
						}
						if (count == 0 && first) {
							level = countDash / 2;
							break;
						}
					}
					encField1 = encField2 - countField + 1;
					msgEncField1EncField2[numMsgP] = level + "," + encField1 + "," + encField2;
					keyFieldMsg[numMsgP] = keyMsg;
					keyMsg="";
					numMsgP++;
				}
			}
		}
		encField2Old = encField2;
		for (int k=0 ; k<numMsgP ;  k++) {
			String operationMsg = findOperation(keyFieldMsg[k], message.getActorfrom(), message.getActorTo());
			String changValueEve;
			if (receiverAG_B) {
				changValueEve = findValueHonest(
						findKeyEle(keyFieldMsg[k], message.getActorfrom(), message.getActorTo(), false),
						message.getActorTo()).replace("($e", "(self");
			
			} else {
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
	private String[] writeKnowledge(Message message, int numMessage, String[] msgField, String typeActor,boolean add)
			throws IOException {
		int numMessagePrec=0;
		if (numMessage>0 ) {numMessagePrec=numMessage;}
 		if (debug) System.out.println(" entro in  writeKnowledge " + KeyActorFrom + "  " + KeyActorTo);
		String[] linesKnowledge = new String[50];
		linesKnowledge[0] = "Prot	protocolMessage(self,$b):=" + changNumMSG[numMessage] + "\n";
		Boolean flgAtorTo = true;
		int numRighe = 1;
		if (debug) System.out.println("writeKnowledge actorTo " + message.getActorTo());
		for (int i = 0; i < 15; i++) {
			if (msgField[i] != null) {
				if (debug) System.out.println("writeKnowledge msgField[i] " + i + " - " + msgField[i]);
				String typeFieldActorFrom = KeyActorFrom.searchEle(msgField[i]);
				if (debug) System.out.println("writeKnowledge typeFieldActorFrom1 " + typeFieldActorFrom);
				if (typeFieldActorFrom == null) {
					flgAtorTo = false;
					typeFieldActorFrom = KeyActorTo.searchEle(msgField[i]);
					if (debug) System.out.println("writeKnowledge typeFieldActorFrom2 " + typeFieldActorFrom);
					if (typeFieldActorFrom == null) {
						typeFieldActorFrom = "Other";
						otherElement.put(message.getActorfrom().substring(0, 1) + " " + msgField[i].toUpperCase(),
								message.getActorfrom().substring(0, 1) + " " + msgField[i].toUpperCase());
					}
				}
				if (debug) System.out.println("writeKnowledge typeFieldActorFrom3 " + typeFieldActorFrom);
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
				if (debug) System.out.println("writeKnowledge end case");

				linesKnowledge[numRighe] = "Know	" + typeFieldActorFrom + "(self,messageField("
						+ typeActor + ",self," + i + "," + changNumMSG[numMessage] + ")):=true\n";
				numRighe++;
				linesKnowledge[numRighe] = "Kno3	" + typeFieldActorFrom + "(self,messageField(" + typeActor
						+ ",self," + i + "," + changNumMSG[numMessagePrec] + ")):=true\n";
				numRighe++;
				if (debug) System.out.println("writeKnowledge add " + add);


				if (debug) System.out.println("writeKnowledge endadd " + add);

				linesKnowledge[numRighe] = "Mess	messageField(self,$b," + i + ","
						+ changNumMSG[numMessage] + "):=messageField(" + typeActor + ",self," + i + ","
						+ changNumMSG[numMessage] + ")\n";
				numRighe++;
				if (debug) System.out.println("writeKnowledge eleEve " + eleEve);
				if (eleEve != null) {
					linesKnowledge[numRighe] = "Mes4	messageField(self,$b," + i + ","
							+ changNumMSG[numMessage] + "):=" + eleEve + "\n";
					numRighe++;
					if (add) {
						keychangEve.put(msgField[i].toUpperCase(), eleEve+ " - " +message.getActorfrom());
 					}
					linesKnowledge[numRighe] = "Mes3	messageField(self,$b," + i + "," + changNumMSG[0]
							+ "):=messageField(" + typeActor + ",self," + i + "," + changNumMSG[numMessage] + ")\n";
					linesKnowledge[numRighe] = "Mes5	messageField(self,$b," + i + "," + changNumMSG[numMessage]
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
		if (debug) System.out.println("writeKnowledge esco  " + linesKnowledge);

		return linesKnowledge;
	}
	// conta quanti campi contiene il sottomessaggio
	private int countLinesKnowledge(String val, String[] linesKnowledge) {
		int tot = 0; 
		for (String e : linesKnowledge) {
			if (e !=null && e.contains(val)) { tot++;}
		}
		return tot;
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
	// Ricerca eventuali chiavi modificate da eve 
	private String findKeyEve(String keyUsed) { 
		for (Map.Entry<String, String> entry : keychangEve.entrySet()) {
			if (entry.getKey().equals(keyUsed.toUpperCase())) {
				return entry.getValue();
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
			indRuleR_Agent++;
			b.write("		let ($e=agentE) in\n");

			String[] listSubPayload = findMsg(message);

			if (i == 0) {
				for (int j = 0; j < 15; j++) {
					if (listSubPayload[j] == null || listSubPayload[j].isEmpty()) {break;}
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
					actorStartProtocol = message.getActorfrom();
					actorReceiveProtocol = message.getActorTo();
					b.write("			if(internalState" + message.getActorfrom().substring(0, 1) + "(self)=IDLE_"
							+ changNumMSG[i] + ")then \n");
					b.write("			        if(receiver=AG_" + message.getActorTo().substring(0, 1) + ")then\n");
					b.write("			                par\n");
					b.write("			                       protocolMessage(self,$e):=" + changNumMSG[i] + "\n");
					for (int k = 0; k < 15; k++) {
						if (msgFieldDet[k] != null) {
							b.write("			                       messageField(self,$e," + k + "," + changNumMSG[i]
									+ "):=" + findValueHonest(msgFieldDet[k].toUpperCase(), message.getActorfrom())
									+ "\n");
							honestElement.put(message.getActorTo().substring(0, 1) + " " + msgFieldDet[k].toUpperCase(),
									"messageField($e,self," + k + "," + changNumMSG[i] + ")");
						}
					}
					if (operation != null && !operation.isEmpty()) {
						b.write("			                       " + reversOperation(operation) + "(" + changNumMSG[i]
								+ "," + levelEncField1EncField2 + "):="
								+ findValueHonest(
										findKeyEle(keyUsed, message.getActorfrom(), message.getActorTo(), false),
										message.getActorTo())
								+ "\n");
					}
					int z = i + 1;
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
					for (int k = 0; k < 15; k++) {
						if (msgFieldDet[k] != null) {
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
				int z = i - 1;
				b.write("			if(internalState" + message.getActorfrom().substring(0, 1) + "(self)=WAITING_"
						+ changNumMSG[i-1] + " and protocolMessage($e,self)=" + changNumMSG[i-1] + ")then\n");
				if (actorStartProtocol.equals(message.getActorTo())) {
					boolean actorNoDecode=false;
					Message messagePrev = messages.getMessage(z);
					String[] msgFieldTotPrev = FindField(messages.getMessage(i-1).getPayload());
					String[] listSubPayloadPrev = findMsg(messagePrev);
					debug = true;
					if (debug) {
						System.out
								.println("1 payload prev i-1" + (i - 1) + " " + messages.getMessage(i - 1).getPayload());
					}
					//Si verifica se la parte del messaggio è decodificabile altrimenti si leva dall'elenco 
					// del messaggio precedente
					findActorFromTo(messagePrev.getActorfrom(), messagePrev.getActorTo());
					String[] NewListSubPayloadPrev = new String[15];
					String NewPayloadPrev = new String();
					int indList = 0;
					for (int k = 0 ; k<15 ; k++) {
						if (listSubPayloadPrev[k] != null) {
							if (debug) {System.out.println("1 parte del messaggio " + listSubPayloadPrev[k]);}
							String keyUsedPrev = findKey(listSubPayloadPrev[k]);
							if (keyUsedPrev == null || KeyActorTo.searchEle(keyUsedPrev) !=null) {
								if (debug) {System.out.println("1 Verifico se posso aggiungere conoscenza");}
								if (indList==0) {
									NewListSubPayloadPrev[indList]=listSubPayloadPrev[k];
									NewPayloadPrev = listSubPayloadPrev[k];
									indList++;
								} else {
									NewListSubPayloadPrev[indList]=listSubPayloadPrev[k];
									NewPayloadPrev = NewPayloadPrev + ","+listSubPayloadPrev[k];
									indList++;									
								}
								String[] msgFieldPrev = new String[15];
								String[] msgEncField1EncField2Prev = new String[15];
								levelEncField1EncField2Prev = calcLevelEncField1EncField2(listSubPayloadPrev[k],
										msgEncField1EncField2Prev, msgFieldPrev,msgFieldTotPrev);
								addKnowActorTo(msgFieldPrev);
							} else {
								if (debug) {System.out.println("1 cancello pezzo di messaggio " + listSubPayloadPrev[k]);}
								listSubPayloadPrev[k]=null;
							}
						}
					}
					if (debug) {System.out.println("1 NewPayloadPrev " + NewPayloadPrev);}
					msgFieldTotPrev = FindField(NewPayloadPrev);
					if (debug) { 
						System.out.println("1 ------> NewListSubPayloadPrev <----------");
						for (String e: NewListSubPayloadPrev) {
							System.out.println("1 ------> " +e+ " <-------------");
						}
					}
					listSubPayloadPrev = NewListSubPayloadPrev;
					
					boolean fistOperation = true;   
					String[] msgFieldPrev = new String[15];
					
					if (debug) {
						System.out.println(">> Elenco campi del payload " + messages.getMessage(i-1).getPayload());
						for (String e : msgFieldTotPrev) {
							if (e !=null) System.out.println("Valore : " + e);
						}
						System.out.println(">> Terminato elenco ");
					}

					for (int f = 0; f < 15; f++) {
						if (listSubPayloadPrev[f] == null || listSubPayloadPrev[f].isEmpty()) {
							break;
						}
						if (debug) {System.out.println("xx analizzo il messaggio " + listSubPayloadPrev[f]);}

						String[] msgEncField1EncField2Prev = new String[15];
						levelEncField1EncField2Prev = calcLevelEncField1EncField2(listSubPayloadPrev[f],
								msgEncField1EncField2Prev, msgFieldPrev,msgFieldTotPrev);
						String[] msgFieldDetPrev = detField(msgFieldPrev,msgFieldTotPrev);
						String keyUsedPrev = findKey(listSubPayloadPrev[f]);
						operationPrev = "";
						findActorFromTo(messagePrev.getActorfrom(), messagePrev.getActorTo());
						if (keyUsedPrev == null || KeyActorTo.searchEle(keyUsedPrev) !=null) {
							if (debug) {System.out.println("xx messagePrev.getActorfrom() " + messagePrev.getActorfrom() + " messagePrev.getActorTo() " + messagePrev.getActorTo());}
							addKnowActorTo(msgFieldPrev);
						}
						if (debug) {System.out.println(" 1 keyUsedPrev " + keyUsedPrev);}
						if (keyUsedPrev != null) {
							operationPrev = findOperation(keyUsedPrev, messagePrev.getActorfrom(), messagePrev.getActorTo());
//							if (KeyActorTo.searchEle(keyUsedPrev) ==null) {actorNoDecode=true;}
						}
						if (debug) {System.out.println(" 2 operationPrev " + operationPrev);}

						if (operationPrev != null && !operationPrev.isEmpty()) {
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
					if (debug) {System.out.println(" 3 detField ");}
					String[] msgFieldDetPrev = detField(msgFieldPrev,msgFieldTotPrev);
					b.write("			                par\n");
					if (debug) {System.out.println(" 4 writeKnowledge ");}
					String[] linesKnowledgePrev = writeKnowledge(messagePrev,z,msgFieldTotPrev,"$e",false);
					String spaces= "					";
					if (debug) {System.out.println(" 5 printKnowledge ");}
					printKnowledge(b,"Kno3",linesKnowledgePrev,spaces);
					b.write("	 		                      protocolMessage(self,$e):="+ changNumMSG[i] +"\n");
					if (debug) {System.out.println(" 6 findMsg ");}
					
					listSubPayload = findMsg(message);
					if (debug) {System.out.println(" 7 listSubPayload ");}	
					int delJ =0;
					for (int j = 0; j < 15; j++) {
						if (listSubPayload[j] == null || listSubPayload[j].isEmpty()) {
							break;
						}
						if (debug) {System.out.println(" 7A listSubPayload " + listSubPayload[j]);}
						String[] msgEncField1EncField2 = new String[15];
						String[] msgField = new String[15];
						String levelEncField1EncField2 = calcLevelEncField1EncField2(listSubPayload[j],
								msgEncField1EncField2, msgField,msgFieldTot);
						String[] msgFieldDet = detField(msgField,msgFieldTot);
						if (debug) {
							System.out.println(" 7B *-------- elenco field Tot *-------");
							for (String e: msgFieldTot) {
								if (e!=null) {System.out.println(" 7B *--------" + e);}
							}
							System.out.println(" 7C *-------- elenco msgField *-------");
							for (String e: msgField) {
								if (e!=null) {System.out.println(" 7C *--------" + e);}
							}
							System.out.println(" 7D *-------- elenco msgFieldDet *-------");
							for (String e: msgFieldDet) {
								if (e!=null) {System.out.println(" 7D *--------" + e);}
							}
						}
						
						
						
						String keyUsed = findKey(listSubPayload[j]);
						String operation = "";
						actorNoDecode=false;
						if (keyUsed != null) {				
							operation = findOperation(keyUsed, message.getActorfrom(), message.getActorTo());
							if (KeyActorFrom.searchEle(keyUsed) ==null && !(KeyActorTo.searchEle(keyUsed).contains("Public")) ) {
								actorNoDecode=true;
								msgFieldTot = FindField(messages.getMessage(i).getPayload().replace(listSubPayload[j], ""));
								delJ++;
								if (debug) {System.out.println(KeyActorTo.searchEle(keyUsed)+ " non prendo i campi " + keyUsed + " Actor FRom " + message.getActorfrom());}

							}						}
						if (!actorNoDecode) {
							for (int k = 0; k < 15; k++) {
								if (msgFieldDet[k] != null) {
									b.write("			                      messageField(self,$e," + k + ","
											+ changNumMSG[i] + "):="
											+ changValueEve(msgFieldDet[k], message.getActorfrom(), true) + "\n");
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
						}
						if (operation != null && !operation.isEmpty() && !actorNoDecode) {
							if (reversOperation(operation).equals("symEnc")) {
								b.write(" 			                      " + reversOperation(operation) + "("
										+ changNumMSG[i] + "," + levelEncField1EncField2 + "):="
										+ findKeyEle(keyUsed, message.getActorfrom(), message.getActorTo(), true)
												.replace("$b", "$e")
										+ "\n");
							} else {
								b.write("  			                      " + reversOperation(operation) + "("
										+ changNumMSG[i] + "," + levelEncField1EncField2 + "):="
										+ findKeyEle(keyUsed, message.getActorfrom(), message.getActorTo(), false)
												.replace("$b", "$e")
										+ "\n");
							}
						}

					}
					if (debug) {System.out.println(" 8 END listSubPayload ");}
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
					debug = false;
				} else {
					b.write("			     if(receiver=AG_"+message.getActorTo().substring(0, 1)+")then\n");
					Message messagePrev = messages.getMessage(i-1);
					String[] listSubPayloadPrev = findMsg(messagePrev);
					String[] msgFieldTotPrev = FindField(messages.getMessage(i-1).getPayload());

				//	debug = true;
					if (debug) {
						System.out
								.println("2 payload prev i-1" + (i - 1) + " " + messages.getMessage(i - 1).getPayload());
					}
					//Si verifica se la parte del messaggio è decodificabile altrimenti si leva dall'elenco 
					// del messaggio precedente
					findActorFromTo(messagePrev.getActorfrom(), messagePrev.getActorTo());
					String[] NewListSubPayloadPrev = new String[15];
					String NewPayloadPrev = new String();
					int indList = 0;
					for (int k = 0 ; k<15 ; k++) {
						if (listSubPayloadPrev[k] != null) {
							if (debug) {System.out.println("2 parte del messaggio " + listSubPayloadPrev[k]);}
							String keyUsedPrev = findKey(listSubPayloadPrev[k]);
							if (keyUsedPrev == null || KeyActorTo.searchEle(keyUsedPrev) !=null) {
								if (debug) {System.out.println("2 Verifico se posso aggiungere conoscenza");}
								if (indList==0) {
									NewListSubPayloadPrev[indList]=listSubPayloadPrev[k];
									NewPayloadPrev = listSubPayloadPrev[k];
									indList++;
								} else {
									NewListSubPayloadPrev[indList]=listSubPayloadPrev[k];
									NewPayloadPrev = NewPayloadPrev + ","+listSubPayloadPrev[k];
									indList++;									
								}
								String[] msgFieldPrev = new String[15];
								String[] msgEncField1EncField2Prev = new String[15];
								levelEncField1EncField2Prev = calcLevelEncField1EncField2(listSubPayloadPrev[k],
										msgEncField1EncField2Prev, msgFieldPrev,msgFieldTotPrev);
								addKnowActorTo(msgFieldPrev);
							} else {
								if (debug) {System.out.println("2 cancello pezzo di messaggio " + listSubPayloadPrev[k]);}
								listSubPayloadPrev[k]=null;
							}

						}
					}
				//	debug = true;
					if (debug) {System.out.println("2 NewPayloadPrev " + NewPayloadPrev);}
					msgFieldTotPrev = FindField(NewPayloadPrev);
					listSubPayloadPrev = NewListSubPayloadPrev;
					if (debug) { 
						System.out.println("2 ------> NewListSubPayloadPrev <----------");
						for (String e: listSubPayloadPrev) {
							System.out.println("2 ------> " +e+ " <-------------");
						}
					}
	
					// debug = false;
					
					boolean fistOperation = true;
					String[] msgFieldPrev = new String[15];
					boolean actorNoDecode=false;
					 
					for (int f = 0; f < 15; f++) {
						if (listSubPayloadPrev[f] == null || listSubPayloadPrev[f].isEmpty()) {
							break;
						}
						if (debug) {System.out.println("2 analizzo ora listSubPayloadPrev " + listSubPayloadPrev[f]);}
						String[] msgEncField1EncField2Prev = new String[15];
						levelEncField1EncField2Prev = calcLevelEncField1EncField2(listSubPayloadPrev[f],
								msgEncField1EncField2Prev, msgFieldPrev,msgFieldTotPrev);
						String[] msgFieldDetPrev = detField(msgFieldPrev,msgFieldTotPrev);
						String keyUsedPrev = findKey(listSubPayloadPrev[f]);
						findActorFromTo(messagePrev.getActorfrom(), messagePrev.getActorTo());
//						if (keyUsedPrev == null || KeyActorTo.searchEle(keyUsedPrev) !=null) {
//							if (debug) {System.out.println("z messagePrev.getActorfrom() " + messagePrev.getActorfrom() + " messagePrev.getActorTo() " + messagePrev.getActorTo());}
//							addKnowActorTo(msgFieldPrev);
//						}
						operationPrev = "";
						if (debug) {System.out.println("z2 keyUsedPrev " + keyUsedPrev);}

						if (keyUsedPrev != null) {
							operationPrev = findOperation(keyUsedPrev, message.getActorfrom(), message.getActorTo());
//							if (KeyActorTo.searchEle(keyUsedPrev) ==null) {actorNoDecode=true;}
						}
						if (debug) {System.out.println("z3 operationPrev " + operationPrev);}
						if (operationPrev != null && !operationPrev.isEmpty()) {
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
					if (debug) {System.out.println("z4 fistOperation " + fistOperation);}

					if (!fistOperation) {
						b.write(") then\n");
					}
					b.write("			                par\n");
					if (debug) {System.out.println("z5 detField ");}
					String[] msgFieldDetPrev = detField(msgFieldPrev,msgFieldTotPrev);
					if (debug) {System.out.println("z5 writeKnowledge ");}
					
					if (debug) { 
						System.out.println("z5 ------> msgFieldTotPrev <----------");
						for (String e: msgFieldTotPrev) {
							System.out.println("z5 ------> " +e+ " <-------------");
						}
					}
					String[] linesKnowledgePrev = writeKnowledge(messagePrev,(i-1),msgFieldTotPrev,"$e",false);
					if (debug) { 
						System.out.println("z5 ------> linesKnowledgePrev <----------");
						for (String e: linesKnowledgePrev) {
							System.out.println("z5 ------> " +e+ " <-------------");
						}
					}
					
					//debug = false;
					String spaces="                            	        ";
					if (debug) {System.out.println("z5 printKnowledge ");}
					printKnowledge(b,"Kno3",linesKnowledgePrev,spaces);
					b.write("			                      protocolMessage(self,$e):="+ changNumMSG[i] +"\n");
					if (debug) {System.out.println("z6 findMsg ");}
					listSubPayload = findMsg(message);
					numOperationMessage=0;
					// pulisce la tabella delle operazioni.
					for (String eleOperationMessage : operationMessage) {
						eleOperationMessage="";
					}
					int delJ=0;
					for (int j = 0; j < 15; j++) {
						if (listSubPayload[j] == null || listSubPayload[j].isEmpty()) {
							break;
						}
						String[] msgEncField1EncField2 = new String[15];
						String[] msgField = new String[15];
						String levelEncField1EncField2 = calcLevelEncField1EncField2(listSubPayload[j],
								msgEncField1EncField2, msgField,msgFieldTot);
						String[] msgFieldDet = detField(msgField,msgFieldTot); 
						String keyUsed = findKey(listSubPayload[j]);
						String operation = "";
						actorNoDecode=false;
						if (keyUsed != null) {
							operation = findOperation(keyUsed, message.getActorfrom(), message.getActorTo());
							if (KeyActorFrom.searchEle(keyUsed) ==null && !(KeyActorTo.searchEle(keyUsed).contains("Public"))) {
								actorNoDecode=true;
								msgFieldTot = FindField(messages.getMessage(i).getPayload().replace(listSubPayload[j], ""));
								delJ++;
							}
						}
						if (!actorNoDecode) {
							for (int k = 0; k < 15; k++) {
								if (msgFieldDet[k] != null) {
									b.write("			                      messageField(self,$e," + k + ","
											+ changNumMSG[i] + "):="
											+ findValueHonest(msgFieldDet[k].toUpperCase(), message.getActorfrom())
											+ "\n");
									honestElement.put(
											message.getActorTo().substring(0, 1) + " " + msgFieldDet[k].toUpperCase(),
											"messageField($e,self," + k + "," + changNumMSG[i] + ")");
								}
							}
							determinesOperation (b,i, j-delJ, message, listSubPayload[j], message.getActorfrom(), "",true);
						}
					}
					if (messages.getMessage(i+1).getActorfrom()!=null && !messages.getMessage(i+1).getActorfrom().isEmpty()) {
					      b.write("			                      internalState"+messages.getMessage(i+1).getActorTo().substring(0, 1)+"(agent" +messages.getMessage(i+1).getActorTo().substring(0, 1) +"):=WAITING_"+changNumMSG[i+1]+"\n");					
					} else {
					      b.write("			                      internalState"+message.getActorfrom().substring(0, 1)+"(agent"+message.getActorfrom().substring(0, 1) + "):=END_"+message.getActorfrom().substring(0, 1)+"\n");								
					}
					b.write("			                endpar\n");
					// se l'attore non ha la chiave per decifrare la parte del payload allora
					// si scrivono le istruzioni che non comprendono la memorizzazione della conoscenza di quella parte del messaggio
					if (!fistOperation) {
						b.write("			        endif\n");
					}

					b.write("			else\n");
					messagePrev = messages.getMessage(i-1);
					listSubPayloadPrev = findMsg(messagePrev);
					msgFieldTotPrev = FindField(messages.getMessage(i-1).getPayload());

					// debug = true;
					if (debug) {
						System.out
								.println("3 payload prev i-1" + (i - 1) + " " + messages.getMessage(i - 1).getPayload());
					}
					//Si verifica se la parte del messaggio è decodificabile altrimenti si leva dall'elenco 
					// del messaggio precedente
					findActorFromTo(messagePrev.getActorfrom(), messagePrev.getActorTo());
					NewListSubPayloadPrev = new String[15];
					NewPayloadPrev = new String();
					indList = 0;
					for (int k = 0 ; k<15 ; k++) {
						if (listSubPayloadPrev[k] != null) {
							if (debug) {System.out.println("3 parte del messaggio " + listSubPayloadPrev[k]);}
							String keyUsedPrev = findKey(listSubPayloadPrev[k]);
							if (keyUsedPrev == null || KeyActorTo.searchEle(keyUsedPrev) !=null) {
								if (debug) {System.out.println("3 Verifico se posso aggiungere conoscenza");}
								if (indList==0) {
									NewListSubPayloadPrev[indList]=listSubPayloadPrev[k];
									NewPayloadPrev = listSubPayloadPrev[k];
									indList++;
								} else {
									NewListSubPayloadPrev[indList]=listSubPayloadPrev[k];
									NewPayloadPrev = NewPayloadPrev + ","+listSubPayloadPrev[k];
									indList++;									
								}
								msgFieldPrev = new String[15];
								String[] msgEncField1EncField2Prev = new String[15];
								levelEncField1EncField2Prev = calcLevelEncField1EncField2(listSubPayloadPrev[k],
										msgEncField1EncField2Prev, msgFieldPrev,msgFieldTotPrev);
								addKnowActorTo(msgFieldPrev);
							} else {
								if (debug) {System.out.println("3 cancello pezzo di messaggio " + listSubPayloadPrev[k]);}
								listSubPayloadPrev[k]=null;
							}

						}
					}
					
					if (debug) {System.out.println("2 NewPayloadPrev " + NewPayloadPrev);}
					msgFieldTotPrev = FindField(NewPayloadPrev);
					listSubPayloadPrev = NewListSubPayloadPrev;
					if (debug) { 
						System.out.println("3 ------> NewListSubPayloadPrev <----------");
						for (String e: listSubPayloadPrev) {
							System.out.println("3 ------> " +e+ " <-------------");
						}
					}
					
					
					fistOperation = true;
					msgFieldPrev = new String[15];
					actorNoDecode=false;
					for (int f = 0; f < 15; f++) {
						if (listSubPayloadPrev[f] == null || listSubPayloadPrev[f].isEmpty()) {
							break;
						}
						String[] msgEncField1EncField2Prev = new String[15];
						levelEncField1EncField2Prev = calcLevelEncField1EncField2(listSubPayloadPrev[f],
								msgEncField1EncField2Prev, msgFieldPrev,msgFieldTotPrev);
						msgFieldDetPrev = detField(msgFieldPrev,msgFieldTotPrev);
						String keyUsedPrev = findKey(listSubPayloadPrev[f]);
						operationPrev = "";
						if (keyUsedPrev != null) {
							operationPrev = findOperation(keyUsedPrev, message.getActorfrom(), message.getActorTo());
						}
						if (operationPrev != null && !operationPrev.isEmpty()) {
							if (fistOperation) {
								b.write(" 			        if(" + operationPrev + "(" + changNumMSG[i-1] + ","
									+ levelEncField1EncField2Prev + ",self)=true");
								fistOperation = false;
							} else {
								b.write(" and " + operationPrev + "(" + changNumMSG[i-1] + ","
									+ levelEncField1EncField2Prev + ",self)=true ");
							}
						}
					}
					if (!fistOperation) {
						b.write(" and receiver=AG_E) then\n");
					}
					b.write("			                par\n");
					linesKnowledgePrev = writeKnowledge(messagePrev,(i-1),msgFieldTotPrev,"$e",false);
					spaces="                            	        ";
					printKnowledge(b,"Kno3",linesKnowledgePrev,spaces);
					b.write("			                      protocolMessage(self,$e):="+ changNumMSG[i] +"\n");
					numOperationMessage=0;
					// pulisce la tabella delle operazioni.
					for (String eleOperationMessage : operationMessage) {
						eleOperationMessage="";
					}

					listSubPayload = findMsg(message);
					delJ=0;
					for (int j = 0; j < 15; j++) {
						if (listSubPayload[j] == null || listSubPayload[j].isEmpty()) {
							break;
						}
						String[] msgEncField1EncField2 = new String[15];
						String[] msgField = new String[15];
						String levelEncField1EncField2 = calcLevelEncField1EncField2(listSubPayload[j],
								msgEncField1EncField2, msgField,msgFieldTot);
						String[] msgFieldDet = detField(msgField,msgFieldTot);
						String keyUsed = findKey(listSubPayload[j]);
						String operation = "";
						actorNoDecode=false;
						if (keyUsed != null) {
							operation = findOperation(keyUsed, message.getActorfrom(), message.getActorTo());
							if (KeyActorFrom.searchEle(keyUsed) ==null && !(KeyActorTo.searchEle(keyUsed).contains("Public"))) {
								actorNoDecode=true;
								msgFieldTot = FindField(messages.getMessage(i).getPayload().replace(listSubPayload[j], ""));
								delJ++;
							}

						}
						if (!actorNoDecode) {
							for (int k = 0; k < 15; k++) {
								if (msgFieldDet[k] != null) {
									b.write("			                      messageField(self,$e,"+k+","+changNumMSG[i]+"):="+changValueEve(msgFieldDet[k], message.getActorfrom(),true)+"\n");						
									honestElement.put("E"+ " "+ changValueEve(msgFieldDet[k], message.getActorfrom(),false).toUpperCase(),"messageField($e,self,"+k+","+changNumMSG[i]+")");
								}
							}
							determinesOperation (b, i, j-delJ, message, listSubPayload[j], message.getActorfrom(), "",false);
						}
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
					if (endMessage) {
						b.write("	rule r_check_" + changNumMSG[i] + " =\n");
						ruleR_Agent[indRuleR_Agent] = message.getActorTo().toUpperCase().substring(0, 1) + " r_check_"
								+ changNumMSG[i]+"[]";
						indRuleR_Agent++;
						b.write("		let ($e=agentE) in\n");
						b.write("			if(internalState" + message.getActorTo().substring(0, 1)
								+ "(self)=WAITING_" + changNumMSG[i] + " and protocolMessage($e,self)=" + changNumMSG[i] + ")then\n");
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
		for (Map.Entry<String, String> entry : honestElement.entrySet()) {
			if (entry.getKey().equals(actorFrom.toUpperCase().substring(0, 1) + " " + value.toUpperCase())) {
				return entry.getValue();
			}
		}
		return value;
	}

	// quando ad operare è l'EVE si deve effettuare il reverse delle chiavi e dei
	// field
	private String changValueEve(String value, String actorFrom, boolean verifyElement) {

		String valueOutput = value;
		String typeFieldActorFrom = KeyActorFrom.searchEle(value);

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
		if (verifyElement) {
			for (Map.Entry<String, String> entry : honestElement.entrySet()) {
				if (entry.getKey().equals("E " + valueOutput.toUpperCase())) {
					return entry.getValue();
				}
			}
		}
		return valueOutput.toUpperCase();
	}
	
	// Aggiunge le conoscenze ricevute all'interno dei payload
	private void addKnowActorTo(String[] msgField) {
		if (debug) System.out.println("*------- devo verificare se ci sono conoscenze da aggiungere -----*");
		String typeFieldActorFrom;
		for (int i=0; i<15; i++) {
			if (msgField[i] !=null && !msgField[i].isEmpty()) {
				if (debug) System.out.println("Analizzo conoscenza " + msgField[i]);
				if (KeyActorTo.searchEle(msgField[i]) ==null) {
					typeFieldActorFrom = KeyActorFrom.searchEle(msgField[i]);
					if (debug) System.out.println("la conoscenza per l'actor from è " + typeFieldActorFrom);
					if (typeFieldActorFrom != null) {
						switch (typeFieldActorFrom) {
						case "Asymmetric Public Key":
							KeyActorTo.addAsymmetricPublicKey(msgField[i]);
							break;
						case "Asymmetric Private Key":
							KeyActorTo.addAsymmetricPrivateKey(msgField[i]);
							break;
						case "Symmetric Key":
							KeyActorTo.addSymmetricKey(msgField[i]);
							break;
						case "Signature Pub Key":
							KeyActorTo.addSignaturePubKey(msgField[i]);
							break;
						case "Signature Priv Key":
							KeyActorTo.addSignaturePrivKey(msgField[i]);
							break;
						case "Hash":
							KeyActorTo.addHashKey(msgField[i]);
							break;
						case "Nonce":
							KeyActorTo.addNonce(msgField[i]);
							break;
						case "Identity Certificate":
							KeyActorTo.addIdCertificate(msgField[i]);
							break;
						case "Bitstring":
							KeyActorTo.addBitstring(msgField[i]);
						case "Tag":
							KeyActorTo.addTag(msgField[i]);
							break;
						case "Timestamp":
							KeyActorTo.addTimestamp(msgField[i]);
							break;
						case "Digest":
							KeyActorTo.addDigest(msgField[i]);
							break;
						}
					}
						
						
				}
			}
		}
		if (debug) System.out.println("*------- Esco -----*");

	}
	
	// dalla tabella si estraggono i messaggi divisi per i vari agenti e si scrivono le rispettive rule
	// per distinguere tra i messaggi a quale agent vanno agganciati si vede il primo carattere della stringa.
	private void writeRuleR_Agent(BufferedWriter b) throws IOException {
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
		found = writeDefaultInitS0Nonce(b, aliceStart, "Alice", found);

		found = writeDefaultInitS0Nonce(b, bobStart, "Bob", found);

		found = writeDefaultInitS0Nonce(b, eveStart, "Eve", found);

		if (actorServer) {

			found = writeDefaultInitS0Nonce(b, serverStart, "Server", found);
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
		found = writeDefaultInitS0IDCer(b, aliceStart, "Alice", found);
		found = writeDefaultInitS0IDCer(b, bobStart, "Bob", found);
		found = writeDefaultInitS0IDCer(b, eveStart, "Eve", found);
		if (actorServer) {
			found = writeDefaultInitS0IDCer(b, serverStart, "Server", found);
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
		found = writeDefaultInitS0BitSt(b, aliceStart, "Alice", found);
		found = writeDefaultInitS0BitSt(b, bobStart, "Bob", found);
		found = writeDefaultInitS0BitSt(b, eveStart, "Eve", found);
		if (actorServer) {
			found = writeDefaultInitS0BitSt(b, serverStart, "Server", found);
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
		found = writeDefaultInitS0Tag(b, aliceStart, "Alice", found);
		found = writeDefaultInitS0Tag(b, bobStart, "Bob", found);
		found = writeDefaultInitS0Tag(b, eveStart, "Eve", found);
		if (actorServer) {
			found = writeDefaultInitS0Tag(b, serverStart, "Server", found);
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
		found = writeDefaultInitS0Dig(b, aliceStart, "Alice", found);
		found = writeDefaultInitS0Dig(b, bobStart, "Bob", found);
		found = writeDefaultInitS0Dig(b, eveStart, "Eve", found);
		if (actorServer) {
			found = writeDefaultInitS0Dig(b, serverStart, "Server", found);
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
		found = writeDefaultInitS0Hot(b, aliceStart, "Alice", found);

		found = writeDefaultInitS0Hot(b, bobStart, "Bob", found);

		found = writeDefaultInitS0Hot(b, eveStart, "Eve", found);

		if (actorServer) {

			found = writeDefaultInitS0Hot(b, serverStart, "Server", found);

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
		found = writeDefaultInitS0Tim(b, aliceStart, "Alice", found);
		found = writeDefaultInitS0Tim(b, bobStart, "Bob", found);
		found = writeDefaultInitS0Tim(b, eveStart, "Eve", found);
		if (actorServer) {
			found = writeDefaultInitS0Tim(b, serverStart, "Server", found);
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
		found = writeDefaultInitS0AsPr(b, aliceStart, "Alice", found);
		found = writeDefaultInitS0AsPr(b, bobStart, "Bob", found);
		found = writeDefaultInitS0AsPr(b, eveStart, "Eve", found);
		if (actorServer) {
			found = writeDefaultInitS0AsPr(b, serverStart, "Server", found);
		}

		if (countIf > 0) {
			b.write(") then true else false endif\n");
			b.write("	function knowsAsymPubKey($a in Agent ,$pk in KnowledgeAsymPubKey)=true\n");
		}

		// Scrittura dello stato S0 per la KnowledgeSymKey
		countIf = 0;
		found = false;
		found = writeDefaultInitS0SymK(b, aliceStart, "Alice", found);
		found = writeDefaultInitS0SymK(b, bobStart, "Bob", found);
		found = writeDefaultInitS0SymK(b, eveStart, "Eve", found);
		if (actorServer) {
			found = writeDefaultInitS0SymK(b, serverStart, "Server", found);
		}

		if (countIf > 0) {
			b.write(") then true else false endif\n");
			;
		}

		// Scrittura dello stato S0 per la knowsSignPubKey e knowsSignPrivKey
		countIf = 0;
		found = false;
		found = writeDefaultInitS0SiPu(b, aliceStart, "Alice", found);
		found = writeDefaultInitS0SiPu(b, bobStart, "Bob", found);
		found = writeDefaultInitS0SiPu(b, eveStart, "Eve", found);
		if (actorServer) {
			found = writeDefaultInitS0SiPu(b, serverStart, "Server", found);
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
