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
	private int levelTot;
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
	private String receiver;
	private String modality;
	private int numOperationMessage;
	private int lastMsgAlice, lastMsgBob, lastMsgEve,lastMsgServer;
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
	private String dollaroA, dollaroB, self, dollaroT,dollaroF,dollaroX,dollaroE;
	private String toolEve;
	private String nameFile;
	private String acronym;
	private String actorStartProtocol = "";
	private String actorReceiveProtocol = "";
	private String aliceStartState = "";
	private String bobStartState = "";
	private String eveStartState = "";
	private String serverStartState = "";
	private BufferedWriter bAsm, bNuSmv;
	String[] changNumMSG = new String[15];
	String[][] properties = new String[10][10];
	private boolean debug;

	private String operationPrev = "";
	private String levelEncField1EncField2Prev = "";
	private boolean endMessage = false;
	boolean fistOperation = true;
	boolean actorNoDecode = false;

	public WriteASM(Boolean actorServer, Messages messages, SecurityKey aliceStart, SecurityKey bobStart,
			SecurityKey eveStart, SecurityKey serverStart, String toolEve, int fieldPosition, int levelTot,
			int numEncField, int numSignField, int numSymField, int numHashField, String nameFile, String acronym
			,String receiver, String modality,String[][] properties)
			throws IOException {
		System.out.println("*--------------- WriteASM --------------*");
		//debug = true;
		this.properties = properties;
		this.modality = modality;
		this.receiver=receiver;
		this.actorServer = actorServer;
		this.messages = messages;
		this.aliceStart = aliceStart;
		this.bobStart = bobStart;
		this.eveStart = eveStart;
		this.serverStart = serverStart;
		this.toolEve = toolEve;
		this.fieldPosition = fieldPosition;
		this.levelTot = levelTot;
		this.numEncField = numEncField;
		this.numSignField = numSignField;
		this.numSymField = numSymField;
		this.numHashField = numHashField;
		this.nameFile = nameFile;
		this.acronym = acronym;
		dollaroA="";
	    dollaroB="";
	    self="";
	    dollaroE="";
	    dollaroT="";
	    dollaroF="";
	    dollaroX="";
		lastMsgAlice=99;
		lastMsgBob=99;
		lastMsgEve=99; 
		lastMsgServer=99;
		changNumMSG[0] = "MA";
		changNumMSG[1] = "MB";
		changNumMSG[2] = "MC";
		changNumMSG[3] = "MD";
		changNumMSG[4] = "ME";
		changNumMSG[5] = "MF";
		changNumMSG[6] = "MG";
		changNumMSG[7] = "MH";
		changNumMSG[8] = "MI";
		changNumMSG[9] = "ML";
		changNumMSG[10] = "MM";
		changNumMSG[11] = "MN";
		changNumMSG[12] = "MO";
		changNumMSG[13] = "MP";
		changNumMSG[14] = "MQ";
		int i = 0;
		for (Message e : messages.getListMessages()) {
			if (e.getNameMess() != null && !e.getNameMess().isEmpty() && !e.getNameMess().isBlank()
					&& !e.getNameMess().equals("")) {
				changNumMSG[i] = e.getNameMess();
			}
			i++;
		}
		 

		if (debug) {
			System.out.println("WriteASM ---> 000");
		}

		// Carico le conoscenze attuali
		loadKnowActual();

		if (debug) {
			System.out.println("WriteASM ---> 001");
		}

		indRuleR_Agent = 0;

		System.out.println("Creo file "+ nameFile);
		
		FileWriter w;
		w = new FileWriter("src/main/resources/AProVerTest/" + nameFile + ".asm");
		System.out.println("Ho Creato file "+ nameFile);
		bAsm = new BufferedWriter(w);
		System.out.println("Ho Creato buffer "+ bAsm);
		
		System.out.println("Creo file "+ nameFile + "Test.asm");
		
		FileWriter q;
		q = new FileWriter("src/main/resources/AProVerTest/" + nameFile + "Test.asm");

		bNuSmv = new BufferedWriter(q);
		
		System.out.println("*--------------- Fine WriteASM --------------*");
	}

	// Carico le conoscenze attuali che possono essere modificate durante
	// l'esecuzione del protocollo
	private void loadKnowActual() {
		// Carico le conoscenze attuali
		alice = new SecurityKey();
		if (aliceStart != null) {
			loadKnowActor(alice, aliceStart);
		} else {
			alice = null;
		}

		bob = new SecurityKey();
		if (bobStart != null) {
			loadKnowActor(bob, bobStart);
		} else {
			bob = null;
		}

		eve = new SecurityKey();
		if (eveStart != null) {
			loadKnowActor(eve, eveStart);
		} else {
			eve = null;
		}
		server = new SecurityKey();
		if (serverStart != null) {
			loadKnowActor(server, serverStart);
		} else {
			server = null;
		}
	}

	private void loadKnowActor(SecurityKey arrived, SecurityKey start) {
		if (debug) {
			System.out.println("WriteASM ---> 002");
		}
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
			arrived.addKnowAcq(e.substring(0, e.indexOf(" - ")), e.substring((e.indexOf(" - ") + 3),e.indexOf(" = ")),Integer.parseInt(e.substring(e.indexOf("=")+2,e.length())));
		}

		if (debug) {
			System.out.println("WriteASM ---> 003");
		}
	}

	// Scrittura prime info file asm
	public boolean writeFile() throws IOException {
		
		if (debug) {
			System.out.println("WriteASM ---> 004");
		}
		if (!initialControl()) {
			bAsm.write("errore dati incompleti");
			bAsm.flush();
			bAsm.close();
			return false;
		}
		if (debug) {
			System.out.println(" Apro il file in lettura " + "src/main/resources/AProVerTest/CryptoLibrary"+acronym+".asm");
		}
		// apertura del file contenente le informazioni della CriptoLibrary 
		// in file è utilizzato per scrivere la asm di test
	 	BufferedReader readCrypt = new BufferedReader(new FileReader("src/main/resources/AProVerTest/CryptoLibrary"+acronym+".asm"));
	 	if (debug) {
	 		System.out.println("inizio la scrittura dei files");
	 	}
		// scrittura info iniziali del file asm
		writeOpen(bAsm,bNuSmv, readCrypt);
		
		// scrittura delle Knowledge
		writeKnowledgeASM(bAsm,bNuSmv,readCrypt);
		bAsm.flush();
		bAsm.close();
		bNuSmv.flush();
		bNuSmv.close();
		if (debug) {
			System.out.println("WriteASM ---> 005");
		}
		return true;
	}

	private boolean initialControl() {
		if (debug) {
			System.out.println("WriteASM ---> 006");
		}
		if (alice == null)
			return false;
		if (bob == null)
			return false;
		if (eve == null)
			return false;
		if (messages == null)
			return false;
		if (debug) {
			System.out.println("WriteASM ---> primi controlli passati");
		}
		if (alice.getAsymmetricPrivateKey().size() > 0 && !(eve.getAsymmetricPrivateKey().size() > 0))
			return false;
		if (debug) {
			System.out.println("WriteASM ---> 2 controlli passati");
		}
		if (alice.getAsymmetricPublicKey().size() > 0 && !(eve.getAsymmetricPublicKey().size() > 0))
			return false;
		if (debug) {
			System.out.println("WriteASM ---> 3 controlli passati");
		}
		if (alice.getSignaturePrivKey().size() > 0 && !(eve.getSignaturePrivKey().size() > 0))
			return false;
		if (debug) {
			System.out.println("WriteASM ---> 4 controlli passati");
		}
		if (alice.getSignaturePubKey().size() > 0 && !(eve.getSignaturePubKey().size() > 0))
			return false;
		if (debug) {
			System.out.println("WriteASM ---> 5 controlli passati");
		}
		if (alice.getSymmetricKey().size() > 0 && !(eve.getSymmetricKey().size() > 0))
			return false;
		if (debug) {
			System.out.println("WriteASM ---> 6 controlli passati");
				}
		if (debug) {
			System.out.println("WriteASM ---> 007");
		}
		return true;
	}

	// Scrittura prime info file asm
	private void writeOpen(BufferedWriter bAsm,BufferedWriter bNuSmv, BufferedReader readCrypt) throws IOException {
		if (debug) {
			System.out.println("writeOpen entro");
		}
			if (debug) {
			System.out.println("WriteASM ---> 008");
		}
		bNuSmv.write("asm " + nameFile + "Test\n");
		bNuSmv.write("\n");
		bNuSmv.write("import StandardLibrary" + "\n");
		bNuSmv.write("import CTLlibrary" +  "\n");
		bNuSmv.write("\n");
		bNuSmv.write("\n");
		bNuSmv.write("signature:\n");
		bNuSmv.write("\n");
		
		writeSignatureNuSvm(bNuSmv,readCrypt);
		
		bAsm.write("asm " + nameFile + "\n");
		bAsm.write("\n");
		bAsm.write("import CryptoLibrary" + acronym + "\n");
		bAsm.write("\n");
		bAsm.write("\n");
		bAsm.write("signature:\n");
		bAsm.write("\n");
		bAsm.write("definitions:\n");
		bNuSmv.write("definitions:\n");
		if (levelTot > 0) {
			levelTot++;
			bAsm.write("	domain Level = {1:" + levelTot + "}\n");
			bNuSmv.write("	domain Level = {1:" + levelTot + "}\n");
		} else {
			bAsm.write("	domain Level = {1}\n");
			bNuSmv.write("	domain Level = {1}\n");
		}
		if (fieldPosition > 1) {
			bAsm.write("	domain FieldPosition = {1:" + fieldPosition + "}\n");
			bNuSmv.write("	domain FieldPosition = {1:" + fieldPosition + "}\n");
		} else {
			bAsm.write("	domain FieldPosition = {1}\n");
			bNuSmv.write("	domain FieldPosition = {1}\n");
		}
		int numEncSymField = numSymField;
		if (numEncField > numSymField) {
			numEncSymField = numEncField;
		}
		if (numEncSymField > 0) {
			if (numEncSymField < 3) {
				bAsm.write("	domain EncField1={1:2}\n");
				bAsm.write("	domain EncField2={1:2}\n");
				bNuSmv.write("	domain EncField1={1:2}\n");
				bNuSmv.write("	domain EncField2={1:2}\n");
			} else {
				// bAsm.write(" domain EncField1={1:"+ numEncSymField +"}\n");
				// bAsm.write(" domain EncField2={2:"+ numEncSymField +"}\n");
				bAsm.write("	domain EncField1={1:" + fieldPosition + "}\n");
				bAsm.write("	domain EncField2={1:" + fieldPosition + "}\n");
				bNuSmv.write("	domain EncField1={1:" + fieldPosition + "}\n");
				bNuSmv.write("	domain EncField2={1:" + fieldPosition + "}\n");

			} 
		} else {
				bNuSmv.write("	domain EncField1={1:2}\n");
				bNuSmv.write("	domain EncField2={1:2}\n");
			}
		bAsm.write("	domain NumMsg={0:15}\n");
		bNuSmv.write("	domain NumMsg={0:15}\n");
		
		if (numSignField > 0) {
			if (numSignField == 1) {
				bAsm.write("	domain SignField1={1:2}\n");
				bAsm.write("	domain SignField2={1:2}\n");
				bNuSmv.write("	domain SignField1={1:2}\n");
				bNuSmv.write("	domain SignField2={1:2}\n");
			} else {
				bAsm.write("	domain SignField1={1:" + numSignField + "}\n");
				bAsm.write("	domain SignField2={1:" + numSignField + "}\n");
				bNuSmv.write("	domain SignField1={1:" + numSignField + "}\n");
				bNuSmv.write("	domain SignField2={1:" + numSignField + "}\n");
			}
		} else {
			bNuSmv.write("	domain SignField1={1}\n");
			bNuSmv.write("	domain SignField2={1}\n");			
		}
		bNuSmv.write("	domain HashField1={1}\n");
		bNuSmv.write("	domain HashField2={1}\n");
		if (numHashField > 0) {
			if (numHashField == 1) {
				bAsm.write("	domain HashField1={1:2}\n");
				bAsm.write("	domain HashField2={1:2}\n");
			} else {
				bAsm.write("	domain HashField1={1:" + numHashField + "}\n");
				bAsm.write("	domain HashField2={1:" + numHashField + "}\n");
			}
		}
		if (debug) {
			System.out.println("WriteASM ---> 009");
		}
		if (debug) {
			System.out.println("writeOpen esco");
		}
		bNuSmv.write("\n");
	}
	// Scrittura del File di Test NuSVM leggendo le informazioni precedentemente scritte su CryptoLibrary
	
	private void writeSignatureNuSvm(BufferedWriter bNuSmv,BufferedReader readCrypt) throws IOException {
		if (actorServer) {
			bNuSmv.write("	enum domain Agenti = {ALICE|BOB|EVE|SERVER}");
		} else {
			bNuSmv.write("	enum domain Agenti = {ALICE|BOB|EVE}");
		}
		bNuSmv.write("\n");
				
		String line = readCrypt.readLine();
		boolean startWrite=false;
		while (line != null && !line.contains("definitions:")) {
			if (startWrite) {
				if (line.contains("subsetof Agent") || line.contains("subsetof Any") || line.contains("static agent")) {
					bNuSmv.write("// " + line);
					bNuSmv.write("\n");
				} else {
					if (line.contains("controlled internalState")) {
						bNuSmv.write("// " + line);
						bNuSmv.write("\n");
						bNuSmv.write(line.replace("Alice -> ", "").replace("Bob -> ", "").replace("Eve -> ", "")
								.replace("Server -> ", ""));
						bNuSmv.write("\n");
					} else {
						if (line.contains("enum domain Knowledge ={")) {
							bNuSmv.write("// " + line);
							bNuSmv.write("\n");
							bNuSmv.write(line.replace("}", "|NULL}"));
							bNuSmv.write("\n");
						} else {
							bNuSmv.write("\n");
							String LineChange = line.replace("Agent", "Agenti");
							LineChange = LineChange.replace("KnowledgeIdentityCertificate", "Knowledge");
							LineChange = LineChange.replace("KnowledgeBitString", "Knowledge");
							LineChange = LineChange.replace("KnowledgeSymKey", "Knowledge");
							LineChange = LineChange.replace("KnowledgeAsymPubKey", "Knowledge");
							LineChange = LineChange.replace("KnowledgeAsymPrivKey", "Knowledge");
							LineChange = LineChange.replace("KnowledgeSignPubKey", "Knowledge");
							LineChange = LineChange.replace("KnowledgeSignPrivKey", "Knowledge");
							LineChange = LineChange.replace("KnowledgeTag", "Knowledge");
							LineChange = LineChange.replace("KnowledgeDigest", "Knowledge");
							LineChange = LineChange.replace("KnowledgeHash", "Knowledge");
							LineChange = LineChange.replace("KnowledgeTimestamp", "Knowledge");
							LineChange = LineChange.replace("KnowledgeNonce", "Knowledge");
							LineChange = LineChange.replace("KnowledgeOther", "Knowledge");
							LineChange = LineChange.replace("monitored chosenReceiver:Receiver", "controlled chosenReceiver:Receiver");
							LineChange = LineChange.replace("monitored chosenMode: Modality", "controlled chosenMode: Modality");
							bNuSmv.write(LineChange);
						}
					}

				}
			}
			if (line.contains("signature:")) {startWrite=true;}
			line = readCrypt.readLine();
		}
		bNuSmv.write("\n");
		bNuSmv.write("	controlled agentA: Agenti \n");
		bNuSmv.write("	controlled agentB: Agenti \n");
		bNuSmv.write("	controlled agentE: Agenti \n");
		bNuSmv.write("\n");
		if (actorServer) {
			bNuSmv.write("	controlled agentS: Agenti \n");
		} 
		
	}

		

	// Scrittura prime info file asm
	private void writeKnowledgeASM(BufferedWriter bAsm, BufferedWriter bNuSmv, BufferedReader readCrypt) throws IOException {
		System.out.println("writeKnowledgeASM entro");
		if (debug) {
			System.out.println("WriteASM ---> 010");
		}
		String[] elencoAsymPrivPub = new String[60];
		String[] elencoSignPrivPub = new String[60];
		bAsm.write("\n");
		writeKnowledgeNonce(bAsm);
		if (debug) {
			System.out.println("WriteASM ---> writeKnowledgeNonce ");
		}
		writeKnowledgeIdentityCertificate(bAsm);
		if (debug) {
			System.out.println("WriteASM ---> writeKnowledgeIdentityCertificate ");
		}
		writeKnowledgeBitString(bAsm);
		if (debug) {
			System.out.println("WriteASM ---> writeKnowledgeBitString ");
		}
		writeKnowledgeSymKey(bAsm);
		if (debug) {
			System.out.println("WriteASM ---> writeKnowledgeSymKey ");
		}
		elencoAsymPrivPub = writeKnowledgeAsymPrivEPubKey(bAsm);
		if (debug) {
			System.out.println("WriteASM ---> writeKnowledgeAsymPrivEPubKey ");
		}
		elencoSignPrivPub = writeKnowledgeSignPrivePubKey(bAsm);
		writeKnowledgeTag(bAsm);
		if (debug) {
			System.out.println("WriteASM ---> writeKnowledgeSignPrivePubKey ");
		}
		writeKnowledgeDigest(bAsm);
		if (debug) {
			System.out.println("WriteASM ---> writeKnowledgeDigest ");
		}
		writeKnowledgeHash(bAsm);
		if (debug) {
			System.out.println("WriteASM ---> writeKnowledgeHash ");
		}
		writeKnowledgeTimestamp(bAsm);
		if (debug) {
			System.out.println("WriteASM ---> writeKnowledgeTimestamp ");
		}
		bAsm.write("\n");
		if (!elencoAsymPrivPub[0].isEmpty()) {
			bAsm.write("	function asim_keyAssociation($a in KnowledgeAsymPubKey)=\n");
			bAsm.write("	       switch( $a )\n");
			bNuSmv.write("	function asim_keyAssociation($a in Knowledge)=\n");
			bNuSmv.write("	       switch( $a )\n");
			for (String s : elencoAsymPrivPub) {
				if (s.isEmpty())
					break;
				bAsm.write("	              case " + s + "\n");
				bNuSmv.write("	              case " + s + "\n");
			}
			bNuSmv.write("	              otherwise NULL \n");
			bAsm.write("	       endswitch\n");
			bNuSmv.write("	       endswitch\n");
		} else {
			bNuSmv.write("	function asim_keyAssociation($a in Knowledge)=\n");
			bNuSmv.write("	       switch( $a )\n");
			bNuSmv.write("	              case NULL: NULL\n");
			bNuSmv.write("	              otherwise NULL \n");
			bNuSmv.write("	       endswitch\n");
		}

		if (!elencoSignPrivPub[0].isEmpty()) {
			bAsm.write("	function sign_keyAssociation($b in KnowledgeSignPrivKey)=\n");
			bAsm.write("	       switch( $b )\n");
			bNuSmv.write("	function sign_keyAssociation($b in Knowledge)=\n");
			bNuSmv.write("	       switch( $b )\n");
			for (String s : elencoSignPrivPub) {
				if (s.isEmpty())
					break;
				bAsm.write("	              case " + s + "\n");
				bNuSmv.write("	              case " + s + "\n");
			}
			bNuSmv.write("	              otherwise NULL \n");
			bAsm.write("	       endswitch\n");
			bNuSmv.write("	       endswitch\n");
		} else {
			bNuSmv.write("	function sign_keyAssociation($b in Knowledge)=\n");
			bNuSmv.write("	       switch( $b )\n");
			bNuSmv.write("	              case NULL: NULL\n");
			bNuSmv.write("	              otherwise NULL \n");
			bNuSmv.write("	       endswitch\n");
		}
		
		writeDefinitionNuSvm(bNuSmv,readCrypt);
		writeMessageAttacker(bAsm,bNuSmv);
		writeMessageHonest(bAsm,bNuSmv);

		writeRuleR_Agent(bAsm,bNuSmv);
		writeDefaultInitS0(bAsm,bNuSmv);
		System.out.println("writeKnowledgeASM esco");
	}

	// Scrittura delle informazioni legate alla Knowledge Nonce
	private void writeKnowledgeNonce(BufferedWriter bAsm) throws IOException {

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

		for (String s : map.keySet()) {
			if (numeMap == 0) {
				bAsm.write("	domain KnowledgeNonce = {" + s);
				numeMap++;
			} else {
				bAsm.write("," + s);
				numeMap++;
			}
			// map.remove(s);
		}
		if (numeMap != 0) {
			bAsm.write("}\n");
		}
		Iterator<Map.Entry<String, String>> it = map.entrySet().iterator();
		while (it.hasNext()) {
			if (it.next().getKey().startsWith("")) {
				it.remove();
			}
		}
		if (debug) {
			System.out.println("WriteASM ---> 011");
		}
	}

	// Scrittura delle informazioni legate alla Knowledge Certificato ID
	private void writeKnowledgeIdentityCertificate(BufferedWriter bAsm) throws IOException {
		if (debug) {
			System.out.println("WriteASM ---> 012");
		}
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

		for (String s : map.keySet()) {
			if (numeMap == 0) {
				bAsm.write("	domain KnowledgeIdentityCertificate = {" + s);
				numeMap++;
			} else {
				bAsm.write("," + s);
				numeMap++;
			}
		}
		if (numeMap != 0) {
			bAsm.write("}\n");
		}
		Iterator<Map.Entry<String, String>> it = map.entrySet().iterator();
		while (it.hasNext()) {
			if (it.next().getKey().startsWith("")) {
				it.remove();
			}
		}
		if (debug) {
			System.out.println("WriteASM ---> 013");
		}
	}

	// Scrittura delle informazioni legate alla Knowledge Bit String
	private void writeKnowledgeBitString(BufferedWriter bAsm) throws IOException {
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

		for (String s : map.keySet()) {
			if (numeMap == 0) {
				bAsm.write("	domain KnowledgeBitString = {" + s);
				numeMap++;
			} else {
				bAsm.write("," + s);
				numeMap++;
			}
		}
		if (numeMap != 0) {
			bAsm.write("}\n");
		}
		Iterator<Map.Entry<String, String>> it = map.entrySet().iterator();
		while (it.hasNext()) {
			if (it.next().getKey().startsWith("")) {
				it.remove();
			}
		}
	}

	// Scrittura delle informazioni legate alla Knowledge chiave simmetrica
	private void writeKnowledgeSymKey(BufferedWriter bAsm) throws IOException {
		if (debug) {
			System.out.println("WriteASM ---> 017");
		}
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

		for (String s : map.keySet()) {
			if (numeMap == 0) {
				bAsm.write("	domain KnowledgeSymKey = {" + s);
				numeMap++;
			} else {
				bAsm.write("," + s);
				numeMap++;
			}
		}
		if (numeMap != 0) {
			bAsm.write("}\n");
		}
		Iterator<Map.Entry<String, String>> it = map.entrySet().iterator();
		while (it.hasNext()) {
			if (it.next().getKey().startsWith("")) {
				it.remove();
			}
		}
		if (debug) {
			System.out.println("WriteASM ---> 018");
		}
	}

	// Scrittura delle info sulle chiavi asimmetriche
	private String[] writeKnowledgeAsymPrivEPubKey(BufferedWriter bAsm) throws IOException {
		String[] elencoPrivPub = new String[60];
		for (int i = 0; i < 60; i++) {
			elencoPrivPub[i] = "";
		}
		if (debug) {
			System.out.println("WriteASM ---> 019 Alice");
		}
		if (alice != null) {
			for (int i = 0; i < alice.getAsymmetricPrivateKey().size(); i++) {
				map.put(alice.getAsymmetricPublicKey().get(i).toUpperCase() + " -> "
						+ alice.getAsymmetricPrivateKey().get(i).toUpperCase(), alice.getAsymmetricPublicKey().get(i));
			}
		}
		if (debug) {
			System.out.println("WriteASM ---> 019 Bob");
		}
		if (bob != null) {
			for (int i = 0; i < bob.getAsymmetricPrivateKey().size(); i++) {
				map.put(bob.getAsymmetricPublicKey().get(i).toUpperCase() + " -> "
						+ bob.getAsymmetricPrivateKey().get(i).toUpperCase(), bob.getAsymmetricPublicKey().get(i));
			}
		}
		if (debug) {
			System.out.println("WriteASM ---> 019 Eve");
		}
		if (eve != null) {
			if (debug) {
				System.out.println("WriteASM ---> 019 Eve size "+ eve.getAsymmetricPrivateKey().size());
			}
			for (int i = 0; i < eve.getAsymmetricPrivateKey().size(); i++) {
				if (debug) {
					System.out.println("WriteASM ---> 019 Eve eve.getAsymmetricPublicKey().get(i) "+ eve.getAsymmetricPublicKey().get(i));
					System.out.println("WriteASM ---> 019 Eve eve.getAsymmetricPrivateKey().get(i).toUpperCase() "+ eve.getAsymmetricPrivateKey().get(i).toUpperCase());
				}
				if (map.get(eve.getAsymmetricPublicKey().get(i).toUpperCase())== null)
					map.put(eve.getAsymmetricPublicKey().get(i).toUpperCase() + " -> "
						+ eve.getAsymmetricPrivateKey().get(i).toUpperCase(), eve.getAsymmetricPublicKey().get(i));
			}
		}
		if (debug) {
			System.out.println("WriteASM ---> 019 Server");
		}
		
		if (server != null) {
			for (int i = 0; i < server.getAsymmetricPrivateKey().size(); i++) {
				map.put(server.getAsymmetricPublicKey().get(i).toUpperCase() + " -> "
						+ server.getAsymmetricPrivateKey().get(i).toUpperCase(),
						server.getAsymmetricPublicKey().get(i));
			}
		}
		if (debug) {
			System.out.println("WriteASM ---> 019 out");
		}
		int numeMap = 0;

		for (String s : map.keySet()) {
			if (numeMap == 0) {
				bAsm.write("	domain KnowledgeAsymPubKey = {" + s.substring(0, s.lastIndexOf(" -> ")));
				elencoPrivPub[numeMap] = s.replace(" -> ", ": ");
				numeMap++;
			} else {
				bAsm.write("," + s.substring(0, s.lastIndexOf(" -> ")));
				elencoPrivPub[numeMap] = s.replace(" -> ", ": ");
				numeMap++;
			}
		}
		if (debug) {
			System.out.println("WriteASM ---> 019 out2");
		}
		if (numeMap != 0) {
			bAsm.write("}\n");
		}
		numeMap = 0;
		for (String s : map.keySet()) {
			if (numeMap == 0) {
				bAsm.write("	domain KnowledgeAsymPrivKey = {" + s.substring(s.lastIndexOf(" -> ") + 4, s.length()));
				numeMap++;
			} else {
				bAsm.write("," + s.substring(s.lastIndexOf(" -> ") + 4, s.length()));
				numeMap++;
			}
		}
		if (debug) {
			System.out.println("WriteASM ---> 019 out3");
		}
		if (numeMap != 0) {
			bAsm.write("}\n");
		}
		Iterator<Map.Entry<String, String>> it = map.entrySet().iterator();
		while (it.hasNext()) {
			if (it.next().getKey().startsWith("")) {
				it.remove();
			}
		}
		if (debug) {
			System.out.println("WriteASM ---> 019 out4 " + elencoPrivPub);
		}
		return elencoPrivPub;
	}

	// Scrittura delle info sulle chiavi per la firma
	private String[] writeKnowledgeSignPrivePubKey(BufferedWriter bAsm) throws IOException {
		String[] elencoPrivPub = new String[60];
		for (int i = 0; i < 60; i++) {
			elencoPrivPub[i] = "";
		}
		if (alice != null) {
			for (int i = 0; i < alice.getSignaturePrivKey().size(); i++) {
				map.put(alice.getSignaturePrivKey().get(i).toUpperCase() + " -> "
						+ alice.getSignaturePubKey().get(i).toUpperCase(), alice.getSignaturePrivKey().get(i));
			}
		}
		if (bob != null) {
			for (int i = 0; i < bob.getSignaturePrivKey().size(); i++) {
				map.put(bob.getSignaturePrivKey().get(i).toUpperCase() + " -> "
						+ bob.getSignaturePubKey().get(i).toUpperCase(), bob.getSignaturePrivKey().get(i));
			}
		}
		if (eve != null) {
			for (int i = 0; i < eve.getSignaturePrivKey().size(); i++) {
				map.put(eve.getSignaturePrivKey().get(i).toUpperCase() + " -> "
						+ eve.getSignaturePubKey().get(i).toUpperCase(), alice.getSignaturePrivKey().get(i));
			}
		}

		if (server != null) {
			for (int i = 0; i < server.getSignaturePrivKey().size(); i++) {
				map.put(server.getSignaturePrivKey().get(i).toUpperCase() + " -> "
						+ server.getSignaturePubKey().get(i).toUpperCase(), alice.getSignaturePrivKey().get(i));
			}
		}
		int numeMap = 0;

		for (String s : map.keySet()) {
			if (numeMap == 0) {
				bAsm.write("	domain KnowledgeSignPrivKey = {" + s.substring(0, s.lastIndexOf(" -> ")));
				elencoPrivPub[numeMap] = s.replace(" -> ", ": ");
				numeMap++;
			} else {
				bAsm.write("," + s.substring(0, s.lastIndexOf(" -> ")));
				elencoPrivPub[numeMap] = s.replace(" -> ", ": ");
				numeMap++;
			}
		}
		if (numeMap != 0) {
			bAsm.write("}\n");
		}
		numeMap = 0;
		for (String s : map.keySet()) {
			if (numeMap == 0) {
				bAsm.write("	domain KnowledgeSignPubKey = {" + s.substring(s.lastIndexOf(" -> ") + 4, s.length()));
				numeMap++;
			} else {
				bAsm.write("," + s.substring(s.lastIndexOf(" -> ") + 4, s.length()));
				numeMap++;
			}
		}
		if (numeMap != 0) {
			bAsm.write("}\n");
		}
		Iterator<Map.Entry<String, String>> it = map.entrySet().iterator();
		while (it.hasNext()) {
			if (it.next().getKey().startsWith("")) {
				it.remove();
			}
		}
		return elencoPrivPub;
	}

	// Scrittura delle informazioni legate alla Knowledge Tag
	private void writeKnowledgeTag(BufferedWriter bAsm) throws IOException {
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

		for (String s : map.keySet()) {
			if (numeMap == 0) {
				bAsm.write("	domain KnowledgeTag = {" + s);
				numeMap++;
			} else {
				bAsm.write("," + s);
				numeMap++;
			}
		}
		if (numeMap != 0) {
			bAsm.write("}\n");
		}
		Iterator<Map.Entry<String, String>> it = map.entrySet().iterator();
		while (it.hasNext()) {
			if (it.next().getKey().startsWith("")) {
				it.remove();
			}
		}

	}

	// Scrittura delle informazioni legate alla Knowledge Digest
	private void writeKnowledgeDigest(BufferedWriter bAsm) throws IOException {
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

		for (String s : map.keySet()) {
			if (numeMap == 0) {
				bAsm.write("	domain KnowledgeDigest = {" + s);
				numeMap++;
			} else {
				bAsm.write("," + s);
				numeMap++;
			}
		}
		if (numeMap != 0) {
			bAsm.write("}\n");
		}
		Iterator<Map.Entry<String, String>> it = map.entrySet().iterator();
		while (it.hasNext()) {
			if (it.next().getKey().startsWith("")) {
				it.remove();
			}
		}
	}

	// Scrittura delle informazioni legate alla Knowledge Hash
	private void writeKnowledgeHash(BufferedWriter bAsm) throws IOException {
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

		for (String s : map.keySet()) {
			if (numeMap == 0) {
				bAsm.write("	domain KnowledgeHashKey = {" + s);
				numeMap++;
			} else {
				bAsm.write("," + s);
				numeMap++;
			}
		}
		if (numeMap != 0) {
			bAsm.write("}\n");
		}
		Iterator<Map.Entry<String, String>> it = map.entrySet().iterator();
		while (it.hasNext()) {
			if (it.next().getKey().startsWith("")) {
				it.remove();
			}
		}
	}

	// Scrittura delle informazioni legate alla Knowledge Timestamp
	private void writeKnowledgeTimestamp(BufferedWriter bAsm) throws IOException {
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

		for (String s : map.keySet()) {
			if (numeMap == 0) {
				bAsm.write("	domain KnowledgeTimestamp = {" + s);
				numeMap++;
			} else {
				bAsm.write("," + s);
				numeMap++;
			}
		}
		if (numeMap != 0) {
			bAsm.write("}\n");
		}
		Iterator<Map.Entry<String, String>> it = map.entrySet().iterator();
		while (it.hasNext()) {
			if (it.next().getKey().startsWith("")) {
				it.remove();
			}
		}
	}
	private void writeDefinitionNuSvm(BufferedWriter bNuSmv,BufferedReader readCrypt) throws IOException {
		if (debug) {
			System.out.println("writeDefinitionNuSvm entro");
		}
		bNuSmv.write("\n");
		String line = readCrypt.readLine();
		boolean startWrite=false;
		while (line != null) {
			bNuSmv.write(line.replace("Agent", "Agenti"));
			bNuSmv.write("\n");
			line = readCrypt.readLine();
		}
		System.out.println("writeDefinitionNuSvm esco");
	}

		
	// Scrittura delle informazioni legate ai messaggi scambiati prendendo in
	// cosniderazione un eventuale attacco
	private void writeMessageAttacker(BufferedWriter bAsm,BufferedWriter bNuSmv) throws IOException {
		if (debug) {
			System.out.println(" Entro writeMessageAttacker");
		}
		bAsm.write("\n");
		bAsm.write("	/*ATTACKER RULES*/\n");
		bNuSmv.write("\n");
		bNuSmv.write("	/*ATTACKER RULES*/\n");
		// si leggono tutti i messaggi del protocollo
		for (int i = 0; i < 15; i++) {
			Message message = messages.getMessage(i);
			if (message.getActorfrom() == null || message.getActorfrom().isEmpty()) {
				if (i > 0) {
					break;
				}
			}
			if (debug) {
				System.out.println(" writeMessageAttacker - leggo messaggio numero " + i + " Actor From " + message.getActorfrom()
				+ " Actor To " + message.getActorTo());
			}
			if (i==0) {
				actorStartProtocol = message.getActorfrom();

			}
			if (i == 0) {
				switch (message.getActorfrom()) {
				case "Alice":
					if (aliceStartState == null || aliceStartState.isEmpty()) {
						aliceStartState = "IDLE_" + changNumMSG[i];
						lastMsgAlice=99;
					}
					break;
				case "Bob":
					if (bobStartState == null || bobStartState.isEmpty()) {
						bobStartState = "IDLE_" + changNumMSG[i];
						lastMsgBob=99;
					}
					break;
				case "Server":
					if (serverStartState == null || serverStartState.isEmpty()) {
						serverStartState = "IDLE_" + changNumMSG[i];
						lastMsgServer=99;
					}
					break;
				case "Eve":
					if (eveStartState == null || eveStartState.isEmpty()) {
						eveStartState = "IDLE_" + changNumMSG[i];
						lastMsgEve=99;
					}
					break;
				}
			}
			
			switch (message.getActorfrom()) {
			case "Alice":
				if(aliceStartState ==null || aliceStartState.isEmpty() || aliceStartState.contains("CHECK")) {
							aliceStartState="WAITING_"+changNumMSG[i];
							lastMsgAlice=99;
				}
				break;
			case "Bob":
				if(bobStartState ==null || bobStartState.isEmpty()|| bobStartState.contains("CHECK")) {
					bobStartState="WAITING_"+changNumMSG[i];
					lastMsgBob=99;
				}
				break;
			case "Server":
				if(serverStartState ==null || serverStartState.isEmpty()|| serverStartState.contains("CHECK")) {
					serverStartState="WAITING_"+changNumMSG[i];
					lastMsgServer=99;
				}
				break;
			case "Eve":
				if(eveStartState ==null || eveStartState.isEmpty()||eveStartState.contains("CHECK")||eveStartState.contains("END")) {
					eveStartState="WAITING_"+changNumMSG[i];
					lastMsgEve=99;
				}
				break;
			}
			switch (message.getActorTo()) {
			case "Alice":
				if(aliceStartState ==null || aliceStartState.isEmpty()) {
					lastMsgAlice=i;
					aliceStartState="CHECK_END_A";
				}
				break;
			case "Bob":
				if(bobStartState ==null || bobStartState.isEmpty()) {
					lastMsgBob=i;
					bobStartState="CHECK_END_A";
				}
				break;
			case "Server":
				if(serverStartState ==null || serverStartState.isEmpty()) {
					lastMsgServer=i;
					serverStartState="CHECK_END_S";
				}
				break;
			case "Eve":
				if(eveStartState ==null || eveStartState.isEmpty()) {
					lastMsgEve=99;
					eveStartState="END_E";
				}
				break;
			}

			if (debug) {
				System.out.println(" writeMessageAttacker - Verifico se elaboro");
			}

			
			if (!(message.getActorTo().equals("Eve") || message.getActorfrom().equals("Eve"))) {
				if (debug) {
					System.out.println(" writeMessageAttacker - decido di elaborare");
				}

				// per ogni messaggio si scrivono l'istruzione Rule e la Let
				bAsm.write("	rule r_message_replay_" + changNumMSG[i] + " =\n");
				bNuSmv.write("	rule r_message_replay_" + changNumMSG[i] + " =\n");
				ruleR_Agent[indRuleR_Agent] = "E r_message_replay_" + changNumMSG[i] + "[]";
				indRuleR_Agent++;
				bAsm.write("		//choose what agets are interested by the message\n");
				bAsm.write("		let ($b=agent" + message.getActorTo().substring(0, 1).toUpperCase() + ",$a=agent"
						+ message.getActorfrom().substring(0, 1).toUpperCase() + ") in\n");
				bAsm.write("		  par \n");
				bNuSmv.write("		//choose what agets are interested by the message\n");
				bNuSmv.write("		let ($x=agentE,$b=agent" + message.getActorTo().substring(0, 1).toUpperCase() + ",$a=agent"
						+ message.getActorfrom().substring(0, 1).toUpperCase() + ") in\n");
				dollaroX="EVE";
				dollaroB=message.getActorTo().toUpperCase();
				dollaroA=message.getActorfrom().toUpperCase();
				dollaroT="";
				dollaroF="";
				dollaroE="";
				self="EVE";
				bNuSmv.write("		  par \n");
//			if (messages.getMessage(i).getPayload().contains("-")) {bAsm.write("		  par \n");}
				// si iniziano a scrivere le istruzoni per la modalità passiva
				writeMessageAttackerPassive(bAsm,bNuSmv, message, i);
				// si iniziano a scrivere le istruzoni per la modalità attiva
				writeMessageAttackerActive(bAsm,bNuSmv, message, i);
//			if (messages.getMessage(i).getPayload().contains("-")) {bAsm.write("		  endpar \n");}
				bAsm.write("		  endpar \n");
				bAsm.write("		endlet \n");
				bNuSmv.write("		  endpar \n");
				bNuSmv.write("		endlet \n");
			}
		}
	}

	// Scrittura delle informazioni legate ai messaggi scambiati prendendo in
	// cosniderazione un eventuale attacco quando EVE è passivo
	private void writeMessageAttackerPassive(BufferedWriter bAsm, BufferedWriter bNuSmv,Message message, int i) throws IOException {
		if (debug) {
			System.out.println(" Entro writeMessageAttackerPassive");
		}

		bAsm.write("			//check the reception of the message and the modality of the attack\n");
		bAsm.write("			if(protocolMessage("+i+",$a,self)=" + changNumMSG[i] + " and protocolMessage("+i+",self,$b)!="
				+ changNumMSG[i] + " and mode=PASSIVE)then\n");
		bAsm.write("			        //in passsive mode if the attacker knows the decryption key, the message payload is readable and it can be added to the attacker knowledge\n");
		bAsm.write("			        // the message must be sent unaltered\n");
		bNuSmv.write("			//check the reception of the message and the modality of the attack\n");
		bNuSmv.write("			if(protocolMessage("+i+","+ dollaroA +","+ self+")=" + changNumMSG[i] + " and protocolMessage("+i+","+self+","+ dollaroB +")!="
				+ changNumMSG[i] + " and mode=PASSIVE)then\n");
		bNuSmv.write("			        //in passive mode if the attacker knows the decryption key, the message payload is readable and it can be added to the attacker knowledge\n");
		bNuSmv.write("			        // the message must be sent unaltered\n");
		//bAsm.write("		          par \n");
		//
		
		writePrevMessageAttackerPassive(bAsm,bNuSmv, message,  i);
		if (debug) {System.out.println("writeMessageAttackerPassive esco da writePrevMessageAttackerPassive");}

		//
		// per ogni messaggio
		// dal payload si estraggono tutti i filed e si scrivono a prescindere
		findActorFromTo(message.getActorfrom(), message.getActorTo());
		String[] msgFieldTot = FindField(messages.getMessage(i).getPayload());
		if (debug) {System.out.println("writeKnowledge 1");}
		String[] linesKnowledge = writeKnowledge(message, i, msgFieldTot, "$a", false);
		if (debug) {
			System.out.println("writeKnowledge 1");
			System.out.println("writeKnowledge 1 " + linesKnowledge[0]);
		}
		String spaces = "                 ";
		printKnowledge(bAsm, "Prot", linesKnowledge, spaces);
		if (debug) {
			System.out.println("printKnowledge(bAsm, \"Prot\", linesKnowledge, spaces);");
		}
		printKnowledge(bAsm, "Mess", linesKnowledge, spaces);
		if (debug) {
			System.out.println("printKnowledge(bAsm, \"Mess\", linesKnowledge, spaces);");
		}		
		//
		// si divide il payload in messaggi separati (se necessario)
		String[] listSubPayload = findMsg(message.getPayload());

		if(debug) {
			System.out.println("writeMessageAttackerPassive i ="+i+" listSubPayload lenght="+listSubPayload.length);
			for(int x=0;x<listSubPayload.length;x++) {
				if (listSubPayload[x] !=null && !listSubPayload[x].isEmpty()) {
					System.out.println("writeMessageAttackerPassive listSubPayload["+x+"]="+listSubPayload[x]);
				}
			}
		}
		// per ogni messaggio si estraggono le operazioni
		int totOpz = 0;
		int endMsgDet = 1;
		for (int j = 0; j < 15; j++) {
			if (listSubPayload[j] == null || listSubPayload[j].isEmpty()) {
				break;
			}
			// per ogni sottomessaggio si scrivono le istruzioni di Encode
			String keyUsed = findKey(listSubPayload[j]);
			String operation = "";
			if (keyUsed != null) {
				totOpz++;
				/*
				 * operation = findOperation(keyUsed, message.getActorfrom(),
				 * message.getActorTo()); String[] msgEncField1EncField2 = new String[15];
				 * String[] msgField = new String[15]; // determino i dati per la scrittura del
				 * tipo di crittografia ha il messaggio String levelEncField1EncField2 =
				 * calcLevelEncField1EncField2(listSubPayload[j], msgEncField1EncField2,
				 * msgField, msgFieldTot); if (reversOperation(operation).equals("symEnc")) {
				 * bAsm.write("                            	" + reversOperation(operation) + "("
				 * + changNumMSG[i] + "," + levelEncField1EncField2 + "):=" +
				 * findKeyEle(keyUsed, message.getActorfrom(), message.getActorTo(), true) +
				 * "\n"); } else { bAsm.write("                            	" +
				 * reversOperation(operation) + "(" + changNumMSG[i] + "," +
				 * levelEncField1EncField2 + "):=" + findKeyEle(keyUsed, message.getActorfrom(),
				 * message.getActorTo(), false) + "\n"); }
				 */
			} else {
				// se nel sottomessaggio non c'è una funzione di crittografia si scrive la konw
				String[] msgEncField1EncField2 = new String[15];
				String[] msgField = new String[15];
				// determino i dati per la scrittura del tipo di crittografia ha il messaggio
				String levelEncField1EncField2 = calcLevelEncField1EncField2(listSubPayload[j], msgEncField1EncField2,
						msgField, msgFieldTot);
				// determino i campi del messaggio e la posizione
				String[] msgFieldDet = detField(msgField, msgFieldTot, endMsgDet);
				endMsgDet = contMsgFielDet(msgFieldDet);
				findActorFromTo(message.getActorfrom(), message.getActorTo());
				if (debug) {System.out.println("writeKnowledge 2");}
				linesKnowledge = writeKnowledge(message, i, msgFieldDet, "$a", true);
				if (debug) {
					System.out.println("writeKnowledge 2");
					System.out.println("writeKnowledge 2 " + linesKnowledge[0]);
				}
				spaces = "                 ";
				printKnowledge(bAsm, "Know", linesKnowledge, spaces);
			}
		}
		// Si rileggono i sottomessaggi per verificare se l'attore riesce a
		// decodificarli e in questo caso si aggiorna la knowlege
		
		endMsgDet=1;
		boolean firstOp = true;
		for (int j = 0; j < 15; j++) {
			if (listSubPayload[j] == null || listSubPayload[j].isEmpty()) {
				break;
			}
			String keyUsed = findKey(listSubPayload[j]);
			String operation = "";
			if (keyUsed != null) {
				operation = findOperation(keyUsed, message.getActorfrom(), message.getActorTo(),i);
				String[] msgEncField1EncField2 = new String[15];
				String[] msgField = new String[15];
				// determino i dati per la scrittura del tipo di crittografia ha il messaggio
				String levelEncField1EncField2 = calcLevelEncField1EncField2(listSubPayload[j], msgEncField1EncField2,
						msgField, msgFieldTot);
				String[] msgFieldDet = detField(msgField, msgFieldTot, endMsgDet);
				endMsgDet = contMsgFielDet(msgFieldDet);
				if (operation != null && !operation.isEmpty()) {
					bAsm.write("			        if(" + operation + "(" + changNumMSG[i] + "," + levelEncField1EncField2
							+ ",self)=true)then\n");
					bAsm.write("                      par \n");
					bNuSmv.write("			        if(" + operation + "(" + changNumMSG[i] + "," + levelEncField1EncField2
							+ ","+ self + ")=true)then\n");
					bNuSmv.write("                      par \n");
					// si scrivono le conoscenze in base ai sotto peyload del messaggio
					if(debug) {System.out.println("printKnowSubPayload -->1");}
					printKnowSubPayload(bAsm,bNuSmv,msgFieldDet,msgFieldTot,listSubPayload[j],message,i,"$a",false,"Know",true);
//					linesKnowledge = writeKnowledge(message, i, msgFieldDet, "$a", false);
//					spaces = "				";
//					printKnowledge(bAsm, "Know", linesKnowledge, spaces);
					spaces = "					";
					if (reversOperation(operation,"encod").equals("symEnc")) {
						bAsm.write("			            " + reversOperation(operation,"encod") + "(" + changNumMSG[i] + ","
								+ levelEncField1EncField2 + "):="
								+ findKeyEle(keyUsed, message.getActorfrom(), message.getActorTo(), true) + "\n");
						bNuSmv.write("			            " + reversOperation(operation,"encod") + "(" + changNumMSG[i] + ","
								+ levelEncField1EncField2 + "):="
								+ findKeyEle(keyUsed, message.getActorfrom(), message.getActorTo(), true).replace("self", self).replace("$a", dollaroA).replace("$b", dollaroB).replace("$t", dollaroT).replace("$e", dollaroE).replace("$f", dollaroF) + "\n");

					} else {
						bAsm.write("			            " + reversOperation(operation,"encod") + "(" + changNumMSG[i] + ","
								+ levelEncField1EncField2 + "):="
								+ findKeyEle(keyUsed, message.getActorfrom(), message.getActorTo(), false) + "\n");

						bNuSmv.write("			            " + reversOperation(operation,"encod") + "(" + changNumMSG[i] + ","
								+ levelEncField1EncField2 + "):="
								+ findKeyEle(keyUsed, message.getActorfrom(), message.getActorTo(), false).replace("self", self).replace("$a", dollaroA).replace("$b", dollaroB).replace("$t", dollaroT).replace("$e", dollaroE).replace("$f", dollaroF) + "\n");
					}

					bAsm.write("                      endpar \n");
					bAsm.write("			        endif \n");
					bNuSmv.write("                      endpar \n");
					bNuSmv.write("			        endif \n");


				}
			}

		}
		if (!firstOp) {
			if (totOpz > 1) {
				bAsm.write("			  endpar \n");
				bNuSmv.write("			  endpar \n");
			}
			bAsm.write("			endif \n");
			bNuSmv.write("			endif \n");
		}
		bAsm.write("		          endpar \n");
		bAsm.write("			endif \n");
		bNuSmv.write("		          endpar \n");
		bNuSmv.write("			endif \n");

	}
	// Scrittura delle conoscenze acquisite in messaggi precedenti
	private void writePrevMessageAttackerPassive(BufferedWriter bAsm, BufferedWriter bNuSmv, Message message, int i) throws IOException {
//---------------------------------------------------------
		if (debug) {System.out.println("Entro writePrevMessageAttackerPassive");}
		int[] listMsgPrev = findMessagePrev("Eve", message.getActorTo(), i);
		int z = i - 1;
		int endMsgDet = 1;
		boolean flgPar = false;
		if (listMsgPrev == null) {
			bAsm.write("		          par \n");
			bNuSmv.write("		          par \n");
		} else {
			for (int k = 0; k < 15; k++) {
				if (listMsgPrev[k] > 90)
					break;
				z = listMsgPrev[k];

				// la prima parte delle istruzioni da scrivere riguardano quelle che permettono
				// di aggiornare le conoscenze dell'attore
				// che riceve il messaggio. per fare questo si deve vedere cosa riceve nel
				// messaggio precedente
				Message messagePrev = messages.getMessage(z);
				String actorFromPrev = "agent" +messagePrev.getActorfrom().substring(0, 1).toUpperCase();
				if (debug) {System.out.println("writePrevMessageAttackerPassive - actorFromPrev " + actorFromPrev);}

				if (messagePrev.getActorfrom().equals(message.getActorfrom())) {
					actorFromPrev = "$a";
				}
				if (messagePrev.getActorfrom().equals(message.getActorTo())) {
					actorFromPrev = "$b";
				}	
				// dal messaggio precedente si estraggono i sott-ayload e l'elenco dei campi
				String[] listSubPayloadPrev = findMsg(messagePrev.getPayload());
				if (debug) {
					System.out.println("writePrevMessageAttackerPassive *--- listSubPayloadPrev ----*" );
					for (String e : listSubPayloadPrev) {
						System.out.println(e);
					}
					System.out.println("* -------------- -------------------------------- -------*");

				}

				String[] msgFieldTotPrev = FindField(messages.getMessage(z).getPayload());
				if (debug) {
					System.out.println("writePrevMessageAttackerPassive *--- msgFieldTotPrev ----*" );
					for (String e : msgFieldTotPrev) {
						System.out.println(e);
					}
					System.out.println("* -------------- -------------------------------- -------*");

				}

				// si impostano le classi dell'attore che trasmette il messaggio e quello che lo
				// riceve
				findActorFromTo(messagePrev.getActorfrom(), messagePrev.getActorTo());

				// Si verifica se la parte del messaggio è decodificabile altrimenti si leva
				// dall'elenco
				// del messaggio precedente

				String[] NewListSubPayloadPrev = new String[15];
				int indList = 0;
				// determino quali sono i campi del payload che possono essere letti
				// dall''attore che riceve il messaggio
				String newPayloadPrev = findNewPayloadPrev(indList, listSubPayloadPrev, msgFieldTotPrev,
						NewListSubPayloadPrev, z);
				if (debug) {
					System.out.println("writePrevMessageAttackerPassive newPayloadPrev "+ newPayloadPrev + "*------- NewListSubPayloadPrev ----*" );
					for (String e : NewListSubPayloadPrev) {
						System.out.println(e);
					}
					System.out.println("* -------------- -------------------------------- -------*");

				}
				
				
				// Si stabilisce l'elenco dei campi che sono conosciuti dall'attore che riceve
				// il messaggio
				msgFieldTotPrev = FindField(newPayloadPrev);
				if (debug) {
					System.out.println("writePrevMessageAttackerPassive - newPayloadPrev " + newPayloadPrev );
				}
				// si memorizzano l'elenco dei sotto-payload che l'attore che riceve il
				// messaggio puo decodificare
				listSubPayloadPrev = NewListSubPayloadPrev;


				flgPar = false;
				// cerca tutti i field che sono in chiaro nel payload per poi scrive il
				// Knowledge
				String[] msgFieldPrevFree = finfFreeFieldPrev(listSubPayloadPrev, msgFieldTotPrev);
				if (debug) {
					System.out.println("writePrevMessageAttackerPassive newPayloadPrev *------- msgFieldPrevFree ----*" );
					for (String e : msgFieldPrevFree) {
						System.out.println(e);
					}
					System.out.println("* -------------- -------------------------------- -------*");

				}
				
				for (String e : msgFieldPrevFree) {
					if (e != null) {
						flgPar = true;
						break;
					}
				}
				if (debug) {
					System.out.println("writePrevMessageAttackerPassive - flgPar " + flgPar );
				}
				if (flgPar) {
					String[] linesKnowledgePrevFree = writeKnowledge(messagePrev, (z), msgFieldPrevFree,
							actorFromPrev, false);
					bAsm.write("		     par\n");
					bNuSmv.write("		     par\n");
					String spaces = "			      ";
					printKnowSubPayload(bAsm, bNuSmv, msgFieldPrevFree, msgFieldTotPrev, listSubPayloadPrev[0], messagePrev,
							(z), actorFromPrev, false, "Kno3", true);
				}

				if (debug) {
					System.out.println("writePrevMessageAttackerPassive - xxxxx");
				}
				// Si richiama la routine per scrivere le if delle operazioni di ogni singolo
				// sotto-payload
				//
				String[] msgFieldPrev = writeIfPayloadPrev(bAsm, messagePrev, message, i, z, listSubPayloadPrev,
						msgFieldTotPrev, "");

				if (debug) {
					System.out.println("writePrevMessageAttackerPassive - yyyyyy");
				}
				String[] msgFieldDetPrev = detField(msgFieldPrev, msgFieldTotPrev, 1);
				endMsgDet = contMsgFielDet(msgFieldDetPrev);

				if (debug) {
					System.out.println("writePrevMessageAttackerPassive - zzzzzz");
				}

				//
				// si inseriscono nell'array linesKnowledgePrev tutte le istruzioni per la
				// memorizzazione delle informazioni
				// Wnowledge , mesfielf etc.
				//

				String[] linesKnowledgePrev = writeKnowledge(messagePrev, (z), msgFieldTotPrev, actorFromPrev,
						false);

				if (debug) {
					System.out.println("writePrevMessageAttackerPassive - kkkkkk");
				}
				String spaces = "			      ";
				//
				// Si scrivono le istruzioni sulle conoscenze
				//
				if (listSubPayloadPrev[0] != null) {
					printKnowSubPayload(bAsm, bNuSmv, msgFieldPrev, msgFieldTotPrev, listSubPayloadPrev[0], messagePrev, (z),
						actorFromPrev, false, "Kno3", true);
				}

				if (debug) {
					System.out.println("writePrevMessageAttackerPassive - yyyyyyy");
				}
			}
		}
	}

	// si scrivono le conoscenze in base ai sotto peyload del messaggio
	// il boolean action server per indicare se modigicare il campo in quanto Eve sta lavorando attivamente
	// il boolena subIf server per inserire le if quando si trova nel payload una parte a cui si applica la crittografia
	private void printKnowSubPayload(BufferedWriter bAsm, BufferedWriter bNuSmv,String[] msgFieldDet, String[] msgFieldTot,String listSubPayloadString, Message message,
			int i, String type, Boolean action,String typeKnow, Boolean subIf) throws IOException {
		// si verifica che il payload analizzato ha un solo livello di criptazione
		// il controllo verifica che non ci siano altri "-" prima dell'ultimo
		
		if(debug) {
			System.out.println("printKnowSubPayload - Dati input - listSubPayloadString " + listSubPayloadString +
					" i " + i + " type " +  type + " action " + action + " typeKnow " + typeKnow + " subIf " + subIf);
			System.out.println("*-----------printKnowSubPayload msgFieldDet -------*");
			for (String e : msgFieldDet) { System.out.println (e);}
			System.out.println("*--------------------------------------------------*");
			System.out.println("*-----------printKnowSubPayload msgFieldTot -------*");
			for (String e : msgFieldTot) { System.out.println (e);}
			System.out.println("*..................................................*");
			System.out.println("printKnowSubPayload i ="+i+" listSubPayload lenght="+listSubPayloadString.length());
			System.out.println("printKnowSubPayload listSubPayloadString="+listSubPayloadString);
			System.out.println("*==================================================*");
		}

		
		if (!listSubPayloadString.substring(1, listSubPayloadString.lastIndexOf("}")).contains("-")) {
			if(debug) {
				System.out.println("printKnowSubPayload non trovo sottopayload cifrati");
			}
			if (debug) {System.out.println("writeKnowledge 3 " + listSubPayloadString);}
			String[] linesKnowledge = writeKnowledge(message, i, msgFieldDet, type, action);
			if (debug) {
				System.out.println("writeKnowledge 3 esci");
				System.out.println("writeKnowledge 3 " + linesKnowledge[0]);
			}
			String spaces = "                    ";
			if(typeKnow.contains("Kno3")) {
				spaces = "			            ";
			} 
			if (debug) {System.out.println("printKnowledge 3 " + typeKnow);}
			
			printKnowledge(bAsm, typeKnow, linesKnowledge, spaces);
			
			if (debug) {System.out.println("printKnowledge 3 esci");}
			return;
		}
		
		if(debug) {
			System.out.println("printKnowSubPayload Trovati sottopayload cifrati");
		}
		// se all'interno del payload ci sono altre funzioni di cifratura oltre quello dell'intero payload si analizzano le sottoparti
		String[] listSubPayload = findMsg(listSubPayloadString.substring(1, listSubPayloadString.lastIndexOf("}")));
		if(debug) {
			System.out.println("printKnowSubPayload i ="+i+" listSubPayload lenght="+listSubPayload.length);
			for(int x=0;x<listSubPayload.length;x++) {
				if (listSubPayload[x] !=null && !listSubPayload[x].isEmpty()) {
					System.out.println("printKnowSubPayload listSubPayload["+x+"]="+listSubPayload[x]);
				}
			}
		}

		int endMsgDet = 1;
		for (int j = 0; j < 15; j++) {
			if (listSubPayload[j] == null || listSubPayload[j].isEmpty()) {
				break;
			}
			if(debug) {
				System.out.println("printKnowSubPayload analizzo " + listSubPayload[j]);
			}
			// per ogni sottomessaggio si scrivono le istruzioni di Encode
			String keyUsed = findKey(listSubPayload[j]);
			if(debug) {
				System.out.println("printKnowSubPayload trovo chiave " + keyUsed);
			}
			String operation = "";
			if (keyUsed != null && subIf) {
				operation = findOperation(keyUsed, message.getActorfrom(), message.getActorTo(),i);
				if(debug) {
					System.out.println("printKnowSubPayload trovo operazione " + operation);
				}
				String[] msgEncField1EncField2 = new String[15];
				String[] msgField = new String[15];
				// determino i dati per la scrittura del tipo di crittografia ha il messaggio
				String levelEncField1EncField2 = calcLevelEncField1EncField2(listSubPayload[j], msgEncField1EncField2,
						msgField, msgFieldTot);
				String[] msgFieldDet2 = detField(msgField, msgFieldTot, endMsgDet);
				endMsgDet = contMsgFielDet(msgFieldDet2);
				if (operation != null && !operation.isEmpty()) {
					bAsm.write("			            if(" + reversOperation(operation,"decod") + "(" + changNumMSG[i] + "," + levelEncField1EncField2
							+ ",self)=true)then\n");
					bNuSmv.write("			            if(" + reversOperation(operation,"decod") + "(" + changNumMSG[i] + "," + levelEncField1EncField2
							+ ","+self +")=true)then\n");
					if (debug) {
						System.out.println("----------->"+levelEncField1EncField2.substring(2, 3)); 
						System.out.println("===========>"+levelEncField1EncField2.substring(4, 5)); 
					}
					if (!levelEncField1EncField2.substring(2,3).equals(levelEncField1EncField2.substring(4,5))) {
						bAsm.write("	   			 	       par \n");
						bNuSmv.write("	   			 	       par \n");
					}
					
					// si scrivono le conoscenze in base ai sotto peyload del messaggio
					if (debug) {System.out.println("writeKnowledge 4");}
 					String[] linesKnowledge2 = writeKnowledge(message, i, msgFieldDet2, type, action);
					if(debug) {
						System.out.println("printKnowSubPayload scrivo knowledge " + typeKnow);
						for(int x=0;x<linesKnowledge2.length;x++) {
							if (linesKnowledge2[x] !=null && !linesKnowledge2[x].isEmpty()) {
								System.out.println("printKnowSubPayload linesKnowledge2["+x+"]="+linesKnowledge2[x]);
							}
						}
					}
 					String spaces = "	   			 	          ";
					printKnowledge(bAsm, typeKnow, linesKnowledge2, spaces);

 					spaces = "					";
					if (!levelEncField1EncField2.substring(2,3).equals(levelEncField1EncField2.substring(4,5))) {
						bAsm.write("	   			 	       endpar \n");
						bNuSmv.write("	   			 	       endpar \n");
					}
					bAsm.write("			            endif \n");
					bNuSmv.write("			            endif \n");
				}
				/*
				 * operation = findOperation(keyUsed, message.getActorfrom(),
				 * message.getActorTo()); String[] msgEncField1EncField2 = new String[15];
				 * String[] msgField = new String[15]; // determino i dati per la scrittura del
				 * tipo di crittografia ha il messaggio String levelEncField1EncField2 =
				 * calcLevelEncField1EncField2(listSubPayload[j], msgEncField1EncField2,
				 * msgField, msgFieldTot); if (reversOperation(operation).equals("symEnc")) {
				 * bAsm.write("                            	" + reversOperation(operation) + "("
				 * + changNumMSG[i] + "," + levelEncField1EncField2 + "):=" +
				 * findKeyEle(keyUsed, message.getActorfrom(), message.getActorTo(), true) +
				 * "\n"); } else { bAsm.write("                            	" +
				 * reversOperation(operation) + "(" + changNumMSG[i] + "," +
				 * levelEncField1EncField2 + "):=" + findKeyEle(keyUsed, message.getActorfrom(),
				 * message.getActorTo(), false) + "\n"); }
				 */
			} else {
				
				if(debug) {
					System.out.println("printKnowSubPayload NON TROVATA OPERAZIONE");
				}

				// se nel sottomessaggio non c'è una funzione di crittografia si scrive la konw
				String[] msgEncField1EncField2 = new String[15];
				String[] msgField = new String[15];
				// determino i dati per la scrittura del tipo di crittografia ha il messaggio
				String levelEncField1EncField2 = calcLevelEncField1EncField2(listSubPayload[j], msgEncField1EncField2,
						msgField, msgFieldTot);
				// determino i campi del messaggio e la posizione
				String[] msgFieldDet2 = detField(msgField, msgFieldTot, endMsgDet);
				endMsgDet = contMsgFielDet(msgFieldDet2);
				findActorFromTo(message.getActorfrom(), message.getActorTo());
				if (debug) {System.out.println("writeKnowledge 4-");}
				String[] linesKnowledge2 = writeKnowledge(message, i, msgFieldDet2, type, action);
				if (debug) {
					System.out.println("writeKnowledge 4");
					System.out.println("writeKnowledge41 " + linesKnowledge2[0]);
				}
				String spaces = "			        ";
				if(typeKnow.contains("Kno3")) {
					spaces = "			            ";
				} 
 				printKnowledge(bAsm, typeKnow, linesKnowledge2, spaces);
			}
		}
	
	}
	// Scrittura delle informazioni legate ai messaggi scambiati prendendo in
	// cosniderazione un eventuale attacco quando EVE è attivo
	private void writeMessageAttackerActive(BufferedWriter bAsm,BufferedWriter bNuSmv, Message message, int i) throws IOException {
		if (debug) {
			System.out.println(" Entro writeMessageAttackerActive");
		}
		bAsm.write("			        //check the reception of the message and the modality of the attack\n");
		bAsm.write("			if(protocolMessage("+i+",$a,self)=" + changNumMSG[i] + " and protocolMessage("+i+",self,$b)!="
				+ changNumMSG[i] + " and mode=ACTIVE)then\n");
		bNuSmv.write("			        //check the reception of the message and the modality of the attack\n");
		bNuSmv.write("			if(protocolMessage("+i+","+ dollaroA + ","+self+")=" + changNumMSG[i] + " and protocolMessage("+i+","+self+","+ dollaroB + ")!="
				+ changNumMSG[i] + " and mode=ACTIVE)then\n");
		
		writePrevMessageAttackerPassive(bAsm, bNuSmv, message,  i);
		if (debug) {System.out.println("writeMessageAttackerPassive esco da writePrevMessageAttackerPassive");}


		
		//
		// per ogni messaggio
		// dal payload si estraggono tutti i filed e si scrivono a prescindere
		findActorFromTo(message.getActorfrom(), message.getActorTo());
		String[] msgFieldTot = FindField(messages.getMessage(i).getPayload());
		if (debug) {System.out.println("writeKnowledge 6");}
		String[] linesKnowledge = writeKnowledge(message, i, msgFieldTot, "$a", false);
		if (debug) {
			System.out.println("writeKnowledge 6");
			System.out.println("writeKnowledge 6 " + linesKnowledge[0]);
		}
		String spaces = "                 ";
		printKnowledge(bAsm, "Prot", linesKnowledge, spaces);
		printKnowledge(bAsm, "Mes2", linesKnowledge, spaces);
		//
		// si divide il payload in messaggi separati (se necessario)
		String[] listSubPayload = findMsg(message.getPayload());
		// per ogni messaggio si estraggono le operazioni
		int totOpz = 0;
		int endMsgDet=1;
		for (int j = 0; j < 15; j++) {
			if (listSubPayload[j] == null || listSubPayload[j].isEmpty()) {
				break;
			}
			if (debug) {System.out.println("writeMessageAttackerActive analizzo il subpayload "+ listSubPayload[j]);}
			// per ogni sottomessaggio si scrivono le istruzioni di Encode
			String keyUsed = findKey(listSubPayload[j]);
			String operation = "";
			if (keyUsed != null) {
				if (debug) {System.out.println("writeMessageAttackerActive non ho trovato crittografia");}

				totOpz++;
				/*
				 * operation = findOperation(keyUsed, message.getActorfrom(),
				 * message.getActorTo()); String[] msgEncField1EncField2 = new String[15];
				 * String[] msgField = new String[15]; // determino i dati per la scrittura del
				 * tipo di crittografia ha il messaggio String levelEncField1EncField2 =
				 * calcLevelEncField1EncField2(listSubPayload[j], msgEncField1EncField2,
				 * msgField, msgFieldTot); if (reversOperation(operation).equals("symEnc")) {
				 * bAsm.write("                            	" + reversOperation(operation) + "("
				 * + changNumMSG[i] + "," + levelEncField1EncField2 + "):=" +
				 * findKeyEle(keyUsed, message.getActorfrom(), message.getActorTo(), true) +
				 * "\n"); } else { bAsm.write("                            	" +
				 * reversOperation(operation) + "(" + changNumMSG[i] + "," +
				 * levelEncField1EncField2 + "):=" + findKeyEle(keyUsed, message.getActorfrom(),
				 * message.getActorTo(), false) + "\n"); }
				 */
			} else {
				if (debug) {System.out.println("writeMessageAttackerActive HO trovato crittografia " + keyUsed);}

				// se nel sottomessaggio non c'è una funzione di crittografia si scrive la konw
				String[] msgEncField1EncField2 = new String[15];
				String[] msgField = new String[15];
				// determino i dati per la scrittura del tipo di crittografia ha il messaggio
				String levelEncField1EncField2 = calcLevelEncField1EncField2(listSubPayload[j], msgEncField1EncField2,
						msgField, msgFieldTot);
				// determino i campi del messaggio e la posizione
				String[] msgFieldDet = detField(msgField, msgFieldTot, endMsgDet);
				endMsgDet = contMsgFielDet(msgFieldDet);
				if (debug) {
					System.out.println("*---- writeMessageAttackerActive msgField ---*");
					for (String e : msgField) {
						System.out.println(e);
					}
					System.out.println("*---- writeMessageAttackerActive msgFieldTot ---*");
					for (String e : msgFieldTot) {
						System.out.println(e);
					}
					System.out.println("*---- writeMessageAttackerActive msgFieldDet ---*");
					for (String e : msgFieldDet) {
						System.out.println(e);
					}
					System.out.println("*---- ---------------------------- ---*");

				}
				
				findActorFromTo(message.getActorfrom(), message.getActorTo());
				if (debug) {System.out.println("writeKnowledge 7");}
				linesKnowledge = writeKnowledge(message, i, msgFieldDet, "$a", true);
				if (debug) {
					System.out.println("writeKnowledge 7");
					System.out.println("writeKnowledge 7 " + linesKnowledge[0]);
				}
				spaces = "                 ";
				printKnowledge(bAsm, "Know", linesKnowledge, spaces);
				printKnowledge(bAsm, "Mes4", linesKnowledge, spaces);
			}
		}

		// Si rileggono i sottomessaggi per verificare se l'attore riesce a
		// decodificarli e in questo caso si aggiorna la knowlege
		boolean firstOp = true;
		int endMseDet=1;
		for (int j = 0; j < 15; j++) {
			if (listSubPayload[j] == null || listSubPayload[j].isEmpty()) {
				break;
			}
			String keyUsed = findKey(listSubPayload[j]);
			String operation = "";
			if (keyUsed != null) {
				operation = findOperation(keyUsed, message.getActorfrom(), message.getActorTo(),i);
				String[] msgEncField1EncField2 = new String[15];
				String[] msgField = new String[15];
				// determino i dati per la scrittura del tipo di crittografia ha il messaggio
				String levelEncField1EncField2 = calcLevelEncField1EncField2(listSubPayload[j], msgEncField1EncField2,
						msgField, msgFieldTot);
				String[] msgFieldDet = detField(msgField, msgFieldTot, endMsgDet);
				endMsgDet = contMsgFielDet(msgFieldDet);
				bAsm.write("			        if(" + operation + "(" + changNumMSG[i] + "," + levelEncField1EncField2
						+ ",self)=true)then\n");

				bAsm.write("	   			     par \n");
				bNuSmv.write("			        if(" + operation + "(" + changNumMSG[i] + "," + levelEncField1EncField2
						+ ","+self+")=true)then\n");

				bNuSmv.write("	   			     par \n");
				String eleEve = findKeyEve(keyUsed);
				// debug=true;
				if (debug && eleEve != null) {
					System.out.println("eleEve " + eleEve + " parte finale "
							+ eleEve.substring(eleEve.indexOf(" - ") + 3) + " Parte iniziale  "
							+ eleEve.substring(0, eleEve.indexOf(" - ")) + " actor To " + message.getActorTo());
				}
				 
				if (eleEve != null) {
					if (eleEve.substring(eleEve.indexOf(" - ") + 3).contains(message.getActorTo())) {
						eleEve = null;
					} else {
						eleEve = eleEve.substring(0, eleEve.indexOf(" - "));
					}
				}
				if (debug) {System.out.println("writeKnowledge 8");}
				linesKnowledge = writeKnowledge(message, i, msgFieldDet, "$a", true);
				if (debug) {
					System.out.println("writeKnowledge 8");
					System.out.println("writeKnowledge 8 " + linesKnowledge[0]);
				}
				spaces = "			         ";
				//printKnowledge(bAsm, "Know", linesKnowledge, spaces);
				printKnowledge(bAsm, "Mes4", linesKnowledge, spaces);
				if(debug) {System.out.println("printKnowSubPayload -->2");}
				printKnowSubPayload(bAsm,bNuSmv,msgFieldDet,msgFieldTot,listSubPayload[j],message,i,"$a",true,"Know",true);
				operation = findOperation(keyUsed, message.getActorfrom(), message.getActorTo(),i);
				if (eleEve != null) {
					bAsm.write("			        	" + reversOperation(operation,"encod") + "(" + changNumMSG[i] + ","
							+ levelEncField1EncField2 + "):=" + eleEve + "\n");
					bNuSmv.write("			        	" + reversOperation(operation,"encod") + "(" + changNumMSG[i] + ","
							+ levelEncField1EncField2 + "):=" + eleEve.replace("self", self).replace("$a", dollaroA).replace("$b", dollaroB).replace("$t", dollaroT).replace("$e", dollaroE).replace("$f", dollaroF) + "\n");
				} else {
					bAsm.write("			        	" + reversOperation(operation,"encod") + "(" + changNumMSG[i] + ","
							+ levelEncField1EncField2 + "):="
							+ findKeyEle(keyUsed, message.getActorfrom(), message.getActorTo(), false) + "\n");
					bNuSmv.write("			        	" + reversOperation(operation,"encod") + "(" + changNumMSG[i] + ","
							+ levelEncField1EncField2 + "):="
							+ findKeyEle(keyUsed, message.getActorfrom(), message.getActorTo(), false).replace("self", self).replace("$a", dollaroA).replace("$b", dollaroB).replace("$t", dollaroT).replace("$e", dollaroE).replace("$f", dollaroF) + "\n");

				}
				bAsm.write("	   			     endpar \n");
				bNuSmv.write("	   			     endpar \n");
				int totCountLinesKnowledgeMes5 = countLinesKnowledge("Mes5", linesKnowledge);
				if (totCountLinesKnowledgeMes5 > 0) {
					bAsm.write("			        else \n");
					bNuSmv.write("			        else \n");
					if (totCountLinesKnowledgeMes5 > 1) {
						bAsm.write("	   			     par \n");
						bNuSmv.write("	   			     par \n");
					}
					spaces = "			         ";
					printKnowledge(bAsm, "Mes5", linesKnowledge, spaces);
					if (totCountLinesKnowledgeMes5 > 1) {
						bAsm.write("	   			     endpar \n");
						bNuSmv.write("	   			     endpar \n");
					}
				}
				bAsm.write("			        endif \n");
				bNuSmv.write("			        endif \n");
			}

		}
		bAsm.write("		          endpar \n");
		bAsm.write("			endif \n");
		bNuSmv.write("		          endpar \n");
		bNuSmv.write("			endif \n");
	}

	// determina l'elenco dei messaggi che compongono il payload
	private String[] findMsg(String partMsg) {
		if (debug) {
			System.out.println("findMsg(String partMsg) " + partMsg);
		}
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

		if (debug) {
			System.out.println("findMsg esco " + listSubPayload);
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
	private String findOperation(String keyUsed, String actorFrom, String actorTo,int numMsg) {
		String operation = null;
		findActorFromTo(actorFrom, actorTo);
		if (KeyActorFrom != null) {
			operation = KeyActorFrom.searchEle(keyUsed,numMsg);
			if (operation == null) {
				if (KeyActorTo != null) {
					operation = KeyActorTo.searchEle(keyUsed,numMsg);
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
		int numField = 0;
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
				msgField[numField + 1] = fieldMsg.toUpperCase();
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

	// determina i campi di output del sottomessaggio (si dividono i messaggi del
	// payload)
	private String[] detField(String[] msgField, String[] msgFieldTot, int init) {
		String[] msgFieldDet = new String[15];
		int i = 1;
		int start = 0;
		int end = 0;
		boolean find = false;
		for (int j = init; j < 15; j++) {
			if (msgField[i] == null) {
				break;
			}
			if (msgFieldTot[j] != null && !msgFieldTot[j].isEmpty()) {
				if (msgField[i].equals(msgFieldTot[j]) && !find) {
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

		for (int k = start; k < end + 1; k++) {
			msgFieldDet[k] = msgFieldTot[k];
		}

		return msgFieldDet;
	}
	
	private int contMsgFielDet(String [] msgFieldDet) {
		int endMsgDet=1;
		int i=0;
		for (String e : msgFieldDet) {
			i++;
			if (e != null && !e.isEmpty()) {
				endMsgDet=i;
			}
		}
		return endMsgDet;
	}

	// routin che server per determinare di quanti field si compone il messaggio e
	// quanti livelli di cripr/encript ci sono
	private String calcLevelEncField1EncField2(String messagePart, String[] msgEncField1EncField2, String[] msgField,
			String[] msgFieldTot) {
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
				msgField[encField2 + 1] = fieldMsg.toUpperCase();
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
					int appoField1 = encField1;
					int appoField2 = encField2;
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

	// determina le operazioni (crittografiche) all'interno del messaggio e scrive
	// sul file di output
	private void determinesOperation(BufferedWriter bAsm, int m, int s, Message message, String messagePart, String agent,
			String space, boolean receiverAG_B) throws IOException {
		 
		if (debug)
			System.out.println(" determinesOperation : m " + m + " s " + s + " messagePart " + messagePart + " agent "
					+ agent + " receiverAG_B  " + receiverAG_B);

		int encField1, encField2, level, numMsgP;
		encField1 = 1;
		encField2 = 0;
		if (s != 0) {
			encField2 = encField2Old;
		}
		;
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
			if (debug)
				System.out.println(" determinesOperation : messagePart.charAt(i) " + messagePart.charAt(i));

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
					keyMsg = "";
					numMsgP++;
				}
			}
		}
		encField2Old = encField2;
		for (int k = 0; k < numMsgP; k++) {
			String operationMsg = findOperation(keyFieldMsg[k], message.getActorfrom(), message.getActorTo(),m);
			String changValueEve;
			
			if (debug ) System.out.println("determinesOperation keyFieldMsg[k] " + keyFieldMsg[k]);
			
			if (debug) {
				System.out.println(" actorStartProtocol " + actorStartProtocol + " - " + message.getActorTo() + " !actorStartProtocol.equals(message.getActorTo()) " + !actorStartProtocol.equals(message.getActorTo()));
			}
			if (!actorStartProtocol.equals(message.getActorTo())) {
				if (receiverAG_B) {
					changValueEve = findValueHonest(changNumMSG[m],
							keyFieldMsg[k],keyFieldMsg[k],
							message.getActorfrom());
	//				changValueEve = findValueHonest(changNumMSG[m],
	//						findKeyEle(keyFieldMsg[k], message.getActorfrom(), message.getActorTo(), false),keyFieldMsg[k],
	//						message.getActorTo()).replace("($e", "(self");
					if (debug) System.out.println("determinesOperation1 changValueEve " + changValueEve);

				} else {
					if (debug)
						System.out.println(" changValueEve 1 " + m + " " + changNumMSG[m] + " keyFieldMsg[k] "+ keyFieldMsg[k]);
					changValueEve = changValueEve(keyFieldMsg[k], message.getActorfrom(),message.getActorTo(), true, changNumMSG[m],m)
 							;
	//				changValueEve = changValueEve(keyFieldMsg[k], message.getActorfrom(),message.getActorTo(), true, changNumMSG[m],m)
 	//						.replace("($e", "(self");
					if (debug) System.out.println("determinesOperation2 changValueEve " + changValueEve);

				}
 				//changValueEve = changValueEve.replace(",self", ",$e");
 				//changValueEve = changValueEve.replace("($b", "(self");
				//if (m==3)
				//	System.out.println(" changValueEve33 " + changValueEve + " " + m + " " + changNumMSG[m]);
			
			} else {
				if (debug)
					System.out.println(" receiverAG_B " + receiverAG_B);
				if (receiverAG_B) {
					changValueEve = findValueHonest(changNumMSG[m],
							findKeyEle(keyFieldMsg[k], message.getActorfrom(), message.getActorTo(), false),keyFieldMsg[k],
							message.getActorTo());
					if (debug)
						System.out.println(" changValueEve1 " + changValueEve + " " + m + " " + changNumMSG[m]);
				} else {
					changValueEve = changValueEve(keyFieldMsg[k], message.getActorTo(),message.getActorfrom(), true, changNumMSG[m],m);
					if (debug)
						System.out.println(" changValueEve2 " + changValueEve + " " + m + " " + changNumMSG[m]);
				}
 				changValueEve = changValueEve.replace("($b", "($e");
				if (debug)
					System.out.println(" changValueEve3 " + changValueEve + " " + m + " " + changNumMSG[m]);
			}
			 
			
			if (k < numMsgP - 1 && (operationMsg.equals("asymEnc") || operationMsg.equals("symEnc")
					|| operationMsg.equals("sign"))) {
				if (debug) {System.out.println(" determina operazione "+ operationMsg + " " + changNumMSG[m] + " " + changValueEve + " keyFieldMsg[k] " + keyFieldMsg[k]);}
				bAsm.write("			            " + operationMsg + "(" + changNumMSG[m] + ","
						+ msgEncField1EncField2[k] + "):=" + changValueEve + "\n");
				bNuSmv.write("			            " + operationMsg + "(" + changNumMSG[m] + ","
						+ msgEncField1EncField2[k] + "):=" + changValueEve.replace("self", self).replace("$a", dollaroA).replace("$b", dollaroB).replace("$t", dollaroT).replace("$e", dollaroE).replace("$f", dollaroF) + "\n");

				operationMessage[numOperationMessage] = reversOperation(operationMsg,"decod") + "(" + changNumMSG[m] + ","
						+ msgEncField1EncField2[k] + ",self):= true";
				numOperationMessage++;
			} else {
				if (debug) {System.out.println(" determina operazione2 "+ operationMsg + " " + changNumMSG[m] + " " + changValueEve + " keyFieldMsg[k] " + keyFieldMsg[k]);}
				bAsm.write("			            " + reversOperation(operationMsg,"encod") + "(" + changNumMSG[m] + ","
						+ msgEncField1EncField2[k] + "):=" + changValueEve + "\n");
				operationMessage[numOperationMessage] = operationMsg + "(" + changNumMSG[m] + ","
						+ msgEncField1EncField2[k] + ",self):= true";
				numOperationMessage++;
				bNuSmv.write("			            " + reversOperation(operationMsg,"encod") + "(" + changNumMSG[m] + ","
							+ msgEncField1EncField2[k] + "):=" + changValueEve.replace("self", self).replace("$a", dollaroA).replace("$b", dollaroB).replace("$t", dollaroT).replace("$e", dollaroE).replace("$f", dollaroF) + "\n");
			}
		}
		 
	}

	// routin che server per determinare di quanti field si compone il messaggio e
	// quanti livelli di cripr/encript ci sono
	private String[] writeKnowledge(Message message, int numMessage, String[] msgField, String typeActor, boolean add)
			throws IOException {
		int numMessagePrec = 0;
		if (numMessage > 0) {
			numMessagePrec = numMessage;
		}
		if (debug)
			System.out.println(" entro in  writeKnowledge " + KeyActorFrom + "  " + KeyActorTo);
		String[] linesKnowledge = new String[50];
		linesKnowledge[0] = "Prot	protocolMessage("+numMessage+",self,$b):=" + changNumMSG[numMessage] + "\n";
		Boolean flgAtorTo = true;
		int numRighe = 1;
		if (debug)
			System.out.println("writeKnowledge actorTo " + message.getActorTo());
		if (debug){
			System.out.println (" *--------  elenco field ---------*");
			for (String e : msgField) {
				System.out.println (e);
			}
			System.out.println (" *--------  ------------ ---------*");

		}
		for (int i = 0; i < 15; i++) {
			if (msgField[i] != null) {
				if (debug)
					System.out.println("writeKnowledge msgField[i] " + i + " - " + msgField[i]);
				String typeFieldActorFrom = KeyActorFrom.searchEle(msgField[i],numMessage);
				if (debug)
					System.out.println("writeKnowledge typeFieldActorFrom1 " + typeFieldActorFrom);
				if (typeFieldActorFrom == null) {
					flgAtorTo = false;
					typeFieldActorFrom = KeyActorTo.searchEle(msgField[i],numMessage);
					if (debug)
						System.out.println("writeKnowledge typeFieldActorFrom2 " + typeFieldActorFrom);
					if (typeFieldActorFrom == null) {
						typeFieldActorFrom = "Other";
						otherElement.put(message.getActorfrom().substring(0, 1) + " " + msgField[i].toUpperCase(),
								message.getActorfrom().substring(0, 1) + " " + msgField[i].toUpperCase());
					}
				} else {
					KeyActorTo.addKnowAcq(msgField[i], typeFieldActorFrom, numMessagePrec);
				}
				if (debug)
					System.out.println("writeKnowledge typeFieldActorFrom3 " + typeFieldActorFrom);
				String eleEve = null;
				switch (typeFieldActorFrom) {
				case "Asymmetric Public Key":
					typeFieldActorFrom = "knowsAsymPubKey";
					eleEve = eve.getAsymmetricPublicKey().get(0);
					for (String e : eve.getAsymmetricPublicKey()) {
						if (KeyActorTo.searchEle(e,numMessage) != null) {
							if (debug)
								System.out.println("cerco chiave comune tra eve e actorTo" + e);
							eleEve = e;
							break;
						}
					}

					if (flgAtorTo) {
						attackerElement.put(message.getActorTo().substring(0, 1) + " " + msgField[i].toUpperCase(),
								"messageField($b,self," + i + "," + changNumMSG[numMessage] + ")");
					}
					break;
				case "Asymmetric Private Key":
					typeFieldActorFrom = "knowsAsymPrivKey";
					eleEve = eve.getAsymmetricPrivateKey().get(0);
					for (String e : eve.getAsymmetricPrivateKey()) {
						if (KeyActorTo.searchEle(e,numMessage) != null) {
							if (debug)
								System.out.println("cerco chiave comune tra eve e actorTo" + e);
							eleEve = e;
							break;
						}
					}

					if (flgAtorTo) {
						attackerElement.put(message.getActorTo().substring(0, 1) + " " + msgField[i].toUpperCase(),
								"messageField($b,self," + i + "," + changNumMSG[numMessage] + ")");
					}
					break;
				case "Symmetric Key":

					typeFieldActorFrom = "knowsSymKey";
					eleEve = eve.getSymmetricKey().get(0);
					for (String e : eve.getSymmetricKey()) {
						if (KeyActorTo.searchEle(e,numMessage) != null) {
							if (debug)
								System.out.println("cerco chiave comune tra eve e actorTo" + e);
							eleEve = e;
							break;
						}
					}
					if (debug)
						System.out.println("Esco da cercare chiave comune tra eve e actorTo" + eleEve);

					 
					if (flgAtorTo) {
						attackerElement.put(message.getActorTo().substring(0, 1) + " " + msgField[i].toUpperCase(),
								"messageField($b,self," + i + "," + changNumMSG[numMessage] + ")");
					}
					break;
				case "Signature Pub Key":
					typeFieldActorFrom = "knowsSignPubKey";
					eleEve = eve.getSignaturePubKey().get(0);
					for (String e : eve.getSignaturePubKey()) {
						if (KeyActorTo.searchEle(e,numMessage) != null) {
							if (debug)
								System.out.println("cerco chiave comune tra eve e actorTo" + e);
							eleEve = e;
							break;
						}
					}

					if (flgAtorTo) {
						attackerElement.put(message.getActorTo().substring(0, 1) + " " + msgField[i].toUpperCase(),
								"messageField($b,self," + i + "," + changNumMSG[numMessage] + ")");
					}
					break;
				case "Signature Priv Key":
					typeFieldActorFrom = "knowsSignPrivKey";
					eleEve = eve.getSignaturePrivKey().get(0);
					for (String e : eve.getSignaturePrivKey()) {
						if (KeyActorTo.searchEle(e,numMessage) != null) {
							if (debug)
								System.out.println("cerco chiave comune tra eve e actorTo" + e);
							eleEve = e;
							break;
						}
					}

					if (flgAtorTo) {
						attackerElement.put(message.getActorTo().substring(0, 1) + " " + msgField[i].toUpperCase(),
								"messageField($b,self," + i + "," + changNumMSG[numMessage] + ")");
					}
					break;
				case "Hash":
					typeFieldActorFrom = "knowsHash";
					eleEve = eve.getHashKey().get(0);
					for (String e : eve.getHashKey()) {
						if (KeyActorTo.searchEle(e,numMessage) != null) {
							if (debug)
								System.out.println("cerco chiave comune tra eve e actorTo" + e);
							eleEve = e;
							break;
						}
					}

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
/*					//System.out.println("Identity Certificate  msgField[i] " + msgField[i]);
					if (eve.getIdCertificate().get(0) != null) {
						//System.out.println("Identity Certificate  actorStartProtocol.contains(\"Alice\") " + actorStartProtocol.contains("Alice") + " alice.getIdCertificate().get(0).equals(msgField[i]) " + alice.getIdCertificate().get(0).equals(msgField[i]));
						if (actorStartProtocol.contains("Alice") && alice.getIdCertificate().get(0)!=null && alice.getIdCertificate().get(0).equals(msgField[i])) {
							eleEve = eve.getIdCertificate().get(0);
							break;
						}
						if (actorStartProtocol.contains("Bob") && bob.getIdCertificate().get(0)!=null && bob.getIdCertificate().get(0).equals(msgField[i])) {
							eleEve = eve.getIdCertificate().get(0);
							break;
						}
					}
*/					
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
				if (debug)
					System.out.println("writeKnowledge end case");

				linesKnowledge[numRighe] = "Know	" + typeFieldActorFrom + "(self,messageField(" + typeActor
						+ ",self," + i + "," + changNumMSG[numMessage] + ")):=true\n";
				numRighe++;
				linesKnowledge[numRighe] = "Kno3" + typeFieldActorFrom + "(self,messageField(" + typeActor
						+ ",self," + i + "," + changNumMSG[numMessagePrec] + ")):=true\n";
				numRighe++;
				if (debug)
					System.out.println("writeKnowledge add " + add);

				if (debug)
					System.out.println("writeKnowledge endadd " + add);
				if (add) {
					honestElement.put("E P " + message.getActorTo() + " Eve " + message.getActorfrom() + " " + numMessage + " " + msgField[i].toUpperCase()+ "-" + msgField[i].toUpperCase(),
						"messageField($e,agent"+ message.getActorTo().substring(0, 1) +"," + i + "," + changNumMSG[numMessage] + ")");
				}
				if (debug) {
					System.out.println("a    inserisco in honestElement  Key: " + "E P " + message.getActorTo() + " Eve " + message.getActorfrom() + " " + numMessage + " " + msgField[i].toUpperCase()+ "-" + msgField[i].toUpperCase()
							+ " --- VALORE -----   messageField($e,agent" + message.getActorTo().substring(0, 1) + ","
							+ i + "," + changNumMSG[numMessage] + ")");
				}
			
				linesKnowledge[numRighe] = "Mess	messageField(self,$b," + i + "," + changNumMSG[numMessage]
						+ "):=messageField(" + typeActor + ",self," + i + "," + changNumMSG[numMessage] + ")\n";
				numRighe++;
				if (debug)
					System.out.println("writeKnowledge eleEve " + eleEve);
				if (eleEve != null) {
					linesKnowledge[numRighe] = "Mes4	messageField(self,$b," + i + "," + changNumMSG[numMessage]
							+ "):=" + eleEve + "\n";
					numRighe++;
					if (add) {
						keychangEve.put(msgField[i].toUpperCase(), eleEve + " - " + message.getActorfrom());
					}
					linesKnowledge[numRighe] = "Mes3	messageField(self,$b," + i + "," + changNumMSG[0]
							+ "):=messageField(" + typeActor + ",self," + i + "," + changNumMSG[numMessage] + ")\n";
					linesKnowledge[numRighe] = "Mes5	messageField(self,$b," + i + "," + changNumMSG[numMessage]
							+ "):=messageField(" + typeActor + ",self," + i + "," + changNumMSG[numMessage] + ")\n";
					numRighe++;
					if (add) {
					honestElement.put(
							"E A " + message.getActorTo() + " Eve " + message.getActorfrom() + " " + numMessage + " "
									+ eleEve.toUpperCase() + "-" + msgField[i].toUpperCase(),
							"messageField($e,agent" + message.getActorTo().substring(0, 1) + "," + i + ","
									+ changNumMSG[numMessage] + ")");
					}
					if (debug) {
						System.out.println("b    inserisco in honestElement  Key: " + "E A " + message.getActorTo()
								+ " Eve " + message.getActorfrom() + " " + numMessage + " " + eleEve.toUpperCase() + "-"
								+ msgField[i].toUpperCase() + " --- VALORE -----   messageField($e,agent"
								+ message.getActorTo().substring(0, 1) + "," + i + "," + changNumMSG[numMessage] + ")");
					}

				} else {
					if (add) {
						honestElement.put(
								"E A " + message.getActorTo()+ " Eve " + message.getActorfrom() + " " + numMessage
										+ " " + msgField[i].toUpperCase() + "-" + msgField[i].toUpperCase(),
								"messageField($e,agent" + message.getActorTo().substring(0, 1) + "," + i + ","
										+ changNumMSG[numMessage] + ")");
						if (debug) {
							System.out.println("c    inserisco in honestElement  Key: " + "E A " + message.getActorTo()
									+ " Eve " + message.getActorfrom() + " " + numMessage + " "
									+ msgField[i].toUpperCase() + "-" + msgField[i].toUpperCase()
									+ " --- VALORE -----   messageField($e,agent" + message.getActorTo().substring(0, 1)
									+ "," + i + "," + changNumMSG[numMessage] + ")");
						}
					}
					linesKnowledge[numRighe] = "Mes2	messageField(self,$b," + i + "," + changNumMSG[numMessage]
							+ "):=messageField(" + typeActor + ",self," + i + "," + changNumMSG[numMessage] + ")\n";
					numRighe++;
					linesKnowledge[numRighe] = "Mes3	messageField(self,$b," + i + "," + changNumMSG[0]
							+ "):=messageField(" + typeActor + ",self," + i + "," + changNumMSG[numMessage] + ")\n";
					numRighe++;
				}
			}
		}
		if (debug)
			System.out.println("writeKnowledge esco  " + linesKnowledge);

		return linesKnowledge;
	}
	// routin che server per determinare di quanti field si compone il messaggio e
	// quanti livelli di cripr/encript ci sono

	// conta quanti campi contiene il sottomessaggio
	private int countLinesKnowledge(String val, String[] linesKnowledge) {
		int tot = 0;
		for (String e : linesKnowledge) {
			if (e != null && e.contains(val)) {
				tot++;
			}
		}
		return tot;
	}

	// conta quanti campi contiene il sottomessaggio
	private int countMsgFieldDet(String[] msgField) {
		int tot = 0;
		for (int i = 0; i < 15; i++) {
			if (msgField[i] != null) {
				tot++;
			}
		}
		return tot;
	}

	// stampa le informazioni registrate nelle fasi precedenti delle Know, field e
	// mess
	private void printKnowledge(BufferedWriter bAsm, String type, String[] linesKnowledge, String spaces)
			throws IOException {
		for (int i = 0; i < 50; i++) {
			if (linesKnowledge[i] != null && linesKnowledge[i].startsWith(type)) {
				bAsm.write(spaces + linesKnowledge[i].substring(4));
				bNuSmv.write(spaces + linesKnowledge[i].substring(4).replace("self", self).replace("$a", dollaroA).replace("$b", dollaroB).replace("$t", dollaroT).replace("$e", dollaroE).replace("$f", dollaroF));
			}
		}
	}


	// inverte decodicifa e codifica nell'operazione del messaggio
	private String reversOperation(String operation,String action) {

		if (operation != null) {
			if (action.equals("decod")) {
			switch (operation) {
			case "asymDec":
				return "asymDec";
			case "asymEnc":
				return "asymDec";
			case "symDec":
				return "symDec";
			case "symEnc":
				return "symDec";
			case "verifySign":
				return "verifySign";
			case "sign":
				return "verifySign";
			case "hash":
				return "hash";
			default:
				return null;
			}
			} else {
				switch (operation) {
				case "asymDec":
					return "asymEnc";
				case "asymEnc":
					return "asymEnc";
				case "symDec":
					return "symEnc";
				case "symEnc":
					return "symEnc";
				case "verifySign":
					return "sign";
				case "sign":
					return "sign";
				case "hash":
					return "hash";
				default:
					return null;
			}
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
		if (keyUsed.equals("KAB")) {System.out.println("findKeyEle keyUsed: " + keyUsed + " actorfrom: " + actorfrom + " reverse: " + reverse);}
		
			for (Map.Entry<String, String> entry : attackerElement.entrySet()) {
				if (entry.getKey().equals(actorfrom.substring(0, 1) + " " + keyUsed.toUpperCase())) {
					if (keyUsed.equals("KAB")) {
						System.out.println("findKeyEle trovato: " + entry.getValue());
					}
					return entry.getValue();
				}
			}
		
		if (reverse) {
			//if (eve.getSymmetricKey().get(0) != null) {
			//	keyUsed = eve.getSymmetricKey().get(0);
			//}
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
		if (keyUsed.equals("KAB")) {System.out.println("findKeyEle keyUsed trovato: " + keyUsed);}
		return keyUsed;
	}

	// Scrittura delle informazioni legate ai messaggi scambiati prendendo in
	// cosniderazione un eventuale attacco
	private void writeMessageHonest(BufferedWriter bAsm, BufferedWriter bNuSmv) throws IOException {
		if (debug) {
			System.out.println(" Entro writeMessageHonest");
		}
		bAsm.write("\n");
		bAsm.write("	/*HONEST AGENT RULES*/	\n");
		bNuSmv.write("\n");
		bNuSmv.write("	/*HONEST AGENT RULES*/	\n");
		System.out.println("/*HONEST AGENT RULES*/");

		// per ogni messaggio si scrivono le istruzioni per la parte onesta
		for (int i = 0; i < 15; i++) {
			Message message = messages.getMessage(i);
			if (message.getActorfrom() == null || message.getActorfrom().isEmpty()) {
				if (i > 0) {
					break;
				}
			}

			//
			// si estraggono i campi contenuti nel messaggio
			//
			String[] msgFieldTot = FindField(messages.getMessage(i).getPayload());

			// si scrive la rule del messaggio estraendo la descrizione del messaggio
			bAsm.write("	rule r_message_" + changNumMSG[i] + " =\n");
			bNuSmv.write("	rule r_message_" + changNumMSG[i] + " =\n");
			
			// si memorizza il nome della rule insieme all'attotr da cui parte il messaggio
			ruleR_Agent[indRuleR_Agent] = message.getActorfrom().toUpperCase().substring(0, 1) + " r_message_"
					+ changNumMSG[i] + "[]";
			indRuleR_Agent++;

			String appoActorFrom=new String();
			String appoActorTo=new String();			
			if (message.getActorfrom().equals("Eve")) {
				bAsm.write("		let ($b=agent" + message.getActorTo().toUpperCase().substring(0, 1) );
				bNuSmv.write("		let ($x=agentE,$b=agent" + message.getActorTo().toUpperCase().substring(0, 1) );
				appoActorFrom = "Eve";
				appoActorTo = message.getActorTo();
				dollaroX="EVE";
				dollaroB=message.getActorTo().toUpperCase();
				dollaroA="";
				dollaroT="";
				dollaroF="";
				self="EVE";
			} else {
				bAsm.write("		let ($e=agentE");
				bNuSmv.write("		let ($x=agent" + message.getActorfrom().toUpperCase().substring(0, 1) + ",$e=agentE");
				appoActorTo = "Eve";
				appoActorFrom = message.getActorfrom();
				dollaroX=message.getActorfrom().toUpperCase();
				dollaroB="";
				dollaroA="";
				dollaroT="";
				dollaroF="";
				dollaroE="EVE";
				self=message.getActorfrom().toUpperCase();
			}
			
			String actorFromPrev=new String();
			String actorToPrev=new String();
			String appoActorFromPrev=new String();
			String appoActorToPrev=new String();

			if (i > 0) {
				appoActorFromPrev = messages.getMessage(i - 1).getActorfrom();
				appoActorToPrev = messages.getMessage(i - 1).getActorTo();
				if (!messages.getMessage(i - 1).getActorfrom().equals("Eve")
						&& !messages.getMessage(i - 1).getActorTo().equals("Eve")) {
					appoActorFromPrev = "Eve";
				} 
			}

			if (i > 0) {
				if (debug) {
					System.out.println("************************");
					System.out.println("appoActorFrom " + appoActorFrom);
					System.out.println("appoActorTo " + appoActorTo);
					System.out.println("messages.getMessage(i).getActorfrom() " + messages.getMessage(i).getActorfrom());
					System.out.println("messages.getMessage(i).getActorTo() " + messages.getMessage(i).getActorTo());
					System.out.println("appoActorFromPrev " + appoActorFromPrev);
					System.out.println("appoActorToPrev " + appoActorToPrev);
					System.out.println("messages.getMessage(i -1).getActorfrom() " + messages.getMessage(i -1).getActorfrom());
					System.out.println("messages.getMessage(i -1).getActorTo() " + messages.getMessage(i-1).getActorTo());
				}
				if (appoActorTo.equals(appoActorToPrev)) {
					actorToPrev = "$e";
				}
				if (appoActorFrom.equals(appoActorToPrev)) {
					actorToPrev = "self";
				}
				if (appoActorTo.equals(appoActorFromPrev)) {
					actorFromPrev = "$e";
				}
				if (appoActorFrom.equals(appoActorFromPrev)) {
					actorFromPrev = "self";
				}
				if (actorToPrev == null || actorToPrev.isEmpty()) {
					actorToPrev = "$t";
					dollaroT=appoActorToPrev.toUpperCase();
					bAsm.write(",$t=agent" + appoActorToPrev.toUpperCase().substring(0, 1));
					bNuSmv.write(",$t=agent" + appoActorToPrev.toUpperCase().substring(0, 1));
					if (debug) {
						System.out.println("----------------------");
						System.out.println(
								"messages.getMessage(i - 1).getActorTo() " + messages.getMessage(i - 1).getActorTo());
						System.out.println("messages.getMessage(i - 1).getActorfrom() "
								+ messages.getMessage(i - 1).getActorfrom());
						System.out.println(
								"messages.getMessage(i).getActorfrom() " + messages.getMessage(i).getActorfrom());
						System.out
								.println("messages.getMessage(i).getActorTo() " + messages.getMessage(i).getActorTo());
						System.out.println(",$t=agent" + appoActorToPrev.toUpperCase().substring(0, 1));
					}
				}
				if (actorFromPrev == null || actorFromPrev.isEmpty()) {
					actorFromPrev = "$f";
					dollaroF=appoActorFromPrev.toUpperCase();
					bAsm.write(",$f=agent" + appoActorFromPrev.toUpperCase().substring(0, 1));					
					bNuSmv.write(",$f=agent" + appoActorFromPrev.toUpperCase().substring(0, 1));					
					if (debug) {
						System.out.println("=======================");
						System.out.println("messages.getMessage(i - 1).getActorTo() " + messages.getMessage(i - 1).getActorTo());
						System.out.println("messages.getMessage(i - 1).getActorfrom() " + messages.getMessage(i - 1).getActorfrom());
						System.out.println("messages.getMessage(i).getActorfrom() " + messages.getMessage(i).getActorfrom());
						System.out.println("messages.getMessage(i).getActorTo() " + messages.getMessage(i).getActorTo());
						System.out.println(",$f=agent" + appoActorFromPrev.toUpperCase().substring(0, 1));
					}
				}
			}
			
			bAsm.write(") in\n");
			bNuSmv.write(") in\n");
			// si estraggono le sotto-parti del payload
			String[] listSubPayload = findMsg(message.getPayload());
			
			if (!(message.getActorTo().equals("Eve") || message.getActorfrom().equals("Eve"))) {
				if (i == 0) {
					firstMessageHonest(bAsm, listSubPayload, msgFieldTot, message, i);
				} else {
					otherMessageHonest(bAsm, listSubPayload, msgFieldTot, message, i, actorFromPrev, actorToPrev);
				}
			} else {
				if (i == 0) {
					eveFirstMessage(bAsm, listSubPayload, msgFieldTot, message, i);
				} else {
					eveOtherMessage(bAsm, bNuSmv, listSubPayload, msgFieldTot, message, i, actorFromPrev, actorToPrev);
				}
			}
			
		}
	}

	// Si scrivono le informazioni del primo messaggio se il mittente o destinatario è eve
	private void eveFirstMessage(BufferedWriter bAsm, String[] listSubPayload, String[] msgFieldTot, Message message,
			int i) throws IOException {
		if (debug) {
			System.out.println("eveFirstMessager leggo il messaggio numero " + i);
		}
		int endMsgDet=1;
		for (int j = 0; j < 15; j++) {
			if (listSubPayload[j] == null || listSubPayload[j].isEmpty()) {
				break;
			}
			String keyUsed = findKey(listSubPayload[j]);
			String operation = "";

			if (keyUsed != null) {
				operation = findOperation(keyUsed, message.getActorfrom(), message.getActorTo(),i);
			} else {
				findActorFromTo(message.getActorfrom(), message.getActorTo());
			}
			String[] msgEncField1EncField2 = new String[15];
			String[] msgField = new String[15];
			String levelEncField1EncField2 = calcLevelEncField1EncField2(listSubPayload[j], msgEncField1EncField2,
					msgField, msgFieldTot);
			String[] msgFieldDet = detField(msgField, msgFieldTot, endMsgDet);
			endMsgDet = contMsgFielDet(msgFieldDet);
			actorStartProtocol = message.getActorfrom();
			actorReceiveProtocol = message.getActorTo();
			bAsm.write("			if(internalState" + message.getActorfrom().substring(0, 1) + "(self)=IDLE_"
					+ changNumMSG[i] + ")then \n");
			bAsm.write("			     par\n");
			bAsm.write("			         protocolMessage("+i+",self,$e):=" + changNumMSG[i] + "\n");
			bNuSmv.write("			if(internalState" + message.getActorfrom().substring(0, 1) + "=IDLE_"
					+ changNumMSG[i] + ")then \n");
			bNuSmv.write("			     par\n");
			bNuSmv.write("			         protocolMessage("+i+","+self+","+dollaroE+"):=" + changNumMSG[i] + "\n");
 
			for (int k = 0; k < 15; k++) {
				if (msgFieldDet[k] != null) {
					bAsm.write("			         messageField(self,$e,"
							+ k + "," + changNumMSG[i] + "):=" + findValueHonest(changNumMSG[0],
									msgFieldDet[k].toUpperCase(), msgFieldDet[k].toUpperCase(), message.getActorfrom())
							+ "\n");
					bNuSmv.write("			         messageField($x,$e,"
							+ k + "," + changNumMSG[i] + "):=" + findValueHonest(changNumMSG[0],
									msgFieldDet[k].toUpperCase(), msgFieldDet[k].toUpperCase(), message.getActorfrom()).replace("self", self).replace("$a", dollaroA).replace("$b", dollaroB).replace("$t", dollaroT).replace("$e", dollaroE).replace("$f", dollaroF)
							+ "\n");
					honestElement.put(
							"E X "+message.getActorTo() + " Eve " + message.getActorfrom() + " " + i + " "
									+ msgFieldDet[k].toUpperCase() + "-" + msgFieldDet[k].toUpperCase(),
							"messageField(agent" + message.getActorfrom().substring(0, 1) + ",$e," + k + ","
									+ changNumMSG[i] + ")");
					honestElement.put(
							message.getActorTo() + " Eve " + message.getActorfrom() + " " + i + " "
									+ msgFieldDet[k].toUpperCase() + "-" + msgFieldDet[k].toUpperCase(),
							"messageField(agent" + message.getActorfrom().substring(0, 1) + ",$e," + k + ","
									+ changNumMSG[i] + ")");
					if (debug) {
						System.out.println("eveFirstMessage da 5 k "+ k + " " + msgFieldDet[k] + "    inserisco in honestElement  Key: E X "
								+ message.getActorTo() + " Eve " + message.getActorfrom() + " " + i + " "
								+ msgFieldDet[k].toUpperCase() + "-" + msgFieldDet[k].toUpperCase()
								+ " --- VALORE -----   messageField(agent" + message.getActorfrom().substring(0, 1)
								+ ",$e," + k + "," + changNumMSG[i] + ")");
					}

					 
					if (debug) {
						System.out.println("eveFirstMessage ramo non Eve- Inserisco in  honestElement:  kiave "
								+ message.getActorTo().substring(0, 1) + " " + msgFieldDet[k].toUpperCase()
								+ " --- Valore " + "messageField($e,agent" + message.getActorTo().substring(0, 1) + ","
								+ k + "," + changNumMSG[i] + ")");
					}
					 
				}
			}
			if (operation != null && !operation.isEmpty()) {
				bAsm.write("			         " + reversOperation(operation, "encod") + "(" + changNumMSG[i] + ","
						+ levelEncField1EncField2 + "):="
						+ findValueHonest(changNumMSG[0],
								findKeyEle(keyUsed, message.getActorfrom(), message.getActorTo(), false), keyUsed,
								message.getActorTo())
						+ "\n");
				bNuSmv.write("			         " + reversOperation(operation, "encod") + "(" + changNumMSG[i] + ","
						+ levelEncField1EncField2 + "):="
						+ findValueHonest(changNumMSG[0],
								findKeyEle(keyUsed, message.getActorfrom(), message.getActorTo(), false), keyUsed,
								message.getActorTo()).replace("self", self).replace("$a", dollaroA).replace("$b", dollaroB).replace("$t", dollaroT).replace("$e", dollaroE).replace("$f", dollaroF)
						+ "\n");
			}
			
			String nextState = findNextState(messages, i);
			bAsm.write("			            internalState" + message.getActorfrom().substring(0, 1) + "(self):="
					+ nextState + "\n");
			bNuSmv.write("			            internalState" + message.getActorfrom().substring(0, 1) + ":="
					+ nextState + "\n");
			bAsm.write("			     endpar\n");
			bNuSmv.write("			     endpar\n");
	bAsm.write("			endif\n");
	bAsm.write("		endlet\n");
	bNuSmv.write("			endif\n");
	bNuSmv.write("		endlet\n");
}
	}
	// Si scrivono le informazioni del primo messaggio
	private void firstMessageHonest(BufferedWriter bAsm, String[] listSubPayload, String[] msgFieldTot, Message message,
			int i) throws IOException {
		int endMsgDet=1;
		for (int j = 0; j < 15; j++) {
			if (listSubPayload[j] == null || listSubPayload[j].isEmpty()) {
				break;
			}
			String keyUsed = findKey(listSubPayload[j]);
			String operation = "";

			if (keyUsed != null) {
				operation = findOperation(keyUsed, message.getActorfrom(), message.getActorTo(),i);
			} else {
				findActorFromTo(message.getActorfrom(), message.getActorTo());
			}
			String[] msgEncField1EncField2 = new String[15];
			String[] msgField = new String[15];
			String levelEncField1EncField2 = calcLevelEncField1EncField2(listSubPayload[j], msgEncField1EncField2,
					msgField, msgFieldTot);
			String[] msgFieldDet = detField(msgField, msgFieldTot, endMsgDet);
			endMsgDet = contMsgFielDet(msgFieldDet);
			actorStartProtocol = message.getActorfrom();
			actorReceiveProtocol = message.getActorTo();
			bAsm.write("			if(internalState" + message.getActorfrom().substring(0, 1) + "(self)=IDLE_"
					+ changNumMSG[i] + ")then \n");
			bNuSmv.write("			if(internalState" + message.getActorfrom().substring(0, 1) + "=IDLE_"
					+ changNumMSG[i] + ")then \n");
//					bAsm.write("			        if(receiver=AG_" + message.getActorTo().substring(0, 1) + ")then\n");
			bAsm.write("			   if(receiver!=AG_E)then\n");
			bAsm.write("			     par\n");
			bAsm.write("			         protocolMessage("+i+",self,$e):=" + changNumMSG[i] + "\n");
			bNuSmv.write("			   if(receiver!=AG_E)then\n");
			bNuSmv.write("			     par\n");
			bNuSmv.write("			         protocolMessage("+i+","+self+","+dollaroE+"):=" + changNumMSG[i] + "\n");

			for (int k = 0; k < 15; k++) {
				if (msgFieldDet[k] != null) {
					bAsm.write("			         messageField(self,$e," + k + "," + changNumMSG[i] + "):="
							+ findValueHonest(changNumMSG[0],msgFieldDet[k].toUpperCase(),msgFieldDet[k].toUpperCase(), message.getActorfrom()) + "\n");
					bNuSmv.write("			         messageField("+self+","+dollaroE+"," + k + "," + changNumMSG[i] + "):="
							+ findValueHonest(changNumMSG[0],msgFieldDet[k].toUpperCase(),msgFieldDet[k].toUpperCase(), message.getActorfrom()).replace("self", self).replace("$a", dollaroA).replace("$b", dollaroB).replace("$t", dollaroT).replace("$e", dollaroE).replace("$f", dollaroF)+ "\n");
					honestElement.put("E Y "+message.getActorTo() + " Eve " + message.getActorfrom() + " " + i + " " + msgFieldDet[k].toUpperCase()+ "-" + msgFieldDet[k].toUpperCase(),
							"messageField(agent"+ message.getActorfrom().substring(0, 1) +",$e," + k + "," + changNumMSG[i] + ")");
					honestElement.put(message.getActorTo() + " Eve " + message.getActorfrom() + " " + i + " " + msgFieldDet[k].toUpperCase()+ "-" + msgFieldDet[k].toUpperCase(),
							"messageField(agent"+ message.getActorfrom().substring(0, 1) +",$e," + k + "," + changNumMSG[i] + ")");

					if (debug) {
						System.out.println("da 5 k "+ k+ " " +msgFieldDet[k] + "    inserisco in honestElement  Key: " + message.getActorTo() + " Eve "
								+ message.getActorfrom()+ " " + i + " " + msgFieldDet[k].toUpperCase()+ "-" + msgFieldDet[k].toUpperCase()
								+ " --- VALORE -----   messageField(agent" + message.getActorfrom().substring(0, 1)
								+ ",$e," + k + "," + changNumMSG[i] + ")");
					}
 
					if (debug) {System.out.println("firstMessageHonest ramo non Eve- Inserisco in  honestElement:  kiave " + message.getActorTo().substring(0, 1) + " " + msgFieldDet[k].toUpperCase() + " --- Valore " + "messageField($e,agent"+ message.getActorTo().substring(0, 1) +"," + k + "," + changNumMSG[i] + ")");}
				}
			}
			if (operation != null && !operation.isEmpty()) {
				bAsm.write("			         " + reversOperation(operation,"encod") + "(" + changNumMSG[i] + ","
						+ levelEncField1EncField2 + "):="
						+ findValueHonest(changNumMSG[0],findKeyEle(keyUsed, message.getActorfrom(), message.getActorTo(), false),keyUsed,
								message.getActorTo())
						+ "\n");
				bNuSmv.write("			         " + reversOperation(operation,"encod") + "(" + changNumMSG[i] + ","
						+ levelEncField1EncField2 + "):="
						+ findValueHonest(changNumMSG[0],findKeyEle(keyUsed, message.getActorfrom(), message.getActorTo(), false),keyUsed,
								message.getActorTo()).replace("self", self).replace("$a", dollaroA).replace("$b", dollaroB).replace("$t", dollaroT).replace("$e", dollaroE).replace("$f", dollaroF)
						+ "\n");
			}

/*
			if (messages.getMessage(i + 1).getActorTo() != null && !messages.getMessage(i + 1).getActorTo().isEmpty()) {
				
		
				String nextState = findNextState(messages,i);
				bAsm.write("			         internalState" + message.getActorfrom().substring(0, 1) + "(agent"
						+ message.getActorfrom().substring(0, 1) + "):="+ nextState
						+ "\n");
				
			}
*/
			String nextState = findNextState(messages,i);
			bAsm.write("			         internalState" + message.getActorfrom().substring(0, 1) + "(self):="+ nextState + "\n");
			bNuSmv.write("			         internalState" + message.getActorfrom().substring(0, 1) + ":="+ nextState + "\n");

			
			bAsm.write("			     endpar\n");
			bAsm.write("			   else\n");
			bAsm.write("			       if(receiver=AG_E)then\n");
			bAsm.write("			         par\n");
			bAsm.write("			            protocolMessage("+i+",self,$e):=" + changNumMSG[i] + "\n");
			
			bNuSmv.write("			     endpar\n");
			bNuSmv.write("			   else\n");
			bNuSmv.write("			       if(receiver=AG_E)then\n");
			bNuSmv.write("			         par\n");
			bNuSmv.write("			            protocolMessage("+i+","+self+","+dollaroE+"):=" + changNumMSG[i] + "\n");
			if (debug) {
				System.out.println("sono nel primo messaggio e nel ramo AG_E");
			}
			for (int k = 0; k < 15; k++) {
				if (msgFieldDet[k] != null) {
					if (debug) {
						System.out.println("    leggo il campo " + msgFieldDet[k]);
					}
					bAsm.write("			            messageField(self,$e," + k + "," + changNumMSG[i]
							+ "):=" + changValueEve(msgFieldDet[k], message.getActorfrom(),message.getActorTo(), true, changNumMSG[i],i)
							+ "\n");
					bNuSmv.write("			            messageField("+self+","+dollaroE+"," + k + "," + changNumMSG[i]
							+ "):=" + changValueEve(msgFieldDet[k], message.getActorfrom(),message.getActorTo(), true, changNumMSG[i],i).replace("self", self).replace("$a", dollaroA).replace("$b", dollaroB).replace("$t", dollaroT).replace("$e", dollaroE).replace("$f", dollaroF)
							+ "\n");
 					honestElement.put("E Z "+message.getActorTo() + " Eve " +message.getActorfrom() +  " " + i + " " + changValueEve(msgFieldDet[k], message.getActorfrom(), message.getActorTo(),false, changNumMSG[i],i).toUpperCase()+ "-"+ msgFieldDet[k].toUpperCase(),
 							"messageField(agent"+ message.getActorfrom().substring(0, 1)  + ",$e," + k + "," + changNumMSG[i] + ")");
 					
 					if (debug) {
						System.out.println("da 4 k "+ k+ " " + msgFieldDet[k] + "    inserisco in honestElement  Key: E Z "+message.getActorTo() + " Eve " +message.getActorfrom() +  " " + i + " " + changValueEve(msgFieldDet[k], message.getActorfrom(), message.getActorTo(),false, changNumMSG[i],i).toUpperCase()+ "-"+ msgFieldDet[k].toUpperCase()
										
								+ " --- VALORE -----   messageField(agent"+ message.getActorfrom().substring(0, 1)  + ",$e," + k + "," + changNumMSG[i] + ")");
 					}
 					honestElement.put(message.getActorTo() + " Eve " +message.getActorfrom() +  " " + i + " " + changValueEve(msgFieldDet[k], message.getActorfrom(), message.getActorTo(),false, changNumMSG[i],i).toUpperCase()+ "-"+ msgFieldDet[k].toUpperCase(),
 							"messageField(agent"+ message.getActorfrom().substring(0, 1)  + ",$e," + k + "," + changNumMSG[i] + ")");

 					if (debug) {
						System.out.println("da 4 k "+ k+ " " + msgFieldDet[k] + "    inserisco in honestElement  Key: " + message.getActorTo() + " Eve "
								+ message.getActorfrom() + " " + i + " "
								+ changValueEve(msgFieldDet[k], message.getActorfrom(), message.getActorTo(),false, changNumMSG[i],i)
										.toUpperCase() + "-"+ msgFieldDet[k].toUpperCase()
								+ " --- VALORE -----   messageField(agent" + message.getActorTo().substring(0, 1)
								+ ",$e," + k + "," + changNumMSG[i] + ")");
					}
					if (debug) {System.out.println("firstMessageHonest ramo Eve - Inserisco in  honestElement:  kiave " +"E" + " " + changValueEve(msgFieldDet[k], message.getActorfrom(),message.getActorTo(), false, changNumMSG[i],i)
					.toUpperCase() + "  --------- Valore " + "messageField($e,agent"+ message.getActorfrom().substring(0, 1)  + "," + k + "," + changNumMSG[i] + ")");}
				}
			}
			if (operation != null && !operation.isEmpty()) {
				bAsm.write("			            " + reversOperation(operation,"encod") + "(" + changNumMSG[i]
						+ "," + levelEncField1EncField2 + "):="
						+ changValueEve(keyUsed, message.getActorfrom(),message.getActorTo(), true, changNumMSG[i],i).toUpperCase() + "\n");
				bNuSmv.write("			            " + reversOperation(operation,"encod") + "(" + changNumMSG[i]
						+ "," + levelEncField1EncField2 + "):="
						+ changValueEve(keyUsed, message.getActorfrom(),message.getActorTo(), true, changNumMSG[i],i).replace("self", self).replace("$a", dollaroA).replace("$b", dollaroB).replace("$t", dollaroT).replace("$e", dollaroE).replace("$f", dollaroF).toUpperCase() + "\n");

				if (debug) {
					System.out.println("    operazione : " + operation + " Reverse " + reversOperation(operation,"encod")
							+ "  Kiave opriginale " + keyUsed + " Chiave rivista "
							+ changValueEve(keyUsed, message.getActorfrom(),message.getActorTo(), true, changNumMSG[i],i).toUpperCase());
				}
			}
/*
			if (messages.getMessage(i + 1).getActorTo() != null && !messages.getMessage(i + 1).getActorTo().isEmpty()) {

				String nextState = findNextState(messages,i);
				bAsm.write("			            internalState" + message.getActorfrom().substring(0, 1) + "(agent"
						+ message.getActorfrom().substring(0, 1) + "):="+ nextState
						+ "\n");
				
			}
*/		
			nextState = findNextState(messages,i);
			bAsm.write("			            internalState" + message.getActorfrom().substring(0, 1) + "(self):="+ nextState + "\n");
			bNuSmv.write("			            internalState" + message.getActorfrom().substring(0, 1) + ":="+ nextState + "\n");
			
			bAsm.write("			         endpar\n");
			bAsm.write("			       endif\n");
			bAsm.write("			   endif\n");
			bAsm.write("			endif\n");
			bAsm.write("		endlet\n");
			bNuSmv.write("			         endpar\n");
			bNuSmv.write("			       endif\n");
			bNuSmv.write("			   endif\n");
			bNuSmv.write("			endif\n");
			bNuSmv.write("		endlet\n");
		}
	}
	// Si scrivono le informazioni successive al primo messaggio se il mittente o destinatario è eve
	private void eveOtherMessage(BufferedWriter bAsm, BufferedWriter bNuSmv,String[] listSubPayload, String[] msgFieldTot, Message message,
			int i, String actorFromPrev, String actorToPrev) throws IOException {
			boolean flgPar = false;
			if (debug) {
				System.out.println("eveOtherMessager leggo il messaggio numero" + i);
			}
			String sigleActTo = "$e";
			if (message.getActorfrom().equals("Eve")) {
				sigleActTo = "$b";
			}
			if (message.getActorfrom().equals("Eve") && actorFromPrev.equals("$e")) {
				actorFromPrev = sigleActTo;
			}
			bAsm.write("			if(internalState" + message.getActorfrom().substring(0, 1) + "(self)=WAITING_"
					+ changNumMSG[i] + " and protocolMessage("+(i-1)+","+ actorFromPrev+ "," + actorToPrev +")=" + changNumMSG[i - 1] + ")then\n");
			bNuSmv.write("			if(internalState" + message.getActorfrom().substring(0, 1) + "=WAITING_"
					+ changNumMSG[i] + " and protocolMessage("+(i-1)+","+ actorFromPrev.replace("self", self).replace("$a", dollaroA).replace("$b", dollaroB).replace("$t", dollaroT).replace("$e", dollaroE).replace("$f", dollaroF)+ "," + actorToPrev.replace("self", self).replace("$a", dollaroA).replace("$b", dollaroB).replace("$t", dollaroT).replace("$e", dollaroE).replace("$f", dollaroF) +")=" + changNumMSG[i - 1] + ")then\n");

			//---------------------------------------------------------
			int[] listMsgPrev = findMessagePrev(message.getActorfrom(), message.getActorTo(), i);
			int z = i - 1;
			int endMsgDet = 1;
			if (debug) {
				System.out.println("findMessagePrev sono uscito con " + listMsgPrev);
			}
			if (listMsgPrev == null) {
				if (debug) {
					System.out.println("findMessagePrev ramo null");
				}
				bAsm.write("			     par\n");
				bNuSmv.write("			     par\n");
			} else {
				if (debug) {
					System.out.println("findMessagePrev ramo non null " + listMsgPrev[0]);
				}
				for (int k = 0; k < 15; k++) {
					if (listMsgPrev[k] > 90)
						break;
					z = listMsgPrev[k];
					if (debug) {
						System.out.println("findMessagePrev k " + k + " " + listMsgPrev[k]);
					}

					// la prima parte delle istruzioni da scrivere riguardano quelle che permettono
					// di aggiornare le conoscenze dell'attore
					// che riceve il messaggio. per fare questo si deve vedere cosa riceve nel
					// messaggio precedente
					Message messagePrev = messages.getMessage(z);
					// dal messaggio precedente si estraggono i sott-ayload e l'elenco dei campi
					String[] listSubPayloadPrev = findMsg(messagePrev.getPayload());
					String[] msgFieldTotPrev = FindField(messages.getMessage(z).getPayload());

					if (debug) {
						System.out.println("2 payload prev z" + (z) + " " + messages.getMessage(z).getPayload());
					}
					// si impostano le classi dell'attore che trasmette il messaggio e quello che lo
					// riceve
					findActorFromTo(messagePrev.getActorfrom(), messagePrev.getActorTo());

					// Si verifica se la parte del messaggio è decodificabile altrimenti si leva
					// dall'elenco
					// del messaggio precedente

					String[] NewListSubPayloadPrev = new String[15];
					int indList = 0;
					// determino quali sono i campi del payload che possono essere letti
					// dall''attore che riceve il messaggio
					String newPayloadPrev = findNewPayloadPrev(indList, listSubPayloadPrev, msgFieldTotPrev,
							NewListSubPayloadPrev, z);
					if (debug) {
						System.out.println("2 NewPayloadPrev " + newPayloadPrev);
					}
					if (debug) {
						System.out.println("2 ------> NewListSubPayloadPrev <----------");
						for (String e : NewListSubPayloadPrev) {
							System.out.println("2 ------> " + e + " <-------------");
						}
					}

					// Si stabilisce l'elenco dei campi che sono conosciuti dall'attore che riceve
					// il messaggio
					msgFieldTotPrev = FindField(newPayloadPrev);
					if (debug) {
						System.out.println("2 ------> msgFieldTotPrev <----------");
						for (String e : msgFieldTotPrev) {
							System.out.println("2 ------> " + e + " <-------------");
						}
					}
					// si memorizzano l'elenco dei sotto-payload che l'attore che riceve il
					// messaggio puo decodificare
					listSubPayloadPrev = NewListSubPayloadPrev;
					if (debug) {
						System.out.println("2 ------> NewListSubPayloadPrev <----------");
						for (String e : listSubPayloadPrev) {
							System.out.println("2 ------> " + e + " <-------------");
						}
					}

					flgPar = false;
					// cerca tutti i field che sono in chiaro nel payload per poi scrive il
					// Knowledge
					String[] msgFieldPrevFree = finfFreeFieldPrev(listSubPayloadPrev, msgFieldTotPrev);
					for (String e : msgFieldPrevFree) {
						if (e != null) {
							flgPar = true;
							break;
						}
					}
					if (debug) {
						System.out.println("z5 ------> msgFieldPrevFree <----------");
						for (String e : msgFieldPrevFree) {
							System.out.println("z5 ------> " + e + " <-------------");
						}
					}

					if (flgPar) {
						String[] linesKnowledgePrevFree = writeKnowledge(messagePrev, (z), msgFieldPrevFree,
								actorFromPrev, false);
						if (debug) {
							System.out.println("z5 ------> linesKnowledgePrevFree <----------");
							for (String e : linesKnowledgePrevFree) {
								System.out.println("z5 ------> " + e + " <-------------");
							}
						}
						bAsm.write("			    par\n");
						bNuSmv.write("			    par\n");
						printKnowSubPayload(bAsm, bNuSmv, msgFieldPrevFree, msgFieldTotPrev, listSubPayloadPrev[0], messagePrev,
								(z), actorFromPrev, false, "Kno3", true);
					}

					// Si richiama la routine per scrivere le if delle operazioni di ogni singolo
					// sotto-payload
					//
					String[] msgFieldPrev = writeIfPayloadPrev(bAsm, messagePrev, message, i, z, listSubPayloadPrev,
							msgFieldTotPrev, "");
					if (debug) {
						System.out.println("z5 ------> msgFieldPrev <----------");
						for (String e : msgFieldPrev) {
							System.out.println("z5 ------> " + e + " <-------------");
						}
					}
					String[] msgFieldDetPrev = detField(msgFieldPrev, msgFieldTotPrev, 1);
					endMsgDet = contMsgFielDet(msgFieldDetPrev);
					if (debug) {
						System.out.println("z5 ------> msgFieldTotPrev <----------");
						for (String e : msgFieldTotPrev) {
							System.out.println("z5 ------> " + e + " <-------------");
						}
					}

					//
					// si inseriscono nell'array linesKnowledgePrev tutte le istruzioni per la
					// memorizzazione delle informazioni
					// Wnowledge , mesfielf etc.
					//
					if (debug) {
						System.out.println("writeKnowledge 10");
					}
					String[] linesKnowledgePrev = writeKnowledge(messagePrev, (z), msgFieldTotPrev, actorFromPrev,
							false);
					if (debug) {
						System.out.println("z5 ------> linesKnowledgePrev <----------");
						for (String e : linesKnowledgePrev) {
							System.out.println("z5 ------> " + e + " <-------------");
						}
					}

					String spaces = "			                      ";
					if (debug) {
						System.out.println("z5 printKnowledge ");
					}
					//
					// Si scrivono le istruzioni sulle conoscenze
					//
					if (debug) {
						System.out.println("printKnowSubPayload -->4");
					}
					printKnowSubPayload(bAsm, bNuSmv, msgFieldPrev, msgFieldTotPrev, listSubPayloadPrev[0], messagePrev, (z),
							actorFromPrev, false, "Kno3", true);
				}
			}
			// printKnowledge(bAsm, "Kno3", linesKnowledgePrev, spaces);
			bAsm.write("			            protocolMessage(" + i + ",self," + sigleActTo + "):=" + changNumMSG[i]
					+ "\n");
			bNuSmv.write("			            protocolMessage(" + i + ","+self+"," + sigleActTo.replace("self", self).replace("$a", dollaroA).replace("$b", dollaroB).replace("$t", dollaroT).replace("$e", dollaroE).replace("$f", dollaroF) + "):=" + changNumMSG[i]
					+ "\n");
			if (debug) {
				System.out.println("z6 findMsg ");
			}
			//
			// dopo aver analizzato il mesaggio precedente si tratta il messaggio attuale
			// per impostare le informazioni da inviare al destinatario
			//
			listSubPayload = findMsg(message.getPayload());
			if (debug) {
				System.out.println(
						"lista payload del messaggio numero " + i + " message.getPayload() " + message.getPayload());
				for (int k = 0; k < listSubPayload.length; k++) {
					if (listSubPayload[k] != null && !listSubPayload[k].isEmpty()) {
						System.out.println("otherMessagerHonest listSubPayload[" + k + "]=" + listSubPayload[k]);
					}
				}
			}
			if (debug) {System.out.println("writeInfoPayloadAct AG_X "   );}
			int delJ =writeInfoPayloadAct (bAsm,  message, i, listSubPayload,  msgFieldTot,"AG_X");

			String nextState = findNextState(messages,i);
			bAsm.write("			            internalState" + message.getActorfrom().substring(0, 1) + "(self):="+ nextState + "\n");
			bNuSmv.write("			            internalState" + message.getActorfrom().substring(0, 1) + ":="+ nextState + "\n");

			bAsm.write("			          endpar\n");
			bNuSmv.write("			          endpar\n");
			// se l'attore non ha la chiave per decifrare la parte del payload allora
			// si scrivono le istruzioni che non comprendono la memorizzazione della
			// conoscenza di quella parte del messaggio
			if (!fistOperation) {
				bAsm.write("			        endif\n");
				bNuSmv.write("			        endif\n");
			}
			if (flgPar) {
				flgPar=false;
				bAsm.write("			    endpar\n");
				bNuSmv.write("			    endpar\n");
			}
			bAsm.write("			   endif\n");
			bNuSmv.write("			   endif\n");

			nextState = findNextState(messages,i);
			//		+ message.getActorfrom().substring(0, 1) + "):="+ nextState
			//		+ "\n");
			if (messages.getMessage(i + 1).getActorfrom() == null || messages.getMessage(i + 1).getActorfrom().isEmpty())
					endMessage = true;
			bAsm.write("		endlet\n");
			bNuSmv.write("		endlet\n");
			
			if (endMessage) {
				ruleRCheck(bAsm,lastMsgAlice,i);
				ruleRCheck(bAsm,lastMsgBob,i);
				ruleRCheck(bAsm, lastMsgEve,i);
				ruleRCheck(bAsm,lastMsgServer,i);
			}
			
			
	}

	// si scrivono le informazioni su messaggi successivi al primo
	private void otherMessageHonest(BufferedWriter bAsm, String[] listSubPayload, String[] msgFieldTot, Message message,
			int i, String actorFromPrev, String actorToPrev) throws IOException {
		if (debug) {System.out.println("leggo il messaggio numero 3");}
		
		boolean flgPar = false;
		bAsm.write("			if(internalState" + message.getActorfrom().substring(0, 1) + "(self)=WAITING_"
				+ changNumMSG[i] + " and protocolMessage("+ (i-1)+","+ actorFromPrev+ "," + actorToPrev +")=" + changNumMSG[i - 1] + ")then\n");
		bNuSmv.write("			if(internalState" + message.getActorfrom().substring(0, 1) + "=WAITING_"
				+ changNumMSG[i] + " and protocolMessage("+ (i-1)+","+ actorFromPrev.replace("self", self).replace("$a", dollaroA).replace("$b", dollaroB).replace("$t", dollaroT).replace("$e", dollaroE).replace("$f", dollaroF)+ "," + actorToPrev.replace("self", self).replace("$a", dollaroA).replace("$b", dollaroB).replace("$t", dollaroT).replace("$e", dollaroE).replace("$f", dollaroF) +")=" + changNumMSG[i - 1] + ")then\n");

		// si scrivono le istruzioni quando il receiver non è l'agent Eve
		bAsm.write("			   if(receiver!=AG_E)then\n");
		bNuSmv.write("			   if(receiver!=AG_E)then\n");
		String actorFromPrevDet = actorToPrev;
		int[] listMsgPrev = findMessagePrev(message.getActorfrom(), message.getActorTo(), i);
		int z= i - 1;
		int endMsgDet=1;
		if (debug) {System.out.println ("findMessagePrev sono uscito con " + listMsgPrev);}
		if (listMsgPrev == null) {
			if (debug) {System.out.println ("findMessagePrev ramo null");}
			bAsm.write("			     par\n");
			bNuSmv.write("			     par\n");
		} else {
			if (debug) {System.out.println ("findMessagePrev ramo non null " + listMsgPrev[0]);}
			for (int k = 0; k < 15; k++) {
				if (listMsgPrev[k]>90) break;
				z = listMsgPrev[k];

			// la prima parte delle istruzioni da scrivere riguardano quelle che permettono
			// di aggiornare le conoscenze dell'attore
			// che riceve il messaggio. per fare questo si deve vedere cosa riceve nel
			// messaggio precedente
			Message messagePrev = messages.getMessage(z);
			if (!message.getActorTo().equals("Eve") && !message.getActorfrom().equals("Eve")) {
				actorFromPrevDet = "$e";
			}
			
			
			
			// dal messaggio precedente si estraggono i sott-ayload e l'elenco dei campi
			String[] listSubPayloadPrev = findMsg(messagePrev.getPayload());
			String[] msgFieldTotPrev = FindField(messages.getMessage(z).getPayload());

			if (debug) {
				System.out.println("2 payload prev z" + (z) + " " + messages.getMessage(z).getPayload());
			}
			// si impostano le classi dell'attore che trasmette il messaggio e quello che lo
			// riceve
			findActorFromTo(messagePrev.getActorfrom(), messagePrev.getActorTo());

			// Si verifica se la parte del messaggio è decodificabile altrimenti si leva
			// dall'elenco
			// del messaggio precedente

			String[] NewListSubPayloadPrev = new String[15];
			int indList = 0;
			// determino quali sono i campi del payload che possono essere letti
			// dall''attore che riceve il messaggio
			String newPayloadPrev = findNewPayloadPrev(indList, listSubPayloadPrev, msgFieldTotPrev,
					NewListSubPayloadPrev,z);
			if (debug) {
				System.out.println("2 NewPayloadPrev " + newPayloadPrev);
			}
			if (debug) {
				System.out.println("2 ------> NewListSubPayloadPrev <----------");
				for (String e : NewListSubPayloadPrev) {
					System.out.println("2 ------> " + e + " <-------------");
				}
			}


			// Si stabilisce l'elenco dei campi che sono conosciuti dall'attore che riceve
			// il messaggio
			msgFieldTotPrev = FindField(newPayloadPrev);
			if (debug) {
				System.out.println("2 ------> msgFieldTotPrev <----------");
				for (String e : msgFieldTotPrev) {
					System.out.println("2 ------> " + e + " <-------------");
				}
			}
			// si memorizzano l'elenco dei sotto-payload che l'attore che riceve il
			// messaggio puo decodificare
			listSubPayloadPrev = NewListSubPayloadPrev;
			if (debug) {
				System.out.println("2 ------> NewListSubPayloadPrev <----------");
				for (String e : listSubPayloadPrev) {
					System.out.println("2 ------> " + e + " <-------------");
				}
			}

			flgPar = false;
  			// cerca tutti i field che sono in chiaro nel payload per poi scrive il Knowledge
			String[] msgFieldPrevFree = finfFreeFieldPrev(listSubPayloadPrev,msgFieldTotPrev);
			for (String e : msgFieldPrevFree) {
				if (e != null) {
					flgPar = true;
					break;
				}
			}
			if (debug) {
				System.out.println("z5 ------> msgFieldPrevFree <----------");
				for (String e : msgFieldPrevFree) {
					System.out.println("z5 ------> " + e + " <-------------");
				}
			}
			
	 		if (flgPar){
				String[] linesKnowledgePrevFree = writeKnowledge(messagePrev, (z), msgFieldPrevFree, actorFromPrevDet,
						false);
				if (debug) {
					System.out.println("z5 ------> linesKnowledgePrevFree <----------");
					for (String e : linesKnowledgePrevFree) {
						System.out.println("z5 ------> " + e + " <-------------");
					}
				}
	 			bAsm.write("			    par\n");
	 			bNuSmv.write("			    par\n");
				printKnowSubPayload(bAsm, bNuSmv, msgFieldPrevFree, msgFieldTotPrev, listSubPayloadPrev[0], messagePrev, (z),
						actorFromPrevDet, false, "Kno3",true);
	 		}
		 
			
			// Si richiama la routine per scrivere le if delle operazioni di ogni singolo
			// sotto-payload
			//
			String[] msgFieldPrev = writeIfPayloadPrev(bAsm, messagePrev, message, i,z, listSubPayloadPrev, msgFieldTotPrev,
					"");
			if (debug) {
				System.out.println("z5 ------> msgFieldPrev <----------");
				for (String e : msgFieldPrev) {
					System.out.println("z5 ------> " + e + " <-------------");
				}
			}
			String[] msgFieldDetPrev = detField(msgFieldPrev, msgFieldTotPrev, 1);
			endMsgDet = contMsgFielDet(msgFieldDetPrev);
			if (debug) {
				System.out.println("z5 ------> msgFieldTotPrev <----------");
				for (String e : msgFieldTotPrev) {
					System.out.println("z5 ------> " + e + " <-------------");
				}
			}

			//
			// si inseriscono nell'array linesKnowledgePrev tutte le istruzioni per la
			// memorizzazione delle informazioni
			// Wnowledge , mesfielf etc.
			//
			if (debug) {System.out.println("writeKnowledge 10");}
			String[] linesKnowledgePrev = writeKnowledge(messagePrev, (z), msgFieldTotPrev, actorFromPrevDet, false);
			if (debug) {
				System.out.println("z5 ------> linesKnowledgePrev <----------");
				for (String e : linesKnowledgePrev) {
					System.out.println("z5 ------> " + e + " <-------------");
				}
			}

			String spaces = "			                      ";
			if (debug) {
				System.out.println("z5 printKnowledge ");
			}
			//
			// Si scrivono le istruzioni sulle conoscenze
			//
			if(debug) {System.out.println("printKnowSubPayload -->4");}
			printKnowSubPayload(bAsm, bNuSmv, msgFieldPrev, msgFieldTotPrev, listSubPayloadPrev[0], messagePrev, (z),
					actorFromPrevDet, false, "Kno3",true);
		}
		}
		//printKnowledge(bAsm, "Kno3", linesKnowledgePrev, spaces);
		bAsm.write("			            protocolMessage("+i+",self,$e):=" + changNumMSG[i] + "\n");
		bNuSmv.write("			            protocolMessage("+i+","+self+","+dollaroE+"):=" + changNumMSG[i] + "\n");
		if (debug) {
			System.out.println("z6 findMsg ");
		}
		//
		// dopo aver analizzato il mesaggio precedente si tratta il messaggio attuale
		// per impostare le informazioni da inviare al destinatario
		//
		listSubPayload = findMsg(message.getPayload());
		if (debug) {
			System.out.println("lista payload del messaggio numero "+ i +" message.getPayload() " +message.getPayload() );
			for(int k=0;k<listSubPayload.length;k++) {
				if (listSubPayload[k] !=null && !listSubPayload[k].isEmpty()) {
					System.out.println("otherMessagerHonest listSubPayload["+k+"]="+listSubPayload[k]);
				}
			}
		}
		if (debug) {System.out.println("writeInfoPayloadAct AG_X "   );}
		int delJ =writeInfoPayloadAct (bAsm,  message, i, listSubPayload,  msgFieldTot,"AG_X");

		String nextState = findNextState(messages,i);
		bAsm.write("			            internalState" + message.getActorfrom().substring(0, 1) + "(self):="+ nextState + "\n");
		bNuSmv.write("			            internalState" + message.getActorfrom().substring(0, 1) + ":="+ nextState + "\n");

		bAsm.write("			          endpar\n");
		bNuSmv.write("			          endpar\n");
		// se l'attore non ha la chiave per decifrare la parte del payload allora
		// si scrivono le istruzioni che non comprendono la memorizzazione della
		// conoscenza di quella parte del messaggio
		if (!fistOperation) {
			bAsm.write("			        endif\n");
			bNuSmv.write("			        endif\n");
		}
		if (flgPar) {
			flgPar=false;
			bAsm.write("			    endpar\n");
			bNuSmv.write("			    endpar\n");
		}
		bAsm.write("			   else\n");
		bNuSmv.write("			   else\n");
		
		// si scrivono le istruzioni quando il receiver non è l'agent Eve
		// la prima parte delle istruzioni da scrivere riguardano quelle che permettono
		// di aggiornare le conoscenze dell'attore
		// che riceve il messaggio. per fare questo si deve vedere cosa riceve nel
		// messaggio precedente
		
		if (debug) System.out.println("messages.getMessage(i).getPayload() ="+messages.getMessage(i).getPayload());
		if (listMsgPrev == null) {
			bAsm.write("			     par\n");
			bNuSmv.write("			     par\n");
		} else {
			for (int k = 0; k < 15; k++) {
				if (listMsgPrev[k] > 90)
					break;
				z = listMsgPrev[k];
				Message messagePrev = messages.getMessage(z);
				// dal messaggio precedente si estraggono i sott-ayload e l'elenco dei campi
				String[] listSubPayloadPrev = findMsg(messagePrev.getPayload());
				String[] msgFieldTotPrev = FindField(messages.getMessage(z).getPayload());
				if (debug) {
					System.out.println("sono nel messaggio numero" + i + " e nel ramo AG_E");
				}
				if (debug) {
					System.out.println("3 payload prev z" + (z) + " " + messages.getMessage(z).getPayload());
				}
				// Si verifica se la parte del messaggio è decodificabile altrimenti si leva
				// dall'elenco
				// del messaggio precedente
				findActorFromTo(messagePrev.getActorfrom(), messagePrev.getActorTo());

				String[] NewListSubPayloadPrev = new String[15];
				String newPayloadPrev = new String();
				int indList = 0;

				newPayloadPrev = findNewPayloadPrev(indList, listSubPayloadPrev, msgFieldTotPrev, NewListSubPayloadPrev,
						z);

				if (debug) {
					System.out.println("2 NewPayloadPrev " + newPayloadPrev);
				}

				// Si stabiliscono l'elenco dei campi che sono conosciuti dall'attore che riceve
				// il messaggio
				msgFieldTotPrev = FindField(newPayloadPrev);
				// si memorizzano l'elenco dei sotto-payload che l'attore che riceve il
				// messaggio puo decodificare
				listSubPayloadPrev = NewListSubPayloadPrev;
				if (debug) {
					System.out.println("3 ------> NewListSubPayloadPrev <----------");
					for (String e : listSubPayloadPrev) {
						System.out.println("3 ------> " + e + " <-------------");
					}
				}
				flgPar = false;
				// cerca tutti i field che sono in chiaro nel payload per poi scrive il
				// Knowledge
				String[] msgFieldPrevFree = finfFreeFieldPrev(listSubPayloadPrev, msgFieldTotPrev);
				for (String e : msgFieldPrevFree) {
					if (e != null) {
						flgPar = true;
						break;
					}
				}
				if (debug) {
					System.out.println("z5 ------> msgFieldPrevFree <----------");
					for (String e : msgFieldPrevFree) {
						System.out.println("z5 ------> " + e + " <-------------");
					}
				}

				if (flgPar) {
					String[] linesKnowledgePrevFree = writeKnowledge(messagePrev, (z), msgFieldPrevFree,
							actorFromPrevDet, false);
					if (debug) {
						System.out.println("z5 ------> linesKnowledgePrevFree <----------");
						for (String e : linesKnowledgePrevFree) {
							System.out.println("z5 ------> " + e + " <-------------");
						}
					}
					bAsm.write("			    par\n");
					bNuSmv.write("			    par\n");
					printKnowSubPayload(bAsm, bNuSmv, msgFieldPrevFree, msgFieldTotPrev, listSubPayloadPrev[0], messagePrev, (z),
							actorFromPrevDet, false, "Kno3", true);
				}

				// Si richiama la routine per scrivere le if delle operazioni di ogni singolo
				// sotto-payload
				//
				fistOperation = true;
				actorNoDecode = false;

				String[] msgFieldPrev = writeIfPayloadPrev(bAsm, messagePrev, message, i, z, listSubPayloadPrev,
						msgFieldTotPrev, " and receiver=AG_E");

				// msgFieldDetPrev = detField(msgFieldPrev,msgFieldTotPrev);

				// linesKnowledgePrev = writeKnowledge(messagePrev, (i - 1), msgFieldTotPrev,
				// "$e", false);
				// spaces = " ";
				if (debug) {
					System.out.println("printKnowSubPayload -->5");
				}
				printKnowSubPayload(bAsm, bNuSmv, msgFieldPrev, msgFieldTotPrev, listSubPayloadPrev[0], messagePrev, (z),
						actorFromPrevDet, false, "Kno3", true);
			}
		}
		//printKnowledge(bAsm, "Kno3", linesKnowledgePrev, spaces);
		bAsm.write("			            protocolMessage("+i+",self,$e):=" + changNumMSG[i] + "\n");
		bNuSmv.write("			            protocolMessage("+i+","+self+","+dollaroE+"):=" + changNumMSG[i] + "\n");

		//
		// dopo aver analizzato il mesaggio precedente si tratta il messaggio attuale
		// per impostare le informazioni da inviare al destinatario
		//
		listSubPayload = findMsg(message.getPayload());
		if (debug) System.out.println("listSubPayload[0] ="+listSubPayload[0]);

		if (debug) {
			System.out.println("writeInfoPayloadAct " );
		}
		delJ = writeInfoPayloadAct (bAsm,  message, i, listSubPayload,  msgFieldTot,"AG_E");
		if (debug) {
			System.out.println("exit writeInfoPayloadAct " + delJ);
		}
//		if (messages.getMessage(i + 1).getActorfrom() != null && !messages.getMessage(i + 1).getActorfrom().isEmpty()
//				&& messages.getMessage(i).getActorfrom().equals(messages.getMessage(i+1).getActorTo()) ) {
//			endMessage = false;
//			bAsm.write("			            internalState"
//					+ messages.getMessage(i + 1).getActorTo().substring(0, 1) + "(agent"
//					+ messages.getMessage(i + 1).getActorTo().substring(0, 1) + "):=WAITING_" + changNumMSG[i + 1]
//					+ "\n");
//		} else {
			nextState = findNextState(messages,i);
			bAsm.write("			            internalState" + message.getActorfrom().substring(0, 1) + "(self):="+ nextState + "\n");
			bNuSmv.write("			            internalState" + message.getActorfrom().substring(0, 1) + ":="+ nextState + "\n");
			//		+ message.getActorfrom().substring(0, 1) + "):="+ nextState
			//		+ "\n");
			if (messages.getMessage(i + 1).getActorfrom() == null || messages.getMessage(i + 1).getActorfrom().isEmpty())
					endMessage = true;
//		}
		bAsm.write("			         endpar\n");
		bNuSmv.write("			         endpar\n");
		if (!fistOperation) {
			bAsm.write("			        endif\n");
			bNuSmv.write("			        endif\n");
		}
		
 		if (flgPar){
 			flgPar = false;
 			bAsm.write("			    endpar\n");
 			bNuSmv.write("			    endpar\n");
 		}
		
		bAsm.write("			   endif\n");
		bAsm.write("			endif\n");
		bAsm.write("		endlet\n");
		bNuSmv.write("			   endif\n");
		bNuSmv.write("			endif\n");
		bNuSmv.write("		endlet\n");	
		
		debug = false;
		if (endMessage) {
			ruleRCheck(bAsm,lastMsgAlice,i);
			ruleRCheck(bAsm,lastMsgBob,i);
			ruleRCheck(bAsm, lastMsgEve,i);
			ruleRCheck(bAsm,lastMsgServer,i);
		}
	}
	//
	private String findNextState(Messages messages,int i){
		switch (messages.getMessage(i).getActorfrom()) {
		case "Alice":
			lastMsgAlice=99;
			break;
		case "Bob":
			lastMsgBob=99;
			break;
		case "Server":
			lastMsgServer=99;
			break;
		case "Eve":
			lastMsgEve=99;
			break;
		}
		int k = 99;
		String nextState ="END_" + messages.getMessage(i).getActorfrom().substring(0, 1);
		String lastActorTo = messages.getMessage(i).getActorTo();
		for (int j = i + 1; j < 15; j++) {
			if (messages.getMessage(j).getActorfrom() == null || messages.getMessage(j).getActorfrom().isEmpty())
				break;
			if (messages.getMessage(j).getActorTo().equals(messages.getMessage(i).getActorfrom())) {
				lastActorTo = messages.getMessage(j).getActorTo();
				k=j;
			}
			if (messages.getMessage(i).getActorfrom().equals(messages.getMessage(j).getActorfrom())) {
				nextState = "WAITING_" + changNumMSG[j];
				return nextState;
			}
		}
		if (messages.getMessage(i).getActorfrom().equals(lastActorTo)) {
			nextState = "CHECK_" + nextState;
			switch (messages.getMessage(i).getActorfrom()) {
			case "Alice":
				lastMsgAlice=k;
				break;
			case "Bob":
				lastMsgBob=k;
				break;
			case "Server":
				lastMsgServer=k;
				break;
			case "Eve":
				lastMsgEve=k;
				break;
			}
		}
		return nextState;
	}
	// Ricerca l'elenco dei messaggi precedenti ricevuti dallattore From non ancora analizzati
	private int[] findMessagePrev(String actorFrom, String actorTo, int i) {
		int[] listPrev = new int[15];
		int x = 0;
		if (debug) {System.out.println ("findMessagePrev leggo actorFrom " + actorFrom );}
		for (int z = i - 1; z >= 0 ; z--) {
			// se il messaggi precedente è stato inviato dall'attore che sta inviando 
			// il messaggio corrente la ricerca si conclude
			if (debug) {System.out.println ("findMessagePrev leggo messaggio n " + z );}
			if (messages.getMessage(z).getActorfrom().equals(actorFrom)||
					(actorFrom.equals("Eve") && !messages.getMessage(z).getActorfrom().equals(actorFrom))
					&& !messages.getMessage(z).getActorTo().equals(actorFrom)) {
				if (debug) {System.out.println ("findMessagePrev esco dal loop " + messages.getMessage(z).getActorfrom() + " = " + actorFrom);}
				break;
			}
			// si memorizza il numero di messaggio precedente non ancora analizzato dall'attore che 
			// sta inviando il messaggio attuale
			if (messages.getMessage(z).getActorTo().equals(actorFrom)) { 
				if (debug) {System.out.println ("findMessagePrev registro  " + z + " dentro " + x);}
            	listPrev[x] = z;
            	x++;
			}
        }
		if (debug) { System.out.println ("findMessagePrev esco con null?" + x );}
		if (x==0) {
			fistOperation = true;
			return null;
		}
		listPrev[x] = 99;
		return listPrev;
	}
	// si ricerca nella tabella i field precedentemente scambiati e ricevuti dall'attore che sta inviando il emssaggio
	private String findValueHonest(String desMsg,String value, String valueOld, String actorFrom ) {
		if (debug) {System.out.println("findValueHonest  value " + value+"-"+ valueOld + " actorFrom "   + actorFrom);}
		int findMsgCur =0;
		
		for (int x=0; x<15; x++) {
			if (changNumMSG[x].equals(desMsg)) {
				findMsgCur =x;
				break;
			}
		}
		
		//ricerco i dati dei campi memorizzati in precedenza 
		int findMsgCurLessOne =findMsgCur - 1;
		if (debug) {System.out.println("findValueHonest ho capito che il messaggio è il numero "+ findMsgCur + " dall'attore di provenienza " + actorFrom);}

		for (Map.Entry<String, String> entry : honestElement.entrySet()) {
			if (debug) {System.out.println("findValueHonest  entry.getKey() " + entry.getKey());}
			if (debug) {System.out.println("findValueHonest  entry.getValue() " + entry.getValue());}
			if (debug) {
				System.out.println("========= valore desMsg" + desMsg + " Valore letto " + entry.getValue()
						+ " sottostringa " + entry.getValue().substring(entry.getValue().lastIndexOf(",") + 1,
								entry.getValue().lastIndexOf(")")));
			}
			int findMsgOld =0;
			for (int x=0; x<15; x++) {
				if (changNumMSG[x].equals(entry.getValue().substring(entry.getValue().lastIndexOf(",")+1, entry.getValue().lastIndexOf(")")))) {
					findMsgOld =x;
					break;
				}
			}	
			if (debug) {
				System.out.println("========= findMsgCur " + findMsgCur + " findMsgOld " + findMsgOld);
				System.out.println(" Confronto-4-5 " + entry.getKey().substring(4, 5) + " CON " + actorFrom.toUpperCase().substring(0, 1));
				System.out.println("         e key: " + entry.getKey() + " deve contenere " + value.toUpperCase()+"-"+valueOld);
				System.out.println("         e num Msg: " + findMsgOld + " == " + findMsgCur);
				System.out.println("         e valore: " + entry.getValue() + " deve contenere " + ",agent  =" + actorFrom.toUpperCase().substring(0, 1));

			}
			if (entry.getKey().substring(4, 5).equals(actorFrom.toUpperCase().substring(0, 1)) && entry.getKey().contains(value.toUpperCase()+"-"+valueOld)
						&& findMsgOld == findMsgCur && entry.getValue().contains(",agent" + actorFrom.toUpperCase().substring(0, 1))) {

				if (debug) {System.out.println("findValueHonest  ho trovato " + value + " e restituisco "+ entry.getValue() + " Modificandolo con " + entry.getValue().replace("agent"+actorFrom.toUpperCase().substring(0, 1), "self"));}
				return entry.getValue().replace("agent"+actorFrom.toUpperCase().substring(0, 1), "self");
			}
			if (entry.getKey().substring(4, 5).equals(actorFrom.toUpperCase().substring(0, 1)) && entry.getKey().contains(value.toUpperCase()+"-"+valueOld)
					&& findMsgOld <= findMsgCur && entry.getKey().substring (7,15).contains("Eve Eve")) {

			if (debug) {System.out.println("findValueHonest  ho trovato " + value + " e restituisco "+ entry.getValue() + " Modificandolo con " + entry.getValue().replace("agentE", "$e").replace("$b", "self"));}
			return entry.getValue().replace("agentE", "$e").replace("$b", "self");
			}			
		}

		if (debug) {System.out.println("findValueHonest  NON trovato Cerco Altro " + value);}
		for (Map.Entry<String, String> entry : honestElement.entrySet()) {
			if (debug) {System.out.println("findValueHonest  entry.getKey() " + entry.getKey());}
			if (debug) {System.out.println("findValueHonest  entry.getValue() " + entry.getValue());}
			if (debug) {
				System.out.println("========= valore desMsg" + desMsg + " Valore letto " + entry.getValue()
						+ " sottostringa " + entry.getValue().substring(entry.getValue().lastIndexOf(",") + 1,
								entry.getValue().lastIndexOf(")")));
			}
			int findMsgOld =0;
			for (int x=0; x<15; x++) {
				if (changNumMSG[x].equals(entry.getValue().substring(entry.getValue().lastIndexOf(",")+1, entry.getValue().lastIndexOf(")")))) {
					findMsgOld =x;
					break;
				}
			}	
			if (debug) {
				System.out.println("========= findMsgCur " + findMsgCur + " findMsgOld " + findMsgOld);
				System.out.println(" Confronto-4-5 " + entry.getKey().substring(4, 5) + " CON " + actorFrom.toUpperCase().substring(0, 1));
				System.out.println("         e key: " + entry.getKey() + " deve contenere " + value.toUpperCase()+"-"+valueOld);
				System.out.println("         e num Msg: " + findMsgOld + " <= " + findMsgCur);
				System.out.println("         e valore: " + entry.getValue() + " deve contenere " + ",agent  =" + actorFrom.toUpperCase().substring(0, 1));

			}
			if (entry.getKey().substring(4, 5).equals(actorFrom.toUpperCase().substring(0, 1)) && entry.getKey().contains(value.toUpperCase()+"-"+valueOld)
						&& findMsgOld <= findMsgCur && entry.getValue().contains(",agent" + actorFrom.toUpperCase().substring(0, 1))) {

				if (debug) {System.out.println("findValueHonest  ho trovato " + value + " e restituisco "+ entry.getValue() + " Modificandolo con " + entry.getValue().replace("agent"+actorFrom.toUpperCase().substring(0, 1), "self"));}
				return entry.getValue().replace("agent"+actorFrom.toUpperCase().substring(0, 1), "self");
			}
			if (entry.getKey().substring(4, 5).equals(actorFrom.toUpperCase().substring(0, 1)) && entry.getKey().contains(value.toUpperCase()+"-"+valueOld)
					&& findMsgOld <= findMsgCur && entry.getKey().substring (7,15).contains("Eve Eve")) {

			if (debug) {System.out.println("findValueHonest  ho trovato " + value + " e restituisco "+ entry.getValue() + " Modificandolo con " + entry.getValue().replace("agentE", "$e").replace("$b", "self"));}
			return entry.getValue().replace("agentE", "$e").replace("$b", "self");
			}			
		}

		if (debug) {System.out.println("findValueHonest  NON trovato Cerco Altro " + value);}

		for (Map.Entry<String, String> entry : honestElement.entrySet()) {
			if (debug) {System.out.println("findValueHonest  entry.getKey() " + entry.getKey());}
			if (debug) {System.out.println("findValueHonest  entry.getValue() " + entry.getValue());}
			if (debug) {
				System.out.println("========= valore desMsg" + desMsg + " Valore letto " + entry.getValue()
						+ " sottostringa " + entry.getValue().substring(entry.getValue().lastIndexOf(",") + 1,
								entry.getValue().lastIndexOf(")")));
			}
			int findMsgOld =0;
			for (int x=0; x<15; x++) {
				if (changNumMSG[x].equals(entry.getValue().substring(entry.getValue().lastIndexOf(",")+1, entry.getValue().lastIndexOf(")")))) {
					findMsgOld =x;
					break;
				}
			}	
			if (debug) {
				System.out.println("========= findMsgCur " + findMsgCur + " findMsgOld " + findMsgOld);
				System.out.println(" Confronto-12-13 " + entry.getKey().substring(12, 13) + " CON " + actorFrom.toUpperCase().substring(0, 1));
				System.out.println("         e key: " + entry.getKey() + " deve contenere " + value.toUpperCase()+"-"+valueOld);
				System.out.println("         e num Msg: " + findMsgOld + " <= " + findMsgCur);
				System.out.println("         e valore: " + entry.getValue() + " deve contenere " + ",agent  =" + actorFrom.toUpperCase().substring(0, 1));

			}
			if (entry.getKey().substring(12,13).equals(actorFrom.toUpperCase().substring(0, 1)) && entry.getKey().contains(value.toUpperCase()+"-"+valueOld)
						&& findMsgOld <= findMsgCur && entry.getValue().contains("(agent" + actorFrom.toUpperCase().substring(0, 1))) {

				if (debug) {System.out.println("findValueHonest  ho trovato " + value + " e restituisco "+ entry.getValue() + " Modificandolo con " + entry.getValue().replace("agent"+actorFrom.toUpperCase().substring(0, 1), "self"));}
				return entry.getValue().replace("agent"+actorFrom.toUpperCase().substring(0, 1), "self");
			}
		}
		if (debug) {System.out.println("findValueHonest  NON trovato niente " + value);}

		return value;
	}
	// si ricerca nella tabella i field precedentemente scambiati e ricevuti dall'attore che sta inviando il emssaggio
	private String findValueHonestEve(String desMsg,String value, String valueOld,String agentTo ) {
		if (debug) {System.out.println("findValueHonestEve  value " + value+"-"+ valueOld + " actorFrom "   + "Eve");}
		int findMsgCur =0;
		
		for (int x=0; x<15; x++) {
			if (changNumMSG[x].equals(desMsg)) {
				findMsgCur =x;
				break;
			}
		}
		
		//ricerco i dati dei campi memorizzati in precedenza 
		int findMsgCurLessOne =findMsgCur - 1;
		if (debug) {System.out.println("findValueHonestEve ho capito che il messaggio è il numero "+ findMsgCur + " dall'attore di provenienza " + "Eve");}

		for (Map.Entry<String, String> entry : honestElement.entrySet()) {
			if (debug) {System.out.println("findValueHonestEve  entry.getKey() " + entry.getKey());}
			if (debug) {System.out.println("findValueHonestEve  entry.getValue() " + entry.getValue());}
			if (debug) {
				System.out.println("========= valore desMsg" + desMsg + " Valore letto " + entry.getValue()
						+ " sottostringa " + entry.getValue().substring(entry.getValue().lastIndexOf(",") + 1,
								entry.getValue().lastIndexOf(")")));
			}
			int findMsgOld =0;
			for (int x=0; x<15; x++) {
				if (changNumMSG[x].equals(entry.getValue().substring(entry.getValue().lastIndexOf(",")+1, entry.getValue().lastIndexOf(")")))) {
					findMsgOld =x;
					break;
				}
			}	
			if (debug) {
				System.out.println("Per Eve======= findMsgCur " + findMsgCur + " findMsgOld " + findMsgOld);
				System.out.println("                   e key: " + entry.getKey() + " deve contenere " + value.toUpperCase()+"-"+valueOld);
				System.out.println("               e num Msg: " + findMsgOld + " == " + findMsgCur);
				System.out.println("       e entry.getValue() " + entry.getValue() + " deve contenere ,$e ");

			}
			if (entry.getKey().contains(value.toUpperCase()+"-"+valueOld) &&
					entry.getValue().contains(",$e") && findMsgOld == findMsgCur ) {
				if (debug) {System.out.println("findValueHonestEve  ho trovato " + value + " e restituisco "+  entry.getValue().replace(",$e", ",$b"));}
				return entry.getValue().replace(",$e", ",self").replace("(agent"+agentTo.substring(0, 1).toUpperCase(), "($b");
			}
		}
		
		if (debug) {System.out.println("findValueHonestEve  NON trovato Cerco Altro " + value);}
		
		for (Map.Entry<String, String> entry : honestElement.entrySet()) {
			if (debug) {System.out.println("findValueHonest  entry.getKey() " + entry.getKey());}
			if (debug) {System.out.println("findValueHonest  entry.getValue() " + entry.getValue());}
			if (debug) {
				System.out.println("========= valore desMsg" + desMsg + " Valore letto " + entry.getValue()
						+ " sottostringa " + entry.getValue().substring(entry.getValue().lastIndexOf(",") + 1,
								entry.getValue().lastIndexOf(")")));
			}
			int findMsgOld =0;
			for (int x=0; x<15; x++) {
				if (changNumMSG[x].equals(entry.getValue().substring(entry.getValue().lastIndexOf(",")+1, entry.getValue().lastIndexOf(")")))) {
					findMsgOld =x;
					break;
				}
			}	
			if (debug) {
				System.out.println("Per Eve======= findMsgCur " + findMsgCur + " findMsgOld " + findMsgOld);
				System.out.println("                   e key: " + entry.getKey() + " deve contenere " + value.toUpperCase()+"-"+valueOld);
				System.out.println("               e num Msg: " + findMsgOld + " <= " + findMsgCur);
				System.out.println("       e entry.getValue() " + entry.getValue() + " deve contenere ,$e ");

			}
			if (entry.getKey().contains(value.toUpperCase()+"-"+valueOld) &&
					entry.getValue().contains(",$e") && findMsgOld <= findMsgCur ) {
				if (debug) {System.out.println("findValueHonestEve  ho trovato " + value + " e restituisco "+  entry.getValue().replace(",$e", ",$b"));}
				return entry.getValue().replace(",$e", ",self").replace("(agent"+agentTo.substring(0, 1).toUpperCase(), "($b");
			}
		}

		if (debug) {System.out.println("findValueHonestEve  NON trovato niente " + value);}

		return value;
	}

	// trova il new payload del messaggio precedente

	private String findNewPayloadPrev(int indList, String[] listSubPayloadPrev, String[] msgFieldTotPrev,
			String[] NewListSubPayloadPrev,int numMsg) {
		String NewPayloadPrev = new String();

		for (int k = 0; k < 15; k++) {
			// si analizza ogni sotto-payload
			// si verifica se la chiave del sotto-paload è conosciuta dall'attore che riceve
			// il messaggio
			// se quindi l'attore riesce a decodificare il messaggio si si memorizza il
			// sott-messaggio altrimenti non
			// viene preso in considerazione.
			// all'interno dell'array NewListSubPayloadPrev vengono memorizzati i
			// sott-payload decodificati
			// all'interno della stringa NewPayloadPrev si inseriscono i sotto-payload
			// separati da una virgola
			if (listSubPayloadPrev[k] != null) {
				if (debug) {
					System.out.println("2 parte del messaggio " + listSubPayloadPrev[k]);
				}
				String keyUsedPrev = findKey(listSubPayloadPrev[k]);
				if (keyUsedPrev == null || KeyActorTo.searchEle(keyUsedPrev,numMsg) != null) {
					if (debug) {
						System.out.println("2 Verifico se posso aggiungere conoscenza");
					}
					if (indList == 0) {
						NewListSubPayloadPrev[indList] = listSubPayloadPrev[k];
						NewPayloadPrev = listSubPayloadPrev[k];
						indList++;
					} else {
						NewListSubPayloadPrev[indList] = listSubPayloadPrev[k];
						NewPayloadPrev = NewPayloadPrev + "," + listSubPayloadPrev[k];
						indList++;
					}
					String[] msgFieldPrev = new String[15];
					String[] msgEncField1EncField2Prev = new String[15];
					levelEncField1EncField2Prev = calcLevelEncField1EncField2(listSubPayloadPrev[k],
							msgEncField1EncField2Prev, msgFieldPrev, msgFieldTotPrev);
					addKnowActorTo(msgFieldPrev,numMsg);
				} else {
					if (debug) {
						System.out.println("2 cancello pezzo di messaggio " + listSubPayloadPrev[k]);
					}
					listSubPayloadPrev[k] = null;
				}

			}
		}
		return NewPayloadPrev;
	}

	// Scrivo le IF dei solo sotto-payload che riesce a decodificare

	private String[] writeIfPayloadPrev(BufferedWriter b,Message messagePrev, Message message,int i,int z, String[] listSubPayloadPrev, String[] msgFieldTotPrev, String addVal) throws IOException {
		actorNoDecode = false;
		fistOperation = true;
		String[] msgFieldPrev = new String[15];
		if (debug) {
			System.out.println("* -------------- writeIfPayloadPrev msgFieldTotPrev -------*");
			for (String e : msgFieldTotPrev) {
				System.out.println(e);
			}
			System.out.println("* -------------- -------------------------------- -------*");
		}
		if (debug) {
			System.out.println("* -------------- writeIfPayloadPrev msgFieldPrev -------*");
			for (String e : msgFieldPrev) {
				System.out.println(e);
			}
			System.out.println("* -------------- -------------------------------- -------*");
		}
		int endMsgDet=1;
		
		for (int f = 0; f < 15; f++) {
			if (listSubPayloadPrev[f] == null || listSubPayloadPrev[f].isEmpty()) {
				break;
			}
			if (debug) {
				System.out.println("2 analizzo ora listSubPayloadPrev " + listSubPayloadPrev[f]);
			}
			String[] msgEncField1EncField2Prev = new String[15];
			levelEncField1EncField2Prev = calcLevelEncField1EncField2(listSubPayloadPrev[f], msgEncField1EncField2Prev,
					msgFieldPrev, msgFieldTotPrev);
			String[] msgFieldDetPrev = detField(msgFieldPrev, msgFieldTotPrev, 1);
			endMsgDet = contMsgFielDet(msgFieldDetPrev);
			if (debug) {
				System.out.println("* -------------- writeIfPayloadPrev msgFieldDetPrev -------*");
				for (String e : msgFieldDetPrev) {
					System.out.println(e);
				}
				System.out.println("* -------------- -------------------------------- -------*");
			}
			String keyUsedPrev = findKey(listSubPayloadPrev[f]);
			findActorFromTo(messagePrev.getActorfrom(), messagePrev.getActorTo());
//						if (keyUsedPrev == null || KeyActorTo.searchEle(keyUsedPrev) !=null) {
//							if (debug) {System.out.println("z messagePrev.getActorfrom() " + messagePrev.getActorfrom() + " messagePrev.getActorTo() " + messagePrev.getActorTo());}
//							addKnowActorTo(msgFieldPrev);
//						}
			operationPrev = "";
			if (debug) {
				System.out.println("z2 keyUsedPrev " + keyUsedPrev);
			}

			if (keyUsedPrev != null) {
				operationPrev = findOperation(keyUsedPrev, message.getActorfrom(), message.getActorTo(),(i-1));
//							if (KeyActorTo.searchEle(keyUsedPrev) ==null) {actorNoDecode=true;}
			}
			if (debug) {
				System.out.println("z3 operationPrev " + operationPrev);
			}
			if (operationPrev != null && !operationPrev.isEmpty() && messagePrev != message) {
				if (fistOperation) {
					bAsm.write(" 			        if(" + operationPrev + "(" + changNumMSG[z] + ","
							+ levelEncField1EncField2Prev + ",self)=true ");
					bNuSmv.write(" 			        if(" + operationPrev + "(" + changNumMSG[z] + ","
							+ levelEncField1EncField2Prev + ","+self+")=true ");

					fistOperation = false;
				} else {
					bAsm.write(" and " + operationPrev + "(" + changNumMSG[z] + "," + levelEncField1EncField2Prev
							+ ",self)=true ");
					bNuSmv.write(" and " + operationPrev + "(" + changNumMSG[z] + "," + levelEncField1EncField2Prev
							+ ","+self+")=true ");
				}
			}
		}
		if (debug) {
			System.out.println("z4 fistOperation " + fistOperation);
		}

		if (!fistOperation && messagePrev != message) {
			bAsm.write(addVal+") then\n");
			bNuSmv.write(addVal.replace("self", self).replace("$a", dollaroA).replace("$b", dollaroB).replace("$t", dollaroT).replace("$e", dollaroE).replace("$f", dollaroF)+") then\n");
		}
		String[] msgFieldDetPrev = detField(msgFieldPrev,msgFieldTotPrev, 1);
		endMsgDet = contMsgFielDet(msgFieldDetPrev);
		bAsm.write("			          par\n");
		bNuSmv.write("			          par\n");
		if (debug) {
			System.out.println("z5 detField ");
		}
		return msgFieldDetPrev;
	}
	
	// si memorizzano i field che , all'interno del payload, non subiscono cifratura
	// con questi field si scrivono le know prima della if di verifica della decifratura
	// se nell'intero payload non sono presenti cifrature restituisce una tabella vuota 

	private String[] finfFreeFieldPrev(String[] listSubPayloadPrev,String[] msgFieldTotPrev) throws IOException {
		actorNoDecode = false;
		fistOperation = true;
		String[] msgFieldFreePrev = new String[15];
		int numCript =0;
		for (int f = 0; f < 15; f++) {
			if (listSubPayloadPrev[f] == null || listSubPayloadPrev[f].isEmpty()) {
				break;
			}
			if (listSubPayloadPrev[f].contains("-")) {
				numCript++;
			}
		}
		
		if (numCript ==0) {
			return msgFieldFreePrev;
		}
		for (int f = 0; f < 15; f++) {
			if (listSubPayloadPrev[f] == null || listSubPayloadPrev[f].isEmpty()) {
				break;
			}
			if (!listSubPayloadPrev[f].contains("-")) {
				String[] eleFieeld = FindField(listSubPayloadPrev[f]);
				for (String e : eleFieeld) {
					if (e !=null && !e.isEmpty()) {
						for (int k=0 ; k<15 ;k++) {
							if (msgFieldTotPrev[k] != null && msgFieldTotPrev[k].equals(e)) {
								msgFieldFreePrev[k] = e;
							}
						}
						
					}
				}
			}

		}
		return msgFieldFreePrev;
	}

	// si legge il messaggio attuale e si determinano le operazioni crittografiche usate
	private int writeInfoPayloadAct(BufferedWriter bAsm, Message message,int i,String[] listSubPayload, String[] msgFieldTot,String agReceiver) throws IOException {
		if (debug) {
			System.out.println("writeInfoPayloadAct " + " i " + i );
		}

		numOperationMessage = 0;
		// pulisce la tabella delle operazioni.
		for (String eleOperationMessage : operationMessage) {
			eleOperationMessage = "";
		}
		int delJ = 0;
		int endMsgDet =1;
		for (int j = 0; j < 15; j++) {
			if (listSubPayload[j] == null || listSubPayload[j].isEmpty()) {
				break;
			}
			if (debug) {System.out.println("writeInfoPayloadAct listSubPayload["+j+"] " + listSubPayload[j]);}

			String[] msgEncField1EncField2 = new String[15];
			String[] msgField = new String[15];
			String levelEncField1EncField2 = calcLevelEncField1EncField2(listSubPayload[j], msgEncField1EncField2,
					msgField, msgFieldTot);
			String[] msgFieldDet = detField(msgField, msgFieldTot, endMsgDet);
			endMsgDet = contMsgFielDet(msgFieldDet);
			
			String keyUsed = findKey(listSubPayload[j]);
			String operation = "";
			actorNoDecode = false;
			if (debug) {
				System.out.println("writeInfoPayloadAct KeyUSed " + keyUsed);
				for (String e : msgFieldDet) {
					if (e != null) 	System.out.println("msgFieldDet " + e);
				}
			}

			if (keyUsed != null) {
				operation = findOperation(keyUsed, message.getActorfrom(), message.getActorTo(),i);
				if (debug) {
					System.out.println("writeInfoPayloadAct Operation " + operation);
				}				
				if (KeyActorFrom.searchEle(keyUsed,i) == null && !(KeyActorTo.searchEle(keyUsed,i).contains("Public"))) {
					actorNoDecode = true;
				}
			/*		msgFieldTot = FindField(messages.getMessage(i).getPayload().replace(listSubPayload[j], ""));
					delJ++;
				}
			*/
			}
			if (debug) {System.out.println("actorNoDecode " + actorNoDecode + " agReceiver " + agReceiver);}

			if (!agReceiver.equals("AG_E")) {
				String sigleActTo = "$e";
				if (message.getActorfrom().equals("Eve")) {
					sigleActTo = "$b";
				}
				if (debug) {System.out.println("writeInfoPayloadAct - Entro nel ramo !AG_E");}
				//if (!actorNoDecode) {
					for (int k = 0; k < 15; k++) {
						if (msgFieldDet[k] != null) {
							if (debug) {System.out.println("writeInfoPayloadAct scrivo messagefield - msgFieldDet[k] " + msgFieldDet[k]);}
							if (message.getActorfrom().equals("Eve")){
									bAsm.write("			            messageField(self,"+ sigleActTo + "," + k + "," + changNumMSG[i]
									+ "):=" + findValueHonestEve(changNumMSG[i],msgFieldDet[k].toUpperCase(), msgFieldDet[k].toUpperCase(),message.getActorTo())
									+ "\n");
									bNuSmv.write("			            messageField("+self+","+ sigleActTo.replace("self", self).replace("$a", dollaroA).replace("$b", dollaroB).replace("$t", dollaroT).replace("$e", dollaroE).replace("$f", dollaroF) + "," + k + "," + changNumMSG[i]
									+ "):=" + findValueHonestEve(changNumMSG[i],msgFieldDet[k].toUpperCase(), msgFieldDet[k].toUpperCase(),message.getActorTo()).replace("self", self).replace("$a", dollaroA).replace("$b", dollaroB).replace("$t", dollaroT).replace("$e", dollaroE).replace("$f", dollaroF)
									+ "\n");

							} else {
								bAsm.write("			            messageField(self,"+ sigleActTo + "," + k + "," + changNumMSG[i]
										+ "):=" + findValueHonest(changNumMSG[i],msgFieldDet[k].toUpperCase(), msgFieldDet[k].toUpperCase(),message.getActorfrom())
										+ "\n");
								bNuSmv.write("			            messageField("+self+","+ sigleActTo.replace("self", self).replace("$a", dollaroA).replace("$b", dollaroB).replace("$t", dollaroT).replace("$e", dollaroE).replace("$f", dollaroF) + "," + k + "," + changNumMSG[i]
										+ "):=" + findValueHonest(changNumMSG[i],msgFieldDet[k].toUpperCase(), msgFieldDet[k].toUpperCase(),message.getActorfrom()).replace("self", self).replace("$a", dollaroA).replace("$b", dollaroB).replace("$t", dollaroT).replace("$e", dollaroE).replace("$f", dollaroF)
										+ "\n");
							}	
							
							if (debug) {System.out.println("writeInfoPayloadAct - messaggio" + changNumMSG[i] + " - findValueHones " + findValueHonest(changNumMSG[i],msgFieldDet[k].toUpperCase(),msgFieldDet[k].toUpperCase(), message.getActorfrom()));}
							honestElement.put("E K "+message.getActorTo() + " Eve " +message.getActorfrom() + " " + i + " "+  msgFieldDet[k].toUpperCase()+ "-"+ msgFieldDet[k].toUpperCase(),
									"messageField(agent"+ message.getActorfrom().substring(0, 1) +"," + sigleActTo + "," + k + "," + changNumMSG[i] + ")");
							honestElement.put(message.getActorTo() + " Eve " +message.getActorfrom() + " " + i + " "+  msgFieldDet[k].toUpperCase()+ "-"+ msgFieldDet[k].toUpperCase(),
									"messageField(agent"+ message.getActorfrom().substring(0, 1) +"," +sigleActTo + "," + k + "," + changNumMSG[i] + ")");

							if (debug) {
								System.out.println("da 3 k "+ k+ " "+ msgFieldDet[k] + "    inserisco in honestElement  Key: E K " + message.getActorTo()
										+ " Eve " + message.getActorfrom()+ " " + i + " "
										+ msgFieldDet[k].toUpperCase() + "-"+ msgFieldDet[k].toUpperCase() + " --- VALORE -----   messageField(agent"
										+ message.getActorfrom().substring(0, 1) + ","+ sigleActTo + "," + k + "," + changNumMSG[i]
										+ ")");
							}
							if (debug) {System.out.println("writeInfoPayloadAct  --- " + message.getActorTo().substring(0, 1) + " " + msgFieldDet[k].toUpperCase()
							 + "  --------- Valore " + "messageField("+ sigleActTo +",agent"+ message.getActorTo().substring(0, 1) +"," + k + "," + changNumMSG[i] + ")");}

						}
					}
					if (debug) {System.out.println("writeInfoPayloadAct ramo xx listSubPayload["+j+"]="+listSubPayload[j]);}					
					determinesOperation(bAsm, i, j - delJ, message, listSubPayload[j], message.getActorfrom(), "", true);
				//}
			} else {
				if (debug) {System.out.println("writeInfoPayloadAct - Entro nel ramo AG_E");}

				//if (!actorNoDecode) {
					for (int k = 0; k < 15; k++) {
						if (msgFieldDet[k] != null) {
							if (debug) {
							System.out.println("    leggo il campo " + msgFieldDet[k]);
							}
							if (debug) {
								System.out.println("2 msgFieldDet[k]  " + msgFieldDet[k]
										+ " message.getActorTo() " + message.getActorTo()
										+ " message.getActorfrom() " + message.getActorfrom()
										+ " actorStartProtocol.equals(message.getActorTo()) "
										+ actorStartProtocol.equals(message.getActorTo()));
							}
							if (actorStartProtocol.equals(message.getActorTo())) {
								if (debug) {
									System.out.println("    Ramo  actorStartProtocol.equals(message.getActorTo()) "
											+ message.getActorTo());
								}
								if (debug) {System.out.println("changValueEve(msgFieldDet[k] ="+ msgFieldDet[k] + ", message.getActorfrom()+\"no chang\"=" + message.getActorfrom() + "no chang, message.getActorTo() ="+message.getActorTo()+",true, changNumMSG[i] = "+ changNumMSG[i] + ",i)  " );}
								bAsm.write("			            messageField(self,$e," + k + "," + changNumMSG[i]
										+ "):=" + changValueEve(msgFieldDet[k], message.getActorfrom()+"no chang", message.getActorTo(),true, changNumMSG[i],i) + "\n");
								bNuSmv.write("			            messageField("+self+","+ dollaroE+"," + k + "," + changNumMSG[i]
										+ "):=" + changValueEve(msgFieldDet[k], message.getActorfrom()+"no chang", message.getActorTo(),true, changNumMSG[i],i).replace("self", self).replace("$a", dollaroA).replace("$b", dollaroB).replace("$t", dollaroT).replace("$e", dollaroE).replace("$f", dollaroF) + "\n");
									
								if (debug) {System.out.println("			                      messageField(self,$e," + k + "," + changNumMSG[i]
										+ "):=" + changValueEve(msgFieldDet[k], message.getActorfrom()+"no chang", message.getActorTo(),true, changNumMSG[i],i) + "\n"    );  };
								// 14-02-2023
										honestElement.put("E J "+message.getActorTo() + 
												" Eve " + message.getActorfrom() + " " + i + " "
														+ changValueEve(msgFieldDet[k], message.getActorfrom()+"no chang", message.getActorTo(),true,
																changNumMSG[i],i).toUpperCase()+ "-"+ msgFieldDet[k].toUpperCase(),
												"messageField(agent"+ message.getActorfrom().substring(0, 1) +",$e," + k + "," + changNumMSG[i] + ")");
										honestElement.put(message.getActorTo() + 
												" Eve " + message.getActorfrom() + " " + i + " "
														+ changValueEve(msgFieldDet[k], message.getActorfrom()+"no chang", message.getActorTo(),true,
																changNumMSG[i],i).toUpperCase()+ "-"+ msgFieldDet[k].toUpperCase(),
												"messageField(agent"+ message.getActorfrom().substring(0, 1) +",$e," + k + "," + changNumMSG[i] + ")");

										if (debug) {
											System.out.println("da2 k "+ k +" "+ msgFieldDet[k] + "    inserisco in honestElement  Key: "
													+ message.getActorTo() + " Eve " + message.getActorfrom() + " " + i
													+ " "
													+ changValueEve(msgFieldDet[k], message.getActorfrom() + "no chang",message.getActorTo(),
															true, changNumMSG[i],i).toUpperCase() + "-"+ msgFieldDet[k].toUpperCase()
													+ " --- VALORE -----   messageField(agent"
													+ message.getActorfrom().substring(0, 1) + ",$e," + k + ","
													+ changNumMSG[i] + ")");
										}
							} else {
								if (debug) {
									System.out.println(
											"    Ramo  DIVERSO DA actorStartProtocol.equals(message.getActorTo()) "
													+ message.getActorTo());
								}
								bAsm.write("			            messageField(self,$e," + k + "," + changNumMSG[i]
										+ "):="
										+ changValueEve(msgFieldDet[k], message.getActorfrom(),message.getActorTo(), true, changNumMSG[i],i)
										+ "\n");
								bNuSmv.write("			            messageField("+self+","+dollaroE+"," + k + "," + changNumMSG[i]
										+ "):=" + changValueEve(msgFieldDet[k], message.getActorfrom()+"no chang", message.getActorTo(),true, changNumMSG[i],i).replace("self", self).replace("$a", dollaroA).replace("$b", dollaroB).replace("$t", dollaroT).replace("$e", dollaroE).replace("$f", dollaroF) + "\n");
	
								if (debug) {System.out.println("			                      messageField(self,$e," + k + "," + changNumMSG[i]
										+ "):="
										+ changValueEve(msgFieldDet[k], message.getActorfrom(),message.getActorTo(), true, changNumMSG[i],i)
										+ "\n"   );}

								honestElement.put("E W "+message.getActorTo() + 
										" Eve " + message.getActorfrom() + " " + i + " "
												+ changValueEve(msgFieldDet[k], message.getActorfrom(),message.getActorTo(), false,
														changNumMSG[i],i).toUpperCase()+ "-"+ msgFieldDet[k].toUpperCase(),
										"messageField(agent"+ message.getActorfrom().substring(0, 1) +",$e," + k + "," + changNumMSG[i] + ")");
								honestElement.put(message.getActorTo() + 
										" Eve " + message.getActorfrom() + " " + i + " "
												+ changValueEve(msgFieldDet[k], message.getActorfrom(),message.getActorTo(), false,
														changNumMSG[i],i).toUpperCase()+ "-"+ msgFieldDet[k].toUpperCase(),
										"messageField(agent"+ message.getActorfrom().substring(0, 1) +",$e," + k + "," + changNumMSG[i] + ")");

								if (debug) {
									System.out.println("da k "+ k + " " + msgFieldDet[k]+ "    inserisco in honestElement  Key: " + message.getActorTo()
											+ " Eve " + message.getActorfrom() + " " + i + " "
											+ changValueEve(msgFieldDet[k], message.getActorfrom(),message.getActorTo(), false,
													changNumMSG[i],i).toUpperCase() + "-"+ msgFieldDet[k].toUpperCase()
											+ " --- VALORE ----- " + "messageField(agent"
											+ message.getActorTo().substring(0, 1) + ",$e," + k + "," + changNumMSG[i]
											+ ")");
								}
								
								if (debug) {System.out.println("writeInfoPayloadAct2 EVE  --- key " + "E" + " "
										+ changValueEve(msgFieldDet[k], message.getActorfrom(),message.getActorTo(), false,
												changNumMSG[i],i).toUpperCase()
								 + "  --------- Valore " + "messageField($e,agent"+ message.getActorTo().substring(0, 1) +"," + k + "," + changNumMSG[i] + ")");}
								

							}
						}
					}
					
					if (actorStartProtocol.equals(message.getActorTo())|| actorNoDecode) {
						if (debug) {System.out.println("writeInfoPayloadAct ramo true listSubPayload["+j+"]="+listSubPayload[j]);}					
						determinesOperation(bAsm, i, j - delJ, message, listSubPayload[j], message.getActorfrom(), "", true);
					} else {
						if (debug) {System.out.println("writeInfoPayloadAct ramo false listSubPayload["+j+"]="+listSubPayload[j]);}					
						determinesOperation(bAsm, i, j - delJ, message, listSubPayload[j], message.getActorfrom(), "", false);
					}
					
				//}
			}
		}
		return delJ;
	}
	// quando ad operare è l'EVE si deve effettuare il reverse delle chiavi e dei
	// field
	private String changValueEve(String value, String actorFrom,String actorTo, boolean verifyElement, String desMsg, int numMsg) {
		 
		if (debug) {
			System.out
					.println("2a changValueEve(String value, String actorFrom, boolean verifyElement,,String desMsg)  "
							+ " value " + value + " actorFrom " + actorFrom + " verifyElement " + verifyElement
							+ " desMsg " + desMsg);
		}

		String valueOutput = value;
		String typeFieldActorFrom = KeyActorFrom.searchEle(value,numMsg);

		boolean found = false;
		// modifica del 07-02-2023
		// if (typeFieldActorFrom != null) {
		if (typeFieldActorFrom != null && !actorFrom.contains("no chang")) {
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
					//valueOutput = eve.getSymmetricKey().get(0);
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
			case "Identity Certificate":
/*				if (eve.getIdCertificate().get(0) != null) {
					if (actorStartProtocol.contains("Alice") && bob.getIdCertificate().get(0)!=null && bob.getIdCertificate().get(0).equals(value)) {
						valueOutput = eve.getIdCertificate().get(0);
						break;
					}
					if (actorStartProtocol.contains("Bob") && alice.getIdCertificate().get(0)!=null && alice.getIdCertificate().get(0).equals(value)) {
						valueOutput = eve.getIdCertificate().get(0);
						break;
					}
				}
*/
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


		// modifica del 07-02-2023
		// if (!found) {
		if (!found && !actorFrom.contains("no chang")) {
			typeFieldActorFrom = KeyActorTo.searchEle(value,numMsg);
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
						//valueOutput = eve.getSymmetricKey().get(0);

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
 
		 if (debug) {
			System.out.println("2f valueOutput " + valueOutput + " desMsg " + desMsg);
			System.out.println("2f agentfrom" +actorFrom.toUpperCase().substring(0, 1));

		 }

		if (verifyElement) {
			int findMsgCur =0;
			
			for (int x=0; x<15; x++) {
				if (changNumMSG[x].equals(desMsg)) {
					findMsgCur =x;
					break;
				}
			}
			int findMsgCurLessOne =findMsgCur - 1;
			for (Map.Entry<String, String> entry : honestElement.entrySet()) {

				int findMsgOld =0;
				for (int x=0; x<15; x++) {
					if (changNumMSG[x].equals(entry.getValue().substring(entry.getValue().lastIndexOf(",")+1, entry.getValue().lastIndexOf(")")))) {
						findMsgOld =x;
						break;
					}
				}	
				if (debug) {
					System.out.println("-------leggo chiave getKey " + entry.getKey());
					System.out.println("-------leggo valore getValue " + entry.getValue());
					System.out.println("-------verifico entry.getKey().substring(0, 1).equals(E) " + entry.getKey().substring(0, 1).equals("E"));
					System.out.println("       entry.getKey().contains("+ valueOutput.toUpperCase()+"-"+value+") " + entry.getKey().contains(valueOutput.toUpperCase()+"-"+value));
					System.out.println("       findMsgOld <= findMsgCur "+ findMsgOld + "<="+ findMsgCur + " " + (findMsgOld <= findMsgCur));
					System.out.println("       !entry.getValue().contains("+desMsg + ") " + (!entry.getValue().contains(desMsg + ")")));
					System.out.println("       entry.getValue().contains(agent" + actorFrom.toUpperCase().substring(0, 1)+") " + entry.getValue().contains("agent" + actorFrom.toUpperCase().substring(0, 1)));
				}
				if (entry.getKey().substring(0, 1).equals("E") && entry.getKey().contains(valueOutput.toUpperCase()+"-"+value)
						&& !entry.getValue().contains(desMsg + ")")) {
					if (debug) {
						System.out.println("-------  	trovata chiave " + entry.getKey());
						System.out.println("-------	    come valore" + entry.getValue());

					}
				}
				if (entry.getKey().substring(0, 1).equals("E") && entry.getKey().contains(valueOutput.toUpperCase()+"-"+value)
						&& findMsgOld == findMsgCur && entry.getValue().contains(",agent" + actorFrom.toUpperCase().substring(0, 1))) {
					if (debug) {
						System.out.println("-----	quindi cambio " + entry.getValue() + " - " + entry.getKey() + " - "
								+ entry.getValue().contains(desMsg + ")"));
					}
					return entry.getValue().replace("agent" + actorFrom.toUpperCase().substring(0, 1), "self");

				}
				if (entry.getKey().substring(0, 1).equals("E") && entry.getKey().contains(valueOutput.toUpperCase()+"-"+value)
						 && findMsgOld == findMsgCurLessOne && entry.getValue().contains("agent" + actorFrom.toUpperCase().substring(0, 1))) {
					if (debug) {
						System.out.println("-----	quindi cambio2 " + entry.getValue() + " - " + entry.getKey() + " - "
								+ entry.getValue().contains(desMsg + ")"));
					}
					return entry.getValue().replace("agent" + actorFrom.toUpperCase().substring(0, 1), "self");

				}
				if (entry.getKey().substring(0, 1).equals("E") && entry.getKey().contains(valueOutput.toUpperCase()+"-"+value)
						&& findMsgOld <= findMsgCur  && entry.getValue().contains(",agent" + actorFrom.toUpperCase().substring(0, 1))) {
					if (debug) {
						System.out.println("-----	quindi cambio3 " + entry.getValue() + " - "
								+ entry.getValue().contains(desMsg + ")"));
					}
					return entry.getValue().replace("agent" + actorFrom.toUpperCase().substring(0, 1), "self");

				}

			}
			for (Map.Entry<String, String> entry : honestElement.entrySet()) {

				int findMsgOld =0;
				for (int x=0; x<15; x++) {
					if (changNumMSG[x].equals(entry.getValue().substring(entry.getValue().lastIndexOf(",")+1, entry.getValue().lastIndexOf(")")))) {
						findMsgOld =x;
						break;
					}
				}	
				if (debug) {
					System.out.println("-------leggo chiave getKey " + entry.getKey());
					System.out.println("-------leggo valore getValue " + entry.getValue());
					System.out.println("-------verifico entry.getKey().substring(0, 1).equals(E) " + entry.getKey().substring(0, 1).equals("E"));
					System.out.println("       entry.getKey().contains("+ valueOutput.toUpperCase()+"-"+value+") " + entry.getKey().contains(valueOutput.toUpperCase()+"-"+value));
					System.out.println("       findMsgOld <= findMsgCur "+ findMsgOld + "<="+ findMsgCur + " " + (findMsgOld <= findMsgCur));
					System.out.println("       !entry.getValue().contains("+desMsg + ") " + (!entry.getValue().contains(desMsg + ")")));
					System.out.println("       entry.getValue().contains(agent" + actorFrom.toUpperCase().substring(0, 1)+") " + entry.getValue().contains("agent" + actorFrom.toUpperCase().substring(0, 1)));
				}
				if (entry.getKey().substring(0, 1).equals("E") && entry.getKey().contains(valueOutput.toUpperCase()+"-"+value)
						&& !entry.getValue().contains(desMsg + ")")) {
					if (debug) {
						System.out.println("-------  	trovata chiave " + entry.getKey());
						System.out.println("-------	    come valore" + entry.getValue());

					}
				}
				if (entry.getKey().substring(0, 1).equals("E") && entry.getKey().contains(valueOutput.toUpperCase()+"-"+value)
						&& findMsgOld < findMsgCur && entry.getValue().contains("agent" + actorFrom.toUpperCase().substring(0, 1))) {
					if (debug) {
						System.out.println("-----	quindi cambio3 " + entry.getValue() + " - "
								+ entry.getValue().contains(desMsg + ")"));
					}
					return entry.getValue().replace("agent" + actorFrom.toUpperCase().substring(0, 1), "self");

				}
				if (entry.getKey().substring(0, 1).equals("E") && entry.getKey().contains(valueOutput.toUpperCase()+"-"+value)
						&& findMsgOld <= findMsgCur && entry.getValue().contains(",agent" + actorFrom.toUpperCase().substring(0, 1))) {
					if (debug) {
						System.out.println("-----	quindi cambio4 " + entry.getValue() + " - "
								+ entry.getValue().contains(desMsg + ")"));
					}
					return entry.getValue().replace("agent" + actorFrom.toUpperCase().substring(0, 1), "self");

				}

			}
	
			
			if (debug) {
				System.out.println("NON HO TROVATO NIENTEEEEEE " + value);

			}


		}
		if (debug) {
			System.out.println("return " + valueOutput.toUpperCase());

		}
		return valueOutput.toUpperCase();
	}

	// Aggiunge le conoscenze ricevute all'interno dei payload
	private void addKnowActorTo(String[] msgField, int numMsg) {
		if (debug)
			System.out.println("*------- devo verificare se ci sono conoscenze da aggiungere -----*");
		String typeFieldActorFrom;
		for (int i = 0; i < 15; i++) {
			if (msgField[i] != null && !msgField[i].isEmpty()) {
				if (debug)
					System.out.println("Analizzo conoscenza " + msgField[i]);
				if (KeyActorTo.searchEle(msgField[i],numMsg) == null) {
					typeFieldActorFrom = KeyActorFrom.searchEle(msgField[i],numMsg);
					if (debug)
						System.out.println("la conoscenza per l'actor from è " + typeFieldActorFrom);
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
		if (debug)
			System.out.println("*------- Esco -----*");

	}

	
	private void ruleRCheck(BufferedWriter bAsm, int i,int lastMsg) throws IOException {
		if (i >90) { return; }
		boolean flgPar = false;
		Message messageCheck = messages.getMessage(i);
		bAsm.write("	rule r_check_" + changNumMSG[i] + " =\n");
		bNuSmv.write("	rule r_check_" + changNumMSG[i] + " =\n");

		ruleR_Agent[indRuleR_Agent] = messageCheck.getActorTo().toUpperCase().substring(0, 1) + " r_check_" + changNumMSG[i]
				+ "[]";
		indRuleR_Agent++;
		String andLet ="";
		dollaroT="";
		if (i!=lastMsg) {
			andLet = " ,$t=agent"+messages.getMessage(lastMsg).getActorTo().substring(0, 1).toUpperCase();
			dollaroT=messages.getMessage(lastMsg).getActorTo();
		}

		if (messageCheck.getActorTo().equals("Eve")) {
			bAsm.write("		let ($e=agent"+ messageCheck.getActorfrom().toUpperCase().substring(0, 1) + andLet +") in\n");
			bNuSmv.write("		let ($x=agent"+ messages.getMessage(i).getActorfrom().toUpperCase().substring(0, 1)+ ",$e=agent"+ messageCheck.getActorfrom().toUpperCase().substring(0, 1) + andLet +") in\n");
			dollaroX=messages.getMessage(i).getActorfrom().toUpperCase();
			dollaroB="";
			dollaroA="";
			dollaroF="";
			dollaroE=messageCheck.getActorfrom().toUpperCase();
			self=messages.getMessage(i).getActorfrom().toUpperCase();
		} else {
			bAsm.write("		let ($e=agentE"+andLet+") in\n");
			bNuSmv.write("		let ($x=agent"+ messageCheck.getActorTo().substring(0, 1)+",$e=agentE"+andLet+") in\n");
			dollaroX=messages.getMessage(i).getActorfrom().toUpperCase();
			dollaroB="";
			dollaroA="";
			dollaroF="";
			dollaroE="EVE";
			self=messageCheck.getActorTo().toUpperCase();
		}
		String andProtocol ="";
		if (i!=lastMsg) {
			andProtocol = " and protocolMessage("+lastMsg+",$e,$t)=" + changNumMSG[lastMsg];
		}
			
		bAsm.write("			if(internalState" + messageCheck.getActorTo().substring(0, 1) + "(self)=CHECK_END_"
				+ messageCheck.getActorTo().toUpperCase().substring(0, 1) + " and protocolMessage("+i+",$e,self)=" + changNumMSG[i]
				+andProtocol +")then\n");
		bNuSmv.write("			if(internalState" + messageCheck.getActorTo().substring(0, 1) + "=CHECK_END_"
				+ messageCheck.getActorTo().toUpperCase().substring(0, 1) + " and protocolMessage("+i+","+dollaroE+","+self+")=" + changNumMSG[i]
				+andProtocol +")then\n");

		bAsm.write("			  par\n");	
		bNuSmv.write("			  par\n");	
		bAsm.write("			        internalState" + messageCheck.getActorTo().substring(0, 1) + "(self):=END_"
		+ messageCheck.getActorTo().substring(0, 1) + "\n");
		bNuSmv.write("			        internalState" + messageCheck.getActorTo().substring(0, 1) + ":=END_"
		+ messageCheck.getActorTo().substring(0, 1) + "\n");
		
		//
		// per ogni messaggio
		// dal payload si estraggono tutti i filed e si scrivono a prescindere
		findActorFromTo(messageCheck.getActorfrom(), messageCheck.getActorTo());
		String[] msgFieldTot = FindField(messages.getMessage(i).getPayload());
		if (debug) {System.out.println("writeKnowledge 1");}
		String[] linesKnowledge = writeKnowledge(messageCheck, i, msgFieldTot, "$e", false);
		if (debug) {
			System.out.println("writeKnowledge 1");
			System.out.println("writeKnowledge 1 " + linesKnowledge[0]);
		}
		//
		// si divide il payload in messaggi separati (se necessario)
		String[] listSubPayload = findMsg(messageCheck.getPayload());

		if(debug) {
			System.out.println("writeMessageAttackerPassive i ="+i+" listSubPayload lenght="+listSubPayload.length);
			for(int x=0;x<listSubPayload.length;x++) {
				if (listSubPayload[x] !=null && !listSubPayload[x].isEmpty()) {
					System.out.println("writeMessageAttackerPassive listSubPayload["+x+"]="+listSubPayload[x]);
				}
			}
		}
		// per ogni messaggio si estraggono le operazioni
		int totOpz = 0;
		int endMsgDet=1;
		for (int j = 0; j < 15; j++) {
			if (listSubPayload[j] == null || listSubPayload[j].isEmpty()) {
				break;
			}
			// per ogni sottomessaggio si scrivono le istruzioni di Encode
			String keyUsed = findKey(listSubPayload[j]);
			String operation = "";
			if (keyUsed != null) {
				totOpz++;
				/*
				 * operation = findOperation(keyUsed, message.getActorfrom(),
				 * message.getActorTo()); String[] msgEncField1EncField2 = new String[15];
				 * String[] msgField = new String[15]; // determino i dati per la scrittura del
				 * tipo di crittografia ha il messaggio String levelEncField1EncField2 =
				 * calcLevelEncField1EncField2(listSubPayload[j], msgEncField1EncField2,
				 * msgField, msgFieldTot); if (reversOperation(operation).equals("symEnc")) {
				 * bAsm.write("                            	" + reversOperation(operation) + "("
				 * + changNumMSG[i] + "," + levelEncField1EncField2 + "):=" +
				 * findKeyEle(keyUsed, message.getActorfrom(), message.getActorTo(), true) +
				 * "\n"); } else { bAsm.write("                            	" +
				 * reversOperation(operation) + "(" + changNumMSG[i] + "," +
				 * levelEncField1EncField2 + "):=" + findKeyEle(keyUsed, message.getActorfrom(),
				 * message.getActorTo(), false) + "\n"); }
				 */
			} else {
				// se nel sottomessaggio non c'è una funzione di crittografia si scrive la konw
				String[] msgEncField1EncField2 = new String[15];
				String[] msgField = new String[15];
				// determino i dati per la scrittura del tipo di crittografia ha il messaggio
				String levelEncField1EncField2 = calcLevelEncField1EncField2(listSubPayload[j], msgEncField1EncField2,
						msgField, msgFieldTot);
				// determino i campi del messaggio e la posizione
				String[] msgFieldDet = detField(msgField, msgFieldTot, endMsgDet);
				endMsgDet = contMsgFielDet(msgFieldDet);
				findActorFromTo(messageCheck.getActorfrom(), messageCheck.getActorTo());
				if (debug) {System.out.println("writeKnowledge 2");}
				linesKnowledge = writeKnowledge(messageCheck, i, msgFieldDet, "$e", false);
				if (debug) {
					System.out.println("writeKnowledge 2");
					System.out.println("writeKnowledge 2 " + linesKnowledge[0]);
				}
				String spaces = "                 ";
				printKnowledge(bAsm, "Know", linesKnowledge, spaces);
			}
		}
		// Si rileggono i sottomessaggi per verificare se l'attore riesce a
		// decodificarli e in questo caso si aggiorna la knowlege
		
		endMsgDet=1;
		boolean firstOp = true;
		for (int j = 0; j < 15; j++) {
			if (listSubPayload[j] == null || listSubPayload[j].isEmpty()) {
				break;
			}
			String keyUsed = findKey(listSubPayload[j]);
			String operation = "";
			if (keyUsed != null) {
				operation = findOperation(keyUsed, messageCheck.getActorfrom(), messageCheck.getActorTo(),i);
				String[] msgEncField1EncField2 = new String[15];
				String[] msgField = new String[15];
				// determino i dati per la scrittura del tipo di crittografia ha il messaggio
				String levelEncField1EncField2 = calcLevelEncField1EncField2(listSubPayload[j], msgEncField1EncField2,
						msgField, msgFieldTot);
				String[] msgFieldDet = detField(msgField, msgFieldTot, endMsgDet);
				endMsgDet = contMsgFielDet(msgFieldDet);
				if (operation != null && !operation.isEmpty()) {
					bAsm.write("			        if(" + operation + "(" + changNumMSG[i] + "," + levelEncField1EncField2
							+ ",self)=true)then\n");
					bNuSmv.write("			        if(" + operation + "(" + changNumMSG[i] + "," + levelEncField1EncField2
							+ ","+self+")=true)then\n");

					int contaField=0;
					for (String e : msgFieldDet) {
						if(e != null && !e.isEmpty()) {
							contaField++;
						}
					}
					if(contaField>1) {
						bAsm.write("                      par \n");
						bNuSmv.write("                      par \n");
					}
					// si scrivono le conoscenze in base ai sotto peyload del messaggio
					if(debug) {System.out.println("printKnowSubPayload -->1");}
					printKnowSubPayload(bAsm,bNuSmv,msgFieldDet,msgFieldTot,listSubPayload[j],messageCheck,i,"$e",false,"Know",false);
					if(contaField>1) {
						bAsm.write("                      endpar \n");
						bNuSmv.write("                      endpar \n");
					}
					bAsm.write("			        endif \n");
					bNuSmv.write("			        endif \n");

				}
			}

		}
		if (!firstOp) {
			if (totOpz > 1) {
				bAsm.write("			  endpar \n");
				bNuSmv.write("			  endpar \n");
			}
			bAsm.write("			endif \n");
			bNuSmv.write("			endif \n");
		}

		bAsm.write("			  endpar\n");		
		bAsm.write("			endif\n");
		bAsm.write("		endlet\n");			
		bNuSmv.write("			  endpar\n");		
		bNuSmv.write("			endif\n");
		bNuSmv.write("		endlet\n");
	}



	// dalla tabella si estraggono i messaggi divisi per i vari agenti e si scrivono
	// le rispettive rule
	// per distinguere tra i messaggi a quale agent vanno agganciati si vede il
	// primo carattere della stringa.
	private void writeRuleR_Agent(BufferedWriter bAsm, BufferedWriter bNuSmv) throws IOException {
		if (debug) {System.out.println("Entro writeRuleR_Agent");}
		bAsm.write("\n");
		bNuSmv.write("\n");
		boolean firtE = true;

		numRuleE = 0;
		numRuleB = 0;
		numRuleS = 0;
		numRuleA = 0;
		for (int i = 0; i < indRuleR_Agent; i++) {
			if (ruleR_Agent[i].substring(0, 1).equals("A")) {
				numRuleA++;
			}
			if (ruleR_Agent[i].substring(0, 1).equals("E")) {
				numRuleE++;
			}
			if (ruleR_Agent[i].substring(0, 1).equals("S")) {
				numRuleS++;
			}
			if (ruleR_Agent[i].substring(0, 1).equals("B")) {
				numRuleB++;
			}
		}
		for (int i = 0; i < indRuleR_Agent; i++) {
			if (ruleR_Agent[i].substring(0, 1).equals("E")) {
				if (firtE) {
					bAsm.write("	rule r_agentERule  =");
					bAsm.write("\n");
					if (numRuleE > 1) {
						bAsm.write("	  par\n");
					}
					bAsm.write("            " + ruleR_Agent[i].substring(2, ruleR_Agent[i].length()));
					bAsm.write("\n");
					firtE = false;
				} else {
					bAsm.write("            " + ruleR_Agent[i].substring(2, ruleR_Agent[i].length()));
					bAsm.write("\n");
				}
			}
		}
		if (!firtE) {
			if (numRuleE > 1) {
				bAsm.write("	  endpar\n");
			}
			bAsm.write("\n");
		}

		boolean firtA = true;
		for (int i = 0; i < indRuleR_Agent; i++) {
			if (ruleR_Agent[i].substring(0, 1).equals("A")) {
				if (firtA) {
					bAsm.write("	rule r_agentARule  =");
					bAsm.write("\n");
					if (numRuleA > 1) {
						bAsm.write("	  par\n");
					}
					bAsm.write("            " + ruleR_Agent[i].substring(2, ruleR_Agent[i].length()));
					bAsm.write("\n");
					firtA = false;
				} else {
					bAsm.write("            " + ruleR_Agent[i].substring(2, ruleR_Agent[i].length()));
					bAsm.write("\n");
				}
			}
		}
		if (!firtA) {
			if (numRuleA > 1) {
				bAsm.write("	  endpar\n");
			}
			bAsm.write("\n");
		}
		boolean firtB = true;
		for (int i = 0; i < indRuleR_Agent; i++) {
			if (ruleR_Agent[i].substring(0, 1).equals("B")) {
				if (firtB) {
					bAsm.write("	rule r_agentBRule  =");
					bAsm.write("\n");
					if (numRuleB > 1) {
						bAsm.write("	  par\n");
					}
					bAsm.write("            " + ruleR_Agent[i].substring(2, ruleR_Agent[i].length()));
					bAsm.write("\n");
					firtB = false;
				} else {
					bAsm.write("            " + ruleR_Agent[i].substring(2, ruleR_Agent[i].length()));
					bAsm.write("\n");
				}
			}
		}
		if (!firtB) {
			if (numRuleB > 1) {
				bAsm.write("	  endpar\n");
			}
			bAsm.write("\n");
		}
		boolean firtS = true;
		for (int i = 0; i < indRuleR_Agent; i++) {
			if (ruleR_Agent[i].substring(0, 1).equals("S")) {
				if (firtS) {
					bAsm.write("	rule r_agentSRule  =");
					bAsm.write("\n");
					if (numRuleS > 1) {
						bAsm.write("	  par\n");
					}
					bAsm.write("            " + ruleR_Agent[i].substring(2, ruleR_Agent[i].length()));
					bAsm.write("\n");
					firtS = false;
				} else {
					bAsm.write("            " + ruleR_Agent[i].substring(2, ruleR_Agent[i].length()));
					bAsm.write("\n");
				}
			}
		}
		if (!firtS) {
			if (numRuleS > 1) {
				bAsm.write("	  endpar\n");
			}
			bAsm.write("\n");
		}
		
		writeProprierties(bNuSmv,properties);
		boolean firtX = true;
		for (int i = 0; i < indRuleR_Agent; i++) {
			if (firtX) {
					bNuSmv.write("	main rule r_Main =");
					bNuSmv.write("\n");
					if ((numRuleS+numRuleE+numRuleA+numRuleB) > 1) {
						bNuSmv.write("	  par\n");
					}
					bNuSmv.write("            " + ruleR_Agent[i].substring(2, ruleR_Agent[i].length()));
					bNuSmv.write("\n");
					firtX = false;
				} else {
					bNuSmv.write("            " + ruleR_Agent[i].substring(2, ruleR_Agent[i].length()));
					bNuSmv.write("\n");
				}
		}
		if (!firtX) {
			if ((numRuleS+numRuleE+numRuleA+numRuleB) > 1) {
				bNuSmv.write("	  endpar\n");
			}
			bNuSmv.write("\n");
		}
		int totProgram=0;
		if (!firtA) {totProgram++;}
		if (!firtB) {totProgram++;}
		if (!firtS) {totProgram++;}
		if (!firtE) {totProgram++;}
		
		bAsm.write("	main rule r_Main =\n");
		if (totProgram>1) {bAsm.write("	  par\n");}
		if (!firtA) {
			bAsm.write("             program(agentA)\n");
		}
		if (!firtB) {
			bAsm.write("             program(agentB)\n");
		}
		if (!firtS) {
			bAsm.write("             program(agentS)\n");
		}
		if (!firtE) {
			bAsm.write("             program(agentE)\n");
		}
		if (totProgram>1) {bAsm.write("	  endpar\n");}
		

	}

	private void writeDefaultInitS0(BufferedWriter bAsm,BufferedWriter bNuSmv) throws IOException {
		if (debug) {System.out.println("Entro writeDefaultInitS0");}
		bAsm.write("default init s0:\n");
		bNuSmv.write("default init s0:\n");
		bNuSmv.write("	function agentA=ALICE \n");
		bNuSmv.write("	function agentB=BOB \n");
		bNuSmv.write("	function agentE=EVE \n");
		if (actorServer) {
			bNuSmv.write("	function agentS=SERVER \n");
		}
		
		if(aliceStartState !=null && !aliceStartState.isEmpty())
			bAsm.write("	function internalStateA($a in  Alice)=" + aliceStartState + "\n");
		if(bobStartState !=null && !bobStartState.isEmpty())
			bAsm.write("	function internalStateB($b in  Bob)=" + bobStartState + "\n");
		if(serverStartState !=null && !serverStartState.isEmpty())
			bAsm.write("	function internalStateS($s in  Server)=" + serverStartState + "\n");
		if(eveStartState !=null && !eveStartState.isEmpty())
			bAsm.write("	function internalStateE($e in  Eve)=" + eveStartState + "\n");

		if(aliceStartState !=null && !aliceStartState.isEmpty())
			bNuSmv.write("	function internalStateA=" + aliceStartState + "\n");
		if(bobStartState !=null && !bobStartState.isEmpty())
			bNuSmv.write("	function internalStateB=" + bobStartState + "\n");
		if(serverStartState !=null && !serverStartState.isEmpty())
			bNuSmv.write("	function internalStateS=" + serverStartState + "\n");
		if(eveStartState !=null && !eveStartState.isEmpty())
			bNuSmv.write("	function internalStateE=" + eveStartState + "\n");

	
	
	
		
		bAsm.write("	function receiver=chosenReceiver\n");
		bNuSmv.write("	function receiver="+receiver+"\n");
		boolean found = false;

		// Scrittura dello stato S0 per la KnowledgeNonce
		countIf = 0;
		found = writeDefaultInitS0Nonce(bAsm, aliceStart, "Alice", found);

		found = writeDefaultInitS0Nonce(bAsm, bobStart, "Bob", found);

		found = writeDefaultInitS0Nonce(bAsm, eveStart, "Eve", found);

		if (actorServer) {

			found = writeDefaultInitS0Nonce(bAsm, serverStart, "Server", found);
		}

		if (countIf > 0) {
			bAsm.write(" false");
			bNuSmv.write(" false");
			for (int i = 0; i < countIf; i++) {
				bAsm.write(" endif");
				bNuSmv.write(" endif");
			}
			bAsm.write("\n");
			bNuSmv.write("\n");
		}

		// Scrittura dello stato S0 per la knowsIdentityCertificate
		countIf = 0;
		found = false;
		found = writeDefaultInitS0IDCer(bAsm, aliceStart, "Alice", found);
		found = writeDefaultInitS0IDCer(bAsm, bobStart, "Bob", found);
		found = writeDefaultInitS0IDCer(bAsm, eveStart, "Eve", found);
		if (actorServer) {
			found = writeDefaultInitS0IDCer(bAsm, serverStart, "Server", found);
		}

		if (countIf > 0) {
			bAsm.write(" false");
			bNuSmv.write(" false");
			for (int i = 0; i < countIf; i++) {
				bAsm.write(" endif");
				bNuSmv.write(" endif");
			}
			bAsm.write("\n");
			bNuSmv.write("\n");
		}

		// Scrittura dello stato S0 per la knowsBitString
		countIf = 0;
		found = false;
		found = writeDefaultInitS0BitSt(bAsm, aliceStart, "Alice", found);
		found = writeDefaultInitS0BitSt(bAsm, bobStart, "Bob", found);
		found = writeDefaultInitS0BitSt(bAsm, eveStart, "Eve", found);
		if (actorServer) {
			found = writeDefaultInitS0BitSt(bAsm, serverStart, "Server", found);
		}

		if (countIf > 0) {
			bAsm.write(" false");
			bNuSmv.write(" false");
			for (int i = 0; i < countIf; i++) {
				bAsm.write(" endif");
				bNuSmv.write(" endif");
			}
			bAsm.write("\n");
			bNuSmv.write("\n");
		}

		// Scrittura dello stato S0 per la KnowledgeTag
		countIf = 0;
		found = false;
		found = writeDefaultInitS0Tag(bAsm, aliceStart, "Alice", found);
		found = writeDefaultInitS0Tag(bAsm, bobStart, "Bob", found);
		found = writeDefaultInitS0Tag(bAsm, eveStart, "Eve", found);
		if (actorServer) {
			found = writeDefaultInitS0Tag(bAsm, serverStart, "Server", found);
		}

		if (countIf > 0) {
			bAsm.write(" false");
			bNuSmv.write(" false");
			for (int i = 0; i < countIf; i++) {
				bAsm.write(" endif");
				bNuSmv.write(" endif");
			}
			bAsm.write("\n");
			bNuSmv.write("\n");
		}

		// Scrittura dello stato S0 per la KnowledgeDigest
		countIf = 0;
		found = false;
		found = writeDefaultInitS0Dig(bAsm, aliceStart, "Alice", found);
		found = writeDefaultInitS0Dig(bAsm, bobStart, "Bob", found);
		found = writeDefaultInitS0Dig(bAsm, eveStart, "Eve", found);
		if (actorServer) {
			found = writeDefaultInitS0Dig(bAsm, serverStart, "Server", found);
		}

		if (countIf > 0) {
			bAsm.write(" false");
			bNuSmv.write(" false");
			for (int i = 0; i < countIf; i++) {
				bAsm.write(" endif");
				bNuSmv.write(" endif");
			}
			bAsm.write("\n");
			bNuSmv.write("\n");
		}

		// Scrittura dello stato S0 per la KnowledgeOther
		countIf = 0;
		found = false;
		found = writeDefaultInitS0Hot(bAsm, aliceStart, "Alice", found);

		found = writeDefaultInitS0Hot(bAsm, bobStart, "Bob", found);

		found = writeDefaultInitS0Hot(bAsm, eveStart, "Eve", found);

		if (actorServer) {

			found = writeDefaultInitS0Hot(bAsm, serverStart, "Server", found);

		}

		if (countIf > 0) {
			bAsm.write(" false");
			bNuSmv.write(" false");
			for (int i = 0; i < countIf; i++) {
				bAsm.write(" endif");
				bNuSmv.write(" endif");
			}
			bAsm.write("\n");
			bNuSmv.write("\n");
		}

		// Scrittura dello stato S0 per la KnowledgeTimestamp
		countIf = 0;
		found = false;
		found = writeDefaultInitS0Tim(bAsm, aliceStart, "Alice", found);
		found = writeDefaultInitS0Tim(bAsm, bobStart, "Bob", found);
		found = writeDefaultInitS0Tim(bAsm, eveStart, "Eve", found);
		if (actorServer) {
			found = writeDefaultInitS0Tim(bAsm, serverStart, "Server", found);
		}

		if (countIf > 0) {
			bAsm.write(" false");
			bNuSmv.write(" false");
			for (int i = 0; i < countIf; i++) {
				bAsm.write(" endif");
				bNuSmv.write(" endif");
			}
			bAsm.write("\n");
			bNuSmv.write("\n");
		}

		// Scrittura dello stato S0 per la knowsAsymPrivKey e knowsAsymPubKey
		countIf = 0;
		found = false;
		found = writeDefaultInitS0AsPr(bAsm, aliceStart, "Alice", found);
		found = writeDefaultInitS0AsPr(bAsm, bobStart, "Bob", found);
		found = writeDefaultInitS0AsPr(bAsm, eveStart, "Eve", found);
		if (actorServer) {
			found = writeDefaultInitS0AsPr(bAsm, serverStart, "Server", found);
		}

		if (countIf > 0) {
			bAsm.write(") then true else false endif\n");
			bAsm.write("	function knowsAsymPubKey($a in Agent ,$pk in KnowledgeAsymPubKey)=true\n");
			bNuSmv.write(") then true else false endif\n");
			bNuSmv.write("	function knowsAsymPubKey($a in Agenti ,$pk in Knowledge)=true\n");

		}

		// Scrittura dello stato S0 per la KnowledgeSymKey
		countIf = 0;
		found = false;
		found = writeDefaultInitS0SymK(bAsm, aliceStart, "Alice", found);
		found = writeDefaultInitS0SymK(bAsm, bobStart, "Bob", found);
		found = writeDefaultInitS0SymK(bAsm, eveStart, "Eve", found);
		if (actorServer) {
			found = writeDefaultInitS0SymK(bAsm, serverStart, "Server", found);
		}

		if (countIf > 0) {
			bAsm.write(") then true else false endif\n");
			bNuSmv.write(") then true else false endif\n");
		}

		// Scrittura dello stato S0 per la knowsSignPubKey e knowsSignPrivKey
		countIf = 0;
		found = false;
		found = writeDefaultInitS0SiPu(bAsm, aliceStart, "Alice", found);
		found = writeDefaultInitS0SiPu(bAsm, bobStart, "Bob", found);
		found = writeDefaultInitS0SiPu(bAsm, eveStart, "Eve", found);
		if (actorServer) {
			found = writeDefaultInitS0SiPu(bAsm, serverStart, "Server", found);
		}

		if (countIf > 0) {
			bAsm.write(") then true else false endif\n");
			bAsm.write("	function knowsSignPubKey($a in Agent ,$spu in KnowledgeSignPubKey)=true\n");
			bNuSmv.write(") then true else false endif\n");
			bNuSmv.write("	function knowsSignPubKey($a in Agenti ,$spu in Knowledge)=true\n");
		}
		bAsm.write("	function mode=chosenMode\n");
		bAsm.write("\n");
		bNuSmv.write("	function mode="+modality+"\n");
		bNuSmv.write("\n");
		if (numRuleA > 0) {
			bAsm.write("	agent Alice:\n");
			bAsm.write("		r_agentARule[]\n");
			bAsm.write("\n");
		}

		if (numRuleB > 0) {
			bAsm.write("	agent Bob:\n");
			bAsm.write("		r_agentBRule[]\n");
			bAsm.write("\n");

		}
		if (numRuleE > 0) {
			bAsm.write("	agent Eve:\n");
			bAsm.write("		r_agentERule[]\n");
		}
		if (numRuleS > 0) {
			if (actorServer) {
				bAsm.write("\n");
				bAsm.write("	agent Server:\n");
				bAsm.write("		r_agentSRule[]\n");
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
	private boolean writeDefaultInitS0Nonce(BufferedWriter bAsm, SecurityKey KeyActor, String agent, boolean foundIn)
			throws IOException {
		boolean found = foundIn;
		boolean first = true;
		for (String ele : KeyActor.getNonce()) {
			if (!found) {
				bAsm.write("	function knowsNonce($a in Agent, $n in KnowledgeNonce)=if($a=agent" + agent.substring(0, 1)
						+ " and $n=" + ele.toUpperCase() + ")");
				bNuSmv.write("	function knowsNonce($a in Agenti, $n in Knowledge)=if($a=agent" + agent.substring(0, 1)
				+ " and $n=" + ele.toUpperCase() + ")");
				countIf++;
				found = true;
			} else {
				if (first) {
					bAsm.write(" if($a=agent" + agent.substring(0, 1) + " and $n=" + ele.toUpperCase() + ")");
					bNuSmv.write(" if($a=agent" + agent.substring(0, 1) + " and $n=" + ele.toUpperCase() + ")");
					countIf++;
				} else {
					bAsm.write(" or ($a=agent" + agent.substring(0, 1) + " and $n=" + ele.toUpperCase() + ")");
					bNuSmv.write(" or ($a=agent" + agent.substring(0, 1) + " and $n=" + ele.toUpperCase() + ")");
				}
			}
			first = false;
		}
		if (countIf > 0 && !first) {
			bAsm.write(" then true else");
			bNuSmv.write(" then true else");
		}
		return found;
	}

	// Scrittura dello stato S0 per la knowsIdentityCertificate
	private boolean writeDefaultInitS0IDCer(BufferedWriter bAsm, SecurityKey KeyActor, String agent, boolean foundIn)
			throws IOException {
		boolean found = foundIn;
		boolean first = true;
		for (String ele : KeyActor.getIdCertificate()) {
			if (!found) {
				bAsm.write("	function knowsIdentityCertificate($a in Agent, $i in KnowledgeIdentityCertificate)=if($a=agent"
						+ agent.substring(0, 1) + " and $i=" + ele.toUpperCase() + ")");
				bNuSmv.write("	function knowsIdentityCertificate($a in Agenti, $i in Knowledge)=if($a=agent"
						+ agent.substring(0, 1) + " and $i=" + ele.toUpperCase() + ")");
				countIf++;
				found = true;
			} else {
				if (first) {
					bAsm.write(" if($a=agent" + agent.substring(0, 1) + " and $i=" + ele.toUpperCase() + ")");
					bNuSmv.write(" if($a=agent" + agent.substring(0, 1) + " and $i=" + ele.toUpperCase() + ")");
					countIf++;
				} else {
					bAsm.write(" or ($a=agent" + agent.substring(0, 1) + " and $i=" + ele.toUpperCase() + ")");
					bNuSmv.write(" or ($a=agent" + agent.substring(0, 1) + " and $i=" + ele.toUpperCase() + ")");
				}
			}
			first = false;
		}
		if (countIf > 0 && !first) {
			bAsm.write(" then true else");
			bNuSmv.write(" then true else");
		}
		return found;
	}

	// Scrittura dello stato S0 per la knowsBitString
	private boolean writeDefaultInitS0BitSt(BufferedWriter bAsm, SecurityKey KeyActor, String agent, boolean foundIn)
			throws IOException {
		boolean found = foundIn;
		boolean first = true;
		for (String ele : KeyActor.getBitstring()) {
			if (!found) {
				bAsm.write("	function knowsBitString($a in Agent, $bs in KnowledgeBitString)=if($a=agent"
						+ agent.substring(0, 1) + " and $bs=" + ele.toUpperCase() + ")");
				bNuSmv.write("	function knowsBitString($a in Agenti, $bs in Knowledge)=if($a=agent"
						+ agent.substring(0, 1) + " and $bs=" + ele.toUpperCase() + ")");
				countIf++;
				found = true;
			} else {
				if (first) {
					bAsm.write(" if($a=agent" + agent.substring(0, 1) + " and $bs=" + ele.toUpperCase() + ")");
					bNuSmv.write(" if($a=agent" + agent.substring(0, 1) + " and $bs=" + ele.toUpperCase() + ")");
					countIf++;
				} else {
					bAsm.write(" or ($a=agent" + agent.substring(0, 1) + " and $bs=" + ele.toUpperCase() + ")");
					bNuSmv.write(" or ($a=agent" + agent.substring(0, 1) + " and $bs=" + ele.toUpperCase() + ")");
				}
			}
			first = false;
		}
		if (countIf > 0 && !first) {
			bAsm.write(" then true else");
			bNuSmv.write(" then true else");
		}
		return found;
	}

	// Scrittura dello stato S0 per la knowsBitString
	private boolean writeDefaultInitS0Tag(BufferedWriter bAsm, SecurityKey KeyActor, String agent, boolean foundIn)
			throws IOException {
		boolean found = foundIn;
		boolean first = true;
		for (String ele : KeyActor.getTag()) {
			if (!found) {
				bAsm.write("	function knowsTag($a in Agent, $tg in KnowledgeTag)=if($a=agent" + agent.substring(0, 1)
				+ " and $tg=" + ele.toUpperCase() + ")");
				bNuSmv.write("	function knowsTag($a in Agenti, $tg in Knowledge)=if($a=agent" + agent.substring(0, 1)
						+ " and $tg=" + ele.toUpperCase() + ")");
				countIf++;
				found = true;
			} else {
				if (first) {
					bAsm.write(" if($a=agent" + agent.substring(0, 1) + " and $tg=" + ele.toUpperCase() + ")");
					bNuSmv.write(" if($a=agent" + agent.substring(0, 1) + " and $tg=" + ele.toUpperCase() + ")");
					countIf++;
				} else {
					bAsm.write(" or ($a=agent" + agent.substring(0, 1) + " and $tg=" + ele.toUpperCase() + ")");
					bNuSmv.write(" or ($a=agent" + agent.substring(0, 1) + " and $tg=" + ele.toUpperCase() + ")");
				}
			}
			first = false;
		}
		if (countIf > 0 && !first) {
			bAsm.write(" then true else");
			bNuSmv.write(" then true else");
		}
		return found;
	}

	// Scrittura dello stato S0 per la knowsDigest
	private boolean writeDefaultInitS0Dig(BufferedWriter bAsm, SecurityKey KeyActor, String agent, boolean foundIn)
			throws IOException {
		boolean found = foundIn;
		boolean first = true;
		for (String ele : KeyActor.getDigest()) {
			if (!found) {
				bAsm.write("	function knowsDigest($a in Agent, $dg in KnowledgeDigest)=if($a=agent"
						+ agent.substring(0, 1) + " and $dg=" + ele.toUpperCase() + ")");
				bNuSmv.write("	function knowsDigest($a in Agenti, $dg in Knowledge)=if($a=agent"
						+ agent.substring(0, 1) + " and $dg=" + ele.toUpperCase() + ")");

				countIf++;
				found = true;
			} else {
				if (first) {
					bAsm.write(" if($a=agent" + agent.substring(0, 1) + " and $dg=" + ele.toUpperCase() + ")");
					bNuSmv.write(" if($a=agent" + agent.substring(0, 1) + " and $dg=" + ele.toUpperCase() + ")");
					countIf++;
				} else {
					bAsm.write(" or ($a=agent" + agent.substring(0, 1) + " and $dg=" + ele.toUpperCase() + ")");
					bNuSmv.write(" or ($a=agent" + agent.substring(0, 1) + " and $dg=" + ele.toUpperCase() + ")");
				}
			}
			first = false;
		}
		if (countIf > 0 && !first) {
			bAsm.write(" then true else");
			bNuSmv.write(" then true else");
		}
		return found;
	}

	// Scrittura dello stato S0 per la knowsOther
	private boolean writeDefaultInitS0Hot(BufferedWriter bAsm, SecurityKey KeyActor, String agent, boolean foundIn)
			throws IOException {
		boolean found = foundIn;
		boolean first = true;
		for (String ele : otherElement.keySet()) {
			if (agent.substring(0, 1).equals(ele.substring(0, 1))) {
				if (!found) {
					bAsm.write("	function knowsOther($a in Agent, $ho in KnowledgeOther)=if($a=agent"
							+ ele.substring(0, 1) + " and $ho=" + ele.substring(2).toUpperCase() + ")");
					bNuSmv.write("	function knowsOther($a in Agenti, $ho in Knowledge)=if($a=agent"
							+ ele.substring(0, 1) + " and $ho=" + ele.substring(2).toUpperCase() + ")");

					countIf++;
					found = true;
				} else {
					if (first) {
						bAsm.write(" if($a=agent" + ele.substring(0, 1) + " and $ho=" + ele.substring(2) + ")");
						bNuSmv.write(" if($a=agent" + ele.substring(0, 1) + " and $ho=" + ele.substring(2) + ")");
						countIf++;
					} else {
						bAsm.write(" or ($a=agent" + ele.substring(0, 1) + " and $ho=" + ele.substring(2) + ")");
						bNuSmv.write(" or ($a=agent" + ele.substring(0, 1) + " and $ho=" + ele.substring(2) + ")");
					}
				}
				first = false;
			}
		}
		if (countIf > 0 && !first) {
			bAsm.write(" then true else");
			bNuSmv.write(" then true else");
		}
		return found;
	}

	// Scrittura dello stato S0 per la knowsTimestamp
	private boolean writeDefaultInitS0Tim(BufferedWriter bAsm, SecurityKey KeyActor, String agent, boolean foundIn)
			throws IOException {
		boolean found = foundIn;
		boolean first = true;
		for (String ele : KeyActor.getTimestamp()) {
			if (!found) {
				bAsm.write("	function knowsTimestamp($a in Agent, $tm in KnowledgeTimestamp)=if($a=agent"
						+ agent.substring(0, 1) + " and $tm=" + ele.toUpperCase() + ")");
				bNuSmv.write("	function knowsTimestamp($a in Agenti, $tm in Knowledge)=if($a=agent"
						+ agent.substring(0, 1) + " and $tm=" + ele.toUpperCase() + ")");

				countIf++;
				found = true;
			} else {
				if (first) {
					bAsm.write(" if($a=agent" + agent.substring(0, 1) + " and $tm=" + ele.toUpperCase() + ")");
					bNuSmv.write(" if($a=agent" + agent.substring(0, 1) + " and $tm=" + ele.toUpperCase() + ")");
					countIf++;
				} else {
					bAsm.write(" or ($a=agent" + agent.substring(0, 1) + " and $tm=" + ele.toUpperCase() + ")");
					bNuSmv.write(" or ($a=agent" + agent.substring(0, 1) + " and $tm=" + ele.toUpperCase() + ")");
				}
			}
			first = false;
		}
		if (countIf > 0) {
			bAsm.write(" then true else");
			bNuSmv.write(" then true else");
		}
		return found;
	}

	// Scrittura dello stato S0 per la knowsAsymPrivKey
	private boolean writeDefaultInitS0AsPr(BufferedWriter bAsm, SecurityKey KeyActor, String agent, boolean foundIn)
			throws IOException {
		boolean found = foundIn;
		for (String ele : KeyActor.getAsymmetricPrivateKey()) {
			if (!found) {
				bAsm.write("	function knowsAsymPrivKey($a in Agent ,$k in KnowledgeAsymPrivKey)=if(($a=agent"
						+ agent.substring(0, 1) + " and $k=" + ele.toUpperCase() + ")");
				bNuSmv.write("	function knowsAsymPrivKey($a in Agenti ,$k in Knowledge)=if(($a=agent"
						+ agent.substring(0, 1) + " and $k=" + ele.toUpperCase() + ")");
				countIf++;
				found = true;
			} else {
				bAsm.write(" or ($a=agent" + agent.substring(0, 1) + " and $k=" + ele.toUpperCase() + ")");
				bNuSmv.write(" or ($a=agent" + agent.substring(0, 1) + " and $k=" + ele.toUpperCase() + ")");
			}
		}
		for (String ele : KeyActor.getKnowAcq()) {
			if (ele.contains("Asymmetric Private Key")) {
				if (!found) {
					bAsm.write("	function knowsAsymPrivKey($a in Agent ,$k in KnowledgeSymKey)=if(($a=agent"
							+ agent.substring(0, 1) + " and $k=" + ele.substring(0, ele.indexOf(" - ")).toUpperCase()
							+ ")");
					bNuSmv.write("	function knowsAsymPrivKey($a in Agenti ,$k in Knowledge)=if(($a=agent"
							+ agent.substring(0, 1) + " and $k=" + ele.substring(0, ele.indexOf(" - ")).toUpperCase()
							+ ")");

					countIf++;
					found = true;
				} else {
					bAsm.write(" or ($a=agent" + agent.substring(0, 1) + " and $k="
							+ ele.substring(0, ele.indexOf(" - ")).toUpperCase() + ")");
					bNuSmv.write(" or ($a=agent" + agent.substring(0, 1) + " and $k="
							+ ele.substring(0, ele.indexOf(" - ")).toUpperCase() + ")");
				}
			}
		}

		return found;
	}

	// Scrittura dello stato S0 per la knowsSymKey
	private boolean writeDefaultInitS0SymK(BufferedWriter bAsm, SecurityKey KeyActor, String agent, boolean foundIn)
			throws IOException {
		boolean found = foundIn;
		for (String ele : KeyActor.getSymmetricKey()) {
			if (!found) {
				bAsm.write("	function knowsSymKey($a in Agent ,$sk in KnowledgeSymKey)=if(($a=agent"
						+ agent.substring(0, 1) + " and $sk=" + ele.toUpperCase() + ")");
				bNuSmv.write("	function knowsSymKey($a in Agenti ,$sk in Knowledge)=if(($a=agent"
						+ agent.substring(0, 1) + " and $sk=" + ele.toUpperCase() + ")");
				countIf++;
				found = true;
			} else {
				bAsm.write(" or ($a=agent" + agent.substring(0, 1) + " and $sk=" + ele.toUpperCase() + ")");
				bNuSmv.write(" or ($a=agent" + agent.substring(0, 1) + " and $sk=" + ele.toUpperCase() + ")");
			}
		}
		for (String ele : KeyActor.getKnowAcq()) {
			if (ele.contains("Symmetric Key")) {
				if (!found) {
					bAsm.write("	function knowsSymKey($a in Agent ,$sk in KnowledgeSymKey)=if(($a=agent"
							+ agent.substring(0, 1) + " and $sk=" + ele.substring(0, ele.indexOf(" - ")).toUpperCase()
							+ ")");
					bNuSmv.write("	function knowsSymKey($a in Agenti ,$sk in Knowledge)=if(($a=agent"
							+ agent.substring(0, 1) + " and $sk=" + ele.substring(0, ele.indexOf(" - ")).toUpperCase()
							+ ")");
					countIf++;
					found = true;
				} else {
					bAsm.write(" or ($a=agent" + agent.substring(0, 1) + " and $sk="
							+ ele.substring(0, ele.indexOf(" - ")).toUpperCase() + ")");
					bNuSmv.write(" or ($a=agent" + agent.substring(0, 1) + " and $sk="
							+ ele.substring(0, ele.indexOf(" - ")).toUpperCase() + ")");

				}
			}
		}

		return found;
	}

	// Scrittura dello stato S0 per la knowsSignPubKey
	private boolean writeDefaultInitS0SiPu(BufferedWriter bAsm, SecurityKey KeyActor, String agent, boolean foundIn)
			throws IOException {
		boolean found = foundIn;

		for (String ele : KeyActor.getSignaturePrivKey()) {
			if (!found) {
				bAsm.write("	function knowsSignPrivKey($a in Agent ,$spr in KnowledgeSignPrivKey)=if(($a=agent"
						+ agent.substring(0, 1) + " and $spr=" + ele.toUpperCase() + ")");
				bNuSmv.write("	function knowsSignPrivKey($a in Agenti ,$spr in Knowledge)=if(($a=agent"
						+ agent.substring(0, 1) + " and $spr=" + ele.toUpperCase() + ")");

				countIf++;
				found = true;
			} else {
				bAsm.write(" or ($a=agent" + agent.substring(0, 1) + " and $spr=" + ele.toUpperCase() + ")");
				bNuSmv.write(" or ($a=agent" + agent.substring(0, 1) + " and $spr=" + ele.toUpperCase() + ")");
			}
		}

		for (String ele : KeyActor.getKnowAcq()) {
			if (ele.contains("Signature Priv Key")) {
				if (!found) {
					bAsm.write("	function knowsSignPrivKey($a in Agent ,$spr in KnowledgeSignPrivKey)=if(($a=agent"
							+ agent.substring(0, 1) + " and $spr=" + ele.substring(0, ele.indexOf(" - ")).toUpperCase()
							+ ")");
					bNuSmv.write("	function knowsSignPrivKey($a in Agenti ,$spr in Knowledge)=if(($a=agent"
							+ agent.substring(0, 1) + " and $spr=" + ele.substring(0, ele.indexOf(" - ")).toUpperCase()
							+ ")");
					countIf++;
					found = true;
				} else {
					bAsm.write(" or ($a=agent" + agent.substring(0, 1) + " and $spr="
							+ ele.substring(0, ele.indexOf(" - ")).toUpperCase() + ")");
					bNuSmv.write(" or ($a=agent" + agent.substring(0, 1) + " and $spr="
							+ ele.substring(0, ele.indexOf(" - ")).toUpperCase() + ")");
				}
			}
		}

		return found;
	}
	private void writeProprierties(BufferedWriter bNuSmv,String[][] properties)
			throws IOException {
		if (debug) {
			System.out.println("writeProprierties");
			
		}
		
		String propr;
		for(int i=0 ; i<10 ; i++) {
			for(int j=0 ; j<10 ; j++) {
				if (properties[i][j] !=null && !properties[i][j].isEmpty()) {
					bNuSmv.write("// properties TAB="+ i + " COL="+j + "\n");
					propr="CTLSPEC " + properties[i][j];
					propr = propr.replace("Alice", "ALICE");
					propr = propr.replace("Bob", "BOB");
					propr = propr.replace("Eve", "EVE");
					propr = propr.replace("Server", "SERVER");
					if (propr.contains("¬af")||
						propr.contains("¬ag")||	
						propr.contains("¬ax")||	
						propr.contains("¬ef")||	
						propr.contains("¬eg")||	
						propr.contains("¬ex")) {
						propr = propr.replace("¬", "not(")+")";
					}
					if (propr.contains("!af")) propr = propr.replace("!af", "not(af")+")";
					if (propr.contains("!ag")) propr = propr.replace("!ag", "not(ag")+")";
					if (propr.contains("!ax")) propr = propr.replace("!ax", "not(ax")+")";
					if (propr.contains("!ef")) propr = propr.replace("!ef", "not(ef")+")";
					if (propr.contains("!eg")) propr = propr.replace("!eg", "not(eg")+")";
					if (propr.contains("!ex")) propr = propr.replace("!ex", "not(er")+")";
					//propr = propr.replace("¬", "not(");
					propr = propr.replace("!", "not");
					bNuSmv.write("  " + propr + "\n");					
				}
			}
		}
	}
}
