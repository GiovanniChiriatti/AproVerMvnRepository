package org.unimi.model;

import java.util.ArrayList;
import java.util.Iterator;

public class SecurityKey {
	ArrayList<String> AsymmetricPublicKey=new ArrayList<String>();
	ArrayList<String> AsymmetricPrivateKey=new ArrayList<String>();
	ArrayList<String> SymmetricKey=new ArrayList<String>();
	ArrayList<String> hashKey=new ArrayList<String>();
	ArrayList<String> bitstring=new ArrayList<String>();
	ArrayList<String> idCertificate=new ArrayList<String>();
	ArrayList<String> nonce=new ArrayList<String>();
	ArrayList<String> signaturePubKey=new ArrayList<String>();
	ArrayList<String> signaturePrivKey=new ArrayList<String>();
	ArrayList<String> tag=new ArrayList<String>();
	ArrayList<String> timestamp=new ArrayList<String>();
	ArrayList<String> digest=new ArrayList<String>();
	
	public SecurityKey() {
	}
// ---------------- Asymmetric Public Key
	public ArrayList<String> getAsymmetricPublicKey() {
		return AsymmetricPublicKey;
	}
	public String getStringAsymmetricPublicKey() {
		String stringAsymmetricPublicKey = "Asymmetric Public Keys = {";
		for (int i=0; i<AsymmetricPublicKey.size();i++) {
			if (i<AsymmetricPublicKey.size()-1) {
				stringAsymmetricPublicKey += AsymmetricPublicKey.get(i) +",";
			}else {
				stringAsymmetricPublicKey += AsymmetricPublicKey.get(i);
			}
		}
		stringAsymmetricPublicKey += "}";
		return stringAsymmetricPublicKey;
	}
	public void setAsymmetricPublicKey(ArrayList<String> asymmetricPublicKey) {
		AsymmetricPublicKey = asymmetricPublicKey;
	}
	public void addAsymmetricPublicKey(String nuovoValore) {
		AsymmetricPublicKey.add(nuovoValore);
	}
	public void remAsymmetricPublicKey(String vecchioValore) {
		AsymmetricPublicKey.remove(vecchioValore);
	}
	public void remAllAsymmetricPublicKey() {
		for(Iterator<String> i = AsymmetricPublicKey.iterator(); i.hasNext();) {
			String str = i.next();
			i.remove();
			}
	}
	
// ---------------- Asymmetric Private Key
	public ArrayList<String> getAsymmetricPrivateKey() {
		return AsymmetricPrivateKey;
	}
	public String getStringAsymmetricPrivateKey() {
		String stringAsymmetricPrivateKey = "Asymmetric Private Keys = {";
		for (int i=0; i<AsymmetricPrivateKey.size();i++) {
			if (i<AsymmetricPrivateKey.size()-1) {
				stringAsymmetricPrivateKey += AsymmetricPrivateKey.get(i) +",";
			}else {
				stringAsymmetricPrivateKey += AsymmetricPrivateKey.get(i);
			}
		}
		stringAsymmetricPrivateKey += "}";
		return stringAsymmetricPrivateKey;
	}
	public void setAsymmetricPrivateKey(ArrayList<String> asymmetricPrivateKey) {
		AsymmetricPrivateKey = asymmetricPrivateKey;
	}
	public void addAsymmetricPrivateKey(String nuovoValore) {
		AsymmetricPrivateKey.add(nuovoValore);
	}
	public void remAsymmetricPrivateKey(String vecchioValore) {
		AsymmetricPrivateKey.remove(vecchioValore);
	}
	public void remAllAsymmetricPrivateKey() {
		for(Iterator<String> i = AsymmetricPrivateKey.iterator(); i.hasNext();) {
			String str = i.next();
			i.remove();
			}
	}
	
// ---------------- Symmetric Key
	public ArrayList<String> getSymmetricKey() {
		return SymmetricKey;
	}
	public String getStringSymmetricKey() {
		String stringSymmetricKey = "Symmetric Keys = {";
		for (int i=0; i<SymmetricKey.size();i++) {
			if (i<SymmetricKey.size()-1) {
				stringSymmetricKey += SymmetricKey.get(i) +",";
			}else {
				stringSymmetricKey += SymmetricKey.get(i);
			}
		}
		stringSymmetricKey += "}";
		return stringSymmetricKey;
	}
	public void setSymmetricKey(ArrayList<String> symmetricKey) {
		SymmetricKey = symmetricKey;
	}
	public void addSymmetricKey(String nuovoValore) {
		SymmetricKey.add(nuovoValore);
	}
	public void remSymmetricKey(String vecchioValore) {
		SymmetricKey.remove(vecchioValore);
	}
	public void remAllSymmetricKey() {
		for(Iterator<String> i = SymmetricKey.iterator(); i.hasNext();) {
			String str = i.next();
			i.remove();
			}
	}
// ---------------- Hash Key
	public void addHashKey(String nuovoValore) {
		hashKey.add(nuovoValore);
	}
	public void remHashKey(String vecchioValore) {
		hashKey.remove(vecchioValore);
	}
	public void remAllHashKey() {
		for(Iterator<String> i = hashKey.iterator(); i.hasNext();) {
			String str = i.next();
			i.remove();
			}
	}
	public ArrayList<String> getHashKey() {
		return hashKey;
	}
	public String getStringHashKey() {
		String stringHashKey = "Hash = {";
		for (int i=0; i<hashKey.size();i++) {
			if (i<hashKey.size()-1) {
				stringHashKey += hashKey.get(i) +",";
			}else {
				stringHashKey += hashKey.get(i);
			}
		}
		stringHashKey += "}";
		return stringHashKey;
	}
	public void setHashKey(ArrayList<String> hashKey) {
		this.hashKey = hashKey;
	}

// ---------------- Bitstrim	
	public void addBitstring(String nuovoValore) {
		bitstring.add(nuovoValore);
	}
	public void remBitstring(String vecchioValore) {
		bitstring.remove(vecchioValore);
	}
	public void remAllBitstring() {
		for(Iterator<String> i = bitstring.iterator(); i.hasNext();) {
			String str = i.next();
			i.remove();
			}
	}
	public ArrayList<String> getBitstring() {
		return bitstring;
	}
	public String getStringBitstring() {
		String stringBitstring = "Bitstrim = {";
		for (int i=0; i<bitstring.size();i++) {
			if (i<bitstring.size()-1) {
				stringBitstring += bitstring.get(i) +",";
			}else {
				stringBitstring += bitstring.get(i);
			}
		}
		stringBitstring += "}";
		return stringBitstring;
	}
	public void setBitstring(ArrayList<String> bitstring) {
		this.bitstring = bitstring;
	}

// ---------------- idCertificate	
	public void addIdCertificate(String nuovoValore) {
		idCertificate.add(nuovoValore);
	}

	public void remIdCertificate(String vecchioValore) {
		idCertificate.remove(vecchioValore);
	}

	public void remAllIdCertificate() {
		for (Iterator<String> i = idCertificate.iterator(); i.hasNext();) {
			String str = i.next();
			i.remove();
		}
	}

	public ArrayList<String> getIdCertificate() {
		return idCertificate;
	}

	public String getStringIdCertificate() {
		String stringIdCertificate = "IdCertificate = {";
		for (int i = 0; i < idCertificate.size(); i++) {
			if (i < idCertificate.size() - 1) {
				stringIdCertificate += idCertificate.get(i) + ",";
			} else {
				stringIdCertificate += idCertificate.get(i);
			}
		}
		stringIdCertificate += "}";
		return stringIdCertificate;
	}

	public void setIdCertificate(ArrayList<String> idCertificate) {
		this.idCertificate = idCertificate;
	}

// ---------------- nonce
	public void addNonce(String nuovoValore) {
		nonce.add(nuovoValore);
	}

	public void remNonce(String vecchioValore) {
		nonce.remove(vecchioValore);
	}

	public void remAllNonce() {
		for (Iterator<String> i = nonce.iterator(); i.hasNext();) {
			String str = i.next();
			i.remove();
		}
	}

	public ArrayList<String> getNonce() {
		return nonce;
	}

	public String getStringNonce() {
		String stringNonce = "Nonce = {";
		for (int i = 0; i < nonce.size(); i++) {
			if (i < nonce.size() - 1) {
				stringNonce += nonce.get(i) + ",";
			} else {
				stringNonce += nonce.get(i);
			}
		}
		stringNonce += "}";
		return stringNonce;
	}

	public void setNonce(ArrayList<String> nonce) {
		this.nonce = nonce;
	}

// ---------------- signature Pub Key
	public void addSignaturePubKey(String nuovoValore) {
		signaturePubKey.add(nuovoValore);
	}

	public void remSignaturePubKey(String vecchioValore) {
		signaturePubKey.remove(vecchioValore);
	}

	public void remAllSignaturePubKey() {
		for (Iterator<String> i = signaturePubKey.iterator(); i.hasNext();) {
			String str = i.next();
			i.remove();
		}
	}

	public ArrayList<String> getSignaturePubKey() {
		return signaturePubKey;
	}

	public String getStringSignaturePubKey() {
		String stringSignature = "Signature Pub Key = {";
		for (int i = 0; i < signaturePubKey.size(); i++) {
			if (i < signaturePubKey.size() - 1) {
				stringSignature += signaturePubKey.get(i) + ",";
			} else {
				stringSignature += signaturePubKey.get(i);
			}
		}
		stringSignature += "}";
		return stringSignature;
	}

	public void setSignaturePubKey(ArrayList<String> signature) {
		this.signaturePubKey = signature;
	}	

	// ---------------- signature Priv Key
		public void addSignaturePrivKey(String nuovoValore) {
			signaturePrivKey.add(nuovoValore);
		}

		public void remSignaturePrivKey(String vecchioValore) {
			signaturePrivKey.remove(vecchioValore);
		}

		public void remAllSignaturePrivKey() {
			for (Iterator<String> i = signaturePrivKey.iterator(); i.hasNext();) {
				String str = i.next();
				i.remove();
			}
		}

		public ArrayList<String> getSignaturePrivKey() {
			return signaturePrivKey;
		}

		public String getStringSignaturePrivKey() {
			String stringSignature = "Signature Priv Key = {";
			for (int i = 0; i < signaturePrivKey.size(); i++) {
				if (i < signaturePrivKey.size() - 1) {
					stringSignature += signaturePrivKey.get(i) + ",";
				} else {
					stringSignature += signaturePrivKey.get(i);
				}
			}
			stringSignature += "}";
			return stringSignature;
		}

		public void setSignaturePrivKey(ArrayList<String> signature) {
			this.signaturePrivKey = signature;
		}	


// ---------------- Tag
	public void addTag(String nuovoValore) {
		tag.add(nuovoValore);
	}

	public void remTag(String vecchioValore) {
		tag.remove(vecchioValore);
	}

	public void remAllTag() {
		for (Iterator<String> i = tag.iterator(); i.hasNext();) {
			String str = i.next();
			i.remove();
		}
	}

	public ArrayList<String> getTag() {
		return tag;
	}

	public String getStringTag() {
		String stringTag = "Tag = {";
		for (int i = 0; i < tag.size(); i++) {
			if (i < tag.size() - 1) {
				stringTag += tag.get(i) + ",";
			} else {
				stringTag += tag.get(i);
			}
		}
		stringTag += "}";
		return stringTag;
	}

	public void setTag(ArrayList<String> tag) {
		this.tag = tag;
	}

// ---------------- Timestamp
	public void addTimestamp(String nuovoValore) {
		timestamp.add(nuovoValore);
	}

	public void remTimestamp(String vecchioValore) {
		timestamp.remove(vecchioValore);
	}

	public void remAllTimestamp() {
		for (Iterator<String> i = timestamp.iterator(); i.hasNext();) {
			String str = i.next();
			i.remove();
		}
	}

	public ArrayList<String> getTimestamp() {
		return timestamp;
	}

	public String getStringTimestamp() {
		String stringTimestamp = "Timestamp = {";
		for (int i = 0; i < timestamp.size(); i++) {
			if (i < timestamp.size() - 1) {
				stringTimestamp += timestamp.get(i) + ",";
			} else {
				stringTimestamp += timestamp.get(i);
			}
		}
		stringTimestamp += "}";
		return stringTimestamp;
	}

	public void setTimestamp(ArrayList<String> timestamp) {
		this.timestamp = timestamp;
	}

// ---------------- Digest
	public void addDigest(String nuovoValore) {
		digest.add(nuovoValore);
	}

	public void remDigest(String vecchioValore) {
		digest.remove(vecchioValore);
	}

	public void remAllDigest() {
		for (Iterator<String> i = digest.iterator(); i.hasNext();) {
			String str = i.next();
			i.remove();
		}
	}

	public ArrayList<String> getDigest() {
		return digest;
	}

	public String getStringDigest() {
		String stringDigest = "Digest = {";
		for (int i = 0; i < digest.size(); i++) {
			if (i < digest.size() - 1) {
				stringDigest += digest.get(i) + ",";
			} else {
				stringDigest += digest.get(i);
			}
		}
		stringDigest += "}";
		return stringDigest;
	}

	public void setDigest(ArrayList<String> digest) {
		this.digest = digest;
	}

// ---------------- Verifica duplicati
	public boolean checkDuplicate(String nuovoValore, String tipo) {
		if (!tipo.equals("01" )) {
			for (int i = 0; i < AsymmetricPublicKey.size(); i++) {
				if (AsymmetricPublicKey.get(i).equals(nuovoValore)) {
					return true;
				}
			}
		}
		if (!tipo.equals("01" )) {
			for (int i = 0; i < AsymmetricPrivateKey.size(); i++) {
				if (AsymmetricPrivateKey.get(i).equals(nuovoValore)) {
					return true;
				}
			}
		}

		if (!tipo.equals("02")) {
			for (int i = 0; i < SymmetricKey.size(); i++) {
				if (SymmetricKey.get(i).equals(nuovoValore)) {
					return true;
				}
			}
		}
		if (!tipo.equals("03")) {
			for (int i = 0; i < hashKey.size(); i++) {
				if (hashKey.get(i).equals(nuovoValore)) {
					return true;
				}
			}
		}
		if (!tipo.equals("04")) {
			for (int i = 0; i < bitstring.size(); i++) {
				if (bitstring.get(i).equals(nuovoValore)) {
					return true;
				}
			}
		}
		if (!tipo.equals("05")) {
			for (int i = 0; i < idCertificate.size(); i++) {
				if (idCertificate.get(i).equals(nuovoValore)) {
					return true;
				}
			}
		}
		
		if (!tipo.equals("06")) {
			for (int i = 0; i < nonce.size(); i++) {
				if (nonce.get(i).equals(nuovoValore)) {
					return true;
				}
			}
		}
		
		if (!tipo.equals("07")) {
			for (int i = 0; i < signaturePubKey.size(); i++) {
				if (signaturePubKey.get(i).equals(nuovoValore)) {
					return true;
				}
			}
		}
		if (!tipo.equals("07")) {
			for (int i = 0; i < signaturePrivKey.size(); i++) {
				if (signaturePrivKey.get(i).equals(nuovoValore)) {
					return true;
				}
			}
		}
	
		if (!tipo.equals("08")) {
			for (int i = 0; i < tag.size(); i++) {
				if (tag.get(i).equals(nuovoValore)) {
					return true;
				}
			}
		}
		
		
		if (!tipo.equals("09")) {
			for (int i = 0; i < timestamp.size(); i++) {
				if (timestamp.get(i).equals(nuovoValore)) {
					return true;
				}
			}
		}

		
		if (!tipo.equals("10")) {
			for (int i = 0; i < digest.size(); i++) {
				if (digest.get(i).equals(nuovoValore)) {
		//			System.out.println("trovato in 11 " + digest.get(i));					

					return true;
				}
			}
		}
		
				
		return false;
	}
// ---------------- trova un elemento in tutte le tabelle
	public String  searchEle(String Valore) {

		for (int i = 0; i < AsymmetricPublicKey.size(); i++) {
			if (AsymmetricPublicKey.get(i).equals(Valore) || AsymmetricPublicKey.get(i).toUpperCase().equals(Valore)) {
				return "Asymmetric Public Key";
			}
		}

		for (int i = 0; i < AsymmetricPrivateKey.size(); i++) {
			if (AsymmetricPrivateKey.get(i).equals(Valore)|| AsymmetricPrivateKey.get(i).toUpperCase().equals(Valore)) {
				return "Asymmetric Private Key";
			}
		}

		for (int i = 0; i < SymmetricKey.size(); i++) {
			if (SymmetricKey.get(i).equals(Valore)|| SymmetricKey.get(i).toUpperCase().equals(Valore)) {
				return "Symmetric Key";
			}
		}
		for (int i = 0; i < signaturePubKey.size(); i++) {
			if (signaturePubKey.get(i).equals(Valore) || signaturePubKey.get(i).toUpperCase().equals(Valore)) {
				return "Signature Pub Key";
			}
		}
		
		for (int i = 0; i < signaturePrivKey.size(); i++) {
			if (signaturePrivKey.get(i).equals(Valore)) {
				return "Signature Priv Key";
			}
		}		

		for (int i = 0; i < hashKey.size(); i++) {
			if (hashKey.get(i).equals(Valore) || hashKey.get(i).toUpperCase().equals(Valore)) {
				return "Hash";
			}

		}
		for (int i = 0; i < idCertificate.size(); i++) {
			if (idCertificate.get(i).equals(Valore) || idCertificate.get(i).toUpperCase().equals(Valore)) {
				return "Identity Certificate";
			}
		}


		for (int i = 0; i < nonce.size(); i++) {
			if (nonce.get(i).equals(Valore) || nonce.get(i).toUpperCase().equals(Valore)) {
				return "Nonce";
			}
		}
		
		for (int i = 0; i < bitstring.size(); i++) {
			if (bitstring.get(i).equals(Valore) || bitstring.get(i).toUpperCase().equals(Valore)) {
				return "Bitstring";
			}
		}

		for (int i = 0; i < tag.size(); i++) {
				if (tag.get(i).equals(Valore)|| tag.get(i).toUpperCase().equals(Valore)) {
					return "Tag";
				}
			}

			for (int i = 0; i < timestamp.size(); i++) {
				if (timestamp.get(i).equals(Valore)|| timestamp.get(i).toUpperCase().equals(Valore)) {
					return "Timestamp";
				}
			}

			for (int i = 0; i < digest.size(); i++) {
				if (digest.get(i).equals(Valore) || digest.get(i).toUpperCase().equals(Valore)) {
					return "Digest";
				}
			}
	
		return null;
	}
}
