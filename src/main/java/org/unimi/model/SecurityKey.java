package org.unimi.model;

import java.util.ArrayList;

public class SecurityKey {
	ArrayList<String> AsymmetricPublicKey=new ArrayList<String>();
	ArrayList<String> AsymmetricPrivateKey=new ArrayList<String>();
	ArrayList<String> SymmetricKey=new ArrayList<String>();
	ArrayList<String> hashKey=new ArrayList<String>();
	
	public SecurityKey() {
	}

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
	public void addHashKey(String nuovoValore) {
		hashKey.add(nuovoValore);
	}
	public void remHashKey(String vecchioValore) {
		hashKey.remove(vecchioValore);
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
	public boolean checkDuplicate(String nuovoValore) {
		for (int i=0; i<AsymmetricPublicKey.size();i++) {
			if (AsymmetricPublicKey.get(i).equals(nuovoValore)) {
				return true;
			}
		}
		
		for (int i=0; i<AsymmetricPrivateKey.size();i++) {
			if (AsymmetricPrivateKey.get(i).equals(nuovoValore)) {
				return true;
			}
		}
		
		for (int i=0; i<SymmetricKey.size();i++) {
			if (SymmetricKey.get(i).equals(nuovoValore)) {
				return true;
			}
		}
		
		for (int i=0; i<hashKey.size();i++) {
			if (hashKey.get(i).equals(nuovoValore)) {
				return true;
			}
		}
		
		return false;
	}
}
