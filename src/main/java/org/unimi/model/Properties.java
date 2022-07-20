package org.unimi.model;

import java.util.ArrayList;

public class Properties {

	private String[][] listPartProperties = new String[8][5];
	private String[] descProperties = new String[8];

	public Properties() {
		for (String descrizione : descProperties) {
			descrizione= "";
		}
		for (int i=0; i<8; i++ ) {
			for (int j=0; j<5; j++ ) {
				listPartProperties[i][j]="";
			}
		}
	
	}

	public void addDescProperties(int pos, String descr) {
		if (pos < 8) {
			descProperties[pos] = descr;
		}
	}

	public void addDescProperties(int posa, int posb, String descr) {
		if (posa < 8 && posb < 6) {
			if (!descProperties[posa].isEmpty()) {
				listPartProperties[posa][posb] = descr;
			}
		}
	}

	public void addNextDescProperties(int posa, String descr) {
		if (posa < 8) {
			if (!descProperties[posa].isEmpty()) {
				for (int posb = 0; posb < 5; posb++) {
					if (listPartProperties[posa][posb].isEmpty()) {
						listPartProperties[posa][posb] = descr;
						return;
					}
				}
			}
		}
	}
	public void delDescProperties(int pos) {
		if (pos < 8) {
			descProperties[pos] = "";
			for (int i=pos+1; i<8;i++){
				descProperties[i-1] =descProperties[i];
				descProperties[i]="";
				for (int j=0; j<5; j++){
					listPartProperties[i-1][j] =listPartProperties[i][j];
					listPartProperties[i][j]="";
				}
			}
		}
	}

	public void delPartProperties(int posa, int posb) {
		if (posa < 8) {
			listPartProperties[posa][posb] = "";
			for (int j = posb + 1; j < 5; j++) {
				listPartProperties[posa][j - 1] = listPartProperties[posa][j];
				listPartProperties[posa][j] = "";
			}

		}
	}

	public void stampaProprieties() {
		System.out.println("@--------- Proprierties ------@");
		for (int i = 0; i < 8; i++) {
			if (!descProperties[i].isEmpty()) {
				System.out.println(descProperties[i]);
				for (int j = 0; j < 5; j++) {
					if (!listPartProperties[i][j].isEmpty()) {
						System.out.println("        " + listPartProperties[i][j]);
					}
				}
			}
		}
	}
}

