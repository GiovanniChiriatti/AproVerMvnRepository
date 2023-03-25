package org.unimi.model;

import java.util.ArrayList;

public class Message {
	private String nameMess;
	private String actorFrom;
	private String actorTo;
	private String payload;
	private Boolean evesIntercept;
	private int numRow1;
	private int numRow2;
	private String[][] listPartMessage = new String[16][16];
	private String[] securityFunctionsPartMessage = new String[16];

	public Message() {
		nameMess="";
		payload = "";
		actorTo = "";
		evesIntercept = true;
		actorFrom = "";
		numRow1 =-1;
		numRow2 =-1;
	}

	public Message(String nameMess, String actorFrom, String actorTo, String payload, Boolean  evesIntercept) {
		super();
		this.nameMess = nameMess;
		this.actorFrom = actorFrom;
		this.actorTo = actorTo;
		this.payload = payload;
		this.evesIntercept = evesIntercept;
	}

	public Message(String actorFrom) {
		super();
		this.actorFrom = actorFrom;
	}

	public String getActorTo() {
		return actorTo;
	}
	public String getNameMess() {
		System.out.println("leggo name MEss " + nameMess);
		return nameMess;
	}
	public void setActorTo(String actorTo) {
		this.actorTo = actorTo;
	}
	public String getActorfrom() {
		return actorFrom;
	}

	public void setNameMess(String nameMess) {
		System.out.println("inserisco name MEss " + nameMess);
		this.nameMess = nameMess;
	}
	public void setActorFrom(String actorFrom) {
		this.actorFrom = actorFrom;
	}
	public Boolean getEvesIntercept() {
		return evesIntercept;
	}

	public void setEvesIntercept(Boolean evesIntercept) {
		this.evesIntercept = evesIntercept;
	}
	public String getPayload() {
		return payload;
	}

	public void setPayload(String payload) {
		System.out.println("setPayload" + payload);
		this.payload = payload;
	}

	public String[][] getListPartMessage() {
		return listPartMessage;
	}
	public void setListPartMessage(String[][] listPartMessage) {
		System.out.println("setListPartMessage"+ listPartMessage[0][0]);
		this.listPartMessage = listPartMessage;
	}
	public void  addListPartMessage(String listPartMessage, int riga) {
		if (numRow1 < 16) {
	//		System.out.println("listPartMessage " + numRow1 + " - "+ riga + " Valore " + listPartMessage);

			this.listPartMessage[numRow1][riga] = listPartMessage;
		}
	}

	private void remListPartMessage() {
		if (numRow1 >= 0) {
			for (int i = 0; i < 16; i++) {
				this.listPartMessage[numRow1][i] = "";
			}
		}
	}
	public String  getListPartMessage(int row , int col) {
		if (row > 15 || col > 15) {
			return null;
		}
		return this.listPartMessage[row][col];
	}
	public String getSecurityFunctionsPartMessage(int row) {
		if (row > 15) {
			return null;
		}
		return securityFunctionsPartMessage[row];
	}
	public String[] getSecurityFunctionsPartMessage() {
		return securityFunctionsPartMessage;
	}
	public void setSecurityFunctionsPartMessage(String[] securityFunctionsPartMessage) {
		System.out.println("securityFunctionsPartMessage"+securityFunctionsPartMessage[0]);
		this.securityFunctionsPartMessage = securityFunctionsPartMessage;
	}
	
	public void addSecurityFunctionsPartMessage(String securityFunctionsPartMessage) {
		
		if (numRow1 < 16) {
			numRow1++;
	//		System.out.println("addSecurityFunctionsPartMessage " + numRow1 + " Valore " + securityFunctionsPartMessage);
			this.securityFunctionsPartMessage[numRow1]= securityFunctionsPartMessage;
		}
	}
	public void remSecurityFunctionsPartMessage() {
		
		if (numRow1 >= 0) {		
			this.securityFunctionsPartMessage[numRow1]= "";
			remListPartMessage();
			numRow1--;
		}
	}

}
