package org.unimi.model;

import java.util.ArrayList;

public class Message {
	private String actorFrom;
	private String actorTo;
	private String payload;
	private Boolean evesIntercept;
	private int numRow1;
	private int numRow2;
	private String[][] listPartMessage = new String[16][16];
	private String[] securityFunctionsPartMessage = new String[16];

	public Message() {
		payload = "";
		actorTo = "";
		evesIntercept = true;
		actorFrom = "";
		numRow1 =-1;
		numRow2 =-1;
	}

	public Message(String actorFrom, String actorTo, String payload, Boolean  evesIntercept) {
		super();
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

	public void setActorTo(String actorTo) {
		this.actorTo = actorTo;
	}
	public String getActorfrom() {
		return actorFrom;
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
		this.payload = payload;
	}

	public String[][] getListPartMessage() {
		return listPartMessage;
	}

	public void  addListPartMessage(String listPartMessage, int riga) {
		if (numRow1 < 16) {
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
	public void addSecurityFunctionsPartMessage(String securityFunctionsPartMessage) {
		
		if (numRow1 < 16) {
			numRow1++;
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
