package org.unimi.model;

import java.util.ArrayList;

public class Messages {
	private Message listMessages[] = new Message[15];

	public Messages() {
		for (int i = 0; i < 15; i++) {
			listMessages[i] = new Message();;
		}
	}
	public Message[] getListMessages() {
		return listMessages;
	}

	public void setListMessages(Message[] listMessages) {
		this.listMessages = listMessages;
	}
	public Message getMessage(int numMessage) {
		return this.listMessages[numMessage];
	}
	public void setMessages(Message message, int numMessage) {
		this.listMessages[numMessage] = message;
	}
	public void remMessages(int numMessage) {
		this.listMessages[numMessage] = new Message();
	}
}
