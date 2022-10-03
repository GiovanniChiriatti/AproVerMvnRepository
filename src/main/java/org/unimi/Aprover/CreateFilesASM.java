package org.unimi.Aprover;

import java.io.IOException;

import org.unimi.model.Messages;
import org.unimi.model.SecurityKey;
import org.unimi.model.WriteASM;
import org.unimi.model.WriteCryptoLibrary;

import javafx.fxml.FXML;
import javafx.scene.control.TextField;
import javafx.scene.input.MouseEvent;
import javafx.scene.text.Text;
import javafx.stage.Stage;

public class CreateFilesASM {
	Messages messages;
	SecurityKey alice, bob, eve, server;
	String toolEve, toolServer;
	private Stage dialogStage;
	@FXML
	private TextField acronymProcolASM;

	@FXML
	private TextField nameProcolASM;

	@FXML
	private Text resultOperation;

	@FXML
	public void initialize() {
		resultOperation.setText("");
	}
	
	public void setDialogStage(Stage dialogStage) {
		this.dialogStage = dialogStage;
	}
	public void receivInfo(Messages messages, SecurityKey alice, SecurityKey bob, SecurityKey eve, SecurityKey server,
			String toolEve, String toolServer) {
		
		this.messages = messages;
		this.alice = alice;
		this.bob = bob;
		this.eve = eve;
		this.server = server;
		this.toolEve = toolEve;
		this.toolServer = toolServer;
	}
	@FXML
	void buttonCreateFiles(MouseEvent event) throws IOException {

		resultOperation.setText("");
		if (acronymProcolASM.getText() == null) {
			resultOperation.setText("Insert Acronym Protocol");
			return;
		}

		if (acronymProcolASM.getText().isEmpty()) {
			resultOperation.setText("Insert Acronym Protocol");
			return;
		}
		if (acronymProcolASM.getText().isBlank()) {
			resultOperation.setText("Insert Acronym Protocol2");
			return;
		}

		if (nameProcolASM.getText() == null) {
			resultOperation.setText("Insert Name Protocol");
			return;
		}

		if (nameProcolASM.getText().isEmpty()) {
			resultOperation.setText("Insert Name Protocol");
			return;
		}

		if (nameProcolASM.getText().isBlank()) {
			resultOperation.setText("Insert Name Protocol");
			return;
		}

		if (nameProcolASM.getText().contains(" ") || acronymProcolASM.getText().contains(" ")) {
			resultOperation.setText("No insert space in Name and Acronym Protocol");
			return;
		}

		if (toolServer.contains("Enable")) {
			WriteCryptoLibrary writeCrypto = new WriteCryptoLibrary(false, messages, alice, bob, eve, null, toolEve,
					acronymProcolASM.getText());
			if (!writeCrypto.writeFile()) {
				resultOperation.setText("Create Files Error");
				return;
			} 
			WriteASM writeASM = new WriteASM(false, messages, alice, bob, eve, null, toolEve,
					writeCrypto.getNumEleMsg(), writeCrypto.getLevelTot(), writeCrypto.getNumEncField(),
					writeCrypto.getNumSignField(), writeCrypto.getNumSymField(), 
					writeCrypto.getNumHashField(),nameProcolASM.getText(),acronymProcolASM.getText());
			if (!writeASM.writeFile()) {
				resultOperation.setText("Create Files Error");
				return;
			}
		} else {
				WriteCryptoLibrary writeCrypto1 = new WriteCryptoLibrary(true, messages, alice, bob, eve, server,
						toolEve, acronymProcolASM.getText());
				if (!writeCrypto1.writeFile()) {
					resultOperation.setText("Create Files Error");
					return;
				}
				WriteASM writeASM1 = new WriteASM(true, messages, alice, bob, eve, server, toolEve,
						writeCrypto1.getNumEleMsg(), writeCrypto1.getLevelTot(), writeCrypto1.getNumEncField(),
						writeCrypto1.getNumSignField(), writeCrypto1.getNumSymField(), 
						writeCrypto1.getNumHashField(),nameProcolASM.getText(),acronymProcolASM.getText());
				if (!writeASM1.writeFile()) {
					resultOperation.setText("Create Files Error");
					return;
				}
			
		}
		resultOperation.setText("Files Created");
		return;

	}
	@FXML
	void buttonFinish(MouseEvent event) {
		dialogStage.close();
		return;
	}
}