package org.unimi.Aprover;

import java.io.File;
import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;


import javafx.collections.FXCollections;
import javafx.collections.ObservableList;
import javafx.event.ActionEvent;
import javafx.event.EventHandler;
import javafx.fxml.FXML;
import javafx.fxml.FXMLLoader;
import javafx.scene.Cursor;
import javafx.scene.ImageCursor;
import javafx.scene.Node;
import javafx.scene.Parent;
import javafx.scene.Scene;
import javafx.scene.control.ComboBox;
import javafx.scene.control.Label;
import javafx.scene.control.ListCell;
import javafx.scene.control.ListView;
import javafx.scene.control.Menu;
import javafx.scene.control.MenuButton;
import javafx.scene.control.MenuItem;
import javafx.scene.control.RadioButton;
import javafx.scene.control.SplitMenuButton;
import javafx.scene.text.Text;
import javafx.scene.text.TextAlignment;
import javafx.scene.text.TextFlow;
import javafx.scene.control.Alert;
import javafx.scene.control.Button;
import javafx.scene.control.ButtonType;
import javafx.scene.control.CheckBox;
import javafx.scene.control.TitledPane;
import javafx.scene.control.Toggle;
import javafx.scene.control.ToggleGroup;
import javafx.scene.image.Image;
import javafx.scene.image.ImageView;
import javafx.scene.input.InputEvent;
import javafx.scene.input.MouseEvent;
import javafx.scene.layout.AnchorPane;
import javafx.scene.layout.BorderPane;
import javafx.scene.layout.ColumnConstraints;
import javafx.scene.layout.GridPane;
import javafx.scene.shape.Line;
import javafx.scene.control.TextField;
import javafx.stage.FileChooser;
import javafx.stage.Modality;
import javafx.stage.FileChooser.ExtensionFilter;
import javafx.stage.Stage;
import javafx.stage.Window;
import javafx.stage.WindowEvent;


import org.unimi.model.*;

public class AddProperties { 
	String operazione;
	int defaultSelRadioButton = 99;
	ObservableList<String> comboBoxListKnowledge; 
	ObservableList<String> comboBoxListActor; 
	public static final ObservableList names =
            FXCollections.observableArrayList();
	private Stage dialogStage;
	SecurityKey alice, bob, eve, server;
    @FXML
    private ListView listview;
    @FXML
    private ToggleGroup group = new ToggleGroup();
    
    @FXML
    private Text propertyTypes, propertyAdd;
    
    @FXML
    private Button closeButton,addButton,remButton,clearButton;
    
    @FXML
    private ComboBox actorKnow, typeKnowledge, ctlSel;
    
	@FXML
	public void initialize() {
		
		comboBoxListKnowledge = FXCollections.observableArrayList(	
				"Asymmetric Private Key",
				"Asymmetric Public Key",
				"Bitstring", 
				"Digest",
				"Hash",
				"Identity Certificate",
				"Nonce",
				"Signature",
				"Symmetric Key",
				"Tag",
				"Timestamp");
		typeKnowledge.setItems(comboBoxListKnowledge);


//        names.addAll(
//                "Adam", "Alex", "Alfred", "Albert",
//                "Brenda", "Connie", "Derek", "Donny",
//                "Lynne", "Myrtle", "Rose", "Rudolph",
//                "Tony", "Trudy", "Williams", "Zach"
//        );
		
		listview.getItems().removeAll(names);
		
        //names.addAll();
        //listview.setItems(names);
        listview.setCellFactory(param -> new RadioListCell());
        
		remButton.setVisible(false);
		clearButton.setVisible(false);
		addButton.setVisible(true);


	}
	
	private class RadioListCell extends ListCell<String> {
        @Override
        public void updateItem(String obj, boolean empty) {

            super.updateItem(obj, empty);
            if (empty) {
                setText(null);
                setGraphic(null);
            } else {
                RadioButton radioButton = new RadioButton(obj);
                radioButton.setToggleGroup(group);
                // Add Listeners if any
                setGraphic(radioButton);
                if (defaultSelRadioButton<99) {
                	radioButton.setSelected(true);
                }
            }
        }
    }
// inizializzazione CLT List e propriety	
	public void setPropertyTypes (String propertyTypesSelected , String[] ctlEle) {
		propertyTypes.setText(propertyTypesSelected); 
		ObservableList<String>  data = FXCollections.observableArrayList();
		for (int i=0; i< ctlEle.length  ; i++) {
			if (!(ctlEle[i] == null)) {
				data.add(ctlEle[i]);
			}
		}
		ctlSel.setItems(data);
		ctlSel.getSelectionModel().select(0);
	}
	// se il server è uno degli attori utilizzabili lo inserisce nella combo altrimenti
	// inserisce nella combo solo Alice Bob e Eve
	public void setActorList (Boolean server) {
		if (server) {
			comboBoxListActor = FXCollections.observableArrayList("Alice","Bob", "Eve","Server");
		} else {
			comboBoxListActor = FXCollections.observableArrayList("Alice","Bob", "Eve");
		}
		actorKnow.setItems(comboBoxListActor);
	}
	
	   public void setDialogStage(Stage dialogStage,SecurityKey alice,SecurityKey bob,SecurityKey eve,SecurityKey server) {
	        
		   this.dialogStage = dialogStage;
	        this.alice=alice;
	        this.bob=bob;
	        this.eve=eve;
	        this.server=server;
	        this.dialogStage.setOnCloseRequest( 
	        	    e -> { 
	        	    		operazione = "NonSalvare";
	        	            e.consume(); 
	        	            dialogStage.close();
	        	         } );
	        
		}
		public String getpropertyAddValue() {
			return propertyAdd.getText();
		}
		public String getOperation() {
			return operazione;
		}
		public void setpropertyAddValue(String propertyMod) {
			propertyAdd.setText(propertyMod);
			clearButton.setVisible(true);
			addButton.setVisible(false);
			remButton.setVisible(true);
			String knowSelect = "";
			String eleSelect = "";
			String ctlSelect = propertyMod.substring(0 , propertyMod.indexOf(" ("));
			
			ctlSel.getSelectionModel().select(ctlSelect);
			if (propertyMod.contains("Alice")) {
				actorKnow.getSelectionModel().select(0);
			    eleSelect = propertyMod.substring(propertyMod.indexOf("Alice,")+6 , propertyMod.indexOf(")=true"));
			}
			if (propertyMod.contains("Bob")) {
				actorKnow.getSelectionModel().select(1);
				eleSelect = propertyMod.substring(propertyMod.indexOf("Bob,")+4 , propertyMod.indexOf(")=true"));
			}
			if (propertyMod.contains("Eve")) {
				actorKnow.getSelectionModel().select(2);
			    eleSelect = propertyMod.substring(propertyMod.indexOf("Eve,")+4 , propertyMod.indexOf(")=true"));
			}
			if (propertyMod.contains("Server")) {
				actorKnow.getSelectionModel().select(3);
			    knowSelect = server.searchEle(propertyMod.substring(propertyMod.indexOf("Server,")+7 , propertyMod.indexOf(")=true")));
			    eleSelect = propertyMod.substring(propertyMod.indexOf("Server,")+7 , propertyMod.indexOf(")=true"));
			}
		    if (knowSelect == null || knowSelect.isEmpty()) {
				knowSelect = alice.searchEle(eleSelect);
		    }
		    if (knowSelect == null || knowSelect.isEmpty()) {
				knowSelect = bob.searchEle(eleSelect);
		    }
		    if (knowSelect == null || knowSelect.isEmpty()) {
				knowSelect = eve.searchEle(eleSelect);
		    }
		    if (knowSelect == null || knowSelect.isEmpty()) {
				knowSelect = server.searchEle(eleSelect);
		    }
			
			if (!(knowSelect ==null || knowSelect.isEmpty())) {
				setKnowledgeSelected(knowSelect, eleSelect);
			}
			if (propertyMod == null||propertyMod.isEmpty() ) {
				clearButton.setVisible(false);
				addButton.setVisible(true);
			} 
		}
	@FXML
	public void typeKnowledgeSelected() {
		defaultSelRadioButton = 99;
		if (group.getSelectedToggle() != null) {
			group.getSelectedToggle().setSelected(false);
		}
		listview.getItems().removeAll(names);
		setKnowledgeSelected(typeKnowledge.getValue().toString(),null);
		
	}
	public void setKnowledgeSelected(String listSel,String eleSelezionato) {
		defaultSelRadioButton = 99;
		listview.getItems().removeAll(names);
		names.clear();
		
		if (listSel.toString().contains("Nonce")) {
			typeKnowledge.getSelectionModel().select(6);
		       for(int i = 0; i <alice.getNonce().size(); i++) {
		    	   names.add(alice.getNonce().get(i));
		       }
		       for(int i = 0; i <bob.getNonce().size(); i++) {
		    	   names.add(bob.getNonce().get(i));
		       }
		       for(int i = 0; i <eve.getNonce().size(); i++) {
		    	   names.add(eve.getNonce().get(i));
		       }
		       for(int i = 0; i <server.getAsymmetricPrivateKey().size(); i++) {
		    	   names.add(server.getNonce().get(i));
		       }
		       listview.setItems(names);

		}
		if (listSel.toString().contains("Bitstring")) {
			typeKnowledge.getSelectionModel().select(2);
			for(int i = 0; i <alice.getBitstring().size(); i++) {
		    	   names.add(alice.getBitstring().get(i));
		       }
		       for(int i = 0; i <bob.getBitstring().size(); i++) {
		    	   names.add(bob.getBitstring().get(i));
		       }
		       for(int i = 0; i <eve.getBitstring().size(); i++) {
		    	   names.add(eve.getBitstring().get(i));
		       }
		       for(int i = 0; i <server.getBitstring().size(); i++) {
		    	   names.add(server.getBitstring().get(i));
		       }
		       listview.setItems(names);

		}
		if (listSel.toString().contains("Hash")) {
			typeKnowledge.getSelectionModel().select(4);
			for(int i = 0; i <alice.getHashKey().size(); i++) {
		    	   names.add(alice.getHashKey().get(i));
		       }
		       for(int i = 0; i <bob.getHashKey().size(); i++) {
		    	   names.add(bob.getHashKey().get(i));
		       }
		       for(int i = 0; i <eve.getHashKey().size(); i++) {
		    	   names.add(eve.getHashKey().get(i));
		       }
		       for(int i = 0; i <server.getHashKey().size(); i++) {
		    	   names.add(server.getHashKey().get(i));
		       }
		       listview.setItems(names);

		}
	
		if (listSel.toString().contains("Digest")) {
			typeKnowledge.getSelectionModel().select(3);
			for(int i = 0; i <alice.getDigest().size(); i++) {
		    	   names.add(alice.getDigest().get(i));
		       }
		       for(int i = 0; i <bob.getDigest().size(); i++) {
		    	   names.add(bob.getDigest().get(i));
		       }
		       for(int i = 0; i <eve.getDigest().size(); i++) {
		    	   names.add(eve.getDigest().get(i));
		       }
		       for(int i = 0; i <server.getDigest().size(); i++) {
		    	   names.add(server.getDigest().get(i));
		       }
		       listview.setItems(names);
		}	
		
		if (listSel.toString().contains("Identity Certificate")) {
			typeKnowledge.getSelectionModel().select(5);
			for(int i = 0; i <alice.getIdCertificate().size(); i++) {
		    	   names.add(alice.getIdCertificate().get(i));
		       }
		       for(int i = 0; i <bob.getIdCertificate().size(); i++) {
		    	   names.add(bob.getIdCertificate().get(i));
		       }
		       for(int i = 0; i <eve.getIdCertificate().size(); i++) {
		    	   names.add(eve.getIdCertificate().get(i));
		       }
		       for(int i = 0; i <server.getIdCertificate().size(); i++) {
		    	   names.add(server.getIdCertificate().get(i));
		       }
		       listview.setItems(names);
	
		}	

		if (listSel.toString().contains("Asymmetric Private Key")) {
			typeKnowledge.getSelectionModel().select(0);
		       for(int i = 0; i <alice.getAsymmetricPrivateKey().size(); i++) {
		    	   names.add(alice.getAsymmetricPrivateKey().get(i));
		       }
		       for(int i = 0; i <bob.getAsymmetricPrivateKey().size(); i++) {
		    	   names.add(bob.getAsymmetricPrivateKey().get(i));
		       }
		       for(int i = 0; i <eve.getAsymmetricPrivateKey().size(); i++) {
		    	   names.add(eve.getAsymmetricPrivateKey().get(i));
		       }
		       for(int i = 0; i <server.getAsymmetricPrivateKey().size(); i++) {
		    	   names.add(server.getAsymmetricPrivateKey().get(i));
		       }
		       listview.setItems(names);
		}	
		if (listSel.toString().contains("Asymmetric Public Key")) {
			typeKnowledge.getSelectionModel().select(1);
		       for(int i = 0; i <alice.getAsymmetricPublicKey().size(); i++) {
		    	   names.add(alice.getAsymmetricPublicKey().get(i));
		       }
		       for(int i = 0; i <bob.getAsymmetricPublicKey().size(); i++) {
		    	   names.add(bob.getAsymmetricPublicKey().get(i));
		       }
		       for(int i = 0; i <eve.getAsymmetricPublicKey().size(); i++) {
		    	   names.add(eve.getAsymmetricPublicKey().get(i));
		       }
		       for(int i = 0; i <server.getAsymmetricPublicKey().size(); i++) {
		    	   names.add(server.getAsymmetricPublicKey().get(i));
		       }
		       listview.setItems(names);
		}			
		if (listSel.toString().contains("Symmetric Key")) {
			typeKnowledge.getSelectionModel().select(8);
		       for(int i = 0; i <alice.getSymmetricKey().size(); i++) {
		    	   names.add(alice.getSymmetricKey().get(i));
		       }
		       for(int i = 0; i <bob.getSymmetricKey().size(); i++) {
		    	   names.add(bob.getSymmetricKey().get(i));
		       }
		       for(int i = 0; i <eve.getSymmetricKey().size(); i++) {
		    	   names.add(eve.getSymmetricKey().get(i));
		       }
		       for(int i = 0; i <server.getSymmetricKey().size(); i++) {
		    	   names.add(server.getSymmetricKey().get(i));
		       }
		       listview.setItems(names);
		}	

		if (listSel.toString().contains("Signature")) {
			typeKnowledge.getSelectionModel().select(7);
			for(int i = 0; i <alice.getSignature().size(); i++) {
		    	   names.add(alice.getSignature().get(i));
		       }
		       for(int i = 0; i <bob.getSignature().size(); i++) {
		    	   names.add(bob.getSignature().get(i));
		       }
		       for(int i = 0; i <eve.getSignature().size(); i++) {
		    	   names.add(eve.getSignature().get(i));
		       }
		       for(int i = 0; i <server.getSignature().size(); i++) {
		    	   names.add(server.getSignature().get(i));
		       }
		       listview.setItems(names);
		}	
		if (listSel.toString().contains("Tag")) {
			typeKnowledge.getSelectionModel().select(9);
//			listview.getItems().removeAll(names);
			for(int i = 0; i <alice.getTag().size(); i++) {
		    	   names.add(alice.getTag().get(i));
		       }
		       for(int i = 0; i <bob.getTag().size(); i++) {
		    	   names.add(bob.getTag().get(i));
		       }
		       for(int i = 0; i <eve.getTag().size(); i++) {
		    	   names.add(eve.getTag().get(i));
		       }
		       for(int i = 0; i <server.getTag().size(); i++) {
		    	   names.add(server.getTag().get(i));
		       }
		       listview.setItems(names);
		}	
		if (listSel.toString().contains("Timestamp")) {
			typeKnowledge.getSelectionModel().select(10);
			for(int i = 0; i <alice.getTimestamp().size(); i++) {
		    	   names.add(alice.getTimestamp().get(i));
		       }
		       for(int i = 0; i <bob.getTimestamp().size(); i++) {
		    	   names.add(bob.getTimestamp().get(i));
		       }
		       for(int i = 0; i <eve.getTimestamp().size(); i++) {
		    	   names.add(eve.getTimestamp().get(i));
		       }
		       for(int i = 0; i <server.getTimestamp().size(); i++) {
		    	   names.add(server.getTimestamp().get(i));
		       }
		       listview.setItems(names);
		}	
		if (eleSelezionato != null) {
			for (int i = 0; i < names.size(); i++) {
				if (names.get(i).equals(eleSelezionato)) {
					listview.getSelectionModel().select(i);
					// group.getSelectedToggle().setSelected(true);
					// RadioButton selectedRadioButton = (RadioButton) group.getToggles().get(i);
					defaultSelRadioButton = i+1;
					for (Toggle t : group.getToggles()) {
						if (((RadioButton) t).getText().equals(eleSelezionato))
							t.setSelected(true);
					}
				}
			}
		}
		
		
		
	} 
	 @FXML 
		public void addButtonIntoField() {
			
			
			
			Stage stage = (Stage) dialogStage.getScene().getWindow();
			Alert.AlertType type = Alert.AlertType.CONFIRMATION;
			Alert alert = new Alert(type, "");
			alert.initModality(Modality.APPLICATION_MODAL);
			alert.initOwner(stage);

			if ((actorKnow.getValue() == "" || actorKnow.getValue() == null)) {
				alert.getDialogPane().setHeaderText(
						"*- Attenction!! Actor not Selected -* \n *- Attenction!! Properties not inserted -*");

				Optional<ButtonType> result = alert.showAndWait();
				return;
			}
			
			
			if (group.getSelectedToggle() == null) {
				alert.getDialogPane().setHeaderText(
						"*- Attenction!! Type not Selected -* \n *- Attenction!! Properties not inserted -*");
				Optional<ButtonType> result = alert.showAndWait();
				return;
			}
			
			RadioButton selectedRadioButton = (RadioButton) group.getSelectedToggle();
			String toogleGroupValue = selectedRadioButton.getText();
			if (propertyAdd.getText().isEmpty()) {
				propertyAdd.setText(ctlSel.getValue() +" (knows("+ actorKnow.getValue() + ","+ toogleGroupValue + ")=true)");
				clearButton.setVisible(true);
				addButton.setVisible(false);
			} else {
				String substring = propertyAdd.getText().substring(0, propertyAdd.getText().length()-1);
				propertyAdd.setText(substring + " and knows("+ actorKnow.getValue() + ","+ toogleGroupValue + ")=true)");
			}
		

		}
	@FXML 
	public void remButtonIntoField() {
			if (propertyAdd.getText().toString().lastIndexOf(" and") > 0) {
				propertyAdd.setText(
						propertyAdd.getText().substring(0, propertyAdd.getText().toString().lastIndexOf(" and")) + ")");
				clearButton.setVisible(false);
				addButton.setVisible(true);
			} else {
				clearButton.setVisible(false);
				addButton.setVisible(true);
				propertyAdd.setText("");
			}
		}
	@FXML 
	public void finishSaving(ActionEvent e) {
			if (!propertyAdd.getText().toString().isEmpty()) {
				operazione = "Saving";
				listview.getItems().removeAll(names);
				dialogStage.close();
				return;
			}

			final Stage stage = (Stage) propertyAdd.getScene().getWindow();
			Alert.AlertType type = Alert.AlertType.ERROR;
			Alert alert = new Alert(type, "");
			alert.initModality(Modality.APPLICATION_MODAL);
			alert.initOwner(stage);

			alert.getDialogPane().setContentText("Expression Not Inserted");
			alert.getDialogPane().setHeaderText("Please add the Expression");
			alert.showAndWait();

		}
	 @FXML 
	 public void finishWithoutSaving(ActionEvent e){
		 operazione = "NotSaving";
		 listview.getItems().removeAll(names);
		 propertyAdd.setText("");
		 dialogStage.close();
	 }
	 @FXML 
	 public void finishRemSaving(ActionEvent e){
		 operazione = "RemSaving";
		 propertyAdd.setText("");
		 listview.getItems().removeAll(names);
		 dialogStage.close();
	 }

	}
