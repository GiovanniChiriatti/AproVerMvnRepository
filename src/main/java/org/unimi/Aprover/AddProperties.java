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
    private Button closeButton,addButton,remButton;
    
    @FXML
    private ComboBox actorKnow, typeKnowledge;
    
	@FXML
	public void initialize() {
		
		comboBoxListKnowledge = FXCollections.observableArrayList(	
				"Bitstring", 
				"Digest",
				"Identity Certificate",
				"Asymmetric Private Key",
				"Asymmetric Public Key",
				"Symmetric Key",
				"Nonce",
				"Signature",
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
            }
        }
    }
	
	public void setPropertyTypes (String propertyTypesSelected) {
		propertyTypes.setText(propertyTypesSelected); 
		
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
			System.out.println("la proprietà da inserire è " + propertyMod);
			propertyAdd.setText(propertyMod);
			remButton.setVisible(true);
		}
	@FXML
	public void typeKnowledgeSelected() {
		if (group.getSelectedToggle() != null) {
			group.getSelectedToggle().setSelected(false);
		}
		listview.getItems().removeAll(names);
		if (typeKnowledge.getValue().toString().contains("Nonce")) {
	        names.addAll("Na", "Nb");
	                listview.setItems(names);
		}
		if (typeKnowledge.getValue().toString().contains("Bitstring")) {
	        names.addAll("Bitstring");
	                listview.setItems(names);
		}
		
		if (typeKnowledge.getValue().toString().contains("Digest")) {
	        names.addAll("Digest");
	                listview.setItems(names);
		}	
		
		if (typeKnowledge.getValue().toString().contains("Identity Certificate")) {
	        names.addAll("ID");
	                listview.setItems(names);
		}	

		if (typeKnowledge.getValue().toString().contains("Asymmetric Private Key")) {
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
		if (typeKnowledge.getValue().toString().contains("Asymmetric Public Key")) {
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
		if (typeKnowledge.getValue().toString().contains("Symmetric Key")) {
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

		if (typeKnowledge.getValue().toString().contains("Signature")) {
	        names.addAll("Signature");
	                listview.setItems(names);
		}	
		if (typeKnowledge.getValue().toString().contains("Tag")) {
			listview.getItems().removeAll(names);
	        names.addAll("Tag");
	                listview.setItems(names);
		}	
		if (typeKnowledge.getValue().toString().contains("Timestamp")) {
	        names.addAll("Timestamp");
	                listview.setItems(names);
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
				propertyAdd.setText("¬EF (knows("+ actorKnow.getValue() + ","+ toogleGroupValue + ")=true)");
			} else {
				String substring = propertyAdd.getText().substring(0, propertyAdd.getText().length()-1);
				propertyAdd.setText(substring + " and knows("+ actorKnow.getValue() + ","+ toogleGroupValue + ")=true)");
			}
		

		}
	@FXML 
	public void remButtonIntoField() {
		System.out.println("----------" + propertyAdd.getText().toString());
			if (propertyAdd.getText().toString().lastIndexOf(" and") > 0) {
				propertyAdd.setText(
						propertyAdd.getText().substring(0, propertyAdd.getText().toString().lastIndexOf(" and")) + ")");
			} else {
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
