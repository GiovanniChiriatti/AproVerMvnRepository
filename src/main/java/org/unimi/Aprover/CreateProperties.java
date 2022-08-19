package org.unimi.Aprover;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileReader;
import java.io.IOException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;

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

import org.unimi.Aprover.SelectAProVerController.StringImageCell;
import org.unimi.model.*;

public class CreateProperties {
	String operazione =" ";
	int defaultSelRadioButton = 99;
	private Stage dialogStage;
	ObservableList<String> comboBoxListActor; 
	ObservableList<String> comboBoxListOther = FXCollections.observableArrayList(); 
	ObservableList<String>  data = FXCollections.observableArrayList();
	ObservableList<String> comboBoxListKnowledge; 
	public static final ObservableList names =
            FXCollections.observableArrayList();
	
	SecurityKey alice, bob, eve, server;
	
	ArrayList<String> wordsNotAllowed=new ArrayList<String>();

	Boolean checkWords;
    @FXML
    private Button closeButton, deleteButton, doneButton, addExpression;

    @FXML
    private ImageView exclamationPoint;

    @FXML
    private TextField expressionValue;

    @FXML
    private ImageView okPoint;

    @FXML
    private TextField properyName;

    @FXML
    private ImageView xPoint;
    
    @FXML
    private ComboBox<String> actorKnow, typeKnowledge, ctlSel, otherComboBox;
    
    @FXML
    private ToggleGroup group = new ToggleGroup();
    
    @FXML
    private ListView listview;
    
    @FXML
    void helpFinishMessage(MouseEvent event) {

    }

    @FXML
    void helpUpdateMessage(MouseEvent event) {

    }

    @FXML
    void relasedHelp(MouseEvent event) {

    }
    
    @FXML
    void properyNameInsertName(MouseEvent event) {
    	if (properyName.getText().contains("Insert Name")) {
    		properyName.setText("");
    	}
    }
    
	@FXML
	public void initialize() {
		System.out.println("entro");
		exclamationPoint.setVisible(false);
		xPoint.setVisible(false);
		okPoint.setVisible(false);
		comboBoxListKnowledge = FXCollections.observableArrayList(	
				" ",
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
		try {
			BufferedReader reader = new BufferedReader(
					new FileReader("src\\main\\resources\\ConfigurationFile\\ValidWord.txt"));
			String line = reader.readLine();
			comboBoxListOther.add(" ");
			while (line != null) {
				comboBoxListOther.add(line);
				line = reader.readLine();
			}
			otherComboBox.setItems(comboBoxListOther);
		} catch (FileNotFoundException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}

		try {
			BufferedReader reader = new BufferedReader(
					new FileReader("src\\main\\resources\\ConfigurationFile\\InvalidCombination.txt"));
			String line = reader.readLine();
			while (line != null) {
				wordsNotAllowed.add(line);
				line = reader.readLine();
			}
		} catch (FileNotFoundException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		
	}
	
	// prima di essere creata la Scene il controller precedente inizializza le informazioni di questo controller
    public void setDialogStage(Stage dialogStage,SecurityKey alice,SecurityKey bob,SecurityKey eve,SecurityKey server, String cntrWords) {
        this.dialogStage = dialogStage;
        this.alice=alice;
        this.bob=bob;
        this.eve=eve;
        this.server=server;
        if (cntrWords.equals("Don't check Words")) {
			checkWords = true;
		} else {
			checkWords = false;
		}
        this.dialogStage.setOnCloseRequest( 
        	    e -> { 
        	    		properyName.setText("");
        	    		operazione = "NonSalvare";
        	            e.consume(); 
        	            dialogStage.close();
        	         } );
       
       

    }
	
	// se il server è uno degli attori utilizzabili lo inserisce nella combo altrimenti
	// inserisce nella combo solo Alice Bob e Eve
	public void setActorList (Boolean server) {
		if (server) {
			comboBoxListActor = FXCollections.observableArrayList(" ", "Alice","Bob", "Eve","Server");
		} else {
			comboBoxListActor = FXCollections.observableArrayList(" ","Alice","Bob", "Eve");
		}
		actorKnow.setItems(comboBoxListActor);
	}
	
	// inizializzazione CLT List 	
		public void setCtlList(String[] ctlEle) {

			data.add(" ");
			for (int i=0; i< ctlEle.length  ; i++) {
				if (!(ctlEle[i] == null)) {
					data.add(ctlEle[i]);
				}
			}
			ctlSel.setItems(data);
		}
		@FXML
		public void typeKnowledgeSelected() {
			System.out.println("typeKnowledgeSelected " + typeKnowledge.getValue());
			defaultSelRadioButton = 99;
			if (group.getSelectedToggle() != null) {
				group.getSelectedToggle().setSelected(false);
			}
			listview.getItems().removeAll(names);
			setKnowledgeSelected(typeKnowledge.getValue().toString());
		}
		
		public void setKnowledgeSelected(String listSel) {
			defaultSelRadioButton = 99;
			listview.getItems().removeAll(names);
			names.clear();
			if (listSel.toString().equals(" ")|| listSel.toString().isEmpty()) {
				System.out.println("cancellooo " + listSel);
				return;
			}
			
			if (listSel.toString().contains("Nonce")) {
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
			if (listSel.toString().contains("Bitstring")) {;
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
//				listview.getItems().removeAll(names);
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
		
		} 
		
	 @FXML 
	 public void finishWithoutSaving(ActionEvent e){
		 operazione = "NotSalving";
		 properyName.setText("");
		 dialogStage.close();
	 }
	 @FXML 
		public void finishSaving(ActionEvent e) {
			if (verifyString() && !properyName.getText().toString().isEmpty() && !properyName.getText().toString().contains("Insert Name")) {
				operazione = "Salving";
				dialogStage.close();
				return;
			}
			final Stage stage = (Stage) properyName.getScene().getWindow();
			Alert.AlertType type = Alert.AlertType.ERROR;
			Alert alert = new Alert(type, "");
			alert.initModality(Modality.APPLICATION_MODAL);
			alert.initOwner(stage);
			if (properyName.getText().toString().isEmpty()
					|| properyName.getText().toString().contains("Insert Name")) {
				errorMessage("Property Name Not Inserted","Please Enter the Property Name");
			} else {
				errorMessage("Expression Not Correctly Inserted","Please modify the Expression");
			}
			
		}
	 
	 @FXML 
	 public void deletePropertiesFinish(ActionEvent e){
		 operazione = "Delete";
		 dialogStage.close();
	 }	
	public void setTxtProperties(String propType, String expression) {
		properyName.setText(propType);
		expressionValue.setText(expression);
		deleteButton.setVisible(true);
	}
	public String getProperyName() {
		return properyName.getText();
	}
	public String getExpressionValue() {
		return expressionValue.getText();
	}
	public String getOperation() {
		return operazione;
	}
	// metodo attivato quando si preme il button "+" presente nel "message Payload Filed
	// vengono trasferiti i vari campi all'interno dell'elenco del "Security Functions"
	    @FXML 
		public void addExpression() {
	    	String expression ="";
			int numSelect = 0;
			if (ctlSel.getValue() != null && !ctlSel.getValue().isEmpty() && !ctlSel.getValue().equals(" ")) {
				numSelect++;
				System.out.println("ctlSel.getValue() "+ ctlSel.getValue());
				expression=ctlSel.getValue().substring(0,ctlSel.getValue().indexOf(" "))+"(";
			}
			if (actorKnow.getValue() != null && !actorKnow.getValue().isEmpty() && !actorKnow.getValue().equals(" ")) {
				numSelect++;
				System.out.println("actorKnow.getValue() "+ actorKnow.getValue());
				expression=actorKnow.getValue();
			}
			if (otherComboBox.getValue() != null && !otherComboBox.getValue().isEmpty()
					&& !otherComboBox.getValue().equals(" ")) {
				numSelect++;
				System.out.println("otherComboBox.getValue() "+ otherComboBox.getValue());

				expression=otherComboBox.getValue();
			}
			
			if(listview.getSelectionModel().getSelectedItem() !=null) {
				numSelect++;
				System.out.println("listview.getSelectionModel().getSelectedItem() "+ listview.getSelectionModel().getSelectedItem());

				expression=listview.getSelectionModel().getSelectedItem().toString();					
			}
			
			if (numSelect == 0) {
				errorMessage("Adding Invalid expression", "Please Selected an Information");
			    return;
			} else {
				if (numSelect > 1) {
					errorMessage("Adding Invalid expression", "Please Selected Only One Information");
					return;
				}
			}
			
			if (expressionValue.getText() == null || expressionValue.getText().isEmpty() ) {
				if (!(ctlSel.getValue() != null && !ctlSel.getValue().isEmpty() && !ctlSel.getValue().equals(" "))) {
					errorMessage("Adding Invalid expression", "The first Word must be CTL Expression");
					return;
				}
			}
			if (!checkCombinationWord(expression)) {
				errorMessage("Adding Invalid expression", "Invalid Word Combination");
				return;
			}				

			expressionValue.setText( expressionValue.getText() + expression);
			ctlSel.setValue(null);
			actorKnow.setValue(null);
			otherComboBox.setValue(null);
			listview.getSelectionModel().clearSelection();
			verifyString();
	    }
	

	public boolean verifyString() {
	
		int numOpen =0;
		int word = 0;
		while (word < expressionValue.getText().length()) {
				if (expressionValue.getText().charAt(word) == '(') {
					numOpen++;
					xPoint.setVisible(true);
					okPoint.setVisible(false);
					System.out.println("2 trovo parentesi aperta " + numOpen);					
				}
				if (expressionValue.getText().charAt(word) == ')' && numOpen==0) {
					System.out.println("3 trovo parentesi chiusa ma non aperta " + numOpen);
					xPoint.setVisible(true);
					okPoint.setVisible(false);
					return false;
				}

				if (expressionValue.getText().charAt(word) == ')' && numOpen>0) {
					numOpen--;
					System.out.println("6 trovo parentesi chiusa " + numOpen);
				}
			word++;
		}
		

		if (numOpen > 0 ) {
			xPoint.setVisible(true);
			okPoint.setVisible(false);
			return false;
		}
		
		if (expressionValue.getText().toString().isEmpty() ||expressionValue.getText().toString().isBlank() ) {
			xPoint.setVisible(true);
			okPoint.setVisible(false);
			return false;
		}			

		xPoint.setVisible(false);
		okPoint.setVisible(true);
		return true;
	}
	
	public boolean checkCombinationWord(String expression) {
		System.out.println("Entro in  checkCombinationWord" + expression);					

		expression = expressionValue.getText()+ expression;
		System.out.println("espressione " + expression + " " +wordsNotAllowed.size());					
		
		for (int i=0; i < wordsNotAllowed.size(); i++ ) {
			if (expression.contains(wordsNotAllowed.get(i))) {
				System.out.println("5 trovo combinazione non valida " + wordsNotAllowed.get(i));					
				return false;
			}
		}
		
		return true;
	}

	public void errorMessage(String msg1, String msg2) {
		final Stage stage = (Stage) properyName.getScene().getWindow();
		Alert.AlertType type = Alert.AlertType.ERROR;
		Alert alert = new Alert(type, "");
		alert.initModality(Modality.APPLICATION_MODAL);
		alert.initOwner(stage);
		alert.getDialogPane().setContentText(msg1);
		alert.getDialogPane().setHeaderText(msg2);
		alert.showAndWait();

	}
}
