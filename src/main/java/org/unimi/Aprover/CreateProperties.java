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

public class CreateProperties {
	String operazione =" ";
	private Stage dialogStage;
	Set wordsAllowed = new HashSet();
	Set separatorCharacters = new HashSet();
	Boolean checkWords;
    @FXML
    private Button closeButton, deleteButton, doneButton;

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
		exclamationPoint.setVisible(false);
		xPoint.setVisible(false);
		okPoint.setVisible(false);
		try {
			BufferedReader reader = new BufferedReader(
					new FileReader("src\\main\\resources\\ConfigurationFile\\ValidWord.txt"));
			String line = reader.readLine();
			while (line != null) {
				wordsAllowed.add(line);
				line = reader.readLine();
			}
		} catch (FileNotFoundException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		try {
			BufferedReader reader = new BufferedReader(
					new FileReader("src\\main\\resources\\ConfigurationFile\\SeparatorCharacters.txt"));
			String line = reader.readLine();
			while (line != null) {
				separatorCharacters.add(line);
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
       
       for(int i = 0; i <alice.getAsymmetricPublicKey().size(); i++) {
    	   wordsAllowed.add(alice.getAsymmetricPublicKey().get(i));
       }
       for(int i = 0; i <alice.getAsymmetricPrivateKey().size(); i++) {
    	   wordsAllowed.add(alice.getAsymmetricPrivateKey().get(i));
       }
       for(int i = 0; i <alice.getSymmetricKey().size(); i++) {
    	   wordsAllowed.add(alice.getSymmetricKey().get(i));
       }
       for(int i = 0; i <alice.getHashKey().size(); i++) {
    	   wordsAllowed.add(alice.getHashKey().get(i));
       }
       for(int i = 0; i <bob.getAsymmetricPublicKey().size(); i++) {
    	   wordsAllowed.add(bob.getAsymmetricPublicKey().get(i));
       }
       for(int i = 0; i <bob.getAsymmetricPrivateKey().size(); i++) {
    	   wordsAllowed.add(bob.getAsymmetricPrivateKey().get(i));
       }
       for(int i = 0; i <bob.getSymmetricKey().size(); i++) {
    	   wordsAllowed.add(bob.getSymmetricKey().get(i));
       }
       for(int i = 0; i <bob.getHashKey().size(); i++) {
    	   wordsAllowed.add(bob.getHashKey().get(i));
       }
       for(int i = 0; i <eve.getAsymmetricPublicKey().size(); i++) {
    	   wordsAllowed.add(eve.getAsymmetricPublicKey().get(i));
       }
       for(int i = 0; i <eve.getAsymmetricPrivateKey().size(); i++) {
    	   wordsAllowed.add(eve.getAsymmetricPrivateKey().get(i));
       }
       for(int i = 0; i <eve.getSymmetricKey().size(); i++) {
    	   wordsAllowed.add(eve.getSymmetricKey().get(i));
       }
       for(int i = 0; i <eve.getHashKey().size(); i++) {
    	   wordsAllowed.add(eve.getHashKey().get(i));
       }
       for(int i = 0; i <server.getAsymmetricPublicKey().size(); i++) {
    	   wordsAllowed.add(server.getAsymmetricPublicKey().get(i));
       }
       for(int i = 0; i <server.getAsymmetricPrivateKey().size(); i++) {
    	   wordsAllowed.add(server.getAsymmetricPrivateKey().get(i));
       }
       for(int i = 0; i <server.getSymmetricKey().size(); i++) {
    	   wordsAllowed.add(server.getSymmetricKey().get(i));
       }
       for(int i = 0; i <server.getHashKey().size(); i++) {
    	   wordsAllowed.add(server.getHashKey().get(i));
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
				alert.getDialogPane().setContentText("Property Name Not Inserted");
				alert.getDialogPane().setHeaderText("Please Enter the Property Name");
				alert.showAndWait();
			} else {
				alert.getDialogPane().setContentText("Expression Not Correctly Inserted");
				alert.getDialogPane().setHeaderText("Please modify the Expression");
				alert.showAndWait();
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
	@FXML
	public boolean verifyString() {
	
		int numOpen =0;
		String lastWord="";
		char LasteparatorCharacters='\0';
		int word = 0;
		while (word < expressionValue.getText().length()) {
			if (separatorCharacters.contains(String.valueOf(expressionValue.getText().charAt(word)))) {
				if (!lastWord.isEmpty()) {
					if (!(wordsAllowed.contains(lastWord)) && checkWords) {
		//				System.out.println("1 non trovo la parola " + lastWord);
						xPoint.setVisible(true);
						okPoint.setVisible(false);
						return false;
					}
				}
				if (expressionValue.getText().charAt(word) == '(') {
					numOpen++;
		//			System.out.println("2 trovo parentesi aperta " + numOpen);
				}
				if (expressionValue.getText().charAt(word) == ')' && numOpen==0) {
		//			System.out.println("3 trovo parentesi chiusa ma non aperta " + numOpen);
					xPoint.setVisible(true);
					okPoint.setVisible(false);
					return false;
				}
				if (expressionValue.getText().charAt(word) == ')' && (!((LasteparatorCharacters==')') || (LasteparatorCharacters=='\0') ))) {
		//			System.out.println("4 trovo parentesi chiusa ma successiva ad altri separatori " + LasteparatorCharacters);
					xPoint.setVisible(true);
					okPoint.setVisible(false);
					return false;
				}
				if (expressionValue.getText().charAt(word) == ',' && (!(LasteparatorCharacters=='\0'))) {
		//			System.out.println("5 trovo virgola ma successiva ad altri separatori " + LasteparatorCharacters);
					xPoint.setVisible(true);
					okPoint.setVisible(false);
					return false;
				}
				if (expressionValue.getText().charAt(word) == ')' && numOpen>0) {
					numOpen--;
		//			System.out.println("6 trovo parentesi chiusa " + numOpen);
				}
				if (!(expressionValue.getText().charAt(word) == ' ')) {
					LasteparatorCharacters = expressionValue.getText().charAt(word);
		//			System.out.println("7 memorizzo precedente separatore -" + LasteparatorCharacters + "-");
				}
				lastWord="";
			} else {
				lastWord = lastWord + (String.valueOf(expressionValue.getText().charAt(word)));
				LasteparatorCharacters = '\0';
			}
			word++;
		}
		
		if (!lastWord.isEmpty()) {
			if (!(wordsAllowed.contains(lastWord)) && checkWords){
				xPoint.setVisible(true);
				okPoint.setVisible(false);
				return false;
			}
		}
		if (numOpen > 0 || LasteparatorCharacters ==','|| LasteparatorCharacters =='=') {
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
}
