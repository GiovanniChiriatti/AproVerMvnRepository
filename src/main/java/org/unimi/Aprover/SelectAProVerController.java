package org.unimi.Aprover;

import java.awt.Desktop;
//import java.awt.*;
import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.IOException;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Optional;
import java.util.Scanner;

import org.controlsfx.control.CheckComboBox;

//import com.sun.prism.paint.Color;
import javafx.collections.FXCollections;
import javafx.collections.ListChangeListener;
import javafx.collections.ObservableList;
import javafx.event.ActionEvent;
import javafx.fxml.FXML;
import javafx.fxml.FXMLLoader;
import javafx.scene.Cursor;
import javafx.scene.Group;
import javafx.scene.ImageCursor;
import javafx.scene.Node;
import javafx.scene.Parent;
import javafx.scene.Scene;
import javafx.scene.control.ComboBox;
import javafx.scene.control.ContentDisplay;
import javafx.scene.control.Label;
import javafx.scene.control.ListCell;
import javafx.scene.control.MenuButton;
import javafx.scene.control.MenuItem;
import javafx.scene.control.RadioButton;
import javafx.scene.control.Tab;
import javafx.scene.control.TabPane;
import javafx.scene.text.Text;
import javafx.scene.text.TextFlow;
import javafx.scene.control.Alert;
import javafx.scene.control.Button;
import javafx.scene.control.ButtonType;
import javafx.scene.control.CheckMenuItem;
import javafx.scene.control.TitledPane;
import javafx.scene.image.Image;
import javafx.scene.image.ImageView;
import javafx.scene.input.MouseEvent;
import javafx.scene.layout.AnchorPane;
import javafx.scene.layout.BorderPane;
import javafx.scene.layout.ColumnConstraints;
import javafx.scene.layout.GridPane;
import javafx.scene.layout.HBox;
import javafx.scene.shape.Line;
import javafx.scene.control.TextField;
import javafx.stage.FileChooser;
import javafx.stage.Modality;
import javafx.stage.FileChooser.ExtensionFilter;
import javafx.stage.Stage;

import org.unimi.model.*;

public class SelectAProVerController {


    static HashMap<String, Image> pictures = new HashMap<>();
	//ObservableList<String> comboBoxList = FXCollections.observableArrayList("Alice", "Bob", "Eye", "Server");

	private MainApp main;

	private List<String> listFiles;

	final String publicKnow = "Asymmetric Public Keys";
	final String privateKnow = "Asymmetric Private Keys";
	final String symmetricKnow = "Symmetric Key";
	final String hashKnow = "Hash";
	SecurityKey alice = new SecurityKey();
	SecurityKey bob = new SecurityKey();
	SecurityKey eye = new SecurityKey();
	SecurityKey server = new SecurityKey();
	Messages messagges = new Messages();
	ConfigurationDataProprieties confProp = new ConfigurationDataProprieties();
	private String appoOldKnowledge= null;
	boolean toolFlag = false;
	boolean helpFlag = false;
	boolean eyeIntercept=false;
	String fileName;
	int numMessage, numMessagePrec;
	
	Node node,node1,node2,node3,node4, line,liey,livy, nodeNext1, nodeNext2,nodeNext3,nodeNext4;

	@FXML
	private AnchorPane initialKnowledge,msgPayloadAncorPane,msgPayloadAncorPane1, TotalAnchorPane;

	@FXML
	private TitledPane titledAlice;

	@FXML
	private TitledPane titledBob;

	@FXML
	private CheckComboBox ListProprieties00, ListProprieties01, ListProprieties02,ListProprieties03,ListProprieties04,ListProprieties05;

	@FXML
	private TitledPane titledEye;

	@FXML
	private TitledPane titledServer;
	
	@FXML
	private TextFlow msgPayload,  msgPayload1;
	@FXML
	//private ComboBox<Label> comboBoxActor;
	private ComboBox comboBoxActor;
	
	@FXML
	private Line line01, line02, line03, line04, line05, line06, line07, line08, line09, line10, line11, line12, line13, line14, line15;
	@FXML
	private Line liey01, liey02, liey03, liey04, liey05, liey06, liey07, liey08, liey09, liey10, liey11, liey12, liey13, liey14, liey15;
	@FXML
	private Line livy01, livy02, livy03, livy04, livy05, livy06, livy07, livy08, livy09, livy10, livy11, livy12, livy13, livy14, livy15;

	@FXML
	private ImageView faceAlice, faceBob, faceEye, faceServer, lineaBob, lineaEye, lineVEye, lineaAlice, lineaServer;

	@FXML
	private Text nomeActor, typeKey, rowEdit, knowPage;

	@FXML
	private Text rowNum1, rowNum2, rowNum3, rowNum4, rowNum5, rowNum6, rowNum7, rowNum8, rowNum9, rowNum10, rowNum11;

	@FXML
	private Button nextButton, prevButton, piuButton, menoButton, finishButton;
	
	@FXML
	private Button aliceButton01, bobButton01, eyeButton01, serverButton01;
	
	@FXML
	private Button aliceButton02, bobButton02, eyeButton02, serverButton02;
	@FXML
	private Button aliceButton03, bobButton03, eyeButton03, serverButton03;
	@FXML
	private Button aliceButton04, bobButton04, eyeButton04, serverButton04;
	
	@FXML
	private Button aliceButton05, bobButton05, eyeButton05, serverButton05;
	
	@FXML
	private Button aliceButton06, bobButton06, eyeButton06, serverButton06;
	
	@FXML
	private Button aliceButton07, bobButton07, eyeButton07, serverButton07;
		
	@FXML
	private Button aliceButton08, bobButton08, eyeButton08, serverButton08;
	@FXML
	private Button aliceButton09, bobButton09, eyeButton09, serverButton09;
	@FXML
	private Button aliceButton10, bobButton10, eyeButton10, serverButton10;
	@FXML
	private Button aliceButton11, bobButton11, eyeButton11, serverButton11;
	@FXML
	private Button aliceButton12, bobButton12, eyeButton12, serverButton12;
	@FXML
	private Button aliceButton13, bobButton13, eyeButton13, serverButton13;	
	@FXML
	private Button aliceButton14, bobButton14, eyeButton14, serverButton14;
	@FXML
	private Button aliceButton15, bobButton15, eyeButton15, serverButton15;
	@FXML
	private Button insertSelect00,insertSelect01,insertSelect02,insertSelect03,insertSelect04,insertSelect05;
	
	@FXML
	private AnchorPane ancorPulsanti;
	
	@FXML
	private GridPane tabeKnowledge, listProprieties00, listProprieties01,listProprieties02, listProprieties03, listProprieties04, listProprieties05;
	
	@FXML
	private Label aliceAsymmetricPublicKey, aliceAsymmetricPrivateKey, aliceSymmetricKey, aliceHash;
	@FXML
	private Label bobAsymmetricPublicKey, bobAsymmetricPrivateKey, bobSymmetricKey, bobHash;
	@FXML
	private Label eyeAsymmetricPublicKey, eyeAsymmetricPrivateKey, eyeSymmetricKey, eyeHash;
	@FXML
	private Label serverAsymmetricPublicKey, serverAsymmetricPrivateKey, serverSymmetricKey, serverHash;

	@FXML
	private Tab tab00,tab01,tab02,tab03,tab04,tab05;
	
	@FXML
	private TabPane tabProprieities;

	@FXML
	private MenuButton choices;
	
	@FXML
	private MenuItem tool,toolEye;

//
// Routin di inizializzazione del Controller
// 

	@FXML
	public void initialize() {
// legge il file di configurazione delle propriet� da testare		
		System.out.println("entro in select");
		readFileConf();
		HBox titleBoxAlice = new HBox();
		ImageView immageAlice = new ImageView(new Image(getClass().getResource("/styles/images/alicepiccola1.png").toExternalForm(),0, 24, true, true));
		titleBoxAlice.getChildren().add(immageAlice);
		titledAlice.setGraphic(titleBoxAlice);
		titledAlice.setContentDisplay(ContentDisplay.RIGHT);
		
		tool.setDisable(false);
		toolEye.setDisable(false);
		
		
		HBox titleBoxBob = new HBox();
		ImageView immageBob = new ImageView(new Image(getClass().getResource("/styles/images/bobpiccola1.png").toExternalForm(),0, 24, true, true));
		titleBoxBob.getChildren().add(immageBob);
		titledBob.setGraphic(titleBoxBob);
		titledBob.setContentDisplay(ContentDisplay.RIGHT);
		
		HBox titleBoxEye = new HBox();
		ImageView immageEye = new ImageView(new Image(getClass().getResource("/styles/images/eyepiccola1.png").toExternalForm(),0, 24, true, true));
		titleBoxEye.getChildren().add(immageEye);
		titledEye.setGraphic(titleBoxEye);
		titledEye.setContentDisplay(ContentDisplay.RIGHT);
		
		HBox titleBoxServer = new HBox();
		ImageView immageServer = new ImageView(new Image(getClass().getResource("/styles/images/serverpiccola1.png").toExternalForm(),0, 24, true, true));
		titleBoxServer.getChildren().add(immageServer);
		titledServer.setGraphic(titleBoxServer);
		titledServer.setContentDisplay(ContentDisplay.RIGHT);
						
// imposta la combobox delle specifice propriertis che possono essere selezionate
		
		for (int i=0 ; i <6 ; i++){
			insePropriertiesIntoTab(i);
		}
	

// si abilitano le visibilit� della combobox per la selezione degli actor
		
		if (tool.getText().contains("Enable")) {
			comboBoxActor.getItems().addAll("Alice", "Eye", "Bob");
			
		} else {
			comboBoxActor.getItems().addAll("Alice", "Eye", "Bob", "Server");
		}
		
        //Set the cellFactory property
		comboBoxActor.setCellFactory(listview -> new StringImageCell());
        // Set the buttonCell property
		comboBoxActor.setButtonCell(new StringImageCell());
		
		
		comboBoxActor.setDisable(false);
// si abilitano le visibilit� dei disegni dei vari attori (facce piu righe)
		faceAlice.setVisible(true);
		lineaAlice.setVisible(true);
		faceBob.setVisible(true);
		lineaBob.setVisible(true);
		faceEye.setVisible(true);
		lineaEye.setVisible(true);
		if (tool.getText().contains("Enable")) {
			faceServer.setVisible(false);
			lineaServer.setVisible(false);
			titledServer.setVisible(false);
		} else {
			faceServer.setVisible(true);
			lineaServer.setVisible(true);
			titledServer.setVisible(true);
		}
			
// si disabilita la visibilit� del Ancor per l'inserimento dei parametri di knowledge		
		initialKnowledge.setVisible(false);

// si inizializzano le variabili che indicano la riga del knowlege da digitare e il tipo di knowledge attivo
		rowEdit.setText("1");
		knowPage.setText("1");
		
		aliceButton01.setVisible(false);
		bobButton01.setVisible(false);
		eyeButton01.setVisible(false);
		
		serverButton01.setVisible(false);
		
		aliceButton02.setVisible(false);
		bobButton02.setVisible(false);
		eyeButton02.setVisible(false);
		serverButton02.setVisible(false);
		
		aliceButton03.setVisible(false);
		bobButton03.setVisible(false);
		eyeButton03.setVisible(false);
		serverButton03.setVisible(false);
			
		aliceButton04.setVisible(false);
		bobButton04.setVisible(false);
		eyeButton04.setVisible(false);
		serverButton04.setVisible(false);
			
		aliceButton05.setVisible(false);
		bobButton05.setVisible(false);
		eyeButton05.setVisible(false);
		serverButton05.setVisible(false);
			
		aliceButton06.setVisible(false);
		bobButton06.setVisible(false);
		eyeButton06.setVisible(false);
		serverButton06.setVisible(false);
			
		aliceButton07.setVisible(false);
		bobButton07.setVisible(false);
		eyeButton07.setVisible(false);
		serverButton07.setVisible(false);
			
		aliceButton08.setVisible(false);
		bobButton08.setVisible(false);
		eyeButton08.setVisible(false);
		serverButton08.setVisible(false);
			
		aliceButton09.setVisible(false);
		bobButton09.setVisible(false);
		eyeButton09.setVisible(false);
		serverButton09.setVisible(false);
			
		aliceButton10.setVisible(false);
		bobButton10.setVisible(false);
		eyeButton10.setVisible(false);
		serverButton10.setVisible(false);
	
		aliceButton11.setVisible(false);
		bobButton11.setVisible(false);
		eyeButton11.setVisible(false);
		serverButton11.setVisible(false);
			
		aliceButton12.setVisible(false);
		bobButton12.setVisible(false);
		eyeButton12.setVisible(false);
		serverButton12.setVisible(false);
	
		aliceButton13.setVisible(false);
		bobButton13.setVisible(false);
		eyeButton13.setVisible(false);
		serverButton13.setVisible(false);
	
		aliceButton14.setVisible(false);
		bobButton14.setVisible(false);
		eyeButton14.setVisible(false);
		serverButton14.setVisible(false);
		
		aliceButton15.setVisible(false);
		bobButton15.setVisible(false);
		eyeButton15.setVisible(false);
		serverButton15.setVisible(false);
		

	}
	
	
	//riutine per inserire le immagini nel combobox degli Actor
	static class StringImageCell extends ListCell<String> {

		@Override
		protected void updateItem(String item, boolean empty) {
			Label label;
			super.updateItem(item, empty);
			if (item == null || empty) {
				setItem(null);
				setGraphic(null);
			} else {
				setText(item);
				ImageView image = getImageView(item);
				label = new Label("", image);
				setGraphic(label);
			}
		}

	}

	private static ImageView getImageView(String imageName) {
		System.out.println("immageview");
		
		SelectAProVerController cell = new SelectAProVerController();
		ImageView imageView = null;
		
			if (!pictures.containsKey(imageName)) {
				pictures.put(imageName, cell.getImage(imageName));
				//pictures.put(imageName,new Image(getClass().getResource("/styles/images/alicepiccola1.png").toExternalForm());
			}
			imageView = new ImageView(pictures.get(imageName));
		System.out.println("immageview exit");
		return imageView;
	}
	
	
	
	private Image getImage(String imageName) {
		Image image = null;
		switch (imageName) {
		case "Alice":
			image = new Image(getClass().getResource("/styles/images/alicepiccola.png").toExternalForm());
			break;
			
		case "Bob":
			image = new Image(getClass().getResource("/styles/images/bobpiccola.png").toExternalForm());
			break;
			
		case "Eye":
			image = new Image(getClass().getResource("/styles/images/eyepiccola.png").toExternalForm());
			break;
			
		case "Server":
			image = new Image(getClass().getResource("/styles/images/serverpiccola.png").toExternalForm());
			break;

		default:
			imageName = null;
		}
		return image;
		
	}

// Chiusura PAgina	
	@FXML

	private void selectClose() {
		final Stage stage = (Stage) aliceButton01.getScene().getWindow();
    	Alert.AlertType type =  Alert.AlertType.CONFIRMATION;
    	Alert alert = new Alert(type, "");
    	alert.initModality(Modality.APPLICATION_MODAL);
    	alert.initOwner(stage);
    	alert.getDialogPane().setContentText("OK to Saving and Exit - Annulla to Exit without Saving ?");
    	alert.getDialogPane().setHeaderText("if you want to save the file click on ok");
    	Optional<ButtonType> result  = alert.showAndWait();
    	if (result.get()== ButtonType.OK) {
    	    	saveFile();
    	}
        
        stage.close();
	}
	// Imposta il cursore per la visualizzazione degli help dei singoli oggetti della form	
		@FXML

		private void selectHelp() {
			Scene sc1 = aliceButton01.getScene();
			if (helpFlag) {
				sc1.setCursor(Cursor.DEFAULT);
				helpFlag = false;
			} else {
			 //	sc1.setCursor(Cursor.OPEN_HAND);
			 	Image image = new Image("/styles/images/questionmarcTrasparente.png");
			 	sc1.setCursor(new ImageCursor (image,
			 									image.getWidth()/2,
			 									image.getHeight() /2));
				helpFlag = true;
			}
		}
		
		// Visualezza l'help della sezione knowledge	
		@FXML

		private void helpKnowledge() {
			
			if (helpFlag) {
				msgPayload.getChildren().clear();
				msgPayloadAncorPane.setLayoutX(0);
				msgPayloadAncorPane.setLayoutY(40);
				writeTxtPreview("this section contains view of knowledge of key of all actor \n (Alice Bob Eyes Server) "  );
				
				msgPayload.setVisible(true);
				msgPayloadAncorPane.setVisible(true);
			}
		}
		// Visualezza l'help della sezione dell�a combocox per la selezione degli actor	
		@FXML

		private void helpActor() {
			
			if (helpFlag) {
				msgPayload.getChildren().clear();
				msgPayloadAncorPane.setLayoutX(0);
				msgPayloadAncorPane.setLayoutY(40);
				writeTxtPreview("select the actor to enter his knowledge "  );
				
				msgPayload.setVisible(true);
				msgPayloadAncorPane.setVisible(true);
			}
		}
		// Visualizza l'help della sezione della combocox per la selezione degli actor	
		@FXML

		private void helpPiu(MouseEvent e) throws Exception {
		
			
			node = (Node) e.getSource();
			String partMessage ="";
			String partMessage2 ="";
			String data = (String) node.getId();

			int riga = Integer.parseInt(data.substring(data.length() - 2));
			
			
			msgPayload.getChildren().clear();

			
			if (data.contains("alice")) partMessage2 = "Alice";
			if (data.contains("bob")) partMessage2 = "Bob";
			if (data.contains("eye")) partMessage2 = "Eyes";
			if (data.contains("server")) partMessage2 = "Server";
			
			if (((Button) node).getText().equals("-")) {
				partMessage="Select for erase message ";
			} else {
				partMessage= "Select to insert the message from " + partMessage2;
			}
			
			if (helpFlag) {
				msgPayload.getChildren().clear();
				msgPayloadAncorPane.setLayoutX(0);
				msgPayloadAncorPane.setLayoutY(40 * riga);
				writeTxtPreview(partMessage);
				
				msgPayload.setVisible(true);
				msgPayloadAncorPane.setVisible(true);
			}
		}	
		// Visualezza l'help del tasto di chiusura della finestra knowledge	
		@FXML
		private void helpChiudiKnowledge() {
			
			if (helpFlag) {
				msgPayload1.getChildren().clear();
				msgPayloadAncorPane1.setLayoutX(400);
				msgPayloadAncorPane1.setLayoutY(40);
				Text msg= new Text("Select to Close Page");
				msgPayload1.getChildren().addAll(msg);
				//writeTxtPreview("Select X for close"  );
				
				msgPayload1.setVisible(true);
				msgPayloadAncorPane1.setVisible(true);
			}
		}
		// Visualezza l'help del tasto per inserire una nuova riga nella finestra knowledge	
		@FXML
		private void helpPiuKnowledge() {
			
			if (helpFlag) {
				msgPayload1.getChildren().clear();
				msgPayloadAncorPane1.setLayoutX(400);
				msgPayloadAncorPane1.setLayoutY(40);
				Text msg= new Text("Select + for insert new row");
				msgPayload1.getChildren().addAll(msg);
				//writeTxtPreview("Select X for close"  );
				
				msgPayload1.setVisible(true);
				msgPayloadAncorPane1.setVisible(true);
			}
		}
		// Visualezza l'help del tasto eliminare una  riga nella finestra knowledge	
		@FXML
		private void helpMenoKnowledge() {
			
			if (helpFlag) {
				msgPayload1.getChildren().clear();
				msgPayloadAncorPane1.setLayoutX(400);
				msgPayloadAncorPane1.setLayoutY(40);
				Text msg= new Text("Select for delete row");
				msgPayload1.getChildren().addAll(msg);
				//writeTxtPreview("Select X for close"  );
				
				msgPayload1.setVisible(true);
				msgPayloadAncorPane1.setVisible(true);
			}
		}
		// Visualezza l'help del tasto per cambiare pagina nella finestra knowledge	
		@FXML
		private void helpNextKnowledge() {
			
			if (helpFlag) {
				msgPayload1.getChildren().clear();
				msgPayloadAncorPane1.setLayoutX(400);
				msgPayloadAncorPane1.setLayoutY(70);
				Text msg= new Text("Select NEXT for enter new type of knowledge");
				msgPayload1.getChildren().addAll(msg);
				//writeTxtPreview("Select X for close"  );
				
				msgPayload1.setVisible(true);
				msgPayloadAncorPane1.setVisible(true);
			}
		}
		// Visualezza l'help del tasto per cambiare pagina nella finestra knowledge	
		@FXML
		private void helpPrevKnowledge() {
			
			if (helpFlag) {
				msgPayload1.getChildren().clear();
				msgPayloadAncorPane1.setLayoutX(400);
				msgPayloadAncorPane1.setLayoutY(70);
				Text msg= new Text("Select PREV to enter the previous knowledge type");
				msgPayload1.getChildren().addAll(msg);
				//writeTxtPreview("Select X for close"  );
				
				msgPayload1.setVisible(true);
				msgPayloadAncorPane1.setVisible(true);
			}
		}
		@FXML
		private void relasedHelp(MouseEvent e) throws Exception {
			
			msgPayload.getChildren().clear();
			msgPayload.setVisible(false);
			msgPayloadAncorPane.setVisible(false);
			msgPayload1.getChildren().clear();
			msgPayload1.setVisible(false);
			msgPayloadAncorPane1.setVisible(false);
		}
//Routin che si attiva ogni qual volta viene selezionato un attore dal ComboBox
// viene verificato se abilitato o meno il server	
	@FXML

	private void selectComboBox() {
		
		if (toolFlag) {
			toolFlag= false;
			return;
		}
		boolean viewLineOK = false;
		if (faceAlice.getOpacity() == 1 &&
				faceBob.getOpacity() == 1 &&
				faceEye.getOpacity() == 1 && (
				faceServer.getOpacity() == 1 || tool.getText().contains("Enable"))) {
				viewLineOK = true;
			}
//rende visibile le icone e le righe delle immagini dei vari attori
		faceAlice.setVisible(true);
		lineaAlice.setVisible(true);
		faceBob.setVisible(true);
		lineaBob.setVisible(true);
		faceEye.setVisible(true);
		lineaEye.setVisible(true);
		if (tool.getText().contains("Enable")) {
			faceServer.setVisible(false);
			lineaServer.setVisible(false);
			titledServer.setVisible(false);
		} else {
			faceServer.setVisible(true);
			lineaServer.setVisible(true);
			titledServer.setVisible(true);
		}

		/*
		 * 
		 * lineaBob.setOpacity(0.31); faceAlice.setOpacity(0.31);
		 * lineaAlice.setOpacity(0.31); faceBob.setOpacity(0.31);
		 * lineaBob.setOpacity(0.31); faceEye.setOpacity(0.31);
		 * lineaEye.setOpacity(0.31); faceServer.setOpacity(0.31);
		 * lineaServer.setOpacity(0.31);
		 */
//rende visibile le icone e le righe delle immagini dei vari actor
//Disabilita la combobox per la selezione degli actor
//inizializza la visibilit� e i dati della form che permetto l'isnerimento dei vari tipi di chiavi
		comboBoxActor.setDisable(true);
		typeKey.setText("Asymmetric Public Keys");
		prevButton.setVisible(false);
		nextButton.setVisible(true);
		finishButton.setVisible(false);
		piuButton.setVisible(true);
		menoButton.setVisible(false);
		knowPage.setText("1");

//verifica quale Actor � stato selezionato e abilita la visibilit� della form di knowledge (initialKnowledge.setVisible(true);)
		if (comboBoxActor.getValue().toString().contains("Alice")) {
			nomeActor.setText("Alice's");
			initialKnowledge.setVisible(true);
			faceAlice.setOpacity(1);
			lineaAlice.setOpacity(1);
			loadTable(alice, "1");
			loadTitledAlice(alice);
		}
		if (comboBoxActor.getValue().toString().contains("Bob")) {
			nomeActor.setText("Bob's");
			initialKnowledge.setVisible(true);
			faceBob.setOpacity(1);
			lineaBob.setOpacity(1);
			loadTable(bob, "1");
			loadTitledBob(bob);
		}
		if (comboBoxActor.getValue().toString().contains("Eye")) {
			nomeActor.setText("Eye's");
			initialKnowledge.setVisible(true);
			faceEye.setOpacity(1);
			lineaEye.setOpacity(1);
			loadTable(eye, "1");
			loadTitledEye(eye);
		}
		if (comboBoxActor.getValue().toString().contains("Server")) {
			nomeActor.setText("Server's");
			initialKnowledge.setVisible(true);
			faceServer.setOpacity(1);
			lineaServer.setOpacity(1);
			loadTable(server, "1");
			loadTitledServer(server);
		}
//se � stata completata la fase di definizione delle varie chiavi per tutti gli attori, abilita il button + per inserire i messaggi 		
		if (faceAlice.getOpacity() == 1 &&
			faceBob.getOpacity() == 1 &&
			faceEye.getOpacity() == 1 && (
			faceServer.getOpacity() == 1 || tool.getText().contains("Enable"))&&
			!viewLineOK) {
			viewLine("01");
		}
	}

//ogni volta che si termina di inserire le chiavi per un sigolo actor viene resettata la combobox
	@FXML

	private void chiudiKnowledge() {

		initialKnowledge.setVisible(false);

		//comboBoxActor.getSelectionModel().clearSelection();
		//comboBoxActor.getItems().removeAll(comboBoxList);
		comboBoxActor.setValue("Actor");
		comboBoxActor.setDisable(false);
		

	}
	//ogni volta che si termina di inserire le chiavi, si salva l'ultima chiave ibnserita e  per un sigolo actor viene resettata la combobox
		@FXML

		private void finishKnowledge() {
			piuKnowledge();	
			chiudiKnowledge();	

		}
//quando nella form di knowledge si preme next si abilitano/disabilitano alcuni pulsanti e si modifica il tipo di kyavi da inserire (es: hash,symmetric,asymmetric etc)	
	
	@FXML

	private void nextKnowledge() {

		piuKnowledge();
		
		if (knowPage.getText().equals("3")) {
			//piuKnowledge();
			typeKey.setText(hashKnow);
			nextButton.setVisible(false);
			finishButton.setVisible(true);
			prevButton.setVisible(true);
			piuButton.setVisible(true);
			menoButton.setVisible(false);
			knowPage.setText("4");
		}
		if (knowPage.getText().equals("2")) {
			typeKey.setText(symmetricKnow);
			nextButton.setVisible(true);
			finishButton.setVisible(false);
			prevButton.setVisible(true);
			piuButton.setVisible(true);
			menoButton.setVisible(false);
			knowPage.setText("3");
		}

		if (knowPage.getText().equals("1")) {
			typeKey.setText(privateKnow);
			nextButton.setVisible(true);
			finishButton.setVisible(false);
			prevButton.setVisible(true);
			piuButton.setVisible(true);
			menoButton.setVisible(false);
			knowPage.setText("2");
		}

		if (comboBoxActor.getValue().toString().contains("Alice")) {
			loadTable(alice, knowPage.getText());
			loadTitledAlice(alice);
		}
		if (comboBoxActor.getValue().toString().contains("Bob")) {
			loadTable(bob, knowPage.getText());
			loadTitledBob(bob);
		}
		if (comboBoxActor.getValue().toString().contains("Eye")) {
			loadTable(eye, knowPage.getText());
			loadTitledEye(eye);
		}
		if (comboBoxActor.getValue().toString().contains("Server")) {
			loadTable(server, knowPage.getText());
			loadTitledServer(server);
		}
	}

//quando nella form di knowledge si preme prev si abilitano/disabilitano alcuni pulsanti e si modifica il tipo di kyavi da inserire (es: hash,symmetric,asymmetric etc)	
	
	@FXML
	private void prevKnowledge() {
		piuKnowledge();
		
		if (knowPage.getText().equals("2")) {
			typeKey.setText(publicKnow);
			nextButton.setVisible(true);
			finishButton.setVisible(false);
			prevButton.setVisible(false);
			piuButton.setVisible(true);
			menoButton.setVisible(false);
			knowPage.setText("1");
		}
		if (knowPage.getText().equals("3")) {
			typeKey.setText(privateKnow);
			nextButton.setVisible(true);
			finishButton.setVisible(false);
			prevButton.setVisible(true);
			piuButton.setVisible(true);
			menoButton.setVisible(false);
			knowPage.setText("2");
		}
		if (knowPage.getText().equals("4")) {
			typeKey.setText(symmetricKnow);
			nextButton.setVisible(true);
			finishButton.setVisible(false);
			prevButton.setVisible(true);
			piuButton.setVisible(true);
			menoButton.setVisible(false);
			knowPage.setText("3");
		}
		if (comboBoxActor.getValue().toString().contains("Alice")) {
			loadTable(alice, knowPage.getText());
			loadTitledAlice(alice);
		}
		if (comboBoxActor.getValue().toString().contains("Bob")) {
			loadTable(bob, knowPage.getText());
			loadTitledBob(bob);
		}
		if (comboBoxActor.getValue().toString().contains("Eye")) {
			loadTable(eye, knowPage.getText());
			loadTitledEye(eye);
		}
		if (comboBoxActor.getValue().toString().contains("Server")) {
			loadTable(server, knowPage.getText());
			loadTitledServer(server);
		}
	}

	
	//Nella sotto-form Knowledge � possibile inserire in ogni pagina piu righe contentneti 
	//le chiavi usate dall'actor. per inserire una nuova riga si preme il pulsante +
	@FXML

	private void piuKnowledge() {
		
		if (comboBoxActor.getValue().toString().contains("Alice")) {
			addSecurityKey(alice, knowPage.getText(), newRow(alice));
			loadTitledAlice(alice);
		}
		if (comboBoxActor.getValue().toString().contains("Bob")) {
			addSecurityKey(bob, knowPage.getText(), newRow(bob));
			loadTitledBob(bob);
		}
		if (comboBoxActor.getValue().toString().contains("Eye")) {
			addSecurityKey(eye, knowPage.getText(), newRow(eye));
			loadTitledEye(eye);
		}
		if (comboBoxActor.getValue().toString().contains("Server")) {

			addSecurityKey(server, knowPage.getText(), newRow(server));
			loadTitledServer(server);
		}
		return;
	}

	// quando si prene il tasto + nel sott-form della knowledge si verifica di non essere arrivato all'ultima riga
	// (massimo 10) si memorizza l'informazione inserita nella riga precedente controllando che non sia duplicata e si abilita la nuova riga
	private String newRow(SecurityKey oggetto) {
		
		
		int rowCurrent = Integer.parseInt(rowEdit.getText());
		if (rowCurrent > 10) {
			return null;
		}

		int appRow, appColumn;
		Node result = null;
		Node resultAppo = null;
		Node resultSblock0 = null;
		Node resultSblock1 = null;
		for (Node node : tabeKnowledge.getChildren()) {
			appRow = 0;
			appColumn = 0;
			result = node;
			if (tabeKnowledge.getRowIndex(node) != null) {
				appRow = tabeKnowledge.getRowIndex(node);
			}
			if (tabeKnowledge.getColumnIndex(node) != null) {
				appColumn = tabeKnowledge.getColumnIndex(node);
			}
			if (appRow == rowCurrent && rowCurrent < 10 && appColumn == 1) {
				resultSblock1 = node;
			}
			if (appRow == rowCurrent && rowCurrent < 10 && appColumn == 0) {
				resultSblock0 = node;

			}
			if (appRow == rowCurrent - 1 && appColumn == 1) {
				if (result == null || ((TextField) result).getText().isEmpty()
						|| ((TextField) result).getText().equals("")) {
					return null;
				} else {
					resultAppo = node;
					if (oggetto.checkDuplicate(((TextField) resultAppo).getText())) {
						Stage stage = (Stage) piuButton.getScene().getWindow();
				    	Alert.AlertType type =  Alert.AlertType.ERROR;
				    	Alert alert = new Alert(type, "");
				    	alert.initModality(Modality.APPLICATION_MODAL);
				    	alert.initOwner(stage);
				    	alert.getDialogPane().setContentText("duplicate data ("+((TextField) resultAppo).getText() +"), insertion not possible");
 			    	    alert.showAndWait();
						return null;
					} else {
						node.setVisible(true);
						node.setDisable(true);
						rowEdit.setText(Integer.toString(rowCurrent + 1));
					}
				}

			}
		}
		if (resultSblock1 != null && resultSblock0 != null) {
			resultSblock1.setVisible(true);
			resultSblock1.setDisable(false);
			resultSblock0.setVisible(true);
			resultSblock1.requestFocus();
			rowEdit.setText(Integer.toString(rowCurrent+1));
		}
// si abilitano o disabilitano i pulsanti "+" e"-"
		if (rowCurrent < 11 && resultAppo != null) {
			menoButton.setVisible(true);
		}
		if (rowCurrent > 9 && resultAppo != null) {
			piuButton.setVisible(false);
		}

		if (appoOldKnowledge == null) {
			return ((TextField) resultAppo).getText();
		} else {
			if (appoOldKnowledge.equals(((TextField) resultAppo).getText())) {
				appoOldKnowledge = null;
				return null;
			} else {
				
				return ((TextField) resultAppo).getText();				
			}
		}
	}

	// si inseriscono le informazioni digitate 
	private void addSecurityKey(SecurityKey oggetto, String tipo, String valore) {

		if (valore != null) {
			switch (tipo) {
			case "1":
				oggetto.addAsymmetricPublicKey(valore);
				break;
			case "2":
				oggetto.addAsymmetricPrivateKey(valore);
				break;
			case "3":
				oggetto.addSymmetricKey(valore);
				break;
			case "4":
				oggetto.addHashKey(valore);
				break;
			}
		}
		if (appoOldKnowledge != null) {
			switch (tipo) {
			case "1":
				oggetto.remAsymmetricPublicKey(appoOldKnowledge);
				break;
			case "2":
				oggetto.remAsymmetricPrivateKey(appoOldKnowledge);
				break;
			case "3":
				oggetto.remSymmetricKey(appoOldKnowledge);
				break;
			case "4":
				oggetto.remHashKey(appoOldKnowledge);
				break;
			}
		}
		appoOldKnowledge = null;
		
	}
	
	//se si preme il pulsante "-" nella sott-form della knowledge 
	// si deve  ripristinare la riga precedente
	@FXML
	private void menoKnowledge() {

		if (comboBoxActor.getValue().toString().contains("Alice")) {
			remSecurityKey(alice, knowPage.getText(), oldRow());
			loadTitledAlice(alice);
		}
		if (comboBoxActor.getValue().toString().contains("Bob")) {

			remSecurityKey(bob, knowPage.getText(), oldRow());
			loadTitledBob(bob);
		}
		if (comboBoxActor.getValue().toString().contains("Eye")) {

			remSecurityKey(eye, knowPage.getText(), oldRow());
			loadTitledEye(eye);
		}
		if (comboBoxActor.getValue().toString().contains("Server")) {

			remSecurityKey(server, knowPage.getText(), oldRow());
			loadTitledServer(server);
		}
		return;
	}
// riprostino della riga precedente 
	private String oldRow() {


		int rowCurrent = Integer.parseInt(rowEdit.getText());
	
		int appRow, appColumn;
		Node result = null;
		Node resultAppo = null;
		Node resultSblock0danascondere = null;
		Node resultSblock1dacancellare = null;
		Node resultSblock1daripristinare = null;
		for (Node node : tabeKnowledge.getChildren()) {
			appRow = 0;
			appColumn = 0;
			result = node;
			if (tabeKnowledge.getRowIndex(node) != null) {appRow = tabeKnowledge.getRowIndex(node);}
			if (tabeKnowledge.getColumnIndex(node) != null) {appColumn = tabeKnowledge.getColumnIndex(node);}
			
			
			if (appRow == rowCurrent-1 && appColumn==1) {
				resultSblock1dacancellare = node;
				}
			if (appRow == rowCurrent-1 && appColumn==0) {
				resultSblock0danascondere = node;
			}
			
			if (appRow == rowCurrent-2 && appColumn == 1 && rowCurrent > 1 ) {
				resultSblock1daripristinare = node;
			}
		}
		String resultReturn = appoOldKnowledge;
		appoOldKnowledge = null;
		if (resultSblock1daripristinare != null) {
			//resultSblock1daripristinare.setVisible(true);
			resultSblock1daripristinare.setDisable(false);
			resultSblock1daripristinare.requestFocus();
			appoOldKnowledge = ((TextField) resultSblock1daripristinare).getText();
			rowEdit.setText(Integer.toString(rowCurrent-1));
			resultSblock0danascondere.setVisible(false);
			resultSblock1dacancellare.setVisible(false);
			resultSblock1dacancellare.setDisable(true);
		}
		if (rowEdit.getText().equals("1") && resultSblock1daripristinare == null) {
			menoButton.setVisible(false);
		}
		piuButton.setVisible(true);
		//String resultReturn = ((TextField) resultSblock1dacancellare).getText();
		((TextField) resultSblock1dacancellare).setText("");
		return resultReturn; 
	}

	//si elimina la riga memorizzata quando viene premuto il tasto "-" nella sott-form knowledge
	private void remSecurityKey(SecurityKey oggetto, String tipo, String valore) {
		if (valore != null && !valore.isEmpty()) {
			switch (tipo) {
			case "1":
				oggetto.remAsymmetricPublicKey(valore);
				break;
			case "2":
				oggetto.remAsymmetricPrivateKey(valore);
				break;
			case "3":
				oggetto.remSymmetricKey(valore);
				break;
			case "4":
				oggetto.remHashKey(valore);
				break;
			}
		}
	}	

	// quando si apre la sott-form knowledge si verifica se sono gia presenti informazioni memorizzate in precedenza
	// e si caricano nella sott-form 
	private void loadTable(SecurityKey oggetto, String tipo) {
		
		//tabeKnowledge.setGridLinesVisible(false);
		
		//tabeKnowledge.getColumnConstraints().clear();
		appoOldKnowledge = null;
		for (Node node : tabeKnowledge.getChildren()) {
			node.setVisible(false);
			if (node !=null && node instanceof TextField) {
			((TextField) node).setText(""); }
		}

		
		ArrayList<String> appoList = new ArrayList<String>();
		switch (tipo) {
		case "1":
			appoList = oggetto.getAsymmetricPublicKey();
			break;
		case "2":
			appoList = oggetto.getAsymmetricPrivateKey();
			break;
		
		case "3":
			appoList = oggetto.getSymmetricKey();
			break;
		case "4":
			//oggetto.getHash();
			appoList = oggetto.getHashKey();
			break;
		}
		
	/*	for (int i = 0; i < appoList.size(); i++) {
			tabeKnowledge.add(new TextField(appoList.get(i)), 1, i);
		}
		for (int i = appoList.size(); i < 11; i++) {
			tabeKnowledge.add(new TextField(""), 1, i);
		}
	*/
		int appRow;
		int appColumn;
		tabeKnowledge.setGridLinesVisible(true);
		for (Node node : tabeKnowledge.getChildren()) {
			
			if (tabeKnowledge.getRowIndex(node) != null) {
				appRow = tabeKnowledge.getRowIndex(node);
			} else {
				appRow = 0;
			}
			if (tabeKnowledge.getColumnIndex(node) != null) {
				appColumn = tabeKnowledge.getColumnIndex(node);
			} else {
				appColumn = 0;
			}
			if (appRow < appoList.size()) {
				node.setVisible(true);
				node.setDisable(true);
				if (node instanceof TextField) {
					((TextField) node).setText(appoList.get(appRow));}
			}
			if (appRow > appoList.size()) {
				node.setVisible(false);
			}
			
			
			if (appRow == appoList.size()) {
				node.setVisible(true);
				node.setDisable(false);
				if (node instanceof TextField) {
					((TextField) node).setText("");
					node.requestFocus();}
			}
		}
		//if (knowPage.getText().equals("3")) {
		//	menoButton.setVisible(false);
		//	piuButton.setVisible(false);
		//	rowEdit.setText("1");
		//	return;
		//}
		rowEdit.setText(Integer.toString(appoList.size()+1));
		if (appoList.size() > 0) {
			menoButton.setVisible(true);
		}
		if (appoList.size() > 9) {
			piuButton.setVisible(false);
		}
	}
	
	private void loadTitledAlice(SecurityKey oggetto) {
		aliceAsymmetricPublicKey.setText(oggetto.getStringAsymmetricPublicKey());
		aliceAsymmetricPrivateKey.setText(oggetto.getStringAsymmetricPrivateKey());
		aliceSymmetricKey.setText(oggetto.getStringSymmetricKey());
		aliceHash.setText(oggetto.getStringHashKey());

	}
	private void loadTitledBob(SecurityKey oggetto) {
		bobAsymmetricPublicKey.setText(oggetto.getStringAsymmetricPublicKey());
		bobAsymmetricPrivateKey.setText(oggetto.getStringAsymmetricPrivateKey());
		bobSymmetricKey.setText(oggetto.getStringSymmetricKey());
		bobHash.setText(oggetto.getStringHashKey());
	}
	private void loadTitledEye(SecurityKey oggetto) {
		eyeAsymmetricPublicKey.setText(oggetto.getStringAsymmetricPublicKey());
		eyeAsymmetricPrivateKey.setText(oggetto.getStringAsymmetricPrivateKey());
		eyeSymmetricKey.setText(oggetto.getStringSymmetricKey());
		eyeHash.setText(oggetto.getStringHashKey());
	}
	private void loadTitledServer(SecurityKey oggetto) {
		serverAsymmetricPublicKey.setText(oggetto.getStringAsymmetricPublicKey());
		serverAsymmetricPrivateKey.setText(oggetto.getStringAsymmetricPrivateKey());
		serverSymmetricKey.setText(oggetto.getStringSymmetricKey());
		serverHash.setText(oggetto.getStringHashKey());
	}
	
	
    // se nel menu Tool viene abilitata o disabilitata l'esistenza del Server nel protocollo di sicurezza
	// si elimina (o reinserisce) tutto ci� che riguarda il server (elenco nella combobox degli actor
	// immagine della linea dei messaggi, elenco chiavi conosciute)
	@FXML

	private void toolSet() {
		int faceEyeX, lineaEyeX, faceBobX, lineaBobX, eyeButtonX,bobButtonX;
		System.out.println("entro sul metodo per selezonare il tool");
		if (tool.getText().contains("Disable")) {
			comboBoxActor.setDisable(false);
			toolFlag = true;
			
			comboBoxActor.getItems().remove(3,4);
			System.out.println("Rimuovo il server");
			toolFlag= true;
			comboBoxActor.setValue("Actor");
			toolFlag= false;
			
			tool.setText("Enable Server");
			System.out.println("imposto a eneble il tool (ma in realt� � disabilitato");
			titledServer.setVisible(false);
			faceServer.setVisible(false);
			lineaServer.setVisible(false);
			serverButton01.setVisible(false);
			faceEyeX= 452;
			lineaEyeX=457;
			faceBobX=863;
			lineaBobX=858;
			eyeButtonX=453;
			bobButtonX=855;
		} else {
			comboBoxActor.setValue("Actor");
			comboBoxActor.setDisable(false);
			
			comboBoxActor.getItems().add("Server");
			tool.setText("Disable Server");
			titledServer.setVisible(true);
			faceServer.setVisible(true);
			lineaServer.setVisible(true);
			if (aliceButton01.isVisible()) {
				if (faceServer.getOpacity()==1) {
					serverButton01.setVisible(true);
				} else {
					serverButton01.setVisible(false);
					bobButton01.setVisible(false);
					eyeButton01.setVisible(false);
					aliceButton01.setVisible(false);
				}
			}
			faceEyeX= 313;
			lineaEyeX=318;
			faceBobX=585;
			lineaBobX=580;
			eyeButtonX=314;
			bobButtonX=577;
		}
		faceEye.setLayoutX(faceEyeX);
		lineaEye.setLayoutX(lineaEyeX);
		faceBob.setLayoutX(faceBobX);
		lineaBob.setLayoutX(lineaBobX);
		eyeButton01.setLayoutX(eyeButtonX);
		eyeButton02.setLayoutX(eyeButtonX);
		eyeButton03.setLayoutX(eyeButtonX);
		eyeButton04.setLayoutX(eyeButtonX);
		eyeButton05.setLayoutX(eyeButtonX);
		eyeButton06.setLayoutX(eyeButtonX);
		eyeButton07.setLayoutX(eyeButtonX);
		eyeButton08.setLayoutX(eyeButtonX);
		eyeButton09.setLayoutX(eyeButtonX);
		eyeButton10.setLayoutX(eyeButtonX);
		eyeButton11.setLayoutX(eyeButtonX);
		eyeButton12.setLayoutX(eyeButtonX);
		eyeButton13.setLayoutX(eyeButtonX);
		eyeButton14.setLayoutX(eyeButtonX);
		eyeButton15.setLayoutX(eyeButtonX);
		bobButton01.setLayoutX(bobButtonX);
		bobButton02.setLayoutX(bobButtonX);
		bobButton03.setLayoutX(bobButtonX);
		bobButton04.setLayoutX(bobButtonX);
		bobButton05.setLayoutX(bobButtonX);
		bobButton06.setLayoutX(bobButtonX);
		bobButton07.setLayoutX(bobButtonX);
		bobButton08.setLayoutX(bobButtonX);
		bobButton09.setLayoutX(bobButtonX);
		bobButton10.setLayoutX(bobButtonX);
		bobButton11.setLayoutX(bobButtonX);
		bobButton12.setLayoutX(bobButtonX);
		bobButton13.setLayoutX(bobButtonX);
		bobButton14.setLayoutX(bobButtonX);
		bobButton15.setLayoutX(bobButtonX);
		if (faceAlice.getOpacity() == 1 &&
				faceBob.getOpacity() == 1 &&
				faceEye.getOpacity() == 1 && (
				faceServer.getOpacity() == 1 || tool.getText().contains("Enable"))){
				viewLine("01");
			}
	}
    // se nel menu Tool viene abilitata o disabilitata l'esistenza del Server nel protocollo di sicurezza
	// si elimina (o reinserisce) tutto ci� che riguarda il server (elenco nella combobox degli actor
	// immagine della linea dei messaggi, elenco chiavi conosciute)
	@FXML

	private void toolSetEye() {
		if (toolEye.getText().contains("Eye Doesn't Create Messages")) {
			eyeButton01.setVisible(false);
			toolEye.setText("Eye Create Messages");
		} else {
			toolEye.setText("Eye Doesn't Create Messages");
			if(aliceButton01.isVisible()) {
				eyeButton01.setVisible(true);
			}
		}
		
	}
	public void setToolStart (String toolStart) {
		if (toolStart.equals("Enable Server")){
			System.out.println("imposto a Disable Server per poi invertire");
			tool.setText("Disable Server");
		} else {
			tool.setText("Enable Server");
			System.out.println("imposto a Enable Server per poi invertire");
		}
		toolInitialSet();
	}
	public void setToolEye (String toolStart) {
		toolEye.setText(toolStart);
	}
	private void toolInitialSet() {
		int faceEyeX, lineaEyeX, faceBobX, lineaBobX, eyeButtonX,bobButtonX;
		System.out.println("entro sul metodo per selezonare il tool");
		if (tool.getText().contains("Disable")) {
			comboBoxActor.setDisable(false);
			toolFlag = true;
			
			comboBoxActor.getItems().remove(3,4);
			System.out.println("Rimuovo il server");
			toolFlag= true;
			comboBoxActor.setValue("Actor");
			toolFlag= false;
			
			tool.setText("Enable Server");
			System.out.println("imposto a eneble il tool (ma in realt� � disabilitato");
			titledServer.setVisible(false);
			faceServer.setVisible(false);
			lineaServer.setVisible(false);
			serverButton01.setVisible(false);
			faceEyeX= 452;
			lineaEyeX=457;
			faceBobX=863;
			lineaBobX=858;
			eyeButtonX=453;
			bobButtonX=855;
		} else {
			comboBoxActor.setValue("Actor");
			comboBoxActor.setDisable(false);
			
			//comboBoxActor.getItems().add("Server");
			tool.setText("Disable Server");
			titledServer.setVisible(true);
			faceServer.setVisible(true);
			lineaServer.setVisible(true);
			if (aliceButton01.isVisible()) {
				if (faceServer.getOpacity()==1) {
					serverButton01.setVisible(true);
				} else {
					serverButton01.setVisible(false);
					bobButton01.setVisible(false);
					eyeButton01.setVisible(false);
					aliceButton01.setVisible(false);
				}
			}
			faceEyeX= 313;
			lineaEyeX=318;
			faceBobX=585;
			lineaBobX=580;
			eyeButtonX=314;
			bobButtonX=577;
		}
		faceEye.setLayoutX(faceEyeX);
		lineaEye.setLayoutX(lineaEyeX);
		faceBob.setLayoutX(faceBobX);
		lineaBob.setLayoutX(lineaBobX);
		eyeButton01.setLayoutX(eyeButtonX);
		eyeButton02.setLayoutX(eyeButtonX);
		eyeButton03.setLayoutX(eyeButtonX);
		eyeButton04.setLayoutX(eyeButtonX);
		eyeButton05.setLayoutX(eyeButtonX);
		eyeButton06.setLayoutX(eyeButtonX);
		eyeButton07.setLayoutX(eyeButtonX);
		eyeButton08.setLayoutX(eyeButtonX);
		eyeButton09.setLayoutX(eyeButtonX);
		eyeButton10.setLayoutX(eyeButtonX);
		eyeButton11.setLayoutX(eyeButtonX);
		eyeButton12.setLayoutX(eyeButtonX);
		eyeButton13.setLayoutX(eyeButtonX);
		eyeButton14.setLayoutX(eyeButtonX);
		eyeButton15.setLayoutX(eyeButtonX);
		bobButton01.setLayoutX(bobButtonX);
		bobButton02.setLayoutX(bobButtonX);
		bobButton03.setLayoutX(bobButtonX);
		bobButton04.setLayoutX(bobButtonX);
		bobButton05.setLayoutX(bobButtonX);
		bobButton06.setLayoutX(bobButtonX);
		bobButton07.setLayoutX(bobButtonX);
		bobButton08.setLayoutX(bobButtonX);
		bobButton09.setLayoutX(bobButtonX);
		bobButton10.setLayoutX(bobButtonX);
		bobButton11.setLayoutX(bobButtonX);
		bobButton12.setLayoutX(bobButtonX);
		bobButton13.setLayoutX(bobButtonX);
		bobButton14.setLayoutX(bobButtonX);
		bobButton15.setLayoutX(bobButtonX);
	}
	// Se viene selezionato il pulsante "+" per inserire i dati del messaggio si verifica a quale actor � relativo
	// la stessa cosa viene eseguita se � stata selezionata la linea del messaggio precedentemente inseirito 
	// o se il pulsante selezionato ha il valore "-"
    // se si � selezionato il pulsante "+" si apre la form per l'inserimento dei dati del messaggio
	// se si � selezionata la riga si apre la form per la modifica dei dati del messaggio
	// se si � selezionato il pultante con il valore "-" si cancella il messaggio ed eventualmente si mette a "+ " il valore del pulsante
	@FXML
	private void selButton(ActionEvent e) throws Exception {
		
		
		node = (Node) e.getSource();
		
		String data = (String) node.getId();
		int riga = Integer.parseInt(data.substring(data.length() - 2));
		
	
		node1 =aliceButton01;
		node2 =bobButton01;
		node3 =eyeButton01;
		node4 =serverButton01; 
		nodeNext1 =null;
		nodeNext2 =null;
		nodeNext3 =null;
		nodeNext4 =null;
		line = line01;
		liey = liey01;  
		int rigaSuccessiva = riga + 1;

		for (Node nodeAppo : ancorPulsanti.getChildren()) {
			if (nodeAppo != null && nodeAppo instanceof Button) {
				if (riga == Integer.valueOf(((Button) nodeAppo).getId().substring(((Button) nodeAppo).getId().length() - 2))) {
					if (((Button) nodeAppo).getId().contains("alice")) {
						node1 = nodeAppo;
					}
					if (((Button) nodeAppo).getId().contains("bob")) {
						node2 = nodeAppo;
					}
					if (((Button) nodeAppo).getId().contains("eye")) {
						node3 = nodeAppo;
					}
					if (((Button) nodeAppo).getId().contains("server")) {
						node4 = nodeAppo;
					}
				}
			}
			if (nodeAppo != null && nodeAppo instanceof Line) {
				if (riga == Integer.valueOf(((Line) nodeAppo).getId().substring(((Line) nodeAppo).getId().length() - 2))
						&& ((Line) nodeAppo).getId().contains("line")  ) {
						line = nodeAppo;
				}
				if (riga == Integer.valueOf(((Line) nodeAppo).getId().substring(((Line) nodeAppo).getId().length() - 2))
						&& ((Line) nodeAppo).getId().contains("liey")  ) {
						liey = nodeAppo;
				}
				if (riga == Integer.valueOf(((Line) nodeAppo).getId().substring(((Line) nodeAppo).getId().length() - 2))
						&& ((Line) nodeAppo).getId().contains("livy")  ) {
						livy = nodeAppo;
				}
			}
			if (nodeAppo != null && nodeAppo instanceof Button) {
				if (rigaSuccessiva == Integer
							.valueOf(((Button) nodeAppo).getId().substring(((Button) nodeAppo).getId().length() - 2))) {
						if (((Button) nodeAppo).getId().contains("alice")) {
							nodeNext1 = nodeAppo;
						}
						if (((Button) nodeAppo).getId().contains("bob")) {
							nodeNext2 = nodeAppo;
						}
						if (((Button) nodeAppo).getId().contains("eye")) {
							nodeNext3 = nodeAppo;
						}
						if (((Button) nodeAppo).getId().contains("server")) {
							nodeNext4 = nodeAppo;
						}
					
				}
			}
		}
		
		
		messagges.remMessages(riga - 1);
		if (((Button) node).getText().equals("-")) {
			node1.setVisible(true);
			node2.setVisible(true);
			if (toolEye.getText().contains("Eye Doesn't Create Messages")) {
				node3.setVisible(true);
			} else {
				node3.setVisible(false);
			}
			if (tool.getText().contains("Disable")) { 
					node4.setVisible(true);
			}
			line.setVisible(false);
			liey.setVisible(false);
			livy.setVisible(false);
			((Button) node).setText("+");
			resetLine();
			return;
		}
		eseButton(data, riga, line, liey, livy);
		
	}
	// Richiama la form per l'inserimento dei messaggi passandogli l'actor da cui parte il messaggio
	// e ricevendo l'actor a cui arriva il messaggio(actorTo). se l'actorTo � impostato predispone i pulsanti 
	// per l'inserimento di un nuovo messaggio 
	private void eseButton(String data, int riga, Node line, Node liey, Node livy) throws Exception {
		String actorFrom = "";
		switch (data.substring(0, 5)) {
		case "alice":
			actorFrom = "Alice";
			break;
		case "bobBu":
			actorFrom = "Bob";
			break;
		case "eyeBu":
			actorFrom = "Eye";
			break;
		case "serve":
			actorFrom = "Server";
			break;
		}

		String actorTo = showCreateMessage(actorFrom, riga);
		if (actorTo != null && !actorTo.isEmpty()) {
			tool.setDisable(true);
			toolEye.setDisable(true);
			viewSpecificLinea(actorTo, actorFrom, line, liey, livy);
		}

	}

	private void viewSpecificLinea(String actorTo, String actorFrom, Node oggetto, Node oggetey, Node oggetvy) {
		node1.setVisible(false);
		node2.setVisible(false);
		node3.setVisible(false);
		node4.setVisible(false);
		node.setVisible(true);
		((Button) node).setText("-");
		
		if (tool.getText().contains("Disable")) {
			if (nodeNext1 != null && !nodeNext1.isVisible() && !nodeNext2.isVisible() && !nodeNext3.isVisible()
					&& !nodeNext4.isVisible()) {
				nodeNext1.setVisible(true);
				nodeNext2.setVisible(true);
				if (toolEye.getText().contains("Eye Doesn't Create Messages")) {
					nodeNext3.setVisible(true);
				} else {
					nodeNext3.setVisible(false);
				}
				nodeNext4.setVisible(true);
			}
		} else {
			if (nodeNext1 != null && !nodeNext1.isVisible() && !nodeNext2.isVisible() 
					&& !nodeNext3.isVisible() 	) {
				nodeNext1.setVisible(true);
				nodeNext2.setVisible(true);
				if (toolEye.getText().contains("Eye Doesn't Create Messages")) {
					nodeNext3.setVisible(true);
				} else {
					nodeNext3.setVisible(false);
				}
				nodeNext4.setVisible(false);
			}
		}
		
		double coordinateXStart = 100;
		double coordinateXEnd = 100;
		double coordinateEyeXStart = 100;
		double coordinateEyeXEnd = 100;
		if (tool.getText().contains("Disable")) {
			coordinateEyeXEnd = 165;
			switch (actorTo) {
			case "Alice":
				coordinateXEnd = -99;
				break;
			case "Eye":
				coordinateXEnd = 163;
				break;
			case "Bob":
				coordinateXEnd = 428;
				break;
			case "Server":
				coordinateXEnd = 715;
				break;
			}
			coordinateEyeXStart = 165;
			switch (actorFrom) {
			case "Alice":
				coordinateXStart = -99;
				break;
			case "Eye":
				coordinateXStart = 165;
				break;
			case "Bob":
				coordinateXStart = 430;
				break;
			case "Server":
				coordinateXStart = 712;
				break;
			}
		} else {
			coordinateEyeXEnd = 303;
			switch (actorTo) {
			case "Alice":
				coordinateXEnd = -99;
				break;
			case "Eye":
				coordinateXEnd = 303;
				break;
			case "Bob":
				coordinateXEnd = 703;
				break;
			}
			coordinateEyeXStart = 303;
			switch (actorFrom) {
			case "Alice":
				coordinateXStart = -99;
				break;
			case "Eye":
				coordinateXStart = 308;
				break;
			case "Bob":
				coordinateXStart = 700;
				break;
			}
		}
		System.out.println(" -------> ActorTo-" + actorTo + "-actorFrom-" + actorFrom + "-eyeIntercept-" + eyeIntercept); 
		if (eyeIntercept && !actorTo.equals("Eye") && !actorFrom.equals("Eye")) {
			System.out.println(" -------> ActorTo " + actorTo + " actorFrom " + actorFrom + " eyeIntercept " + eyeIntercept); 
			((Line) oggetto).setEndX(coordinateEyeXEnd);
			((Line) oggetto).setStartX(coordinateXStart);
			oggetto.setVisible(true);

			((Line) oggetey).setEndX(coordinateXEnd);
			((Line) oggetey).setStartX(coordinateEyeXStart);
			oggetey.setVisible(true);
			
			((Line) oggetvy).setEndX(coordinateEyeXStart);
			((Line) oggetvy).setStartX(coordinateEyeXStart);
			oggetvy.setVisible(true);
		} else{
			((Line) oggetto).setEndX(coordinateXEnd);
			((Line) oggetto).setStartX(coordinateXStart);
			oggetto.setVisible(true);
		}

	}
	   /**
     * Apre la schermata per l'inserimento dei dati del messaggio i parametri sono:
     * 
     * @param SecurityKEy con i dati di sicurezza 
     * 		  Messages Elenco dei messaggi gia inseriti
     * 		  actorfrom attore da dove parte il messaggio
     *        messageNumber  numero del messaggio  
     * @return actorTo.
	 * @throws Exception 
     */
 
    public String showCreateMessage(String actorFrom, int messageNumber) throws Exception {

    	FXMLLoader loader = new FXMLLoader();
        loader.setLocation(getClass().getResource("/fxml/CreateMessageAProVer.fxml"));
        AnchorPane page = (AnchorPane) loader.load();
     
        Stage dialogStage = new Stage();
                
        dialogStage.initModality(Modality.WINDOW_MODAL);
        
        Scene scene = new Scene(page);
        dialogStage.setScene(scene);
        
        CreateMessageAProVer controller = loader.getController();
        controller.setDialogStage(dialogStage);
        if (actorFrom.equals("Alice")) {
        	controller.setInfo(alice, messagges.getMessage(messageNumber-1));
        }
        if (actorFrom.equals("Bob")) {
        	controller.setInfo(bob, messagges.getMessage(messageNumber-1));
        }
        if (actorFrom.equals("Eye")) {
        	controller.setInfo(eye, messagges.getMessage(messageNumber-1));
        }
        if (actorFrom.equals("Server")) {
        	controller.setInfo(server, messagges.getMessage(messageNumber-1));
        }
        controller.setActorFrom(actorFrom,messageNumber,tool.getText(),toolEye.getText());
        controller.setHelp(helpFlag);
        

        
        dialogStage.showAndWait();
        eyeIntercept = controller.getEyesIntercept();
        System.out.println("FLAG INSERITO PER EYES Intercept " + eyeIntercept);
        return controller.getActorTo();

    
    }
	@FXML
	private void selLine(MouseEvent e) throws Exception {

		node = (Node) e.getSource();
		
		String data = (String) node.getId();
		int riga = Integer.parseInt(data.substring(data.length() - 2));
		System.out.println("modificl la riga : "+riga);
		showModifyMessage(messagges.getMessage(riga - 1).getActorfrom().toString(),riga);
	}
	@FXML
	private void moveLine(MouseEvent e) throws Exception {

		node = (Node) e.getSource();
		
		String data = (String) node.getId();
		int riga = Integer.parseInt(data.substring(data.length() - 2));
		
		
		msgPayload.getChildren().clear();
		msgPayloadAncorPane.setLayoutX(124);
		msgPayloadAncorPane.setLayoutY((42*riga)+30);
		writeTxtPreview("Message: " + messagges.getMessage(riga - 1).getPayload()+ "\n Select for modify message");
		
		msgPayload.setVisible(true);
		msgPayloadAncorPane.setVisible(true);
	}
	
    private void writeTxtPreview(String compactMessageFinale) {
    	msgPayload.getChildren().clear();
    	int endDash = compactMessageFinale.indexOf("-");
    	int startDash = 0;
    	boolean pedice = false;
    	Text normal = new Text("sub");
    	Text normal2 = new Text("sub");
    	while (endDash >0) {
    		if (pedice) {

		    	Text sub2 = new Text(compactMessageFinale.substring(startDash+1, endDash));
		    	sub2.setTranslateY(normal.getFont().getSize() * 0.3);
		    	msgPayload.getChildren().addAll(sub2);
		    	startDash = endDash +1;
		    	pedice = false;
    		} else {
    			normal2 = new Text(compactMessageFinale.substring(startDash, endDash));
    			msgPayload.getChildren().addAll(normal2);
    			pedice=true;
    			startDash = endDash;
    		}
    		
    		endDash = compactMessageFinale.indexOf("-", startDash+1);
    	}
    	if (startDash == 0 || !pedice) {
			normal = new Text(compactMessageFinale.substring(startDash,compactMessageFinale.length()));
			msgPayload.getChildren().addAll(normal);
		}
    }
	@FXML
	private void relasedLine(MouseEvent e) throws Exception {

		node = (Node) e.getSource();
		
		String data = (String) node.getId();
		int riga = Integer.parseInt(data.substring(data.length() - 2));
		
		msgPayload.getChildren().clear();
		msgPayload.setVisible(false);
		msgPayloadAncorPane.setVisible(false);
	}

	public void showModifyMessage(String actorFrom, int messageNumber) throws Exception {

		FXMLLoader loader = new FXMLLoader();
		loader.setLocation(getClass().getResource("/fxml/CreateMessageAProVer.fxml"));
		AnchorPane page = (AnchorPane) loader.load();

		Stage dialogStage = new Stage();

		dialogStage.initModality(Modality.WINDOW_MODAL);

		Scene scene = new Scene(page);
		dialogStage.setScene(scene);

		CreateMessageAProVer controller = loader.getController();
		controller.setDialogStage(dialogStage);

		if (actorFrom.equals("Alice")) {
			controller.setInfo(alice, messagges.getMessage(messageNumber - 1));
		}
		if (actorFrom.equals("Bob")) {
			controller.setInfo(bob, messagges.getMessage(messageNumber - 1));
		}
		if (actorFrom.equals("Eye")) {
			controller.setInfo(eye, messagges.getMessage(messageNumber - 1));
		}
		if (actorFrom.equals("Server")) {
			controller.setInfo(server, messagges.getMessage(messageNumber - 1));
		}

		controller.setMessage(messageNumber);
		controller.setHelp(helpFlag);

		dialogStage.showAndWait();
        eyeIntercept = controller.getEyesIntercept();
        System.out.println("FLAG INSERITO PER EYES Intercept " + eyeIntercept);

		return;

	}

	private void viewLine(String nRow) {

		for (Node node : ancorPulsanti.getChildren()) {
			if (node != null && node instanceof Line) {
				node.setVisible(false);
			}

			if (node != null && node instanceof Button) {
				node.setVisible(false);
				if (((Button) node).getId().contains(nRow) ) {
					node.setVisible(true);
					if (((Button) node).getId().contains("server") && tool.getText().contains("Enable")) {
						node.setVisible(false);
					}
					if (((Button) node).getId().contains("eye") && !toolEye.getText().contains("Eye Doesn't Create Messages")) {
						node.setVisible(false);
					}
				}
			}
		}

	}

	private void resetLine() {
		int ultimoValido = 0;
		for (Node node : ancorPulsanti.getChildren()) {
			if (node != null && node instanceof Button) {
				if (((Button) node).getText().contains("-")) {
					if (ultimoValido < Integer
							.valueOf(((Button) node).getId().substring(((Button) node).getId().length() - 2))) {
						ultimoValido = Integer
								.valueOf(((Button) node).getId().substring(((Button) node).getId().length() - 2));
					}
				}
			}
		}
		ultimoValido++;

		for (Node node : ancorPulsanti.getChildren()) {
			if (node != null && node instanceof Button) {
				if (ultimoValido < Integer
						.valueOf(((Button) node).getId().substring(((Button) node).getId().length() - 2))) {
					node.setVisible(false);
				}
			}
		}
		if (ultimoValido < 2) {tool.setDisable(false);toolEye.setDisable(false);}
	}

	private void readFileConf() {
		try {
			int numberRow = -1;
		 	BufferedReader reader = new BufferedReader(new FileReader("src\\main\\resources\\ConfigurationFile\\ConfProp.txt"));
	 
			String line = reader.readLine();
			while (line != null) {
				numberRow++;
				insertProprieties(line);
				insertTab(numberRow);
				line = reader.readLine();
			}
			deleteTab(numberRow + 1);
			/*
			  				ListProprieties02.getCheckModel().getCheckedItems().addListener(new ListChangeListener<String>() {
					public void onChanged(ListChangeListener.Change<? extends String> c) {
						for (int i = 0; i < ListProprieties02.getCheckModel().getCheckedItems().size(); i++) {

							insertListProprities(listProprieties02, ListProprieties02);
							// System.out.println(ListProprieties00.getCheckModel().getCheckedItems().get(i));
						}
					}
				});
			 */
			if (numberRow > -1) {
				ListProprieties00.getCheckModel().getCheckedItems().addListener(new ListChangeListener<String>() {
					public void onChanged(ListChangeListener.Change<? extends String> c) {
							insertListProprities(listProprieties00, ListProprieties00);
					}
				});
			}
			if (numberRow > 0) {
				ListProprieties01.getCheckModel().getCheckedItems().addListener(new ListChangeListener<String>() {
					public void onChanged(ListChangeListener.Change<? extends String> c) {
							insertListProprities(listProprieties01, ListProprieties01);
							// System.out.println(ListProprieties00.getCheckModel().getCheckedItems().get(i));
					}
				});
			}
			if (numberRow > 1) {
				ListProprieties02.getCheckModel().getCheckedItems().addListener(new ListChangeListener<String>() {
					public void onChanged(ListChangeListener.Change<? extends String> c) {
							insertListProprities(listProprieties02, ListProprieties02);
							// System.out.println(ListProprieties00.getCheckModel().getCheckedItems().get(i));
					}
				});
			}
			if (numberRow > 2) {
				ListProprieties03.getCheckModel().getCheckedItems().addListener(new ListChangeListener<String>() {
					public void onChanged(ListChangeListener.Change<? extends String> c) {
							insertListProprities(listProprieties03, ListProprieties03);
							// System.out.println(ListProprieties00.getCheckModel().getCheckedItems().get(i));
					}
				});
			}
			if (numberRow > 3) {
				ListProprieties04.getCheckModel().getCheckedItems().addListener(new ListChangeListener<String>() {
					public void onChanged(ListChangeListener.Change<? extends String> c) {
							insertListProprities(listProprieties04, ListProprieties04);
							// System.out.println(ListProprieties00.getCheckModel().getCheckedItems().get(i));
					}
				});
			}
			if (numberRow > 4) {
				ListProprieties05.getCheckModel().getCheckedItems().addListener(new ListChangeListener<String>() {
					public void onChanged(ListChangeListener.Change<? extends String> c) {
							insertListProprities(listProprieties05, ListProprieties05);
							// System.out.println(ListProprieties00.getCheckModel().getCheckedItems().get(i));
					}
				});
			}
			
		} catch (FileNotFoundException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
	}

	private void insertProprieties(String Line) {

		Scanner in = new Scanner(Line);
		int count = 0;
		boolean done = false;
		while (in.hasNextLine()) {
			String line1 = in.nextLine();
			Scanner t = new Scanner(line1);
			while (t.hasNext()) {
				if (count == 0) {
					confProp.setListNameTab(t.next());
				} else {
					confProp.setProprietiesValue(t.next());
				}
				count++;
			}
		}
	}

	private void insertTab(int numberRow) {

		switch (numberRow) {
		case 0:
			tab00.setText(confProp.getListNameTab(numberRow));
		case 1:
			tab01.setText(confProp.getListNameTab(numberRow));
		case 2:
			tab02.setText(confProp.getListNameTab(numberRow));
		case 3:
			tab03.setText(confProp.getListNameTab(numberRow));
		case 4:
			tab04.setText(confProp.getListNameTab(numberRow));
		case 5:
			tab05.setText(confProp.getListNameTab(numberRow));
		default:
			break;
		}
	}

	private void deleteTab(int numberRow) {
		for (int i = numberRow; i < 6; i++) {
			switch (i) {
			case 0:
				tabProprieities.getTabs().remove(tab00);
				break;
			case 1:
				tabProprieities.getTabs().remove(tab01);
				break;
			case 2:
				tabProprieities.getTabs().remove(tab02);
				break;
			case 3:
				tabProprieities.getTabs().remove(tab03);
				break;
			case 4:
				tabProprieities.getTabs().remove(tab04);
				break;
			case 5:
				tabProprieities.getTabs().remove(tab05);
				break;
			default:
				break;
			}
		}
	}

	private void insePropriertiesIntoTab(int numProprierties) {
		if (confProp.getListNameTab(numProprierties) != null && confProp.getListNameTab(numProprierties) != ""
				&& !confProp.getListNameTab(numProprierties).isEmpty()) {
			final ObservableList<String> strings = FXCollections.observableArrayList();
			for (int i = 0; i < 5; i++) {
				if (confProp.getProprietiesValue(numProprierties, i) != null
						&& confProp.getProprietiesValue(numProprierties, i) != ""
						&& !confProp.getProprietiesValue(numProprierties, i).isEmpty()) {
					strings.add(confProp.getProprietiesValue(numProprierties, i));
				}
			}
			switch (numProprierties) {
			case 0:
				ListProprieties00.getItems().addAll(strings);
				break;
			case 1:
				ListProprieties01.getItems().addAll(strings);
				break;
			case 2:
				ListProprieties02.getItems().addAll(strings);
				break;
			case 3:
				ListProprieties03.getItems().addAll(strings);
				break;
			case 4:
				ListProprieties04.getItems().addAll(strings);
				break;
			case 5:
				ListProprieties05.getItems().addAll(strings);
				break;
			default:
				break;
			}
			
		}
	}




	private void insertListProprities(GridPane listProprieties0x, CheckComboBox ListProprieties0x) {
		ObservableList list = ListProprieties0x.getCheckModel().getCheckedItems();
		int riga = 0;
		int appRow, appColumn;
		for (Node node : listProprieties0x.getChildren()) {
			if (node != null && node instanceof TextField) {
				((TextField) node).setText("");
			}
			if (node != null && node instanceof Text) {
				((Text) node).setText("");
			}
		}
		for (Object obj : list) {

			for (Node node : listProprieties0x.getChildren()) {

				if (listProprieties0x.getRowIndex(node) != null) {
					appRow = listProprieties0x.getRowIndex(node);
				} else {
					appRow = 0;
				}
				if (listProprieties0x.getColumnIndex(node) != null) {
					appColumn = listProprieties0x.getColumnIndex(node);
				} else {
					appColumn = 0;
				}
				if (appRow == riga && appColumn == 0 && node != null && node instanceof TextField) {
					((TextField) node).setText(obj.toString());
					break;
				}
			}
			riga++;
		}
			
	}
// se si � deciso di aprire un vecchio file si leggono le info dentro il file e si caricano i dati negli oggetti
	public void setFileStart(String oldFileName) {
		try {
			
			if (oldFileName == null || oldFileName.isEmpty()) {
				fileName = "";
				return;
			}
			fileName = oldFileName;
			FileReader reader = new FileReader(fileName);
			Scanner in = new Scanner(reader);
			// ma anche Scanner in = new Scanner(System.in);
			String typeInfo = null;
			numMessagePrec = 99;
			while (in.hasNextLine()) {
				String line = in.nextLine();
				// se la riga del file letto non � un'intestazione si richiama il metodo per inserire i dati nei rispettivi oggetti
				if (verifyDati(line)== null) {
					addInfo(line, typeInfo);
				} else {
					typeInfo = verifyDati(line);
				}
				
			}
			// con i dati degli oggetti si riempiono le informazioni dei Knowledge dei vari actor 
			loadTitledAlice(alice);
			loadTitledBob(bob);
			loadTitledEye(eye);
			loadTitledServer(server);
		} catch (IOException r) {
			r.printStackTrace();
		}
	}
	private String verifyDati(String line) {
		if (line.equals("tool value ") ||
			line.equals("toolEye value ") ||
			line.equals("dati Alice AsymmetricPublicKey ") ||
			line.equals("dati Alice AsymmetricPrivateKey ") ||
			line.equals("dati Alice SymmetricKey ") ||
			line.equals("dati Bob AsymmetricPublicKey ") ||
			line.equals("dati Bob AsymmetricPrivateKey ") ||
			line.equals("dati Bob SymmetricKey ") ||	
			line.equals("dati Eye AsymmetricPublicKey ") ||
			line.equals("dati Eye AsymmetricPrivateKey ") ||
			line.equals("dati Eye SymmetricKey ") ||
			line.equals("dati Server AsymmetricPublicKey ") ||
			line.equals("dati Server AsymmetricPrivateKey ") ||
			line.equals("dati Server SymmetricKey ") ||
			line.equals("dati Messaggi ") ||
			line.contains("dati Messaggio") ||
			line.contains("dati listPartMessage j=") ||
			line.contains("dati SecurityFunctionsPartMessage j=")){
				return line;
			}
			
		return null;
	}
	// la line rappresenta la riga letta nel file mentre il typeInfo il titolo/intestazione letto in precedenza
	// il titolo rappresenta cosa contengono le informazioni lette su line
	private void addInfo(String line,String typeInfo) {
		if (typeInfo.equals("tool value ")) {
			setToolStart(line);
		}
		if (typeInfo.equals("toolEye value ")) {
			setToolEye(line);
		}
		if (typeInfo.equals("dati Alice AsymmetricPublicKey ")) {
			faceAlice.setOpacity(1);
			lineaAlice.setOpacity(1);
			alice.addAsymmetricPublicKey(line);
		}
		if (typeInfo.equals("dati Alice AsymmetricPrivateKey ")) {
			faceAlice.setOpacity(1);
			lineaAlice.setOpacity(1);
			alice.addAsymmetricPrivateKey(line);
		}
		if (typeInfo.equals("dati Alice SymmetricKey ")) {
			faceAlice.setOpacity(1);
			lineaAlice.setOpacity(1);
			alice.addSymmetricKey(line);
		}
		
		if (typeInfo.equals("dati Bob AsymmetricPublicKey ")) {
			faceBob.setOpacity(1);
			lineaBob.setOpacity(1);
			bob.addAsymmetricPublicKey(line);
		}
		if (typeInfo.equals("dati Bob AsymmetricPrivateKey ")) {
			faceBob.setOpacity(1);
			lineaBob.setOpacity(1);
			bob.addAsymmetricPrivateKey(line);
		}
		if (typeInfo.equals("dati Bob SymmetricKey ")) {
			faceBob.setOpacity(1);
			lineaBob.setOpacity(1);
			bob.addSymmetricKey(line);
		}

		if (typeInfo.equals("dati Eye AsymmetricPublicKey ")) {
			faceEye.setOpacity(1);
			lineaEye.setOpacity(1);
			eye.addAsymmetricPublicKey(line);
		}
		if (typeInfo.equals("dati Eye AsymmetricPrivateKey ")) {
			faceEye.setOpacity(1);
			lineaEye.setOpacity(1);
			eye.addAsymmetricPrivateKey(line);
		}
		if (typeInfo.equals("dati Eye SymmetricKey ")) {
			faceEye.setOpacity(1);
			lineaEye.setOpacity(1);
			eye.addSymmetricKey(line);
		}

		if (typeInfo.equals("dati Server AsymmetricPublicKey ")) {
			faceServer.setOpacity(1);
			lineaServer.setOpacity(1);
			server.addAsymmetricPublicKey(line);
		}
		if (typeInfo.equals("dati Server AsymmetricPrivateKey ")) {
			faceServer.setOpacity(1);
			lineaServer.setOpacity(1);
			server.addAsymmetricPrivateKey(line);
		}
		if (typeInfo.equals("dati Server SymmetricKey ")) {
			faceServer.setOpacity(1);
			lineaServer.setOpacity(1);
			server.addSymmetricKey(line);
		}
		if (typeInfo.equals("dati Messaggi ")) {
			System.out.println("--------->"+ typeInfo);
			//se � stata completata la fase di definizione delle varie chiavi per tutti gli attori, abilita il button + per inserire i messaggi 		
			if (faceAlice.getOpacity() == 1 &&
				faceBob.getOpacity() == 1 &&
				faceEye.getOpacity() == 1 && (
				faceServer.getOpacity() == 1 || tool.getText().contains("Enable"))){
				viewLine("01");
			}
		}
		if (typeInfo.contains("dati Messaggio")) {
				// se esiste almeno un messaggio si cambia il colore (opacit�) dei disegni degli attori e si 
				// visualizzano i pulsanti + per inserire i messaggi
				faceAlice.setOpacity(1);
				lineaAlice.setOpacity(1);
				faceBob.setOpacity(1);
				lineaBob.setOpacity(1);
				faceEye.setOpacity(1);
				lineaEye.setOpacity(1);
				faceServer.setOpacity(1);
				lineaServer.setOpacity(1);
				
				numMessage = Integer.parseInt(typeInfo.substring(15, typeInfo.length()));
				if (line.contains("ActorFrom ")){
					messagges.getListMessages()[numMessage].setActorFrom(line.substring(10, line.length()));
				}
				if (line.contains("ActorTo ")){
					messagges.getListMessages()[numMessage].setActorTo(line.substring(8, line.length()));
				}
				if (line.contains("Eye Intercept ")){
					messagges.getListMessages()[numMessage].setEyesIntercept(Boolean.valueOf(line.substring(14, line.length())));
					eyeIntercept = Boolean.valueOf(line.substring(14, line.length()));
				}
				if (line.contains("Messages ")){
					messagges.getListMessages()[numMessage].setPayload(line.substring(9, line.length()));
					viewSetLine(messagges.getListMessages()[numMessage].getActorTo(),messagges.getListMessages()[numMessage].getActorfrom(),numMessage,numMessagePrec);
					numMessagePrec = numMessage;
				}
		}
		if (typeInfo.contains("dati SecurityFunctionsPartMessage j=")) {
			messagges.getListMessages()[numMessage].addSecurityFunctionsPartMessage(line);		
		}
		if (typeInfo.contains("dati listPartMessage j=")) {
			int j = Integer.parseInt(typeInfo.substring(23, 25).replace(" ", ""));
			int k= Integer.parseInt(typeInfo.substring(26, typeInfo.length()).replace("k=", "").replace("=", "").replace(" ",""));
			messagges.getListMessages()[numMessage].addListPartMessage(line, k);		
		}
	}
// si visualizzano i pulsanti e la linea del messaggio presnete sul file
	private void viewSetLine(String actorToMsg,String  actorFromMsg , int numLineMessage, int numMessagePrec) {
		node1 =aliceButton01;
		node2 =bobButton01;
		node3 =eyeButton01;
		node4 =serverButton01; 
		nodeNext1 =null;
		nodeNext2 =null;
		nodeNext3 =null;
		nodeNext4 =null;
		line = line01;
		int riga = numLineMessage +1 ;
		int rigaSuccessiva = numLineMessage + 2;
		System.out.println("Riga successiva " + rigaSuccessiva + " riga " + riga + " prec " +numMessagePrec);

		for (Node nodeAppo : ancorPulsanti.getChildren()) {
			if (nodeAppo != null && nodeAppo instanceof Button) {
				if (riga == Integer.valueOf(((Button) nodeAppo).getId().substring(((Button) nodeAppo).getId().length() - 2))) {
					if (((Button) nodeAppo).getId().contains("alice")) {
						node1 = nodeAppo;
					}
					if (((Button) nodeAppo).getId().contains("bob")) {
						node2 = nodeAppo;
					}
					if (((Button) nodeAppo).getId().contains("eye")) {
						node3 = nodeAppo;
					}
					if (((Button) nodeAppo).getId().contains("server")) {
						node4 = nodeAppo;
					}
				}
				if ((riga > Integer.valueOf(((Button) nodeAppo).getId().substring(((Button) nodeAppo).getId().length() - 2))) 
					&& (numMessagePrec+1 < Integer.valueOf(((Button) nodeAppo).getId().substring(((Button) nodeAppo).getId().length() - 2)))){
					if ((((Button) nodeAppo).getId().contains("server") && tool.getText().contains("Disable")) || !((Button) nodeAppo).getId().contains("server")) {
						nodeAppo.setVisible(true);
					}
				}
				
			}
			if (nodeAppo != null && nodeAppo instanceof Line) {
				if (riga == Integer.valueOf(((Line) nodeAppo).getId().substring(((Line) nodeAppo).getId().length() - 2))
						&& ((Line) nodeAppo).getId().contains("line")) {
						line = nodeAppo;
				}
				if (riga == Integer.valueOf(((Line) nodeAppo).getId().substring(((Line) nodeAppo).getId().length() - 2))
						&& ((Line) nodeAppo).getId().contains("liey")) {
					liey = nodeAppo;
				}
				if (riga == Integer.valueOf(((Line) nodeAppo).getId().substring(((Line) nodeAppo).getId().length() - 2))
						&& ((Line) nodeAppo).getId().contains("livy")) {
					livy = nodeAppo;
				}
			}
			if (nodeAppo != null && nodeAppo instanceof Button) {
				if (rigaSuccessiva == Integer
							.valueOf(((Button) nodeAppo).getId().substring(((Button) nodeAppo).getId().length() - 2))) {
					System.out.println("trovata riga successiva ");	
					if (((Button) nodeAppo).getId().contains("alice")) {
							nodeNext1 = nodeAppo;
						}
						if (((Button) nodeAppo).getId().contains("bob")) {
							nodeNext2 = nodeAppo;
						}
						if (((Button) nodeAppo).getId().contains("eye")) {
							nodeNext3 = nodeAppo;
						}
						if (((Button) nodeAppo).getId().contains("server")) {
							nodeNext4 = nodeAppo;
						}
					
				}
			}
		} 
		switch (actorFromMsg) {
		case "Alice":
			node = node1;
			break;
		case "Bob":
			node = node2;
			break;
		case "Eye":
			node = node3;
			break;
		case "Server":
			node = node4;
			break;
		}
		viewSpecificLinea(actorToMsg, actorFromMsg, line,liey,livy);
		tool.setDisable(true);
		toolEye.setDisable(true);
		if (tool.getText().contains("Disable")) {
			if (nodeNext1 != null && !nodeNext1.isVisible() && !nodeNext2.isVisible() && !nodeNext3.isVisible()
					&& !nodeNext4.isVisible()) {
				nodeNext1.setVisible(true);
				nodeNext2.setVisible(true);
				if (toolEye.getText().contains("Eye Doesn't Create Messages")) {
					nodeNext3.setVisible(true);
				} else {
					nodeNext3.setVisible(false);
				}
				nodeNext4.setVisible(true);
			}
		} else {
			if (nodeNext1 != null && !nodeNext1.isVisible() && !nodeNext2.isVisible() 
					&& !nodeNext3.isVisible() 	) {
				nodeNext1.setVisible(true);
				nodeNext2.setVisible(true);
				if (toolEye.getText().contains("Eye Doesn't Create Messages")) {
					nodeNext3.setVisible(true);
				} else {
					nodeNext3.setVisible(false);
				}
				nodeNext4.setVisible(false);
			}
		}

		
	}
	
// quando si richiede il salvataggio del file si verifica se il file esiste altrimenti si crea e poi si inseriscono i dati nel file	
	@FXML
	private void saveFile() {

		if (fileName == null || fileName.isEmpty()) {
			String out = new SimpleDateFormat("yyyy-MM-dd HH-mm-ss'.avr'").format(new Date());
			fileName = "src/main/resources/AProVerFile/protocol-" + out;
			String Dir = "src/main/resources/AProVerFile";
			boolean success = (new File(Dir)).mkdir();
			File file = new File(fileName);
			writeFile();
		} else {
			System.out.println("Il file eistente");
			writeFile();
		}
		
	}
//si leggono gli oggetti delle classi SecurityKEy e si inseriscono le info nel file
	private void writeFile() {
		try {
			File file = new File(fileName);
			FileWriter fw = new FileWriter(file);
			BufferedWriter bw = new BufferedWriter(fw);
			bw.write("tool value \n");
			bw.write(tool.getText() + "\n");
			bw.write("toolEye value \n");
			bw.write(toolEye.getText() + "\n");			
			
			bw.write("dati Alice AsymmetricPublicKey \n");

			for (int i = 0; i < alice.getAsymmetricPublicKey().size(); i++) {
				bw.write(alice.getAsymmetricPublicKey().get(i) + "\n");
			}
			bw.write("dati Alice AsymmetricPrivateKey \n");

			for (int i = 0; i < alice.getAsymmetricPrivateKey().size(); i++) {
				bw.write(alice.getAsymmetricPrivateKey().get(i) + "\n");
			}
			bw.write("dati Alice SymmetricKey \n");

			for (int i = 0; i < alice.getSymmetricKey().size(); i++) {
				bw.write(alice.getSymmetricKey().get(i) + "\n");
			}

			
			bw.write("dati Bob AsymmetricPublicKey \n");

			for (int i = 0; i < bob.getAsymmetricPublicKey().size(); i++) {
				bw.write(bob.getAsymmetricPublicKey().get(i) + "\n");
			}
			bw.write("dati Bob AsymmetricPrivateKey \n");

			for (int i = 0; i < bob.getAsymmetricPrivateKey().size(); i++) {
				bw.write(bob.getAsymmetricPrivateKey().get(i) + "\n");
			}
			bw.write("dati Bob SymmetricKey \n");

			for (int i = 0; i < bob.getSymmetricKey().size(); i++) {
				bw.write(bob.getSymmetricKey().get(i) + "\n");
			}
			bw.write("dati Eye AsymmetricPublicKey \n");

			for (int i = 0; i < eye.getAsymmetricPublicKey().size(); i++) {
				bw.write(eye.getAsymmetricPublicKey().get(i) + "\n");
			}
			bw.write("dati Eye AsymmetricPrivateKey \n");

			for (int i = 0; i < eye.getAsymmetricPrivateKey().size(); i++) {
				bw.write(eye.getAsymmetricPrivateKey().get(i) + "\n");
			}
			bw.write("dati Eye SymmetricKey \n");

			for (int i = 0; i < eye.getSymmetricKey().size(); i++) {
				bw.write(eye.getSymmetricKey().get(i) + "\n");
			}
			bw.write("dati Server AsymmetricPublicKey \n");

			for (int i = 0; i < server.getAsymmetricPublicKey().size(); i++) {
				bw.write(server.getAsymmetricPublicKey().get(i) + "\n");
			}
			bw.write("dati Server AsymmetricPrivateKey \n");

			for (int i = 0; i < server.getAsymmetricPrivateKey().size(); i++) {
				bw.write(server.getAsymmetricPrivateKey().get(i) + "\n");
			}
			bw.write("dati Server SymmetricKey \n");

			for (int i = 0; i < server.getSymmetricKey().size(); i++) {
				bw.write(server.getSymmetricKey().get(i) + "\n");
			}
			bw.flush();
			bw.write("dati Messaggi \n");

			for (int i = 0; i < 15; i++) {
				if (!messagges.getListMessages()[i].getActorfrom().isEmpty()) {
					bw.write("dati Messaggio " + i + "\n");
					bw.write("ActorFrom " + messagges.getListMessages()[i].getActorfrom() + "\n");
					bw.write("ActorTo " + messagges.getListMessages()[i].getActorTo() + "\n");
					bw.write("Eye Intercept " + messagges.getListMessages()[i].getEyesIntercept() + "\n");
					bw.write("Messages " + messagges.getListMessages()[i].getPayload() + "\n");
					bw.flush();
					for (int j = 0; j < 15; j++) {
						//� importante prima inserire i dati dall'array SecurityFunctionsPartMessage prima delle parti del messsaggio
						if (messagges.getListMessages()[i].getSecurityFunctionsPartMessage(j) != null) {
							bw.write("dati SecurityFunctionsPartMessage j=" + j + "\n");
							bw.write(messagges.getListMessages()[i].getSecurityFunctionsPartMessage(j) + "\n");
						}						
						for (int k = 0; k < 15; k++) {
							if (messagges.getListMessages()[i].getListPartMessage()[j][k] != null) {
								if (!messagges.getListMessages()[i].getListPartMessage()[j][k].isEmpty()) {
									bw.write("dati listPartMessage j=" + j + " k=" + k + "\n");
									bw.write(messagges.getListMessages()[i].getListPartMessage()[j][k] + "\n");
									bw.flush();
								}
							}
						}

					}
				}
			}
			bw.flush();
			bw.close();
		} catch (IOException r) {
			r.printStackTrace();
		}
	}
	// se viene cliccato dal men� l'opzione about si visualizza il file PdF 
	@FXML
	public void about() throws IOException {
		File file = new File("src\\main\\resources\\ConfigurationFile\\Help.pdf");
		Desktop.getDesktop().open(file);
	}

}
