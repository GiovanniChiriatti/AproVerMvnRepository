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
import javafx.event.EventHandler;
import javafx.fxml.FXML;
import javafx.fxml.FXMLLoader;
import javafx.geometry.Insets;
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
import javafx.scene.text.Font;
import javafx.scene.text.FontPosture;
import javafx.scene.text.Text;
import javafx.scene.text.TextAlignment;
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
import javafx.scene.shape.Circle;
import javafx.scene.shape.Line;
import javafx.scene.control.TextField;
import javafx.stage.FileChooser;
import javafx.stage.Modality;
import javafx.stage.FileChooser.ExtensionFilter;
import javafx.stage.Stage;

import org.unimi.model.*;

public class SelectAProVerController {


    static HashMap<String, Image> pictures = new HashMap<>();
	//ObservableList<String> comboBoxList = FXCollections.observableArrayList("Alice", "Bob", "Eve", "Server");

	private MainApp main;

	private List<String> listFiles;

	final String publicKnow = "Asymmetric Public Keys                                                         Asymmetric Private Keys";
	final String privateKnow = "Asymmetric Private Keys";
	final String symmetricKnow = "Symmetric Key";
	final String hashKnow = "Hash";
	final String bitstringKnow = "Bitstring";
	final String idCertificateKnow = "Id Certificate														  Actor Proprity";
	final String nonceKnow = "Nonce";
	final String signatureKnow = "Signature Public Key                                                        Signature Private Key";
	final String tagKnow = "Tag";
	final String timestampKnow = "Timestamp";
	final String digestKnow = "Digest (restult of Hash Function)";

	SecurityKey alice = new SecurityKey();
	SecurityKey bob = new SecurityKey();
	SecurityKey eve = new SecurityKey();
	SecurityKey server = new SecurityKey();
	SecurityKey appoFrom;
	SecurityKey appoTo;
	
	Messages messages = new Messages();
	//Properties proprieties = new Properties();
	ConfigurationDataProprieties confProp = new ConfigurationDataProprieties();
	private String appoOldKnowledge= null;
	boolean toolFlag = false;
	boolean helpFlag = false;
	boolean eveIntercept=false;
	String fileName;
	int numMessage, numMessagePrec, numCtlEle;
	private String[] ctlEle = new String[16];
	
	Node node,node1,node2,node3,node4, line,liey,msg,msf,livy, nodeNext1, nodeNext2,nodeNext3,nodeNext4;
	String[] elencoKnowledge = new String[15];
	String[] elencoKnowledge2 = new String[15];
	
	@FXML
	private AnchorPane initialKnowledge,msgPayloadAncorPane,msgPayloadAncorPane1, TotalAnchorPane,ancorTabe08;

	@FXML
	private TitledPane titledAlice;

	@FXML
	private TitledPane titledBob;

	@FXML
	private CheckComboBox ListProprieties00, ListProprieties01, ListProprieties02,ListProprieties03,ListProprieties04,ListProprieties05,ListProprieties06,ListProprieties07,ListProprieties08;

	@FXML
	private TitledPane titledEve;

	@FXML
	private TitledPane titledServer;
	
	@FXML
	private TextFlow msgPayload,  msgPayload1;
	@FXML
	private TextFlow msg01, msg02, msg03, msg04, msg05, msg06, msg07, msg08, msg09, msg10, msg11, msg12, msg13, msg14, msg15;
	@FXML
	private TextFlow msf01, msf02, msf03, msf04, msf05, msf06, msf07, msf08, msf09, msf10, msf11, msf12, msf13, msf14, msf15;

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
	private ImageView faceAlice, faceBob, faceEve, faceServer, lineaBob, lineaEve, lineVEve, lineaAlice, lineaServer;

	@FXML
	private Text nomeActor, typeKey, rowEdit, knowPage;

	@FXML
	private Text rowNum1, rowNum2, rowNum3, rowNum4, rowNum5, rowNum6, rowNum7, rowNum8, rowNum9, rowNum10, rowNum11;

	@FXML
	private Button Alice01, Alice02, Alice03, Alice04,Alice05,Alice06,Alice07,Alice08,Alice09,Alice10,Alice11,Alice12;
	@FXML
	private Button Bob01, Bob02, Bob03, Bob04, Bob05, Bob06, Bob07, Bob08, Bob09, Bob10, Bob11, Bob12;
	@FXML
	private Button Eve01, Eve02, Eve03, Eve04, Eve, Eve06, Eve07, Eve08, Eve09, Eve10, Eve11, Eve12;
	@FXML
	private Button Server01, Server02, Server03, Server04, Server05, Server06, Server07, Server08, Server09, Server10 , Server11, Server12;
	@FXML
	private Button nextButton, prevButton, finishButton;
	
	@FXML
	private Button aliceButton01, bobButton01, eveButton01, serverButton01;
	
	@FXML
	private Button aliceButton02, bobButton02, eveButton02, serverButton02;
	@FXML
	private Button aliceButton03, bobButton03, eveButton03, serverButton03;
	@FXML
	private Button aliceButton04, bobButton04, eveButton04, serverButton04;
	
	@FXML
	private Button aliceButton05, bobButton05, eveButton05, serverButton05;
	
	@FXML
	private Button aliceButton06, bobButton06, eveButton06, serverButton06;
	
	@FXML
	private Button aliceButton07, bobButton07, eveButton07, serverButton07;
		
	@FXML
	private Button aliceButton08, bobButton08, eveButton08, serverButton08;
	@FXML
	private Button aliceButton09, bobButton09, eveButton09, serverButton09;
	@FXML
	private Button aliceButton10, bobButton10, eveButton10, serverButton10;
	@FXML
	private Button aliceButton11, bobButton11, eveButton11, serverButton11;
	@FXML
	private Button aliceButton12, bobButton12, eveButton12, serverButton12;
	@FXML
	private Button aliceButton13, bobButton13, eveButton13, serverButton13;	
	@FXML
	private Button aliceButton14, bobButton14, eveButton14, serverButton14;
	@FXML
	private Button aliceButton15, bobButton15, eveButton15, serverButton15;
	@FXML
	private Button propriertiesButton;
	
	@FXML
	private Button insertSelect00,insertSelect01,insertSelect02,insertSelect03,insertSelect04,insertSelect05;
	
	@FXML
	private Button serverButton;
	
	@FXML
	private Button addProp00,addProp01,addProp02;
	
	@FXML
	private Button modProp00, modProp01,modProp02,modProp03,modProp04,modProp05,modProp06, modProp07,modProp08,modProp09;
	
	@FXML
	private Button modProp10, modProp11,modProp12,modProp13,modProp14,modProp15,modProp16, modProp17,modProp18,modProp19;
	
	@FXML
	private Button modProp20, modProp21,modProp22,modProp23,modProp24,modProp25,modProp26, modProp27,modProp28,modProp29;
		
	@FXML
	private AnchorPane ancorPulsanti;
	
	@FXML
	private GridPane tabeKnowledge, listProprieties00, listProprieties01,listProprieties02, listProprieties03, listProprieties04, listProprieties05,listProprieties06, listProprieties07, listProprieties08;
	
	@FXML
	private Label aliceAsymmetricPublicKey, aliceAsymmetricPrivateKey, aliceSymmetricKey, aliceHash, aliceBitstring,aliceIdCertificate,aliceNonce, aliceSignaturePubKey,aliceSignaturePrivKey, aliceTag, aliceTimestamp, aliceDigest ;
	@FXML
	private Label bobAsymmetricPublicKey, bobAsymmetricPrivateKey, bobSymmetricKey, bobHash, bobBitstring,bobIdCertificate,bobNonce, bobSignaturePubKey,bobSignaturePrivKey, bobTag, bobTimestamp, bobDigest;
	@FXML
	private Label eveAsymmetricPublicKey, eveAsymmetricPrivateKey, eveSymmetricKey, eveHash, eveBitstring,eveIdCertificate,eveNonce, eveSignaturePubKey,eveSignaturePrivKey, eveTag, eveTimestamp, eveDigest;
	@FXML
	private Label serverAsymmetricPublicKey, serverAsymmetricPrivateKey, serverSymmetricKey, serverHash, serverBitstring,serverIdCertificate,serverNonce, serverSignaturePubKey,serverSignaturePrivKey, serverTag, serverTimestamp, serverDigest;

	@FXML
	private Tab tab00,tab01,tab02,tab03,tab04,tab05,tab06,tab07,tab08;
	
	@FXML
	private TabPane tabProprieities;

	@FXML
	private MenuButton choices;
	
	@FXML
	private MenuItem tool,toolEve,toolCheck;
	
	private GridPane[] proprlistProprietiesTb  = new GridPane[10];
	private Tab[] tabTb  = new Tab[10];
	
//
// Routin di inizializzazione del Controller
// 

	@FXML
	private void initialize() {
// memorizzo in una tabella i link ai gridPane e ai tab delle tab properties	
		proprlistProprietiesTb[0] = listProprieties00;
		proprlistProprietiesTb[1] = listProprieties01;
		proprlistProprietiesTb[2] = listProprieties02;
		proprlistProprietiesTb[3] = listProprieties03;
		proprlistProprietiesTb[4] = listProprieties04;
		proprlistProprietiesTb[5] = listProprieties05;
		proprlistProprietiesTb[6] = listProprieties06;
		proprlistProprietiesTb[7] = listProprieties07;
		proprlistProprietiesTb[8] = listProprieties08;
		tabTb[0]= tab00;
		tabTb[1]= tab01;
		tabTb[2]= tab02;
		tabTb[3]= tab03;
		tabTb[4]= tab04;
		tabTb[5]= tab05;
		tabTb[6]= tab06;
		tabTb[7]= tab07;
		tabTb[8]= tab08;

		
// legge il file di configurazione delle propriet� da testare		
		
		readFileConf();
		HBox titleBoxAlice = new HBox();
		ImageView immageAlice = new ImageView(new Image(getClass().getResource("/styles/images/alicepiccola1.png").toExternalForm(),0, 24, true, true));
		titleBoxAlice.getChildren().add(immageAlice);
		titledAlice.setGraphic(titleBoxAlice);
		titledAlice.setContentDisplay(ContentDisplay.RIGHT);
		
		tool.setDisable(false);
		toolEve.setDisable(false);
		serverButton.setDisable(false);
		
		
		HBox titleBoxBob = new HBox();
		ImageView immageBob = new ImageView(new Image(getClass().getResource("/styles/images/bobpiccola1.png").toExternalForm(),0, 24, true, true));
		titleBoxBob.getChildren().add(immageBob);
		titledBob.setGraphic(titleBoxBob);
		titledBob.setContentDisplay(ContentDisplay.RIGHT);
		
		HBox titleBoxEve = new HBox();
		ImageView immageEve = new ImageView(new Image(getClass().getResource("/styles/images/evepiccola1.png").toExternalForm(),0, 24, true, true));
		titleBoxEve.getChildren().add(immageEve);
		titledEve.setGraphic(titleBoxEve);
		titledEve.setContentDisplay(ContentDisplay.RIGHT);
		
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
			comboBoxActor.getItems().addAll("Alice", "Eve" , "Bob");
			
		} else {
			comboBoxActor.getItems().addAll("Alice", "Eve", "Bob", "Server");
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
		faceEve.setVisible(true);
		lineaEve.setVisible(true);
		if (tool.getText().contains("Enable")) {
			faceServer.setVisible(false);
			lineaServer.setVisible(false);
			titledServer.setDisable(true);
		} else {
			faceServer.setVisible(true);
			lineaServer.setVisible(true);
			titledServer.setDisable(false);
		}
			
// si disabilita la visibilit� del Ancor per l'inserimento dei parametri di knowledge		
		initialKnowledge.setVisible(false);

// si inizializzano le variabili che indicano la riga del knowlege da digitare e il tipo di knowledge attivo
		rowEdit.setText("1");
		knowPage.setText("01");
		typeKey.setText(publicKnow);
		
		aliceButton01.setVisible(false);
		bobButton01.setVisible(false);
		eveButton01.setVisible(false);
		
		serverButton01.setVisible(false);
		
		aliceButton02.setVisible(false);
		bobButton02.setVisible(false);
		eveButton02.setVisible(false);
		serverButton02.setVisible(false);
		
		aliceButton03.setVisible(false);
		bobButton03.setVisible(false);
		eveButton03.setVisible(false);
		serverButton03.setVisible(false);
			
		aliceButton04.setVisible(false);
		bobButton04.setVisible(false);
		eveButton04.setVisible(false);
		serverButton04.setVisible(false);
			
		aliceButton05.setVisible(false);
		bobButton05.setVisible(false);
		eveButton05.setVisible(false);
		serverButton05.setVisible(false);
			
		aliceButton06.setVisible(false);
		bobButton06.setVisible(false);
		eveButton06.setVisible(false);
		serverButton06.setVisible(false);
			
		aliceButton07.setVisible(false);
		bobButton07.setVisible(false);
		eveButton07.setVisible(false);
		serverButton07.setVisible(false);
			
		aliceButton08.setVisible(false);
		bobButton08.setVisible(false);
		eveButton08.setVisible(false);
		serverButton08.setVisible(false);
			
		aliceButton09.setVisible(false);
		bobButton09.setVisible(false);
		eveButton09.setVisible(false);
		serverButton09.setVisible(false);
			
		aliceButton10.setVisible(false);
		bobButton10.setVisible(false);
		eveButton10.setVisible(false);
		serverButton10.setVisible(false);
	
		aliceButton11.setVisible(false);
		bobButton11.setVisible(false);
		eveButton11.setVisible(false);
		serverButton11.setVisible(false);
			
		aliceButton12.setVisible(false);
		bobButton12.setVisible(false);
		eveButton12.setVisible(false);
		serverButton12.setVisible(false);
	
		aliceButton13.setVisible(false);
		bobButton13.setVisible(false);
		eveButton13.setVisible(false);
		serverButton13.setVisible(false);
	
		aliceButton14.setVisible(false);
		bobButton14.setVisible(false);
		eveButton14.setVisible(false);
		serverButton14.setVisible(false);
		
		aliceButton15.setVisible(false);
		bobButton15.setVisible(false);
		eveButton15.setVisible(false);
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
				
		SelectAProVerController cell = new SelectAProVerController();
		ImageView imageView = null;
		
			if (!pictures.containsKey(imageName)) {
				pictures.put(imageName, cell.getImage(imageName));
				//pictures.put(imageName,new Image(getClass().getResource("/styles/images/alicepiccola1.png").toExternalForm());
			}
			imageView = new ImageView(pictures.get(imageName));
		
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
			
		case "Eve":
			image = new Image(getClass().getResource("/styles/images/evepiccola.png").toExternalForm());
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

		private void selectLink() {
			Scene sc1 = aliceButton01.getScene();
			if (helpFlag) {
				sc1.setCursor(Cursor.DEFAULT);
				helpFlag = false;
			} else {
			 //	sc1.setCursor(Cursor.OPEN_HAND);
				sc1.setCursor(Cursor.OPEN_HAND);
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
				writeTxtPreview("this section contains view of knowledge of key of all actor \n (Alice Bob Eves Server) "  );
				
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
			if (data.contains("eve")) partMessage2 = "Eves";
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
				Text msgText= new Text("Select to Close Page");
				msgPayload1.getChildren().addAll(msgText);
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
				Text msgText= new Text("Select + for insert new row");
				msgPayload1.getChildren().addAll(msgText);
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
				Text msgText= new Text("Select for delete row");
				msgPayload1.getChildren().addAll(msgText);
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
				Text msgText= new Text("Select NEXT for enter new type of knowledge");
				msgPayload1.getChildren().addAll(msgText);
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
				Text msgText= new Text("Select PREV to enter the previous knowledge type");
				msgPayload1.getChildren().addAll(msgText);
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
			//	faceEve.getOpacity() == 1 && 
				(faceServer.getOpacity() == 1 || tool.getText().contains("Enable"))) {
				viewLineOK = true;
			}
//rende visibile le icone e le righe delle immagini dei vari attori
		faceAlice.setVisible(true);
		lineaAlice.setVisible(true);
		faceBob.setVisible(true);
		lineaBob.setVisible(true);
		faceEve.setVisible(true);
		lineaEve.setVisible(true);
		if (tool.getText().contains("Enable")) {
			faceServer.setVisible(false);
			lineaServer.setVisible(false);
			titledServer.setDisable(true);
		} else {
			faceServer.setVisible(true);
			lineaServer.setVisible(true);
			titledServer.setDisable(false);
		}

		/*
		 * 
		 * lineaBob.setOpacity(0.31); faceAlice.setOpacity(0.31);
		 * lineaAlice.setOpacity(0.31); faceBob.setOpacity(0.31);
		 * lineaBob.setOpacity(0.31); faceEve.setOpacity(0.31);
		 * lineaEve.setOpacity(0.31); faceServer.setOpacity(0.31);
		 * lineaServer.setOpacity(0.31);
		 */
//rende visibile le icone e le righe delle immagini dei vari actor
//Disabilita la combobox per la selezione degli actor
//inizializza la visibilit� e i dati della form che permetto l'isnerimento dei vari tipi di chiavi
		comboBoxActor.setDisable(true);
		typeKey.setText("Asymmetric Public Keys");
		prevButton.setDisable(true);
		nextButton.setDisable(false);
		//finishButton.setVisible(false);
		//piuButton.setVisible(true);
		
		knowPage.setText("01");
		typeKey.setText(publicKnow);

//verifica quale Actor � stato selezionato e abilita la visibilit� della form di knowledge (initialKnowledge.setVisible(true);)
		if (comboBoxActor.getValue().toString().contains("Alice")) {
			nomeActor.setText("Alice's");
			initialKnowledge.setVisible(true);
			faceAlice.setOpacity(1);
			lineaAlice.setOpacity(1);
			loadTable(alice, "01");
			loadTitledAlice(alice);
		}
		if (comboBoxActor.getValue().toString().contains("Bob")) {
			nomeActor.setText("Bob's");
			initialKnowledge.setVisible(true);
			faceBob.setOpacity(1);
			lineaBob.setOpacity(1);
			loadTable(bob, "01");
			loadTitledBob(bob);
		}
		if (comboBoxActor.getValue().toString().contains("Eve")) {
			nomeActor.setText("Eve's");
			initialKnowledge.setVisible(true);
			faceEve.setOpacity(1);
			lineaEve.setOpacity(1);
			loadTable(eve, "01");
			loadTitledEve(eve);
		}
		if (comboBoxActor.getValue().toString().contains("Server")) {
			nomeActor.setText("Server's");
			initialKnowledge.setVisible(true);
			faceServer.setOpacity(1);
			lineaServer.setOpacity(1);
			loadTable(server, "01");
			loadTitledServer(server);
		}
//se � stata completata la fase di definizione delle varie chiavi per tutti gli attori, abilita il button + per inserire i messaggi 		
		if (faceAlice.getOpacity() == 1 &&
			faceBob.getOpacity() == 1 &&
		//	faceEve.getOpacity() == 1 && 
			(faceServer.getOpacity() == 1 || tool.getText().contains("Enable"))&&
			!viewLineOK) {
			viewLine("01");
		}
	}
	
	//Routin che si attiva ogni qual volta viene selezionata una riga sulle tabelle della conoscenza	
		@FXML

		private void selectKnowledgeDetails(ActionEvent e) throws Exception   {
			if (toolFlag) {
				toolFlag= false;
				return;
			}

			node = (Node) e.getSource();

			String data = (String) node.getId();

			String riga = data.substring(data.length() - 2);
			String act = data.substring(0,data.length() - 2);
			
			boolean viewLineOK = false;
			if (faceAlice.getOpacity() == 1 &&
					faceBob.getOpacity() == 1 &&
				//	faceEve.getOpacity() == 1 && 
					(faceServer.getOpacity() == 1 || tool.getText().contains("Enable"))) {
					viewLineOK = true;
				}
	//rende visibile le icone e le righe delle immagini dei vari attori
			faceAlice.setVisible(true);
			lineaAlice.setVisible(true);
			faceBob.setVisible(true);
			lineaBob.setVisible(true);
			faceEve.setVisible(true);
			lineaEve.setVisible(true);
			if (tool.getText().contains("Enable")) {
				faceServer.setVisible(false);
				lineaServer.setVisible(false);
				titledServer.setDisable(true);
			} else {
				faceServer.setVisible(true);
				lineaServer.setVisible(true);
				titledServer.setDisable(false);
			}


	//rende visibile le icone e le righe delle immagini dei vari actor
	//Disabilita la combobox per la selezione degli actor
	//inizializza la visibilit� e i dati della form che permetto l'isnerimento dei vari tipi di chiavi
			comboBoxActor.setDisable(true);
			if (riga.equals("01")) { 
				riga="01";
				typeKey.setText(publicKnow);
				prevButton.setDisable(true);
				nextButton.setDisable(false);
			}
			if (riga.equals("02")) { 
				riga="01";
				typeKey.setText(publicKnow);
				prevButton.setDisable(true);
				nextButton.setDisable(false);
			}
			if (riga.equals("03")) { 
				riga="02";
				typeKey.setText(symmetricKnow);
				prevButton.setDisable(false);
				nextButton.setDisable(false);
			}
			if (riga.equals("04")) { 
				riga="03";
				typeKey.setText(hashKnow);
				prevButton.setDisable(false);
				nextButton.setDisable(false);
			}
			if (riga.equals("05")) { 
				riga="04";
				typeKey.setText(bitstringKnow);
				prevButton.setDisable(false);
				nextButton.setDisable(false);
			}
			if (riga.equals("06")) {
				riga="05";
				typeKey.setText(idCertificateKnow);
				prevButton.setDisable(false);
				nextButton.setDisable(false);
			}
			if (riga.equals("07")) { 
				riga="06";
				typeKey.setText(nonceKnow);
				prevButton.setDisable(false);
				nextButton.setDisable(false);
			}
			if (riga.equals("08")) { 
				riga="07";
				typeKey.setText(signatureKnow);
				prevButton.setDisable(false);
				nextButton.setDisable(false);
			}
			if (riga.equals("09")) { 
				riga="07";
				typeKey.setText(signatureKnow);
				prevButton.setDisable(false);
				nextButton.setDisable(false);
			}
			if (riga.equals("10")) { 
				riga="08";
				typeKey.setText(tagKnow);
				prevButton.setDisable(false);
				nextButton.setDisable(false);
			}
			if (riga.equals("11")) { 
				riga="09";
				typeKey.setText(timestampKnow);
				prevButton.setDisable(false);
				nextButton.setDisable(false);
			}
			if (riga.equals("12")) { 
				riga="10";
				typeKey.setText(digestKnow);
				prevButton.setDisable(false);
				nextButton.setDisable(true);
			}
			
			//finishButton.setVisible(false);
			//piuButton.setVisible(true);
			
			knowPage.setText(riga);
			
	//verifica quale Actor � stato selezionato e abilita la visibilit� della form di knowledge (initialKnowledge.setVisible(true);)
			if (act.contains("Alice")) {
				toolFlag= true;
				comboBoxActor.setValue("Alice");
				nomeActor.setText("Alice's");
				initialKnowledge.setVisible(true);
				faceAlice.setOpacity(1);
				lineaAlice.setOpacity(1);
				loadTable(alice, riga);
				loadTitledAlice(alice);
			}
			if (act.contains("Bob")) {
				toolFlag= true;
				comboBoxActor.setValue("Bob");
				nomeActor.setText("Bob's");
				initialKnowledge.setVisible(true);
				faceBob.setOpacity(1);
				lineaBob.setOpacity(1);
				loadTable(bob, riga);
				loadTitledBob(bob);
			}
			if (act.contains("Eve")) {
				toolFlag= true;
				comboBoxActor.setValue("Eve");
				nomeActor.setText("Eve's");
				initialKnowledge.setVisible(true);
				faceEve.setOpacity(1);
				lineaEve.setOpacity(1);
				loadTable(eve, riga);
				loadTitledEve(eve);
			}
			if (act.contains("Server")) {
				toolFlag= true;
				comboBoxActor.setValue("Server");
				nomeActor.setText("Server's");
				initialKnowledge.setVisible(true);
				faceServer.setOpacity(1);
				lineaServer.setOpacity(1);
				loadTable(server, riga);
				loadTitledServer(server);
			}
	//se � stata completata la fase di definizione delle varie chiavi per tutti gli attori, abilita il button + per inserire i messaggi 		
			if (faceAlice.getOpacity() == 1 &&
				faceBob.getOpacity() == 1 &&
			//	faceEve.getOpacity() == 1 && 
				(faceServer.getOpacity() == 1 || tool.getText().contains("Enable"))&&
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
			if (compattaKnowledge()!=null) {
				final Stage stage = (Stage) aliceButton01.getScene().getWindow();
				Alert.AlertType type =  Alert.AlertType.ERROR;
				Alert alert = new Alert(type, "");
		    	alert.initModality(Modality.APPLICATION_MODAL);
		    	alert.initOwner(stage);
		    	alert.getDialogPane().setContentText("Modify or Delete the Duplicate Value");
		    	alert.getDialogPane().setHeaderText("Duplicate Value Found : " + compattaKnowledge());
		    	alert.showAndWait();
				return;
			}
			if (knowPage.getText() == "01" || knowPage.getText() == "07" ) {
			    if (verifyPubPriv()!=null) {
			    	final Stage stage = (Stage) aliceButton01.getScene().getWindow();
			    	Alert.AlertType type =  Alert.AlertType.ERROR;
			    	Alert alert = new Alert(type, "");
			    	alert.initModality(Modality.APPLICATION_MODAL);
			    	alert.initOwner(stage);
			    	alert.getDialogPane().setContentText("Insert key Private and Public in the same row");
			    	alert.getDialogPane().setHeaderText("There must be a public key pair and a private key : " +verifyPubPriv());
			    	alert.showAndWait();
			    	return;
			   }
			}

			if (knowPage.getText() == "05" ) {
			    if (verifyPubPriv()!=null) {
			    	final Stage stage = (Stage) aliceButton01.getScene().getWindow();
			    	Alert.AlertType type =  Alert.AlertType.ERROR;
			    	Alert alert = new Alert(type, "");
			    	alert.initModality(Modality.APPLICATION_MODAL);
			    	alert.initOwner(stage);
			    	alert.getDialogPane().setContentText("Insert Id Certificate and Propriety in the same row");
			    	alert.getDialogPane().setHeaderText("There must be a Id Certificate pair and a her proprietary : " +verifyPubPriv());
			    	alert.showAndWait();
			    	return;
			   }
			}
			if (knowPage.getText() == "05" ) {
			    if (verifyPropId()!=null) {
			    	final Stage stage = (Stage) aliceButton01.getScene().getWindow();
			    	Alert.AlertType type =  Alert.AlertType.ERROR;
			    	Alert alert = new Alert(type, "");
			    	alert.initModality(Modality.APPLICATION_MODAL);
			    	alert.initOwner(stage);
			    	alert.getDialogPane().setContentText("Enter the Correct Actor");
			    	alert.getDialogPane().setHeaderText("Actor value must be Alice or Bob or Eve or Server " +verifyPropId() );
			    	alert.showAndWait();
			    	return;
			   }
			}			
			piuKnowledge();	
			chiudiKnowledge();	

		}
//quando nella form di knowledge si preme next si abilitano/disabilitano alcuni pulsanti e si modifica il tipo di kiavi da inserire (es: hash,symmetric,asymmetric etc)	
	
	@FXML

	private void nextKnowledge() {
		
		if (compattaKnowledge()!=null) {
			final Stage stage = (Stage) aliceButton01.getScene().getWindow();
			Alert.AlertType type =  Alert.AlertType.ERROR;
			Alert alert = new Alert(type, "");
	    	alert.initModality(Modality.APPLICATION_MODAL);
	    	alert.initOwner(stage);
	    	alert.getDialogPane().setContentText("Modify or Delete the Duplicate Value");
	    	alert.getDialogPane().setHeaderText("Duplicate Value Found : " + compattaKnowledge());
	    	alert.showAndWait();
			return;
		}
		
		if (knowPage.getText() == "01" || knowPage.getText() == "07" ) {
		    if (verifyPubPriv()!=null) {
		    	final Stage stage = (Stage) aliceButton01.getScene().getWindow();
		    	Alert.AlertType type =  Alert.AlertType.ERROR;
		    	Alert alert = new Alert(type, "");
		    	alert.initModality(Modality.APPLICATION_MODAL);
		    	alert.initOwner(stage);
		    	alert.getDialogPane().setContentText("Insert key Private and Public in the same row");
		    	alert.getDialogPane().setHeaderText("There must be a public key pair and a private key : " +verifyPubPriv());
		    	alert.showAndWait();
		    	return;
		   }
		}

		if (knowPage.getText() == "05" ) {
		    if (verifyPubPriv()!=null) {
		    	final Stage stage = (Stage) aliceButton01.getScene().getWindow();
		    	Alert.AlertType type =  Alert.AlertType.ERROR;
		    	Alert alert = new Alert(type, "");
		    	alert.initModality(Modality.APPLICATION_MODAL);
		    	alert.initOwner(stage);
		    	alert.getDialogPane().setContentText("Insert Id Certificate and Propriety in the same row");
		    	alert.getDialogPane().setHeaderText("There must be a Id Certificate pair and a her proprietary : " +verifyPubPriv());
		    	alert.showAndWait();
		    	return;
		   }
		}
		if (knowPage.getText() == "05" ) {
		    if (verifyPropId()!=null) {
		    	final Stage stage = (Stage) aliceButton01.getScene().getWindow();
		    	Alert.AlertType type =  Alert.AlertType.ERROR;
		    	Alert alert = new Alert(type, "");
		    	alert.initModality(Modality.APPLICATION_MODAL);
		    	alert.initOwner(stage);
		    	alert.getDialogPane().setContentText("Enter the Correct Actor");
		    	alert.getDialogPane().setHeaderText("Actor value must be Alice or Bob or Eve or Server " +verifyPropId() );
		    	alert.showAndWait();
		    	return;
		   }
		}
		
		piuKnowledge();
		
		if (knowPage.getText().equals("09")) {
			//piuKnowledge();
			typeKey.setText(digestKnow);
			nextButton.setDisable(true);
			
			//finishButton.setVisible(true);
			prevButton.setDisable(false);
			//piuButton.setVisible(true);
			knowPage.setText("10");
		} 	
		
		if (knowPage.getText().equals("08")) {
			//piuKnowledge();
			typeKey.setText(timestampKnow);
			nextButton.setDisable(false);
			
			//finishButton.setVisible(true);
			prevButton.setDisable(false);
			//piuButton.setVisible(true);
			knowPage.setText("09");
		} 	
		
		if (knowPage.getText().equals("07")) {
			//piuKnowledge();
			typeKey.setText(tagKnow);
			nextButton.setDisable(false);
			
			//finishButton.setVisible(true);
			prevButton.setDisable(false);
			//piuButton.setVisible(true);
			knowPage.setText("08");
		} 	
		
		if (knowPage.getText().equals("06")) {
			//piuKnowledge();
			typeKey.setText(signatureKnow);
			nextButton.setDisable(false);
			
			//finishButton.setVisible(true);
			prevButton.setDisable(false);
			//piuButton.setVisible(true);
			knowPage.setText("07");
		} 	
		
		if (knowPage.getText().equals("05")) {
			//piuKnowledge();
			typeKey.setText(nonceKnow);
			nextButton.setDisable(false);
			
			//finishButton.setVisible(true);
			prevButton.setDisable(false);
			//piuButton.setVisible(true);
			knowPage.setText("06");
		} 	
		
		if (knowPage.getText().equals("04")) {
			//piuKnowledge();
			typeKey.setText(idCertificateKnow);
			nextButton.setDisable(false);
			
			//finishButton.setVisible(true);
			prevButton.setDisable(false);
			//piuButton.setVisible(true);
			knowPage.setText("05");
		} 	
		
		
		if (knowPage.getText().equals("03")) {
			//piuKnowledge();
			typeKey.setText(bitstringKnow);
			nextButton.setDisable(false);
			
			//finishButton.setVisible(true);
			prevButton.setDisable(false);
			//piuButton.setVisible(true);
			knowPage.setText("04");
		} 	
		
		if (knowPage.getText().equals("02")) {
			//piuKnowledge();
			typeKey.setText(hashKnow);
			nextButton.setDisable(false);
			
			//finishButton.setVisible(true);
			prevButton.setDisable(false);
			//piuButton.setVisible(true);
			knowPage.setText("03");
		}
		if (knowPage.getText().equals("01")) {
			typeKey.setText(symmetricKnow);
			nextButton.setDisable(false);
			//finishButton.setVisible(false);
			prevButton.setDisable(false);
			//piuButton.setVisible(true);
			knowPage.setText("02");
		}


		if (comboBoxActor.getValue().toString().contains("Alice")) {
			loadTable(alice, knowPage.getText());
			loadTitledAlice(alice);
		}
		if (comboBoxActor.getValue().toString().contains("Bob")) {
			loadTable(bob, knowPage.getText());
			loadTitledBob(bob);
		}
		if (comboBoxActor.getValue().toString().contains("Eve")) {
			loadTable(eve, knowPage.getText());
			loadTitledEve(eve);
		}
		if (comboBoxActor.getValue().toString().contains("Server")) {
			loadTable(server, knowPage.getText());
			loadTitledServer(server);
		}
		 
	}

// La routin legge gli elementi di knowledge inseriti e li compatta eliminando sia le righe bianche che gli spazi
// dopo aver compattato verifica se ci sono duplicati sia all'interno che in altre kiavi 	
	private String compattaKnowledge(){
		int indice=0;
		int appRow;
		int appColumn;
		for (int i=0; i<15; i++) {
				elencoKnowledge[i] ="";
				elencoKnowledge2[i] ="";
		}
		for (Node node : tabeKnowledge.getChildren()) {
			if (GridPane.getColumnIndex(node) != null) {
				appColumn = GridPane.getColumnIndex(node);
			} else {
				appColumn = 0;
			}
			if (node !=null && node instanceof TextField && !((TextField) node).getText().isEmpty() && appColumn==1) {
				elencoKnowledge[indice] = ((TextField) node).getText().trim().replaceAll("\\s", ""); 
				if (!elencoKnowledge[indice].isEmpty()) {
					indice ++;
				}
			}
		}
		
		for (int i=0; i<15; i++) {
			if (elencoKnowledge[i]== null) {
				elencoKnowledge[i] ="";
			}
		}
		indice=0;

		for (Node node : tabeKnowledge.getChildren()) {
			if (GridPane.getColumnIndex(node) != null) {
				appColumn = GridPane.getColumnIndex(node);
			} else {
				appColumn = 0;
			}
			if (node !=null && node instanceof TextField && !((TextField) node).getText().isEmpty() && appColumn==2) {
				elencoKnowledge2[indice] = ((TextField) node).getText().trim().replaceAll("\\s", ""); 
				if (!elencoKnowledge2[indice].isEmpty()) {
					elencoKnowledge2[indice] = elencoKnowledge2[indice].substring(0, 1).toUpperCase()
							+ elencoKnowledge2[indice].substring(1).toLowerCase();
					indice++;
				}
			}
		}
		
		for (int i=0; i<15; i++) {
			if (elencoKnowledge2[i]== null) {
				elencoKnowledge2[i] ="";
			}
		}

		tabeKnowledge.setGridLinesVisible(true);
		for (Node node : tabeKnowledge.getChildren()) {
			
			if (GridPane.getRowIndex(node) != null) {
				appRow = GridPane.getRowIndex(node);
			} else {
				appRow = 0;
			}
			if (GridPane.getColumnIndex(node) != null) {
				appColumn = GridPane.getColumnIndex(node);
			} else {
				appColumn = 0;
			}
				if (node instanceof TextField && appColumn==1) {
					((TextField) node).setText(elencoKnowledge[appRow]);
			}
				if (node instanceof TextField && appColumn==2) {
					((TextField) node).setText(elencoKnowledge2[appRow]);
			}

		}

// verifica duplicati all'interno dell'elenco
		Boolean doppioni = false;
		for (int i=0; i<15; i++) {
			if (!(elencoKnowledge[i] == null) && !elencoKnowledge[i].isEmpty() && !(elencoKnowledge2[i] == null)&& elencoKnowledge[i].equals(elencoKnowledge2[i]) && !elencoKnowledge2[i].isEmpty()) {
				return elencoKnowledge[i]; 
			}
			for (int j=i+1 ; j<15; j++) {
				if (!(elencoKnowledge[i] == null) && elencoKnowledge[i].equals(elencoKnowledge[j]) && !elencoKnowledge[i].isEmpty()) {
					return elencoKnowledge[i]; 
				}
				if (!(elencoKnowledge[i] == null) && !elencoKnowledge[i].isEmpty() && elencoKnowledge[i].equals(elencoKnowledge2[j]) && !elencoKnowledge2[i].isEmpty()) {
					return elencoKnowledge[i]; 
				}
				if (!(elencoKnowledge2[i] == null) && elencoKnowledge2[i].equals(elencoKnowledge2[j]) && !elencoKnowledge2[i].isEmpty()) {
					return elencoKnowledge2[i]; 
				}
				if (!(elencoKnowledge2[i] == null)&& !elencoKnowledge2[i].isEmpty() && elencoKnowledge2[i].equals(elencoKnowledge[j]) && !elencoKnowledge[i].isEmpty()) {
					return elencoKnowledge2[i]; 
				}
			}
		}

		
		// verifica duplicati su altri elenchi
		if (comboBoxActor.getValue().toString().contains("Alice")) {
			for (int i = 0; i < 15; i++) {
				if (elencoKnowledge[i] != null && !elencoKnowledge[i].isEmpty()) {
					if (alice.checkDuplicate(elencoKnowledge[i], knowPage.getText())) {
						return elencoKnowledge[i];
					}
				}
				if (elencoKnowledge2[i] != null && !elencoKnowledge2[i].isEmpty()) {
					if (alice.checkDuplicate(elencoKnowledge2[i], knowPage.getText())) {
						return elencoKnowledge2[i];
					}
				}
			}
			
		}
		if (comboBoxActor.getValue().toString().contains("Bob")) {
			for (int i = 0; i < 15; i++) {
				if (elencoKnowledge[i] != null && !elencoKnowledge[i].isEmpty()) {
					if (bob.checkDuplicate(elencoKnowledge[i], knowPage.getText())) {
						return elencoKnowledge[i];
					}
				}
				if (elencoKnowledge2[i] != null && !elencoKnowledge2[i].isEmpty()) {
					if (bob.checkDuplicate(elencoKnowledge2[i], knowPage.getText())) {
						return elencoKnowledge2[i];
					}
				}
			}
		}
		if (comboBoxActor.getValue().toString().contains("Eve")) {
			for (int i = 0; i < 15; i++) {
				if (elencoKnowledge[i] != null && !elencoKnowledge[i].isEmpty()) {
					if (eve.checkDuplicate(elencoKnowledge[i], knowPage.getText())) {
						return elencoKnowledge[i];
					}
				}
				if (elencoKnowledge2[i] != null && !elencoKnowledge2[i].isEmpty()) {
					if (eve.checkDuplicate(elencoKnowledge2[i], knowPage.getText())) {
						return elencoKnowledge[i];
					}
				}
			}
		}
		if (comboBoxActor.getValue().toString().contains("Server")) {
			for (int i = 0; i < 15; i++) {
				if (elencoKnowledge[i] != null && !elencoKnowledge[i].isEmpty()) {
					if (server.checkDuplicate(elencoKnowledge[i], knowPage.getText())) {
						return elencoKnowledge[i];
					}
				}
				if (elencoKnowledge2[i] != null && !elencoKnowledge2[i].isEmpty()) {
					if (server.checkDuplicate(elencoKnowledge2[i], knowPage.getText())) {
						return elencoKnowledge2[i];
					}
				}
			}
		}
		return null;
	}
// La routin verifica che siano state inserite coppie chiave pubblica e chiave privata 	
	private String verifyPubPriv(){
		for (int i = 0; i < 15; i++) {
			if (elencoKnowledge[i] != null && !elencoKnowledge[i].isEmpty()){
				if (elencoKnowledge2[i].isEmpty()){
					return elencoKnowledge[i];
				}		
			}
			if (elencoKnowledge2[i] != null && !elencoKnowledge2[i].isEmpty()){
				if (elencoKnowledge[i].isEmpty()){
					return elencoKnowledge2[i];
				}		
			}
		}
		return null;
	}
	
	// La routin verifica che siano state inserite coppie chiave pubblica e chiave privata 	
		private String verifyPropId(){
			for (int i = 0; i < 15; i++) {
				if (elencoKnowledge2[i] != null && !elencoKnowledge2[i].isEmpty()) {
					   if (!(elencoKnowledge2[i].toUpperCase().equals("ALICE") ||
						    elencoKnowledge2[i].toUpperCase().equals("BOB") || 
						    elencoKnowledge2[i].toUpperCase().equals("EVE") || 
						    elencoKnowledge2[i].toUpperCase().equals("SERVER"))){
						   
						return elencoKnowledge2[i];
					}		
				}
			}
			return null;
		}
//quando nella form di knowledge si preme prev si abilitano/disabilitano alcuni pulsanti e si modifica il tipo di kyavi da inserire (es: hash,symmetric,asymmetric etc)	
	
	@FXML
	private void prevKnowledge() {
		if (compattaKnowledge()!=null) {
			final Stage stage = (Stage) aliceButton01.getScene().getWindow();
			Alert.AlertType type =  Alert.AlertType.ERROR;
			Alert alert = new Alert(type, "");
	    	alert.initModality(Modality.APPLICATION_MODAL);
	    	alert.initOwner(stage);
	    	alert.getDialogPane().setContentText("Modify or Delete the Duplicate Value");
	    	alert.getDialogPane().setHeaderText("Duplicate Value Found : " + compattaKnowledge());
	    	alert.showAndWait();
			return;
		}
		
		if (knowPage.getText() == "01" || knowPage.getText() == "07" ) {
		    if (verifyPubPriv()!=null) {
		    	final Stage stage = (Stage) aliceButton01.getScene().getWindow();
		    	Alert.AlertType type =  Alert.AlertType.ERROR;
		    	Alert alert = new Alert(type, "");
		    	alert.initModality(Modality.APPLICATION_MODAL);
		    	alert.initOwner(stage);
		    	alert.getDialogPane().setContentText("Insert key Private and Public in the same row");
		    	alert.getDialogPane().setHeaderText("There must be a public key pair and a private key : " +verifyPubPriv());
		    	alert.showAndWait();
		    	return;
		   }
		}

		if (knowPage.getText() == "05" ) {
		    if (verifyPubPriv()!=null) {
		    	final Stage stage = (Stage) aliceButton01.getScene().getWindow();
		    	Alert.AlertType type =  Alert.AlertType.ERROR;
		    	Alert alert = new Alert(type, "");
		    	alert.initModality(Modality.APPLICATION_MODAL);
		    	alert.initOwner(stage);
		    	alert.getDialogPane().setContentText("Insert Id Certificate and Propriety in the same row");
		    	alert.getDialogPane().setHeaderText("There must be a Id Certificate pair and a her proprietary : " +verifyPubPriv());
		    	alert.showAndWait();
		    	return;
		   }
		}
		
		if (knowPage.getText() == "05" ) {
		    if (verifyPropId()!=null) {
		    	final Stage stage = (Stage) aliceButton01.getScene().getWindow();
		    	Alert.AlertType type =  Alert.AlertType.ERROR;
		    	Alert alert = new Alert(type, "");
		    	alert.initModality(Modality.APPLICATION_MODAL);
		    	alert.initOwner(stage);
		    	alert.getDialogPane().setContentText("Enter the Correct Actor ");
		    	alert.getDialogPane().setHeaderText("Actor value must be Alice or Bob or Eve or Server " + verifyPropId() );
		    	alert.showAndWait();
		    	return;
		   }
		}
		
		piuKnowledge();

		
		if (knowPage.getText().equals("02")) {
			typeKey.setText(publicKnow);
			nextButton.setDisable(false);
			//finishButton.setVisible(false);
			prevButton.setDisable(true);
			//piuButton.setVisible(true);
			knowPage.setText("01");
		}

		if (knowPage.getText().equals("03")) {
			typeKey.setText(symmetricKnow);
			nextButton.setDisable(false);
			//finishButton.setVisible(false);
			prevButton.setDisable(false);
			//piuButton.setVisible(true);
			knowPage.setText("02");
		}
		if (knowPage.getText().equals("04")) {
			typeKey.setText(hashKnow);
			nextButton.setDisable(false);
			//finishButton.setVisible(false);
			prevButton.setDisable(false);
			//piuButton.setVisible(true);
			knowPage.setText("03");
		}
		if (knowPage.getText().equals("05")) {
			typeKey.setText(bitstringKnow);
			nextButton.setDisable(false);
			//finishButton.setVisible(false);
			prevButton.setDisable(false);
			//piuButton.setVisible(true);
			knowPage.setText("04");
		}
		if (knowPage.getText().equals("06")) {
			typeKey.setText(idCertificateKnow);
			nextButton.setDisable(false);
			//finishButton.setVisible(false);
			prevButton.setDisable(false);
			//piuButton.setVisible(true);
			knowPage.setText("05");
		}
		if (knowPage.getText().equals("07")) {
			typeKey.setText(nonceKnow);
			nextButton.setDisable(false);
			//finishButton.setVisible(false);
			prevButton.setDisable(false);
			//piuButton.setVisible(true);
			knowPage.setText("06");
		}
		if (knowPage.getText().equals("08")) {
			typeKey.setText(signatureKnow);
			nextButton.setDisable(false);
			//finishButton.setVisible(false);
			prevButton.setDisable(false);
			//piuButton.setVisible(true);
			knowPage.setText("07");
		}
		if (knowPage.getText().equals("09")) {
			typeKey.setText(tagKnow);
			nextButton.setDisable(false);
			//finishButton.setVisible(false);
			prevButton.setDisable(false);
			//piuButton.setVisible(true);
			knowPage.setText("08");
		}
		if (knowPage.getText().equals("10")) {
			typeKey.setText(timestampKnow);
			nextButton.setDisable(false);
			//finishButton.setVisible(false);
			prevButton.setDisable(false);
			//piuButton.setVisible(true);
			knowPage.setText("09");
		}

		if (comboBoxActor.getValue().toString().contains("Alice")) {
			loadTable(alice, knowPage.getText());
			loadTitledAlice(alice);
		}
		if (comboBoxActor.getValue().toString().contains("Bob")) {
			loadTable(bob, knowPage.getText());
			loadTitledBob(bob);
		}
		if (comboBoxActor.getValue().toString().contains("Eve")) {
			loadTable(eve, knowPage.getText());
			loadTitledEve(eve);
		}
		if (comboBoxActor.getValue().toString().contains("Server")) {
			loadTable(server, knowPage.getText());
			loadTitledServer(server);
		}
	}

	
	//Nella sotto-form Knowledge � possibile inserire in ogni pagina piu righe contentneti 
	//le chiavi usate dall'actor. per inserire una nuova riga si preme il pulsante +
	@FXML

	private Boolean piuKnowledge() {
		
		if (comboBoxActor.getValue().toString().contains("Alice")) {
			addSecurityKey(alice, knowPage.getText());
			loadTitledAlice(alice);
		}
		if (comboBoxActor.getValue().toString().contains("Bob")) {
			addSecurityKey(bob, knowPage.getText());
			loadTitledBob(bob);
		}
		if (comboBoxActor.getValue().toString().contains("Eve")) {
			addSecurityKey(eve, knowPage.getText());
			loadTitledEve(eve);
		}
		if (comboBoxActor.getValue().toString().contains("Server")) {
			addSecurityKey(server, knowPage.getText());
			loadTitledServer(server);
		}
		return true;
	}

	// si inseriscono le informazioni digitate 
	private void addSecurityKey(SecurityKey oggetto, String tipo) {
		
		switch (tipo) {
		case "01":
			oggetto.remAllAsymmetricPublicKey();
			oggetto.remAllAsymmetricPrivateKey();
			break;
		case "02":
			oggetto.remAllSymmetricKey();
			break;
		case "03":
			oggetto.remAllHashKey();
			break;
		case "04":
			oggetto.remAllBitstring();
			break;
		case "05":
			oggetto.remAllIdCertificate();
			break;
		case "06":
			oggetto.remAllNonce();
			break;
		case "07":
			oggetto.remAllSignaturePubKey();
			oggetto.remAllSignaturePrivKey();
			break;
		case "08":
			oggetto.remAllTag();
			break;
		case "09":
			oggetto.remAllTimestamp();
			break;
		case "10":
			oggetto.remAllDigest();
			break;
			
		}
		int appColumn;
		for (Node node : tabeKnowledge.getChildren()) {
				if (node instanceof TextField) {
					if (GridPane.getColumnIndex(node) != null) {
						appColumn = GridPane.getColumnIndex(node);
					} else {
						appColumn = 0;
					}
					if (((TextField) node).getText().toString() != null && !((TextField) node).getText().toString().isEmpty()) {
						switch (tipo) {
						case "01":
							if (appColumn == 1) {
								oggetto.addAsymmetricPublicKey(((TextField) node).getText().toString().replaceAll("\\s", ""));
							} else {
								oggetto.addAsymmetricPrivateKey(((TextField) node).getText().toString().replaceAll("\\s", ""));
							}
							break;
						case "02":
							oggetto.addSymmetricKey(((TextField) node).getText().toString().replaceAll("\\s", ""));
							break;
						case "03":
							oggetto.addHashKey(((TextField) node).getText().toString().replaceAll("\\s", ""));
							break;
						case "04":
							oggetto.addBitstring(((TextField) node).getText().toString().replaceAll("\\s", ""));
							break;
						case "05":
							if (appColumn == 1) {
								oggetto.addIdCertificate(((TextField) node).getText().toString().replaceAll("\\s", ""));
							} else {
								oggetto.addIdCertificateProp(((TextField) node).getText().toString().replaceAll("\\s", ""));								
							}
							break;
						case "06":
							oggetto.addNonce(((TextField) node).getText().toString().replaceAll("\\s", ""));
							break;
						case "07":
							if (appColumn == 1) {
								oggetto.addSignaturePubKey(((TextField) node).getText().toString().replaceAll("\\s", ""));
							} else {
								oggetto.addSignaturePrivKey(((TextField) node).getText().toString().replaceAll("\\s", ""));
							}
							break;

						case "08":
							oggetto.addTag(((TextField) node).getText().toString().replaceAll("\\s", ""));
							break;
						case "09":
							oggetto.addTimestamp(((TextField) node).getText().toString().replaceAll("\\s", ""));
							break;
						case "10":
							oggetto.addDigest(((TextField) node).getText().toString().replaceAll("\\s", ""));
							break;
							
						}
					}

			}

		}

	
		
	}

	// quando si apre la sott-form knowledge si verifica se sono gia presenti informazioni memorizzate in precedenza
	// e si caricano nella sott-form 
	private void loadTable(SecurityKey oggetto, String tipo) {
		
		appoOldKnowledge = null;
		int appColumn;
		for (Node node : tabeKnowledge.getChildren()) {
			node.setVisible(true);
			if (GridPane.getColumnIndex(node) != null) {
				appColumn = GridPane.getColumnIndex(node);
			} else {
				appColumn = 0;
			}
			if (node !=null && node instanceof TextField && tipo != "01" && tipo != "05" && tipo != "07" && appColumn==2) {
				node.setVisible(false);
			}
			if (node !=null && node instanceof TextField) {
			((TextField) node).setText(""); }
		}

		
		ArrayList<String> appoList = new ArrayList<String>();
		ArrayList<String> appoList2 = new ArrayList<String>();
		switch (tipo) {
		case "01":
			appoList = oggetto.getAsymmetricPublicKey();
			appoList2 = oggetto.getAsymmetricPrivateKey();
			break;
		
		case "02":
			appoList = oggetto.getSymmetricKey();
			break;
		case "03":
			appoList = oggetto.getHashKey();
			break;
		case "04":
			appoList = oggetto.getBitstring();
			break;
		case "05":
			appoList = oggetto.getIdCertificate();
			appoList2 = oggetto.getIdCertificateProp();
			break;
		case "06":
			appoList = oggetto.getNonce();
			break;
		case "07":
			appoList = oggetto.getSignaturePubKey();
			appoList2 = oggetto.getSignaturePrivKey();
			break;
		case "08":
			appoList = oggetto.getTag();
			break;
		case "09":
			appoList = oggetto.getTimestamp();
			break;
		case "10":
			appoList = oggetto.getDigest();
			break;
		}
		

		int appRow;

		tabeKnowledge.setGridLinesVisible(true);
		for (Node node : tabeKnowledge.getChildren()) {
			
			if (GridPane.getRowIndex(node) != null) {
				appRow = GridPane.getRowIndex(node);
			} else {
				appRow = 0;
			}
			if (GridPane.getColumnIndex(node) != null) {
				appColumn = GridPane.getColumnIndex(node);
			} else {
				appColumn = 0;
			}
			if (appRow < appoList.size()) {
				if (node instanceof TextField) {
					if (appColumn==1) {
						((TextField) node).setText(appoList.get(appRow));
					} else {
						if (appRow < appoList2.size()) {
							((TextField) node).setText(appoList2.get(appRow));
						}
					}
				}
			}

			
			
			if (appRow == appoList.size() && appColumn == 1) {
				node.setVisible(true);
				if (node instanceof TextField) {
					((TextField) node).setText("");
					node.requestFocus();}
			}
		}

	}
	
	private void loadTitledAlice(SecurityKey oggetto) {
		aliceAsymmetricPublicKey.setText(oggetto.getStringAsymmetricPublicKey());
		aliceAsymmetricPrivateKey.setText(oggetto.getStringAsymmetricPrivateKey());
		aliceSymmetricKey.setText(oggetto.getStringSymmetricKey());
		aliceHash.setText(oggetto.getStringHashKey());
		aliceBitstring.setText(oggetto.getStringBitstring());
		aliceIdCertificate.setText(oggetto.getStringIdCertificate());
		aliceNonce.setText(oggetto.getStringNonce());
		aliceSignaturePubKey.setText(oggetto.getStringSignaturePubKey());
		aliceSignaturePrivKey.setText(oggetto.getStringSignaturePrivKey());
		aliceTag.setText(oggetto.getStringTag());
		aliceTimestamp.setText(oggetto.getStringTimestamp());
		aliceDigest.setText(oggetto.getStringDigest());

	}
	private void loadTitledBob(SecurityKey oggetto) {
		bobAsymmetricPublicKey.setText(oggetto.getStringAsymmetricPublicKey());
		bobAsymmetricPrivateKey.setText(oggetto.getStringAsymmetricPrivateKey());
		bobSymmetricKey.setText(oggetto.getStringSymmetricKey());
		bobHash.setText(oggetto.getStringHashKey());
		bobBitstring.setText(oggetto.getStringBitstring());
		bobIdCertificate.setText(oggetto.getStringIdCertificate());
		bobNonce.setText(oggetto.getStringNonce());
		bobSignaturePubKey.setText(oggetto.getStringSignaturePubKey());
		bobSignaturePrivKey.setText(oggetto.getStringSignaturePrivKey());
		bobTag.setText(oggetto.getStringTag());
		bobTimestamp.setText(oggetto.getStringTimestamp());
		bobDigest.setText(oggetto.getStringDigest());
		
	}
	private void loadTitledEve(SecurityKey oggetto) {
		eveAsymmetricPublicKey.setText(oggetto.getStringAsymmetricPublicKey());
		eveAsymmetricPrivateKey.setText(oggetto.getStringAsymmetricPrivateKey());
		eveSymmetricKey.setText(oggetto.getStringSymmetricKey());
		eveHash.setText(oggetto.getStringHashKey());
		eveBitstring.setText(oggetto.getStringBitstring());
		eveIdCertificate.setText(oggetto.getStringIdCertificate());
		eveNonce.setText(oggetto.getStringNonce());
		eveSignaturePubKey.setText(oggetto.getStringSignaturePubKey());
		eveSignaturePrivKey.setText(oggetto.getStringSignaturePrivKey());
		eveTag.setText(oggetto.getStringTag());
		eveTimestamp.setText(oggetto.getStringTimestamp());
		eveDigest.setText(oggetto.getStringDigest());
	}
	private void loadTitledServer(SecurityKey oggetto) {
		serverAsymmetricPublicKey.setText(oggetto.getStringAsymmetricPublicKey());
		serverAsymmetricPrivateKey.setText(oggetto.getStringAsymmetricPrivateKey());
		serverSymmetricKey.setText(oggetto.getStringSymmetricKey());
		serverHash.setText(oggetto.getStringHashKey());
		serverBitstring.setText(oggetto.getStringBitstring());
		serverIdCertificate.setText(oggetto.getStringIdCertificate());
		serverNonce.setText(oggetto.getStringNonce());
		serverSignaturePubKey.setText(oggetto.getStringSignaturePubKey());
		serverSignaturePrivKey.setText(oggetto.getStringSignaturePrivKey());
		serverTag.setText(oggetto.getStringTag());
		serverTimestamp.setText(oggetto.getStringTimestamp());
		serverDigest.setText(oggetto.getStringDigest());
	}
	
	
    // se nel menu Tool viene abilitata o disabilitata l'esistenza del Server nel protocollo di sicurezza
	// si elimina (o reinserisce) tutto ci� che riguarda il server (elenco nella combobox degli actor
	// immagine della linea dei messaggi, elenco chiavi conosciute)
	@FXML

	private void toolSet() {
		int faceEveX, lineaEveX, faceBobX, lineaBobX, eveButtonX,bobButtonX;
		
		if (tool.getText().contains("Disable")) {
			comboBoxActor.setDisable(false);
			toolFlag = true;
			
			comboBoxActor.getItems().removeAll("Server");
			toolFlag= true;
			comboBoxActor.setValue("Actor");
			toolFlag= false;
			
			tool.setText("Enable Server");
			serverButton.setText("Enable Server");
			titledServer.setDisable(true);
			faceServer.setVisible(false);
			lineaServer.setVisible(false);
			serverButton01.setVisible(false);
			faceEveX= 452;
			lineaEveX=457;
			faceBobX=863;
			lineaBobX=858;
			eveButtonX=453;
			bobButtonX=855;
		} else {
			comboBoxActor.setValue("Actor");
			comboBoxActor.setDisable(false);
			
			comboBoxActor.getItems().add("Server");
			tool.setText("Disable Server");
			serverButton.setText("Disable Server");
			titledServer.setDisable(false);
			faceServer.setVisible(true);
			lineaServer.setVisible(true);
			if (aliceButton01.isVisible()) {
				if (faceServer.getOpacity()==1) {
					serverButton01.setVisible(true);
				} else {
					serverButton01.setVisible(false);
					bobButton01.setVisible(false);
					eveButton01.setVisible(false);
					aliceButton01.setVisible(false);
				}
			}
			faceEveX= 313;
			lineaEveX=318;
			faceBobX=585;
			lineaBobX=580;
			eveButtonX=314;
			bobButtonX=577;
		}
		faceEve.setLayoutX(faceEveX);
		lineaEve.setLayoutX(lineaEveX);
		faceBob.setLayoutX(faceBobX);
		lineaBob.setLayoutX(lineaBobX);
		eveButton01.setLayoutX(eveButtonX);
		eveButton02.setLayoutX(eveButtonX);
		eveButton03.setLayoutX(eveButtonX);
		eveButton04.setLayoutX(eveButtonX);
		eveButton05.setLayoutX(eveButtonX);
		eveButton06.setLayoutX(eveButtonX);
		eveButton07.setLayoutX(eveButtonX);
		eveButton08.setLayoutX(eveButtonX);
		eveButton09.setLayoutX(eveButtonX);
		eveButton10.setLayoutX(eveButtonX);
		eveButton11.setLayoutX(eveButtonX);
		eveButton12.setLayoutX(eveButtonX);
		eveButton13.setLayoutX(eveButtonX);
		eveButton14.setLayoutX(eveButtonX);
		eveButton15.setLayoutX(eveButtonX);
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
			//	faceEve.getOpacity() == 1 && 
				(faceServer.getOpacity() == 1 || tool.getText().contains("Enable"))){
				viewLine("01");
			}
	}
    // se nel menu Tool viene abilitata o disabilitata l'esistenza del Server nel protocollo di sicurezza
	// si elimina (o reinserisce) tutto ci� che riguarda il server (elenco nella combobox degli actor
	// immagine della linea dei messaggi, elenco chiavi conosciute)
	@FXML

	private void toolSetEve() {
		if (toolEve.getText().contains("Eve Doesn't Create Messages")) {
			eveButton01.setVisible(false);
			toolEve.setText("Eve Create Messages");
		} else {
			toolEve.setText("Eve Doesn't Create Messages");
			if(aliceButton01.isVisible()) {
				eveButton01.setVisible(true);
			}
		}
		
	}
	  // Tool per abilitata o disabilitata il controllo delle parole per verificare le properties
		@FXML

		private void toolSetChek() {
			if (toolCheck.getText().equals("Don't check Words")) {
				toolCheck.setText("Check Words");
			} else {
				toolCheck.setText("Don't check Words");
			}
			
		}
	public void setToolStart (String toolStart) {
		if (toolStart.equals("Enable Server")){
			tool.setText("Disable Server");
			serverButton.setText("Disable Server");
		} else {
			tool.setText("Enable Server");
			serverButton.setText("Enable Server");
		}
		toolInitialSet();
	}
	public void setToolEve (String toolStart) {
		toolEve.setText(toolStart);
	}
	private void toolInitialSet() {
		int faceEveX, lineaEveX, faceBobX, lineaBobX, eveButtonX,bobButtonX;
		if (tool.getText().contains("Disable")) {
			comboBoxActor.setDisable(false);
			toolFlag = true;
 			comboBoxActor.getItems().removeAll("Server");
			toolFlag= true;
			comboBoxActor.setValue("Actor");
			toolFlag= false;
			tool.setText("Enable Server");
			serverButton.setText("Enable Server");
			titledServer.setDisable(true);
			faceServer.setVisible(false);
			lineaServer.setVisible(false);
			serverButton01.setVisible(false);
			faceEveX= 452;
			lineaEveX=457;
			faceBobX=863;
			lineaBobX=858;
			eveButtonX=453;
			bobButtonX=855;
		} else {
			comboBoxActor.setValue("Actor");
			comboBoxActor.setDisable(false);
		
			comboBoxActor.getItems().add("Server");
			tool.setText("Disable Server");
			serverButton.setText("Disable Server");
			titledServer.setDisable(false);
			faceServer.setVisible(true);
			lineaServer.setVisible(true);
			if (aliceButton01.isVisible()) {
				if (faceServer.getOpacity()==1) {
					serverButton01.setVisible(true);
				} else {
					serverButton01.setVisible(false);
					bobButton01.setVisible(false);
					eveButton01.setVisible(false);
					aliceButton01.setVisible(false);
				}
			}
			faceEveX= 313;
			lineaEveX=318;
			faceBobX=585;
			lineaBobX=580;
			eveButtonX=314;
			bobButtonX=577;
		}
		faceEve.setLayoutX(faceEveX);
		lineaEve.setLayoutX(lineaEveX);
		faceBob.setLayoutX(faceBobX);
		lineaBob.setLayoutX(lineaBobX);
		eveButton01.setLayoutX(eveButtonX);
		eveButton02.setLayoutX(eveButtonX);
		eveButton03.setLayoutX(eveButtonX);
		eveButton04.setLayoutX(eveButtonX);
		eveButton05.setLayoutX(eveButtonX);
		eveButton06.setLayoutX(eveButtonX);
		eveButton07.setLayoutX(eveButtonX);
		eveButton08.setLayoutX(eveButtonX);
		eveButton09.setLayoutX(eveButtonX);
		eveButton10.setLayoutX(eveButtonX);
		eveButton11.setLayoutX(eveButtonX);
		eveButton12.setLayoutX(eveButtonX);
		eveButton13.setLayoutX(eveButtonX);
		eveButton14.setLayoutX(eveButtonX);
		eveButton15.setLayoutX(eveButtonX);
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
		node3 =eveButton01;
		node4 =serverButton01; 
		nodeNext1 =null;
		nodeNext2 =null;
		nodeNext3 =null;
		nodeNext4 =null;
		line = line01;
		liey = liey01;  
		msg=msg01;
		msf=msf01;
		
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
					if (((Button) nodeAppo).getId().contains("eve")) {
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
			if (nodeAppo != null && nodeAppo instanceof TextFlow) {
				if (riga == Integer.valueOf(((TextFlow) nodeAppo).getId().substring(((TextFlow) nodeAppo).getId().length() - 2))
						&& ((TextFlow) nodeAppo).getId().contains("msg")  ) {
						msg = nodeAppo;
				}
				if (riga == Integer.valueOf(((TextFlow) nodeAppo).getId().substring(((TextFlow) nodeAppo).getId().length() - 2))
						&& ((TextFlow) nodeAppo).getId().contains("msf")  ) {
						msf = nodeAppo;
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
						if (((Button) nodeAppo).getId().contains("eve")) {
							nodeNext3 = nodeAppo;
						}
						if (((Button) nodeAppo).getId().contains("server")) {
							nodeNext4 = nodeAppo;
						}
					
				}
			}
		}
		
		
		messages.remMessages(riga - 1);
		if (((Button) node).getText().equals("-")) {
			node1.setVisible(true);
			node2.setVisible(true);
			if (toolEve.getText().contains("Eve Doesn't Create Messages")) {
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
			msg.setVisible(false);
			msf.setVisible(false);
			((Button) node).setText("+");
			resetLine();
			return;
		}
		eseButton(data, riga, line, liey, livy,msg, msf);
		
	}
	// Richiama la form per l'inserimento dei messaggi passandogli l'actor da cui parte il messaggio
	// e ricevendo l'actor a cui arriva il messaggio(actorTo). se l'actorTo � impostato predispone i pulsanti 
	// per l'inserimento di un nuovo messaggio 
	private void eseButton(String data, int riga, Node line, Node liey, Node livy, Node msg, Node msf) throws Exception {
		String actorFrom = "";
		switch (data.substring(0, 5)) {
		case "alice":
			actorFrom = "Alice";
			break;
		case "bobBu":
			actorFrom = "Bob";
			break;
		case "eveBu":
			actorFrom = "Eve";
			break;
		case "serve":
			actorFrom = "Server";
			break;
		}

		String actorTo = showCreateMessage(actorFrom, riga);
		if (actorTo != null && !actorTo.isEmpty()) {
			tool.setDisable(true);
			toolEve.setDisable(true);
			serverButton.setDisable(true);
			viewSpecificLinea(actorTo, actorFrom, line, liey, livy,msg,msf,riga);
		}

	}

	private void viewSpecificLinea(String actorTo, String actorFrom, Node oggetto, Node oggetey, Node oggetvy, Node oggetmsg, Node oggetmsf,int riga) {
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
				if (toolEve.getText().contains("Eve Doesn't Create Messages")) {
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
				if (toolEve.getText().contains("Eve Doesn't Create Messages")) {
					nodeNext3.setVisible(true);
				} else {
					nodeNext3.setVisible(false);
				}
				nodeNext4.setVisible(false);
			}
		}
		
		double coordinateMsg = 90;
		double coordinateMsf = 0;
		double coordinateXStart = 100;
		double coordinateXEnd = 100;
		double coordinateEveXStart = 100;
		double coordinateEveXEnd = 100;
		((TextFlow) oggetmsg).setTextAlignment(TextAlignment.LEFT);
		((TextFlow) oggetmsf).setTextAlignment(TextAlignment.RIGHT);
		if (tool.getText().contains("Disable")) {
			coordinateEveXEnd = 165;
			switch (actorTo) {
			case "Alice":
				coordinateXEnd = -99;
				break;
			case "Eve":
				coordinateXEnd = 163;
				break;
			case "Bob":
				coordinateXEnd = 428;
				break;
			case "Server":
				coordinateXEnd = 715;
				break;
			}
			coordinateEveXStart = 165;
			switch (actorFrom) {
			case "Alice":
				coordinateXStart = -99;
				break;
			case "Eve":
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
			coordinateEveXEnd = 303;
			switch (actorTo) {
			case "Alice":
				coordinateXEnd = -99;
				break;
			case "Eve":
				coordinateXEnd = 303;
				break;
			case "Bob":
				coordinateXEnd = 703;
				break;
			}
			coordinateEveXStart = 303;
			switch (actorFrom) {
			case "Alice":
				
				coordinateXStart = -99;
				break;
			case "Eve":
				coordinateXStart = 308;
				break;
			case "Bob":
				coordinateXStart = 700;
				break;
			}
		}
		if (tool.getText().contains("Disable")) {
			if (actorFrom.equals("Eve")) {
				((TextFlow) oggetmsg).setTextAlignment(TextAlignment.RIGHT);
				if (!actorTo.equals("Alice")) {
					((TextFlow) oggetmsg).setTextAlignment(TextAlignment.LEFT);
					coordinateMsg = 335;
				}
			}
			if (actorFrom.equals("Bob")) {
				((TextFlow) oggetmsg).setTextAlignment(TextAlignment.LEFT);
				coordinateMsg = 605;
				if (actorTo.equals("Alice")) {
					((TextFlow) oggetmsg).setTextAlignment(TextAlignment.LEFT);
					coordinateMsg = 90;
				}
				if (actorTo.equals("Eve")) {
					((TextFlow) oggetmsg).setTextAlignment(TextAlignment.RIGHT);
					coordinateMsg = 335;
				}
				if (actorTo.equals("Server") && eveIntercept) {
					((TextFlow) oggetmsg).setTextAlignment(TextAlignment.RIGHT);
					coordinateMsg = 335;
				}
			}
			if (actorFrom.equals("Server")) {
				((TextFlow) oggetmsg).setTextAlignment(TextAlignment.RIGHT);
				coordinateMsg = 605;
			}
		}
		if (tool.getText().contains("Disable")) {
			System.out.println("A "+ actorTo);
			if (actorFrom.equals("Alice")) {
				System.out.println("A1");
				if (actorTo.equals("Eve")) {
					coordinateMsf = 0;
				}
				if (actorTo.equals("Bob")) {
					System.out.println("A2");
					((TextFlow) oggetmsf).setTextAlignment(TextAlignment.RIGHT);
					coordinateMsf = 335;
				}
				if (actorTo.equals("Server")) {
					((TextFlow) oggetmsf).setTextAlignment(TextAlignment.RIGHT);
					coordinateMsf = 605;
				}
			}
			if (actorFrom.equals("Eve")) {
				if (actorTo.equals("Alice")) {
					coordinateMsf = 0;
				}
				if (actorTo.equals("Bob")) {
					coordinateMsf = 0;
				}
				if (actorTo.equals("Server")) {
					((TextFlow) oggetmsf).setTextAlignment(TextAlignment.RIGHT);
					coordinateMsf = 605;
				}
			}
			if (actorFrom.equals("Bob")) {
				if (actorTo.equals("Alice")) {
					((TextFlow) oggetmsf).setTextAlignment(TextAlignment.RIGHT);
					coordinateMsf = 335;
				}
				if (actorTo.equals("Eve")) {
					coordinateMsf = 0;
				}
				if (actorTo.equals("Server")) {
					coordinateMsf = 0;
					if (eveIntercept) {
						((TextFlow) oggetmsf).setTextAlignment(TextAlignment.RIGHT);
						coordinateMsf = 605;
					}
				}
			}
			if (actorFrom.equals("Server")) {
				if (actorTo.equals("Alice")) {
					((TextFlow) oggetmsf).setTextAlignment(TextAlignment.LEFT);
					coordinateMsf = 90;
				}
				if (actorTo.equals("Eve")) {
					((TextFlow) oggetmsf).setTextAlignment(TextAlignment.LEFT);
					coordinateMsf = 335;
				}
				if (actorTo.equals("Bob")) {
					coordinateMsf = 0;
					if (eveIntercept) {
						((TextFlow) oggetmsf).setTextAlignment(TextAlignment.RIGHT);
						coordinateMsf = 335;
					}
				}
			}
		}
		
		if (tool.getText().contains("Enable")) {
			if (actorFrom == "Eve") {
				((TextFlow) oggetmsg).setTextAlignment(TextAlignment.RIGHT);
				coordinateMsg = 205;
				if (!actorTo.equals("Alice")) {
					((TextFlow) oggetmsg).setTextAlignment(TextAlignment.LEFT);
					coordinateMsg = 485;
				}
			}
			if (actorFrom.equals("Bob")) {
				((TextFlow) oggetmsg).setTextAlignment(TextAlignment.RIGHT);
				coordinateMsg = 605;
			}
		}
		
		if (tool.getText().contains("Enable")) {
			System.out.println("B " + actorFrom + "-" + actorTo);
			if (actorFrom.equals("Alice")) {
				System.out.println("B1 " + actorTo);
				if (actorTo.equals("Eve")) {
					coordinateMsf = 0;
				} 
				if (actorTo.equals("Bob")) {
					System.out.println("B2 " + actorTo);
					((TextFlow) oggetmsf).setTextAlignment(TextAlignment.RIGHT);
					coordinateMsf = 605;
				}
			}
			if (actorFrom.equals("Eve")) {
				coordinateMsf = 0;
			}
			if (actorFrom.equals("Bob")) {
				if (actorTo.equals("Alice")) {
					((TextFlow) oggetmsf).setTextAlignment(TextAlignment.LEFT);
					coordinateMsf = 90;
				}
				if (actorTo.equals("Eve")) {
					coordinateMsf = 0;
				}
			}
		}
		
		if (eveIntercept && !actorTo.equals("Eve") && !actorFrom.equals("Eve")) {
			((Line) oggetto).setEndX(coordinateEveXEnd);
			((Line) oggetto).setStartX(coordinateXStart);
			oggetto.setVisible(true);

			((Line) oggetey).setEndX(coordinateXEnd);
			((Line) oggetey).setStartX(coordinateEveXStart);
			oggetey.setVisible(true);
			
			((Line) oggetvy).setEndX(coordinateEveXStart);
			((Line) oggetvy).setStartX(coordinateEveXStart);
			oggetvy.setVisible(true);
		} else{
			((Line) oggetto).setEndX(coordinateXEnd);
			((Line) oggetto).setStartX(coordinateXStart);
			oggetto.setVisible(true);
		}
		writeMsgLine(messages.getMessage(riga - 1).getPayload(),oggetmsg);
		writeMsgLine(messages.getMessage(riga - 1).getPayload(),oggetmsf);

		((TextFlow) oggetmsg).setLayoutX(coordinateMsg);
		((TextFlow) oggetmsg).setVisible(true);
		((TextFlow) oggetmsf).setVisible(false);
		if (coordinateMsf !=0) {
			((TextFlow) oggetmsf).setLayoutX(coordinateMsf);
			((TextFlow) oggetmsf).setVisible(true);
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
 
    private String showCreateMessage(String actorFrom, int messageNumber) throws Exception {

    	FXMLLoader loader = new FXMLLoader();
        loader.setLocation(getClass().getResource("/fxml/CreateMessageAProVer.fxml"));
        AnchorPane page = (AnchorPane) loader.load();
     
        Stage dialogStage = new Stage();
                
        dialogStage.initModality(Modality.WINDOW_MODAL);
        
        Scene scene = new Scene(page);
        dialogStage.setScene(scene);
        
        CreateMessageAProVer controller = loader.getController();
        controller.setDialogStage(dialogStage);
        appoFrom=null;

        if (actorFrom.equals("Alice")) {
        	appoFrom=alice;
        }
        if (actorFrom.equals("Bob")) {
        	appoFrom=bob;
        }
        if (actorFrom.equals("Eve")) {
        	appoFrom=eve;
        }
        if (actorFrom.equals("Server")) {
        	appoFrom=server;
        }
        
        
        //controller.setInfo(appoFrom, messages.getMessage(messageNumber-1),null);
        controller.setSecurity(alice,bob,eve,server);
        controller.setActorFrom(actorFrom,messageNumber,tool.getText(),toolEve.getText());
        controller.setHelp(helpFlag);
        controller.setInfo(appoFrom,messages, messages.getMessage(messageNumber-1),null,messageNumber);

        
        dialogStage.showAndWait();
        eveIntercept = controller.getEvesIntercept();
        return controller.getActorTo();

    
    }
    private void writeMsgLine(String compactMessageFinale, Node msgxx) {
    	((TextFlow) msgxx).getChildren().clear();
    	int endDash = compactMessageFinale.indexOf("-");
    	int startDash = 0;
    	boolean pedice = false;
    	Text normal = new Text("sub");
    	Text normal2 = new Text("sub");
    	normal2.setStyle("-fx-font: 2 arial;");
    	normal.setStyle("-fx-font: 2 arial;");
    	while (endDash >0) {
    		if (pedice) {

		    	Text sub2 = new Text(compactMessageFinale.substring(startDash+1, endDash));
		    	sub2.setTranslateY(normal.getFont().getSize() * 0.3);
		    	((TextFlow) msgxx).getChildren().addAll(sub2);
		    	startDash = endDash +1;
		    	pedice = false;
    		} else {
    			normal2 = new Text(compactMessageFinale.substring(startDash, endDash));
    			((TextFlow) msgxx).getChildren().addAll(normal2);
    			pedice=true;
    			startDash = endDash;
    		}
    		
    		endDash = compactMessageFinale.indexOf("-", startDash+1);
    	}
    	if (startDash == 0 || !pedice) {
			normal = new Text(compactMessageFinale.substring(startDash,compactMessageFinale.length()));
			((TextFlow) msgxx).getChildren().addAll(normal);
		}
    }
    
	@FXML
	private void selLine(MouseEvent e) throws Exception {

		node = (Node) e.getSource();
		
		String data = (String) node.getId();
		int riga = Integer.parseInt(data.substring(data.length() - 2));
		showModifyMessage(messages.getMessage(riga - 1).getActorfrom().toString(),riga,messages.getMessage(riga - 1).getActorTo().toString());
		
		
		for (Node nodeAppo : ancorPulsanti.getChildren()) {
			if (nodeAppo != null && nodeAppo instanceof TextFlow) {
				if (riga == Integer.valueOf(((TextFlow) nodeAppo).getId().substring(((TextFlow) nodeAppo).getId().length() - 2))
						&& ((TextFlow) nodeAppo).getId().contains("msg")  ) {
						msg = nodeAppo;
				}
				if (riga == Integer.valueOf(((TextFlow) nodeAppo).getId().substring(((TextFlow) nodeAppo).getId().length() - 2))
						&& ((TextFlow) nodeAppo).getId().contains("msf")  ) {
						msf = nodeAppo;
				}
			}
		}
		
		writeMsgLine(messages.getMessage(riga - 1).getPayload(),msg);
		((TextFlow) msg).setVisible(true);
		writeMsgLine(messages.getMessage(riga - 1).getPayload(),msf);
		//((TextFlow) msf).setVisible(true);
		
	}
	//routine che visualizza il payload quando si passa il mouse sulla linea (La riutine è stata sospesa)
	@FXML
	private void moveLine(MouseEvent e) throws Exception {
		return;
		
/*		node = (Node) e.getSource();
		
		String data = (String) node.getId();
		int riga = Integer.parseInt(data.substring(data.length() - 2));
		
		
		msgPayload.getChildren().clear();
		msgPayloadAncorPane.setLayoutX(124);
		msgPayloadAncorPane.setLayoutY((42*riga)+30);
		writeTxtPreview("Message: " + messages.getMessage(riga - 1).getPayload()+ "\n Select for modify message");
		
		msgPayload.setVisible(true);
		msgPayloadAncorPane.setVisible(true);
*/
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

	private void showModifyMessage(String actorFrom, int messageNumber,String actorTo) throws Exception {

		FXMLLoader loader = new FXMLLoader();
		loader.setLocation(getClass().getResource("/fxml/CreateMessageAProVer.fxml"));
		AnchorPane page = (AnchorPane) loader.load();

		Stage dialogStage = new Stage();

		dialogStage.initModality(Modality.WINDOW_MODAL);

		Scene scene = new Scene(page);
		dialogStage.setScene(scene);

		CreateMessageAProVer controller = loader.getController();
		controller.setDialogStage(dialogStage);
        appoFrom=null;

        if (actorFrom.equals("Alice")) {
        	appoFrom=alice;
        }
        if (actorFrom.equals("Bob")) {
        	appoFrom=bob;
        }
        if (actorFrom.equals("Eve")) {
        	appoFrom=eve;
        }
        if (actorFrom.equals("Server")) {
        	appoFrom=server;
        }
        appoTo=null;

        if (actorTo.equals("Alice")) {
        	appoTo=alice;
        }
        if (actorTo.equals("Bob")) {
        	appoTo=bob;
        }
        if (actorTo.equals("Eve")) {
        	appoTo=eve;
        }
        if (actorTo.equals("Server")) {
        	appoTo=server;
        }      
        
        controller.setSecurity(alice,bob,eve,server);
        controller.setInfo(appoFrom, messages, messages.getMessage(messageNumber-1),appoTo,messageNumber);
		controller.setHelp(helpFlag);
		
		controller.setMessage(messageNumber);
		
		dialogStage.showAndWait();
        eveIntercept = controller.getEvesIntercept();

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
					if (((Button) node).getId().contains("eve") && !toolEve.getText().contains("Eve Doesn't Create Messages")) {
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
		if (ultimoValido < 2) {tool.setDisable(false);toolEve.setDisable(false);serverButton.setDisable(false);}
	}

	private void readFileConf() {
		try {
			int numberRow = -1;
		 	BufferedReader reader = new BufferedReader(new FileReader("src\\main\\resources\\ConfigurationFile\\ConfProp.txt"));
	 
			String line = reader.readLine();
			while (line != null && !line.contains("Altre")) {
				numberRow++;
				insertProprieties(line);
				insertTab(numberRow);
				line = reader.readLine();
			}
			numCtlEle = 0;
			while (line != null) {
				if (!line.contains("Altre")){
					ctlEle[numCtlEle] = line;
					numCtlEle ++;
				}
				line = reader.readLine();
			}
			deleteTab(numberRow + 1);
			/*
			  				ListProprieties02.getCheckModel().getCheckedItems().addListener(new ListChangeListener<String>() {
					public void onChanged(ListChangeListener.Change<? extends String> c) {
						for (int i = 0; i < ListProprieties02.getCheckModel().getCheckedItems().size(); i++) {

							insertListProperties(listProprieties02, ListProprieties02);
							// System.out.println(ListProprieties00.getCheckModel().getCheckedItems().get(i));
						}
					}
				});
			 */
			if (numberRow > -1) {
				ListProprieties00.getCheckModel().getCheckedItems().addListener(new ListChangeListener<String>() {
					public void onChanged(ListChangeListener.Change<? extends String> c) {
							insertListProperties(listProprieties00, ListProprieties00);
					}
				});
			}
			if (numberRow > 0) {
				ListProprieties01.getCheckModel().getCheckedItems().addListener(new ListChangeListener<String>() {
					public void onChanged(ListChangeListener.Change<? extends String> c) {
							insertListProperties(listProprieties01, ListProprieties01);
							// System.out.println(ListProprieties00.getCheckModel().getCheckedItems().get(i));
					}
				});
			}
			if (numberRow > 1) {
				ListProprieties02.getCheckModel().getCheckedItems().addListener(new ListChangeListener<String>() {
					public void onChanged(ListChangeListener.Change<? extends String> c) {
							insertListProperties(listProprieties02, ListProprieties02);
							// System.out.println(ListProprieties00.getCheckModel().getCheckedItems().get(i));
					}
				});
			}
			if (numberRow > 2) {
				ListProprieties03.getCheckModel().getCheckedItems().addListener(new ListChangeListener<String>() {
					public void onChanged(ListChangeListener.Change<? extends String> c) {
							insertListProperties(listProprieties03, ListProprieties03);
							// System.out.println(ListProprieties00.getCheckModel().getCheckedItems().get(i));
					}
				});
			}
			if (numberRow > 3) {
				ListProprieties04.getCheckModel().getCheckedItems().addListener(new ListChangeListener<String>() {
					public void onChanged(ListChangeListener.Change<? extends String> c) {
							insertListProperties(listProprieties04, ListProprieties04);
							// System.out.println(ListProprieties00.getCheckModel().getCheckedItems().get(i));
					}
				});
			}
			if (numberRow > 4) {
				ListProprieties05.getCheckModel().getCheckedItems().addListener(new ListChangeListener<String>() {
					public void onChanged(ListChangeListener.Change<? extends String> c) {
							insertListProperties(listProprieties05, ListProprieties05);
							// System.out.println(ListProprieties00.getCheckModel().getCheckedItems().get(i));
					}
				});
			}
			if (numberRow > 5) {
				ListProprieties06.getCheckModel().getCheckedItems().addListener(new ListChangeListener<String>() {
					public void onChanged(ListChangeListener.Change<? extends String> c) {
							insertListProperties(listProprieties06, ListProprieties06);
							// System.out.println(ListProprieties00.getCheckModel().getCheckedItems().get(i));
					}
				});
			}
			
			if (numberRow > 6) {
				ListProprieties07.getCheckModel().getCheckedItems().addListener(new ListChangeListener<String>() {
					public void onChanged(ListChangeListener.Change<? extends String> c) {
							insertListProperties(listProprieties07, ListProprieties07);
							// System.out.println(ListProprieties00.getCheckModel().getCheckedItems().get(i));
					}
				});
			}
			if (numberRow > 7) {
				ListProprieties08.getCheckModel().getCheckedItems().addListener(new ListChangeListener<String>() {
					public void onChanged(ListChangeListener.Change<? extends String> c) {
							insertListProperties(listProprieties08, ListProprieties08);
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
			count=0;
			String line1 = in.nextLine();
			Scanner t = new Scanner(line1);
			while (t.hasNext()) {
				if (count == 0) {
					confProp.setListNameTab(t.next(),"");
				} else {
					confProp.setCtlValue(t.next());
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
		case 6:
			tab06.setText(confProp.getListNameTab(numberRow));
		case 7:
			tab07.setText(confProp.getListNameTab(numberRow));
		case 8:
			tab08.setText(confProp.getListNameTab(numberRow));
		default:
			break;
		}
	}

	private void deleteTab(int numberRow) {
		
		if (numberRow > 8)
			return;

		for (int i = numberRow; i < 9; i++) {
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
			case 6:
				tabProprieities.getTabs().remove(tab06);
				break;
			case 7:
				tabProprieities.getTabs().remove(tab07);
				break;
			case 8:
				tabProprieities.getTabs().remove(tab08);
				break;
			default:
				break;
			}

		}
		tabProprieities.getTabs().add(tab08);
		tab08.setText("+");
		// tab08.setGraphic(new Circle(0, 0, 10));
		// Image image = new
		// Image(getClass().getResourceAsStream("/styles/images/alicepiccola.png"));
		// tab08.setGraphic(new ImageView(image));

		tab08.setOnSelectionChanged(e -> {
			try {
				if (showProperties(8)) {
					if (tabProprieities.getTabs().size() - 1 == 3) {
						tabProprieities.getTabs().add(tabProprieities.getTabs().size() - 1, tab03);
						tab03.setText(confProp.getListNameTab(3));
					} else {
						if (tabProprieities.getTabs().size() - 1 == 4) {
							tabProprieities.getTabs().add(tabProprieities.getTabs().size() - 1, tab04);
							tab04.setText(confProp.getListNameTab(4));
						} else {
							if (tabProprieities.getTabs().size() - 1 == 5) {
								tabProprieities.getTabs().add(tabProprieities.getTabs().size() - 1, tab05);
								tab05.setText(confProp.getListNameTab(5));
							} else {
								if (tabProprieities.getTabs().size() - 1 == 6) {
									tabProprieities.getTabs().add(tabProprieities.getTabs().size() - 1, tab06);
									tab06.setText(confProp.getListNameTab(6));
								} else {
									if (tabProprieities.getTabs().size() - 1 == 7) {
										tabProprieities.getTabs().add(tabProprieities.getTabs().size() - 1, tab07);
										tab07.setText(confProp.getListNameTab(7));
									}
								}
							}
						}
					}
					if (tabProprieities.getTabs().size() - 1 < 8) {
						tabProprieities.getSelectionModel().select(tabProprieities.getTabs().size() - 2);
					} else {
						tabProprieities.getSelectionModel().select(tabProprieities.getTabs().size() - 2);
						tabProprieities.getTabs().remove(tab08);
					}
				} else {
					tabProprieities.getSelectionModel().select(tabProprieities.getTabs().size() - 2);
				}

			} catch (Exception e1) {

				e1.printStackTrace();
			}
		});
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



	private void insertListProperties(GridPane listProprieties0x, CheckComboBox ListProprieties0x) {
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

				if (GridPane.getRowIndex(node) != null) {
					appRow = GridPane.getRowIndex(node);
				} else {
					appRow = 0;
				}
				if (GridPane.getColumnIndex(node) != null) {
					appColumn = GridPane.getColumnIndex(node);
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
	private void rewriteEleProperties (GridPane listProprieties0x,int tab) {
		int appRow = 0;
		for (Node node : listProprieties0x.getChildren()) {
			if (GridPane.getRowIndex(node) != null) {
				appRow = GridPane.getRowIndex(node);
			} else {
				appRow = 0;
			}
			if (node != null && node instanceof TextField) {
				((TextField) node).setText(confProp.getProprietiesValue(tab, appRow));
			}
			if (node != null && node instanceof Button && tab < 3) {
				if (confProp.getProprietiesValue(tab, appRow) == null
						|| confProp.getProprietiesValue(tab, appRow).isEmpty()) {
					((Button) node).setVisible(false);
				} else {
					((Button) node).setVisible(true);
				}
			}

		}
	}
	
	
	private void insertEleProperties(GridPane listProprieties0x, String properties, int row, int tab) {
		int appRow = 0;
		for (Node node : listProprieties0x.getChildren()) {
			if (GridPane.getRowIndex(node) != null) {
				appRow = GridPane.getRowIndex(node);
			} else {
				appRow = 0;
			}
			if (node != null && node instanceof TextField) {
				if (appRow == row) {
					((TextField) node).setText(properties);
				}
			}
			if (node != null && node instanceof Button && tab < 3) {
				if (appRow == row) {
					((Button) node).setVisible(true);
				}
			}

		}

	}

	private Node selecttEleProperties(GridPane listProprieties0x,  int row) {

		int appRow = 0;
		for (Node node : listProprieties0x.getChildren()) {
			if (GridPane.getRowIndex(node) != null) {
				appRow = GridPane.getRowIndex(node);
			} else {
				appRow = 0;
			}
			if (node != null && node instanceof TextField) {
				if (appRow == row) {
					return node;
				}
			}
		}
		return null;
	}
	
	//@FXML
    private boolean showProperties(int numTab) throws Exception {

    	FXMLLoader loader = new FXMLLoader();
        loader.setLocation(getClass().getResource("/fxml/CreateProperties.fxml"));
        AnchorPane page = (AnchorPane) loader.load();
     
        Stage dialogStage = new Stage();
                
        dialogStage.initModality(Modality.WINDOW_MODAL);
        
        Scene scene = new Scene(page);
        dialogStage.setScene(scene);
        
        CreateProperties controller = loader.getController();
        controller.setDialogStage(dialogStage,alice,bob,eve,server,toolCheck.getText(),true);
        if (numTab != 8){
        	controller.setTxtProperties(confProp.getListNameTab(numTab), confProp.getProprietiesValue(numTab,0));
        }
		if (tool.getText().contains("Disable")) {
			controller.setActorList(true);
		} else {
			controller.setActorList(false);
		}
		controller.setCtlList(ctlEle);
        dialogStage.showAndWait();
        if(controller.getOperation().equals("Delete")){
        	confProp.delListTab(numTab);
        	for (int numberRow=0; numberRow < (confProp.getNumListNameTab()+1); numberRow++){
        		insertTab(numberRow);
        	}
        	deleteTab(confProp.getNumListNameTab()+1);
        	return false;
        }
        
		if (!controller.getProperyName().isEmpty()) {
			if (numTab == 8) {
				confProp.setListNameTab(controller.getProperyName(), controller.getExpressionValue());
				switch (confProp.getNumListNameTab()) {
				case 0:
					insertEleProperties(listProprieties00, controller.getExpressionValue(), 0,0);
					break;
				case 1:
					insertEleProperties(listProprieties01, controller.getExpressionValue(), 0,1);
					break;
				case 2:
					insertEleProperties(listProprieties02, controller.getExpressionValue(), 0,2);
					break;
				case 3:
					insertEleProperties(listProprieties03, controller.getExpressionValue(), 0,3);
					break;
				case 4:
					insertEleProperties(listProprieties04, controller.getExpressionValue(), 0,4);
					break;
				case 5:
					insertEleProperties(listProprieties05, controller.getExpressionValue(), 0,5);
					break;
				case 6:
					insertEleProperties(listProprieties06, controller.getExpressionValue(), 0,6);
					break;
				case 7:
					insertEleProperties(listProprieties07, controller.getExpressionValue(), 0,7);
					break;
				case 8:
					insertEleProperties(listProprieties08, controller.getExpressionValue(), 0,8);
					break;
				}
				return true;
			} else {
				confProp.updListNameTab(numTab, controller.getProperyName(), controller.getExpressionValue());
				switch (numTab) {
				case 0:
					insertEleProperties(listProprieties00, controller.getExpressionValue(), 0,1);
					break;
				case 1:
					insertEleProperties(listProprieties01, controller.getExpressionValue(), 0,2);
					break;
				case 2:
					insertEleProperties(listProprieties02, controller.getExpressionValue(), 0,3);
					break;
				case 3:
					insertEleProperties(listProprieties03, controller.getExpressionValue(), 0,4);
					break;
				case 4:
					insertEleProperties(listProprieties04, controller.getExpressionValue(), 0,5);
					break;
				case 5:
					insertEleProperties(listProprieties05, controller.getExpressionValue(), 0,6);
					break;
				case 6:
					insertEleProperties(listProprieties06, controller.getExpressionValue(), 0,7);
					break;
				case 7:
					insertEleProperties(listProprieties07, controller.getExpressionValue(), 0,8);
					break;
				case 8:
					insertEleProperties(listProprieties08, controller.getExpressionValue(), 0,9);
					break;
				}



				tabProprieities.getSelectionModel().select(numTab);
				return true;
			}
		}
        
        
        return false;

    
    }
	
	@FXML
	private void selButtonProperties(ActionEvent e) throws Exception {
		
		node = (Node) e.getSource();
		
		String data = (String) node.getId();
		int riga = Integer.parseInt(data.substring(data.length() - 2));
		if (showProperties(riga)) {
			//((Tab) node).setText(confProp.getListNameTab(riga));
			switch (riga) {
			case 3:
				tab03.setText(confProp.getListNameTab(riga));
				break;
			case 4:
				tab04.setText(confProp.getListNameTab(riga));
				break;
			case 5:
				tab05.setText(confProp.getListNameTab(riga));
				break;
			case 6:
				tab06.setText(confProp.getListNameTab(riga));
				break;
			case 7:
				tab07.setText(confProp.getListNameTab(riga));
				break;
			}
		}
		
	}
	
	@FXML
	private void selButtonAddProperties(ActionEvent e) throws Exception {

		node = (Node) e.getSource();
		
		String data = (String) node.getId();
		int tab = Integer.parseInt(data.substring(data.length() - 2));
		showAddProperties(tab,"ADD",0);
		
	}
	
    private void showAddProperties(int tab,String operation,int row) throws Exception {
   /*
		FXMLLoader loader = new FXMLLoader();
        loader.setLocation(getClass().getResource("/fxml/AddProperties.fxml"));
        AnchorPane page = (AnchorPane) loader.load();
     
        Stage dialogStage = new Stage();
                
        dialogStage.initModality(Modality.WINDOW_MODAL);
        
        Scene scene = new Scene(page);
        dialogStage.setScene(scene);
        
        AddProperties controller = loader.getController();
        controller.setDialogStage(dialogStage,alice,bob,eve,server);
        
		switch (tab) {
		case 0:
			controller.setPropertyTypes(tab00.getText(),confProp.getCtlTab(0));
			break;
		case 1:
			controller.setPropertyTypes(tab01.getText(),confProp.getCtlTab(1));
			break;
		case 2:
			controller.setPropertyTypes(tab02.getText(),confProp.getCtlTab(2));
			break;
		}
        
		if (tool.getText().contains("Disable")) {
			controller.setActorList(true);
		} else {
			controller.setActorList(false);
		}
		if (operation.contains("UPD")) {
			Node node = null;
			switch (tab) {
			case 0:
				node = selecttEleProperties(listProprieties00, row);
				break;
			case 1:
				node = selecttEleProperties(listProprieties01, row);
				break;
			case 2:
				node = selecttEleProperties(listProprieties02, row);
				break;
			case 3:
				node = selecttEleProperties(listProprieties03, row);
				break;
			case 4:
				node = selecttEleProperties(listProprieties04, row);
				break;
			case 5:
				node = selecttEleProperties(listProprieties05, row);
				break;
			case 6:
				node = selecttEleProperties(listProprieties06, row);
				break;
			case 7:
				node = selecttEleProperties(listProprieties07, row);
				break;
			case 8:
				node = selecttEleProperties(listProprieties08, row);
				break;
			}
			if (node != null) {
				controller.setpropertyAddValue(((TextField) node).getText());
			}
		}

        dialogStage.showAndWait();
        
        if (controller.getOperation().equals("Saving")) {
        	int column;
        	if (operation.contains("UPD")) {
        		column = row;
        		confProp.setElePropertisValue(controller.getpropertyAddValue(),tab,column);
        	} else {
        		column = confProp.setNextPropertisValue(controller.getpropertyAddValue(),tab);
        	}
           	switch (tab) {
			case 0:
				insertEleProperties(listProprieties00, controller.getpropertyAddValue(), column,0);
				break;
			case 1:
				insertEleProperties(listProprieties01, controller.getpropertyAddValue(), column,1);
				break;
			case 2:
				insertEleProperties(listProprieties02, controller.getpropertyAddValue(), column,2);
				break;
			case 3:
				insertEleProperties(listProprieties03, controller.getpropertyAddValue(), column,3);
				break;
			case 4:
				insertEleProperties(listProprieties04, controller.getpropertyAddValue(), column,4);
				break;
			case 5:
				insertEleProperties(listProprieties05, controller.getpropertyAddValue(), column,5);
				break;
			case 6:
				insertEleProperties(listProprieties06, controller.getpropertyAddValue(), column,6);
				break;
			case 7:
				insertEleProperties(listProprieties07, controller.getpropertyAddValue(), column,7);
				break;
			case 8:
				insertEleProperties(listProprieties08, controller.getpropertyAddValue(), column,8);
				break;
			}
        }
        
        if (controller.getOperation().equals("RemSaving")) {
        	confProp.delPropertiesTab(tab,row);    
           	switch (tab) {
			case 0:
				rewriteEleProperties(listProprieties00,0);
				break;
			case 1:
				rewriteEleProperties(listProprieties01,1);
				break;
			case 2:
				rewriteEleProperties(listProprieties02,2);
				break;
			case 3:
				rewriteEleProperties(listProprieties03,3);
				break;
			case 4:
				rewriteEleProperties(listProprieties04,4);
				break;
			case 5:
				rewriteEleProperties(listProprieties05,5);
				break;
			case 6:
				rewriteEleProperties(listProprieties06,6);
				break;
			case 7:
				rewriteEleProperties(listProprieties07,7);
				break;
			case 8:
				rewriteEleProperties(listProprieties08,8);
				break;
			}
        }
*/

    	FXMLLoader loader = new FXMLLoader();
        loader.setLocation(getClass().getResource("/fxml/CreateProperties.fxml"));
        AnchorPane page = (AnchorPane) loader.load();
     
        Stage dialogStage = new Stage();
                
        dialogStage.initModality(Modality.WINDOW_MODAL);
        
        Scene scene = new Scene(page);
        dialogStage.setScene(scene);
        
        CreateProperties controller = loader.getController();
        controller.setDialogStage(dialogStage,alice,bob,eve,server,toolCheck.getText(),false);
        if (tab != 8){
         	controller.setTxtProperties(confProp.getListNameTab(tab), "");
        }
        
		if (tool.getText().contains("Disable")) {
			controller.setActorList(true);
		} else {
			controller.setActorList(false);
		}
		if (operation.contains("UPD")) {
			Node node = null;
			switch (tab) {
			case 0:
				node = selecttEleProperties(listProprieties00, row);
				break;
			case 1:
				node = selecttEleProperties(listProprieties01, row);
				break;
			case 2:
				node = selecttEleProperties(listProprieties02, row);
				break;
			case 3:
				node = selecttEleProperties(listProprieties03, row);
				break;
			case 4:
				node = selecttEleProperties(listProprieties04, row);
				break;
			case 5:
				node = selecttEleProperties(listProprieties05, row);
				break;
			case 6:
				node = selecttEleProperties(listProprieties06, row);
				break;
			case 7:
				node = selecttEleProperties(listProprieties07, row);
				break;
			case 8:
				node = selecttEleProperties(listProprieties08, row);
				break;
			}
			if (node != null) {
				controller.setTxtProperties(confProp.getListNameTab(tab),((TextField) node).getText());
			}
		}
        
        
        
		if (tool.getText().contains("Disable")) {
			controller.setActorList(true);
		} else {
			controller.setActorList(false);
		}
		controller.setCtlList(ctlEle);
		
		
		
		dialogStage.showAndWait();
		
		System.out.println("controller.getOperation() " + controller.getOperation());
		System.out.println("controller.getExpressionValue() " + controller.getExpressionValue());
		System.out.println("operation " + operation);
		System.out.println("tab " + tab + " row " + row);

		
		
		if (controller.getOperation().equals("Saving")) {
        	int column;
        	if (operation.contains("UPD")) {
        		column = row;
        		confProp.setElePropertisValue(controller.getExpressionValue(),tab,column);
        	} else {
        		column = confProp.setNextPropertisValue(controller.getExpressionValue(),tab);
        	}
        	System.out.println("tab " + tab + " column " + column);
           	switch (tab) {
			case 0:
				insertEleProperties(listProprieties00, controller.getExpressionValue(), column,0);
				break;
			case 1:
				insertEleProperties(listProprieties01, controller.getExpressionValue(), column,1);
				break;
			case 2:
				insertEleProperties(listProprieties02, controller.getExpressionValue(), column,2);
				break;
			case 3:
				insertEleProperties(listProprieties03, controller.getExpressionValue(), column,3);
				break;
			case 4:
				insertEleProperties(listProprieties04, controller.getExpressionValue(), column,4);
				break;
			case 5:
				insertEleProperties(listProprieties05, controller.getExpressionValue(), column,5);
				break;
			case 6:
				insertEleProperties(listProprieties06, controller.getExpressionValue(), column,6);
				break;
			case 7:
				insertEleProperties(listProprieties07, controller.getExpressionValue(), column,7);
				break;
			case 8:
				insertEleProperties(listProprieties08, controller.getExpressionValue(), column,8);
				break;
			}
        }
		
        if (controller.getOperation().equals("Delete")) {
        	confProp.delPropertiesTab(tab,row);    
           	switch (tab) {
			case 0:
				rewriteEleProperties(listProprieties00,0);
				break;
			case 1:
				rewriteEleProperties(listProprieties01,1);
				break;
			case 2:
				rewriteEleProperties(listProprieties02,2);
				break;
			case 3:
				rewriteEleProperties(listProprieties03,3);
				break;
			case 4:
				rewriteEleProperties(listProprieties04,4);
				break;
			case 5:
				rewriteEleProperties(listProprieties05,5);
				break;
			case 6:
				rewriteEleProperties(listProprieties06,6);
				break;
			case 7:
				rewriteEleProperties(listProprieties07,7);
				break;
			case 8:
				rewriteEleProperties(listProprieties08,8);
				break;
			}
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
			loadTitledEve(eve);
			loadTitledServer(server);
		} catch (IOException r) {
			r.printStackTrace();
		}
	}
	private String verifyDati(String line) {
		if (line.equals("tool value ") ||
			line.equals("toolEve value ") ||
			line.equals("dati Alice AsymmetricPublicKey ") ||
			line.equals("dati Alice AsymmetricPrivateKey ") ||
			line.equals("dati Alice SymmetricKey ") ||
			line.equals("dati Alice Hash ") ||
			line.equals("dati Alice Bitstring ") ||
			line.equals("dati Alice IdCertificate ") ||
			line.equals("dati Alice IdCertificatProp ") ||
			line.equals("dati Alice Nonce ") ||
			line.equals("dati Alice Signature Priv Key ") ||
			line.equals("dati Alice Signature Pub Key ") ||
			line.equals("dati Alice Tag ")||
			line.equals("dati Alice Timestamp ")||
			line.equals("dati Alice Digest ")||
			line.equals("dati Alice KnowAcq ")||
			line.equals("dati Bob AsymmetricPublicKey ") ||
			line.equals("dati Bob AsymmetricPrivateKey ") ||
			line.equals("dati Bob SymmetricKey ") ||	
			line.equals("dati Bob Hash ") ||
			line.equals("dati Bob Bitstring ") ||
			line.equals("dati Bob IdCertificate ") ||
			line.equals("dati Bob IdCertificatProp ") ||
			line.equals("dati Bob Nonce ") ||
			line.equals("dati Bob Signature Pub Key ") ||
			line.equals("dati Bob Signature Priv Key ") ||
			line.equals("dati Bob Tag ")||
			line.equals("dati Bob Timestamp ")||
			line.equals("dati Bob Digest ")||
			line.equals("dati Bob KnowAcq ")||
			line.equals("dati Eve AsymmetricPublicKey ") ||
			line.equals("dati Eve AsymmetricPrivateKey ") ||
			line.equals("dati Eve SymmetricKey ") ||
			line.equals("dati Eve Hash ") ||
			line.equals("dati Eve Bitstring ") ||
			line.equals("dati Eve IdCertificate ") ||
			line.equals("dati Eve IdCertificatProp ") ||
			line.equals("dati Eve Nonce ") ||
			line.equals("dati Eve Signature Pub Key ") ||
			line.equals("dati Eve Signature Priv Key ") ||
			line.equals("dati Eve Tag ")||
			line.equals("dati Eve Timestamp ")||
			line.equals("dati Eve Digest ")||
			line.equals("dati Eve KnowAcq ")||
			line.equals("dati Server AsymmetricPublicKey ") ||
			line.equals("dati Server AsymmetricPrivateKey ") ||
			line.equals("dati Server SymmetricKey ") ||
			line.equals("dati Server Hash ") ||
			line.equals("dati Server Bitstring ") ||
			line.equals("dati Server IdCertificate ") ||
			line.equals("dati Server IdCertificatProp ") ||
			line.equals("dati Server Nonce ") ||
			line.equals("dati Server Signature Pub Key ") ||
			line.equals("dati Server Signature Priv Key ") ||
			line.equals("dati Server Tag ")||
			line.equals("dati Server Timestamp ")||
			line.equals("dati Server Digest ")||
			line.equals("dati Server KnowAcq ")||
			line.equals("dati Messaggi ") ||
			line.contains("dati Messaggio") ||
			line.contains("dati listPartMessage j=") ||
			line.contains("dati Properties") ||
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
		if (typeInfo.equals("toolEve value ")) {
			setToolEve(line);
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
		if (typeInfo.equals("dati Alice Hash ")) {
			faceAlice.setOpacity(1);
			lineaAlice.setOpacity(1);
			alice.addHashKey(line);
		}
		if (typeInfo.equals("dati Alice Bitstring ")) {
			faceAlice.setOpacity(1);
			lineaAlice.setOpacity(1);
			alice.addBitstring(line);
		}
		if (typeInfo.equals("dati Alice IdCertificate ")) {
			faceAlice.setOpacity(1);
			lineaAlice.setOpacity(1);
			alice.addIdCertificate(line);
		}
		if (typeInfo.equals("dati Alice IdCertificatProp ")) {
			faceAlice.setOpacity(1);
			lineaAlice.setOpacity(1);
			alice.addIdCertificateProp(line);
		}
		if (typeInfo.equals("dati Alice Nonce ")) {
			faceAlice.setOpacity(1);
			lineaAlice.setOpacity(1);
			alice.addNonce(line);
		}
		if (typeInfo.equals("dati Alice Signature Pub Key ")) {
			faceAlice.setOpacity(1);
			lineaAlice.setOpacity(1);
			alice.addSignaturePubKey(line);
		}
		if (typeInfo.equals("dati Alice Signature Priv Key ")) {
			faceAlice.setOpacity(1);
			lineaAlice.setOpacity(1);
			alice.addSignaturePrivKey(line);
		}
		if (typeInfo.equals("dati Alice Tag ")) {
			faceAlice.setOpacity(1);
			lineaAlice.setOpacity(1);
			alice.addTag(line);
		}
		if (typeInfo.equals("dati Alice Timestamp ")) {
			faceAlice.setOpacity(1);
			lineaAlice.setOpacity(1);
			alice.addTimestamp(line);
		}
		if (typeInfo.equals("dati Alice Digest ")) {
			faceAlice.setOpacity(1);
			lineaAlice.setOpacity(1);
			alice.addDigest(line);
		}
		if (typeInfo.equals("dati Alice KnowAcq ")) {
			alice.addKnowAcq(line.substring(0,line.indexOf("-")-1),line.substring(line.indexOf("-")+2,line.length() ));
			System.out.println("------------> know acq :" + (line.substring(0,line.indexOf("-")-1) + ": -- :" + line.substring(line.indexOf("-")+2,line.length() ))+ ":");
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
		
		if (typeInfo.equals("dati Bob Hash ")) {
			faceBob.setOpacity(1);
			lineaBob.setOpacity(1);
			bob.addHashKey(line);
		}
		if (typeInfo.equals("dati Bob Bitstring ")) {
			faceBob.setOpacity(1);
			lineaBob.setOpacity(1);
			bob.addBitstring(line);
		}
		if (typeInfo.equals("dati Bob IdCertificate ")) {
			faceBob.setOpacity(1);
			lineaBob.setOpacity(1);
			bob.addIdCertificate(line);
		}
		if (typeInfo.equals("dati Bob IdCertificatProp ")) {
			faceBob.setOpacity(1);
			lineaBob.setOpacity(1);
			bob.addIdCertificateProp(line);
		}
		if (typeInfo.equals("dati Bob Nonce ")) {
			faceBob.setOpacity(1);
			lineaBob.setOpacity(1);
			bob.addNonce(line);
		}
		if (typeInfo.equals("dati Bob Signature Pub Key ")) {
			faceBob.setOpacity(1);
			lineaBob.setOpacity(1);
			bob.addSignaturePubKey(line);
		}
		if (typeInfo.equals("dati Bob Signature Priv Key ")) {
			faceBob.setOpacity(1);
			lineaBob.setOpacity(1);
			bob.addSignaturePrivKey(line);
		}
		if (typeInfo.equals("dati Bob Tag ")) {
			faceBob.setOpacity(1);
			lineaBob.setOpacity(1);
			bob.addTag(line);
		}
		if (typeInfo.equals("dati Bob Timestamp ")) {
			faceBob.setOpacity(1);
			lineaBob.setOpacity(1);
			bob.addTimestamp(line);
		}
		if (typeInfo.equals("dati Bob Digest ")) {
			faceBob.setOpacity(1);
			lineaBob.setOpacity(1);
			bob.addDigest(line);
		}
		if (typeInfo.equals("dati Bob KnowAcq ")) {
			bob.addKnowAcq(line.substring(0,line.indexOf("-")-1),line.substring(line.indexOf("-")+2,line.length() ));
			System.out.println("------------> know acq :" + (line.substring(0,line.indexOf("-")-1) + ": -- :" + line.substring(line.indexOf("-")+2,line.length() ))+ ":");
		}


		if (typeInfo.equals("dati Eve AsymmetricPublicKey ")) {
			faceEve.setOpacity(1);
			lineaEve.setOpacity(1);
			eve.addAsymmetricPublicKey(line);
		}
		if (typeInfo.equals("dati Eve AsymmetricPrivateKey ")) {
			faceEve.setOpacity(1);
			lineaEve.setOpacity(1);
			eve.addAsymmetricPrivateKey(line);
		}
		if (typeInfo.equals("dati Eve SymmetricKey ")) {
			faceEve.setOpacity(1);
			lineaEve.setOpacity(1);
			eve.addSymmetricKey(line);
		}

		if (typeInfo.equals("dati Eve Hash ")) {
			faceEve.setOpacity(1);
			lineaEve.setOpacity(1);
			eve.addHashKey(line);
		}
		if (typeInfo.equals("dati Eve Bitstring ")) {
			faceEve.setOpacity(1);
			lineaEve.setOpacity(1);
			eve.addBitstring(line);
		}
		if (typeInfo.equals("dati Eve IdCertificate ")) {
			faceEve.setOpacity(1);
			lineaEve.setOpacity(1);
			eve.addIdCertificate(line);
		}
		if (typeInfo.equals("dati Eve IdCertificatProp ")) {
			faceEve.setOpacity(1);
			lineaEve.setOpacity(1);
			eve.addIdCertificateProp(line);
		}
		if (typeInfo.equals("dati Eve Nonce ")) {
			faceEve.setOpacity(1);
			lineaEve.setOpacity(1);
			eve.addNonce(line);
		}
		if (typeInfo.equals("dati Eve Signature Pub Key ")) {
			faceEve.setOpacity(1);
			lineaEve.setOpacity(1);
			eve.addSignaturePubKey(line);
		}
		if (typeInfo.equals("dati Eve Signature Priv Key ")) {
			faceEve.setOpacity(1);
			lineaEve.setOpacity(1);
			eve.addSignaturePrivKey(line);
		}
		if (typeInfo.equals("dati Eve Tag ")) {
			faceEve.setOpacity(1);
			lineaEve.setOpacity(1);
			eve.addTag(line);
		}
		if (typeInfo.equals("dati Eve Timestamp ")) {
			faceEve.setOpacity(1);
			lineaEve.setOpacity(1);
			eve.addTimestamp(line);
		}
		if (typeInfo.equals("dati Eve Digest ")) {
			faceEve.setOpacity(1);
			lineaEve.setOpacity(1);
			eve.addDigest(line);
		}
		if (typeInfo.equals("dati Eve KnowAcq ")) {
			eve.addKnowAcq(line.substring(0,line.indexOf("-")-1),line.substring(line.indexOf("-")+2,line.length() ));
			System.out.println("------------> know acq :" + (line.substring(0,line.indexOf("-")-1) + ": -- :" + line.substring(line.indexOf("-")+2,line.length() ))+ ":");
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
		if (typeInfo.equals("dati Server Hash ")) {
			faceServer.setOpacity(1);
			lineaServer.setOpacity(1);
			server.addHashKey(line);
		}
		if (typeInfo.equals("dati Server Bitstring ")) {
			faceServer.setOpacity(1);
			lineaServer.setOpacity(1);
			server.addBitstring(line);
		}
		if (typeInfo.equals("dati Server IdCertificate ")) {
			faceServer.setOpacity(1);
			lineaServer.setOpacity(1);
			server.addIdCertificate(line);
		}
		if (typeInfo.equals("dati Server IdCertificatProp ")) {
			faceServer.setOpacity(1);
			lineaServer.setOpacity(1);
			server.addIdCertificateProp(line);
		}
		if (typeInfo.equals("dati Server Nonce ")) {
			faceServer.setOpacity(1);
			lineaServer.setOpacity(1);
			server.addNonce(line);
		}
		if (typeInfo.equals("dati Server Signature Pub Key ")) {
			faceServer.setOpacity(1);
			lineaServer.setOpacity(1);
			server.addSignaturePubKey(line);
		}
		if (typeInfo.equals("dati Server Signature Priv Key ")) {
			faceServer.setOpacity(1);
			lineaServer.setOpacity(1);
			server.addSignaturePrivKey(line);
		}
		if (typeInfo.equals("dati Server Tag ")) {
			faceServer.setOpacity(1);
			lineaServer.setOpacity(1);
			server.addTag(line);
		}
		if (typeInfo.equals("dati Server Timestamp ")) {
			faceServer.setOpacity(1);
			lineaServer.setOpacity(1);
			server.addTimestamp(line);
		}
		if (typeInfo.equals("dati Server Digest ")) {
			faceServer.setOpacity(1);
			lineaServer.setOpacity(1);
			server.addDigest(line);
		}
		if (typeInfo.equals("dati Server KnowAcq ")) {
			server.addKnowAcq(line.substring(0,line.indexOf("-")-1),line.substring(line.indexOf("-")+2,line.length() ));
			System.out.println("------------> know acq :" + (line.substring(0,line.indexOf("-")-1) + ": -- :" + line.substring(line.indexOf("-")+2,line.length() ))+ ":");
		}

		
		if (typeInfo.equals("dati Messaggi ")) {
			//se � stata completata la fase di definizione delle varie chiavi per tutti gli attori, abilita il button + per inserire i messaggi 		
//			if (faceAlice.getOpacity() == 1 &&
//				faceBob.getOpacity() == 1 &&
//			//	faceEve.getOpacity() == 1 && 
//				(faceServer.getOpacity() == 1 || tool.getText().contains("Enable"))){
				viewLine("01");
//			}
		}
		if (typeInfo.contains("dati Messaggio")) {
				// se esiste almeno un messaggio si cambia il colore (opacit�) dei disegni degli attori e si 
				// visualizzano i pulsanti + per inserire i messaggi
				faceAlice.setOpacity(1);
				lineaAlice.setOpacity(1);
				faceBob.setOpacity(1);
				lineaBob.setOpacity(1);
				faceEve.setOpacity(1);
				lineaEve.setOpacity(1);
				faceServer.setOpacity(1);
				lineaServer.setOpacity(1);
				
				numMessage = Integer.parseInt(typeInfo.substring(15, typeInfo.length()));
				if (line.contains("NameMess ")){
					messages.getListMessages()[numMessage].setNameMess(line.substring(9, line.length()));
				}
				if (line.contains("ActorFrom ")){
					messages.getListMessages()[numMessage].setActorFrom(line.substring(10, line.length()));
				}
				if (line.contains("ActorTo ")){
					messages.getListMessages()[numMessage].setActorTo(line.substring(8, line.length()));
				}
				if (line.contains("Eve Intercept ")){
					messages.getListMessages()[numMessage].setEvesIntercept(Boolean.valueOf(line.substring(14, line.length())));
					eveIntercept = Boolean.valueOf(line.substring(14, line.length()));
				}
				if (line.contains("Messages ")){
					messages.getListMessages()[numMessage].setPayload(line.substring(9, line.length()));
					viewSetLine(messages.getListMessages()[numMessage].getActorTo(),messages.getListMessages()[numMessage].getActorfrom(),numMessage,numMessagePrec);
					numMessagePrec = numMessage;
				}
		}
		if (typeInfo.contains("dati SecurityFunctionsPartMessage j=")) {
			messages.getListMessages()[numMessage].addSecurityFunctionsPartMessage(line);		
		}
		if (typeInfo.contains("dati listPartMessage j=")) {
			int j = Integer.parseInt(typeInfo.substring(23, 25).replace(" ", ""));
			int k= Integer.parseInt(typeInfo.substring(26, typeInfo.length()).replace("k=", "").replace("=", "").replace(" ",""));
			messages.getListMessages()[numMessage].addListPartMessage(line, k);		
		}
		if (typeInfo.equals("dati Properties ")) {
			if (line.contains("TAB =")) {
				int tab=Integer.valueOf(line.substring(5, 6));
				confProp.updListNameTab(tab,line.substring(7, line.length()), "");
			 	if (tab >2) {
			 		tabProprieities.getTabs().add(tabProprieities.getTabs().size() - 1, tabTb[tab]);	
			 		tabTb[tab].setText(line.substring(7, line.length()));
			 	}
			 	if (tab >6) {tabProprieities.getTabs().remove(8);};
			}
			if (line.contains("COL =")) {
				int tab=Integer.valueOf(line.substring(5, 6));
				int col=Integer.valueOf(line.substring(6, 7));
				confProp.setElePropertisValue(line.substring(8, line.length()), tab,col);
				insertEleProperties(proprlistProprietiesTb[tab], line.substring(8, line.length()), col,tab);

			}
		}
	}
// si visualizzano i pulsanti e la linea del messaggio presente sul file
	private void viewSetLine(String actorToMsg,String  actorFromMsg , int numLineMessage, int numMessagePrec) {
		node1 =aliceButton01;
		node2 =bobButton01;
		node3 =eveButton01;
		node4 =serverButton01; 
		nodeNext1 =null;
		nodeNext2 =null;
		nodeNext3 =null;
		nodeNext4 =null;
		line = line01;
		msg = msg01;
		msf = msf01;
		int riga = numLineMessage +1 ;
		int rigaSuccessiva = numLineMessage + 2;

		for (Node nodeAppo : ancorPulsanti.getChildren()) {
			if (nodeAppo != null && nodeAppo instanceof Button) {
				if (riga == Integer.valueOf(((Button) nodeAppo).getId().substring(((Button) nodeAppo).getId().length() - 2))) {
					if (((Button) nodeAppo).getId().contains("alice")) {
						node1 = nodeAppo;
					}
					if (((Button) nodeAppo).getId().contains("bob")) {
						node2 = nodeAppo;
					}
					if (((Button) nodeAppo).getId().contains("eve")) {
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
			
			if (nodeAppo != null && nodeAppo instanceof TextFlow) {
				if (riga == Integer.valueOf(((TextFlow) nodeAppo).getId().substring(((TextFlow) nodeAppo).getId().length() - 2))
						&& ((TextFlow) nodeAppo).getId().contains("msg")  ) {
						msg = nodeAppo;
				}
				if (riga == Integer.valueOf(((TextFlow) nodeAppo).getId().substring(((TextFlow) nodeAppo).getId().length() - 2))
						&& ((TextFlow) nodeAppo).getId().contains("msf")  ) {
						msf = nodeAppo;
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
						if (((Button) nodeAppo).getId().contains("eve")) {
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
		case "Eve":
			node = node3;
			break;
		case "Server":
			node = node4;
			break;
		}
		System.out.println("---------->" + actorToMsg + " " + actorFromMsg + " " + riga);
		viewSpecificLinea(actorToMsg, actorFromMsg, line,liey,livy,msg,msf,riga);
		tool.setDisable(true);
		toolEve.setDisable(true);
		serverButton.setDisable(true);
		if (tool.getText().contains("Disable")) {
			if (nodeNext1 != null && !nodeNext1.isVisible() && !nodeNext2.isVisible() && !nodeNext3.isVisible()
					&& !nodeNext4.isVisible()) {
				nodeNext1.setVisible(true);
				nodeNext2.setVisible(true);
				if (toolEve.getText().contains("Eve Doesn't Create Messages")) {
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
				if (toolEve.getText().contains("Eve Doesn't Create Messages")) {
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
			bw.write("toolEve value \n");
			bw.write(toolEve.getText() + "\n");			
			
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
			bw.write("dati Alice Hash \n");

			for (int i = 0; i < alice.getHashKey().size(); i++) {
				bw.write(alice.getHashKey().get(i) + "\n");
			}
			bw.write("dati Alice Bitstring \n");

			for (int i = 0; i < alice.getBitstring().size(); i++) {
				bw.write(alice.getBitstring().get(i) + "\n");
			}

			bw.write("dati Alice IdCertificate \n");

			for (int i = 0; i < alice.getIdCertificate().size(); i++) {
				bw.write(alice.getIdCertificate().get(i) + "\n");
			}
			bw.write("dati Alice IdCertificatProp \n");

			for (int i = 0; i < alice.getIdCertificateProp().size(); i++) {
				bw.write(alice.getIdCertificateProp().get(i) + "\n");
			}
			bw.write("dati Alice Nonce \n");

			for (int i = 0; i < alice.getNonce().size(); i++) {
				bw.write(alice.getNonce().get(i) + "\n");
			}
			bw.write("dati Alice Signature Pub Key \n");

			for (int i = 0; i < alice.getSignaturePubKey().size(); i++) {
				bw.write(alice.getSignaturePubKey().get(i) + "\n");
			}
			bw.write("dati Alice Signature Priv Key \n");

			for (int i = 0; i < alice.getSignaturePrivKey().size(); i++) {
				bw.write(alice.getSignaturePrivKey().get(i) + "\n");
			}
			bw.write("dati Alice Tag \n");

			for (int i = 0; i < alice.getTag().size(); i++) {
				bw.write(alice.getTag().get(i) + "\n");
			}
			bw.write("dati Alice Timestamp \n");

			for (int i = 0; i < alice.getTimestamp().size(); i++) {
				bw.write(alice.getTimestamp().get(i) + "\n");
			}
			bw.write("dati Alice Digest \n");

			for (int i = 0; i < alice.getDigest().size(); i++) {
				bw.write(alice.getDigest().get(i) + "\n");
			}
			bw.write("dati Alice KnowAcq \n");
			System.out.println("alice.getKnowAcq");
			for (int i = 0; i < alice.getKnowAcq().size(); i++) {
				bw.write(alice.getKnowAcq().get(i) + "\n");
			}
			System.out.println("fin alice.getKnowAcq");

			
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
			bw.write("dati Bob Hash \n");

			for (int i = 0; i < bob.getHashKey().size(); i++) {
				bw.write(bob.getHashKey().get(i) + "\n");
			}
			bw.write("dati Bob Bitstring \n");

			for (int i = 0; i < bob.getBitstring().size(); i++) {
				bw.write(bob.getBitstring().get(i) + "\n");
			}

			bw.write("dati Bob IdCertificate \n");

			for (int i = 0; i < bob.getIdCertificate().size(); i++) {
				bw.write(bob.getIdCertificate().get(i) + "\n");
			}
			bw.write("dati Bob IdCertificatProp \n");

			for (int i = 0; i < bob.getIdCertificateProp().size(); i++) {
				bw.write(bob.getIdCertificateProp().get(i) + "\n");
			}
			bw.write("dati Bob Nonce \n");

			for (int i = 0; i < bob.getNonce().size(); i++) {
				bw.write(bob.getNonce().get(i) + "\n");
			}
			bw.write("dati Bob Signature Pub Key \n");

			for (int i = 0; i < bob.getSignaturePubKey().size(); i++) {
				bw.write(bob.getSignaturePubKey().get(i) + "\n");
			}
			bw.write("dati Bob Signature Priv Key \n");

			for (int i = 0; i < bob.getSignaturePrivKey().size(); i++) {
				bw.write(bob.getSignaturePrivKey().get(i) + "\n");
			}
			bw.write("dati Bob Tag \n");

			for (int i = 0; i < bob.getTag().size(); i++) {
				bw.write(bob.getTag().get(i) + "\n");
			}
			bw.write("dati Bob Timestamp \n");

			for (int i = 0; i < bob.getTimestamp().size(); i++) {
				bw.write(bob.getTimestamp().get(i) + "\n");
			}
			bw.write("dati Bob Digest \n");

			for (int i = 0; i < bob.getDigest().size(); i++) {
				bw.write(bob.getDigest().get(i) + "\n");
			}
			System.out.println("bob.getKnowAcq");
			bw.write("dati Bob KnowAcq \n");
			for (int i = 0; i < bob.getKnowAcq().size(); i++) {
				bw.write(bob.getKnowAcq().get(i) + "\n");
			}
			System.out.println("fin bob.getKnowAcq");
			
			bw.write("dati Eve AsymmetricPublicKey \n");

			for (int i = 0; i < eve.getAsymmetricPublicKey().size(); i++) {
				bw.write(eve.getAsymmetricPublicKey().get(i) + "\n");
			}
			bw.write("dati Eve AsymmetricPrivateKey \n");

			for (int i = 0; i < eve.getAsymmetricPrivateKey().size(); i++) {
				bw.write(eve.getAsymmetricPrivateKey().get(i) + "\n");
			}
			bw.write("dati Eve SymmetricKey \n");

			for (int i = 0; i < eve.getSymmetricKey().size(); i++) {
				bw.write(eve.getSymmetricKey().get(i) + "\n");
			}
			bw.write("dati Eve Hash \n");

			for (int i = 0; i < eve.getHashKey().size(); i++) {
				bw.write(eve.getHashKey().get(i) + "\n");
			}
			bw.write("dati Eve Bitstring \n");

			for (int i = 0; i < eve.getBitstring().size(); i++) {
				bw.write(eve.getBitstring().get(i) + "\n");
			}

			bw.write("dati Eve IdCertificate \n");

			for (int i = 0; i < eve.getIdCertificate().size(); i++) {
				bw.write(eve.getIdCertificate().get(i) + "\n");
			}
			bw.write("dati Eve IdCertificatProp \n");

			for (int i = 0; i < eve.getIdCertificateProp().size(); i++) {
				bw.write(eve.getIdCertificateProp().get(i) + "\n");
			}
			bw.write("dati Eve Nonce \n");

			for (int i = 0; i < eve.getNonce().size(); i++) {
				bw.write(eve.getNonce().get(i) + "\n");
			}
			bw.write("dati Eve Signature Pub Key \n");

			for (int i = 0; i < eve.getSignaturePubKey().size(); i++) {
				bw.write(eve.getSignaturePubKey().get(i) + "\n");
			}
			bw.write("dati Eve Signature Priv Key \n");

			for (int i = 0; i < eve.getSignaturePrivKey().size(); i++) {
				bw.write(eve.getSignaturePrivKey().get(i) + "\n");
			}
			bw.write("dati Eve Tag \n");

			for (int i = 0; i < eve.getTag().size(); i++) {
				bw.write(eve.getTag().get(i) + "\n");
			}
			bw.write("dati Eve Timestamp \n");

			for (int i = 0; i < eve.getTimestamp().size(); i++) {
				bw.write(eve.getTimestamp().get(i) + "\n");
			}
			bw.write("dati Eve Digest \n");

			for (int i = 0; i < eve.getDigest().size(); i++) {
				bw.write(eve.getDigest().get(i) + "\n");
			}
			System.out.println("ve.getKnowAcq");
			bw.write("dati Eve KnowAcq \n");
			for (int i = 0; i < eve.getKnowAcq().size(); i++) {
				bw.write(eve.getKnowAcq().get(i) + "\n");
			}
			System.out.println("fin eve.getKnowAcq");
			
			
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
			bw.write("dati Server Hash \n");

			for (int i = 0; i < server.getHashKey().size(); i++) {
				bw.write(server.getHashKey().get(i) + "\n");
			}
			bw.write("dati Server Bitstring \n");

			for (int i = 0; i < server.getBitstring().size(); i++) {
				bw.write(server.getBitstring().get(i) + "\n");
			}

			bw.write("dati Server IdCertificate \n");

			for (int i = 0; i < server.getIdCertificate().size(); i++) {
				bw.write(server.getIdCertificate().get(i) + "\n");
			}
			bw.write("dati Server IdCertificatProp \n");

			for (int i = 0; i < server.getIdCertificateProp().size(); i++) {
				bw.write(server.getIdCertificateProp().get(i) + "\n");
			}
			bw.write("dati Server Nonce \n");

			for (int i = 0; i < server.getNonce().size(); i++) {
				bw.write(server.getNonce().get(i) + "\n");
			}
			bw.write("dati Server Signature Pub Key \n");

			for (int i = 0; i < server.getSignaturePubKey().size(); i++) {
				bw.write(server.getSignaturePubKey().get(i) + "\n");
			}
			bw.write("dati Server Signature Priv Key \n");

			for (int i = 0; i < server.getSignaturePrivKey().size(); i++) {
				bw.write(server.getSignaturePrivKey().get(i) + "\n");
			}
			bw.write("dati Server Tag \n");

			for (int i = 0; i < server.getTag().size(); i++) {
				bw.write(server.getTag().get(i) + "\n");
			}
			bw.write("dati Server Timestamp \n");

			for (int i = 0; i < server.getTimestamp().size(); i++) {
				bw.write(server.getTimestamp().get(i) + "\n");
			}
			bw.write("dati Server Digest \n");

			for (int i = 0; i < server.getDigest().size(); i++) {
				bw.write(server.getDigest().get(i) + "\n");
			}
			bw.write("dati Server KnowAcq \n");
			System.out.println("fin server.getKnowAcq");
			for (int i = 0; i < server.getKnowAcq().size(); i++) {
				bw.write(server.getKnowAcq().get(i) + "\n");
			}
			System.out.println("fin server.getKnowAcq");
			
			bw.flush();
			bw.write("dati Messaggi \n");
			if (aliceButton01.isVisible() && aliceButton01.getText().equals("+")) {
				bw.write("+ \n");
			}
				

			for (int i = 0; i < 15; i++) {
				if (!messages.getListMessages()[i].getActorfrom().isEmpty()) {
					bw.write("dati Messaggio " + i + "\n");
					bw.write("NameMess " + messages.getListMessages()[i].getNameMess() + "\n");
					bw.write("ActorFrom " + messages.getListMessages()[i].getActorfrom() + "\n");
					bw.write("ActorTo " + messages.getListMessages()[i].getActorTo() + "\n");
					bw.write("Eve Intercept " + messages.getListMessages()[i].getEvesIntercept() + "\n");
					bw.write("Messages " + messages.getListMessages()[i].getPayload() + "\n");
					bw.flush();
					for (int j = 0; j < 15; j++) {
						//� importante prima inserire i dati dall'array SecurityFunctionsPartMessage prima delle parti del messsaggio
						if (messages.getListMessages()[i].getSecurityFunctionsPartMessage(j) != null) {
							bw.write("dati SecurityFunctionsPartMessage j=" + j + "\n");
							bw.write(messages.getListMessages()[i].getSecurityFunctionsPartMessage(j) + "\n");
						}						
						for (int k = 0; k < 15; k++) {
							if (messages.getListMessages()[i].getListPartMessage()[j][k] != null) {
								if (!messages.getListMessages()[i].getListPartMessage()[j][k].isEmpty()) {
									bw.write("dati listPartMessage j=" + j + " k=" + k + "\n");
									bw.write(messages.getListMessages()[i].getListPartMessage()[j][k] + "\n");
									bw.flush();
								}
							}
						}

					}
				}
				
			}
			bw.flush();
			bw.write("dati Properties \n");
			for (int i = 0; i < 10; i++) {
				if (!(confProp.getListNameTab(i)== null || confProp.getListNameTab(i).isEmpty())) {
					bw.write("TAB =" + i + " " + confProp.getListNameTab(i)+ "\n");			
					for (int j = 0; j < 10; j++) {
						if (!(confProp.getProprietiesValue(i, j)== null || confProp.getProprietiesValue(i, j).isEmpty())) {
							bw.write("COL =" +i+ j + " " + confProp.getProprietiesValue(i, j)+ "\n");
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
	
	// richiama la scrittura del file aSM	
	@FXML
	private void writeFileAsm() throws IOException {
		FXMLLoader loader = new FXMLLoader();
        loader.setLocation(getClass().getResource("/fxml/CreateFilesASM.fxml"));
        AnchorPane page = (AnchorPane) loader.load();
     
        Stage dialogStage = new Stage();
                
        dialogStage.initModality(Modality.WINDOW_MODAL);
        
        Scene scene = new Scene(page);
        dialogStage.setScene(scene);
        
        CreateFilesASM controller = loader.getController();
        controller.setDialogStage(dialogStage);
        controller.receivInfo(messages,alice,bob,eve,server,toolEve.getText(),tool.getText());
        dialogStage.showAndWait();
        
/*		if (tool.getText().contains("Enable")) {
			WriteCryptoLibrary writeCrypto = new WriteCryptoLibrary(false,messages,alice,bob,eve,null,toolEve.getText());
			WriteASM writeASM = new WriteASM(false,messages,alice,bob,eve,null,toolEve.getText(),writeCrypto.getNumEleMsg(), writeCrypto.getLevelTot(),
					writeCrypto.getNumEncField (),writeCrypto.getNumSignField(), writeCrypto.getNumSymField(),writeCrypto.getNumHashField());
		} else {
			WriteCryptoLibrary writeCrypto = new WriteCryptoLibrary(true,messages,alice,bob,eve,server,toolEve.getText());
			WriteASM writeASM = new WriteASM(true,messages,alice,bob,eve,server,toolEve.getText(),writeCrypto.getNumEleMsg(),writeCrypto.getLevelTot(),
					writeCrypto.getNumEncField (),writeCrypto.getNumSignField(), writeCrypto.getNumSymField(),writeCrypto.getNumHashField());

		}
*/
	}

	// se viene cliccato dal menu l'opzione about si visualizza il file PdF 
	@FXML
	private void about() throws IOException {
		File file = new File("src\\main\\resources\\ConfigurationFile\\Help.pdf");
		Desktop.getDesktop().open(file);
	}
	@FXML
	private void selButtonModProperties(ActionEvent e) throws Exception {

		node = (Node) e.getSource();
		
		String data = (String) node.getId();
		int col= Integer.parseInt(data.substring(data.length() - 1));
		int tab= Integer.parseInt(data.substring(data.length() - 2,data.length()-1));
		showAddProperties(tab,"UPD",col);
		
	}

}
