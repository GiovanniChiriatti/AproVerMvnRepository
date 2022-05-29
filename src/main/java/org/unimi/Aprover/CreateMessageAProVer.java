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

public class CreateMessageAProVer {

	ObservableList<String> comboBoxList; 
	ObservableList<String> payloadFieldList; 
	private MainApp main;
	private Stage dialogStage;
	private String[][] oldMessagePayloadField = new String[16][16];
	private String[] oldSecurityFunction = new String[16];
	
	SecurityKey securityKey;
	Message  message;
	int numMessage,appRow,appColumn,numNodiMessagePayloadField, NumNodiSecurityFunctions;
	Node nodeTabeSecurityFunctionCurrent;
	Boolean helpFlag = true;
	
	
    @FXML
    private TextField actorFrom, msgPayload;

    @FXML
    private ComboBox actorTo;

    @FXML
    private AnchorPane initialKnowledge,msgPayloadAncorPane;

    @FXML
    private Text rowNum1,rowNum2,rowNum3,rowNum4,rowNum5,rowNum6,rowNum7, rowNum8;
    
    @FXML
    private Text textSecurityFunction;

  
    @FXML
    private GridPane tabeMessage;

    @FXML
    private GridPane tabeSecurityFunction;

    @FXML
    private Button closeButton,piuTabeMessage, menoSecurityFunction, doneButton;
    
    @FXML
    private MenuButton menuSecurityFunction;
    
    @FXML
    private TextFlow txtPreview, payloadField, payloadField2,textFlowSecurity;

    @FXML
    private CheckBox ceckPayloadField,ceckPayloadField2, evesIntercept;
//
// Routin di inizializzazione del Controller
// 

	@FXML
	public void initialize() {
		
		doneButton.setVisible(false);
		menuSecurityFunction.setVisible(false);
		numNodiMessagePayloadField= -1;
		NumNodiSecurityFunctions=-1;
	}
	
// prima di essere creata la Scene il controller precedente inizializza le informazioni di questo controller
    public void setDialogStage(Stage dialogStage) {
        this.dialogStage = dialogStage;
        
        // Set the dialog icon.
        this.dialogStage.getIcons().add(new Image("file:edit.png"));
     
        /*
           this.dialogStage.setOnCloseRequest(new EventHandler<WindowEvent>() {
            public void handle(WindowEvent we) {
            	System.out.println("Stage is closing");
            	closeWindows(null);
            }
        });
      */  
        this.dialogStage.setOnCloseRequest( 
        	    e -> { 
        	             e.consume(); 
        	             closeWindows(null); 
        	         } );
    }
    
 // prima di essere creata la Scene il controller precedente inizializza le informazioni di questo controller
 // qui viene passato il numero del messaggio quando si sta effettuando la modifica del messaggio gia creato in precedenza
 // in questo caso il controller imposta le informazioni registrate nella classe Message
    public void setMessage(int numMessage) {
    	
    	this.numMessage = numMessage;
    	
        this.actorFrom.setText(message.getActorfrom());
        this.evesIntercept.setSelected(message.getEvesIntercept());
        comboBoxList = FXCollections.observableArrayList(message.getActorTo());
        actorTo.setItems(comboBoxList);
        actorTo.getSelectionModel().selectFirst();
        evesIntercept.setDisable(true);

		for (int j = 0; j < 16; j++) {
			oldSecurityFunction[j] = "";
			if (message.getSecurityFunctionsPartMessage(j) != null
					&& !message.getSecurityFunctionsPartMessage(j).isEmpty()) {
				oldSecurityFunction[j] = message.getSecurityFunctionsPartMessage(j);
        		Node nodeVuotoSecurityFuncion = cercaNodoVuotoSecurityFuncion();
        		inserisciInSecurityFuncionPedice(nodeVuotoSecurityFuncion,oldSecurityFunction[j] );
        		NumNodiSecurityFunctions=j;
            	for (int i=0; i<16;i++) {
            		oldMessagePayloadField[j][i] = message.getListPartMessage(j, i);
            	}
			}
			if (message.getPayload().isEmpty()) {
				textFlowSecurity.getChildren().clear();
				txtPreview.getChildren().clear();
				ceckPayloadField.setSelected(false);
				ceckPayloadField.setVisible(false);
				ceckPayloadField2.setSelected(false);
				ceckPayloadField2.setVisible(false);
				payloadField.getChildren().clear();
				payloadField2.getChildren().clear();
				payloadField.setVisible(false);
				payloadField2.setVisible(false);
			} else {
				textFlowSecurity.getChildren().clear();
				txtPreview.getChildren().clear();
				ceckPayloadField.setSelected(false);
				ceckPayloadField.setVisible(true);
				ceckPayloadField2.setSelected(false);
				ceckPayloadField2.setVisible(true);
				payloadField.getChildren().clear();
				payloadField2.getChildren().clear();
				payloadField.setVisible(true);
				payloadField2.setVisible(true);
			}

			writeTxtPreview(createPreviewField());
			Node nodeLastSecurytyFunction = searchLastSecurityFuncion(NumNodiSecurityFunctions);
 			writeTextField(nodeLastSecurytyFunction);
 			
		}
 
    }
    
// prima di essere creata la Scene il controller precedente inizializza le informazioni di questo controller
// in questo caso si richiede di creare un nuovo messaggio e il controller riceve l'acctor da cui parte il messaggio
// si inizializza la combobox per la ricerca dell'actor destinatario del messaggio (nell'elenco si esclude l'actor di partenza)    
    public void setActorFrom(String actorFrom,int numMessage, String tool, String toolEve) {
        this.numMessage = numMessage;
        this.actorFrom.setText(actorFrom);
        boolean unicAcrotTo = false;
               
		if (tool.contains("Disable")) {
			if (toolEve.contains("Eve Create Messages")) {
				switch (actorFrom) {
				case "Alice":
					comboBoxList = FXCollections.observableArrayList("Bob", "Server");
					break;
				case "Bob":
					comboBoxList = FXCollections.observableArrayList("Alice", "Server");
					break;
				case "Eve":
					comboBoxList = FXCollections.observableArrayList("Alice", "Server");
					break;
				case "Server":
					comboBoxList = FXCollections.observableArrayList("Alice", "Bob");
					break;
				}
			}
		}
		if (tool.contains("Disable")) {
			if (toolEve.contains("Eve Doesn't Create Messages")) {
				switch (actorFrom) {
				case "Alice":
					comboBoxList = FXCollections.observableArrayList("Bob", "Eve", "Server");
					break;
				case "Bob":
					comboBoxList = FXCollections.observableArrayList("Alice", "Eve", "Server");
					break;
				case "Eve":
					comboBoxList = FXCollections.observableArrayList("Alice", "Bob", "Server");
					break;
				case "Server":
					comboBoxList = FXCollections.observableArrayList("Alice", "Bob", "Eve");
					break;
				}
			}
		}
		if (tool.contains("Enable")) {
			if (toolEve.contains("Eve Doesn't Create Messages")) {
				switch (actorFrom) {
				case "Alice":
					comboBoxList = FXCollections.observableArrayList("Bob", "Eve");
					break;
				case "Bob":
					comboBoxList = FXCollections.observableArrayList("Alice", "Eve");
					break;
				case "Eve":
					comboBoxList = FXCollections.observableArrayList("Alice", "Bob");
					break;
				}
			}
		}
		if (tool.contains("Enable")) {
			if (toolEve.contains("Eve Create Messages")) {
				unicAcrotTo = true;
				switch (actorFrom) {
				case "Alice":
					comboBoxList = FXCollections.observableArrayList("Bob");
					break;
				case "Bob":
					comboBoxList = FXCollections.observableArrayList("Alice");
					break;
				case "Eve":
					comboBoxList = FXCollections.observableArrayList("Alice");
					break;
				}
			}
		}
        actorTo.setItems(comboBoxList);
        if (unicAcrotTo) {
        	actorTo.getSelectionModel().selectFirst();
        }
        
    }
    
 // prima di essere creata la Scene il controller precedente inizializza le impostazioni sul cursore help che se attivato fa evidenziare le info sui singoli oggetti
     public void setHelp(Boolean inHelpFlag) {
    	 Scene sc1 = closeButton.getScene();
    	 helpFlag = inHelpFlag;
    	 if (!helpFlag) {
				sc1.setCursor(Cursor.DEFAULT);
			} else {
			 //	sc1.setCursor(Cursor.OPEN_HAND);
			 	Image image = new Image("unimi/aprover/view/questionmarcTrasparente.png");
			 	sc1.setCursor(new ImageCursor (image,
			 									image.getWidth()/2,
			 									image.getHeight() /2));
			}
    	 
     }


// prima di essere creata la Scene il controller precedente inizializza le informazioni di questo controller
// il controller chiamante passa i dati della classe SecurityKey che contiene le informazioni delle chiavi di sicurezza possedute 
// dall'actor che invia il messaggio e l'elenco di tutti i  messaggi    
// in questo metodo si costruisce il men� per la visualizzazione delle security function
    public void setInfo(SecurityKey securityKey, Message message) {

    	this.securityKey = securityKey;
    	this.message = message;
    	
    	textFlowSecurity.getChildren().clear();
    	
    	if (securityKey.getAsymmetricPublicKey() !=null && !securityKey.getAsymmetricPublicKey().isEmpty() ) {
    		Menu menu = new Menu();
            prepareMenuItem(menu, "Asymmetric Encryption", menuSecurityFunction);
            MenuItem subMenuItem;
            for (int i=0; i< securityKey.getAsymmetricPublicKey().size(); i++) {
            	subMenuItem = new MenuItem(securityKey.getAsymmetricPublicKey().get(i));
            	String a = securityKey.getAsymmetricPublicKey().get(i);
            	subMenuItem.setOnAction(new EventHandler<ActionEvent>() {
                    public void handle(ActionEvent t) {
                    	AddPartSecurityMessage(a);
                    }
                });
            	menu.getItems().add(subMenuItem);
            }
            menuSecurityFunction.getItems().addAll(menu);
    	}
       	if (securityKey.getSymmetricKey() !=null && !securityKey.getSymmetricKey().isEmpty()) {
    		Menu menu = new Menu();
            prepareMenuItem(menu, "Symmetric Encryption", menuSecurityFunction);
            MenuItem subMenuItem;
            for (int i=0; i< securityKey.getSymmetricKey().size(); i++) {
            	subMenuItem = new MenuItem(securityKey.getSymmetricKey().get(i));
            	String a = securityKey.getSymmetricKey().get(i);
            	subMenuItem.setOnAction(new EventHandler<ActionEvent>() {
            		public void handle(ActionEvent t) {
            			AddPartSecurityMessage(a);
                    }
                });
            	menu.getItems().add(subMenuItem); 	
            }
            menuSecurityFunction.getItems().addAll(menu);
    	}
       	if (securityKey.getAsymmetricPrivateKey() !=null && !securityKey.getAsymmetricPrivateKey().isEmpty()) {
       		Menu menu = new Menu();
            prepareMenuItem(menu, "Signature", menuSecurityFunction);
            MenuItem subMenuItem;
            for (int i=0; i< securityKey.getAsymmetricPrivateKey().size(); i++) {
            	subMenuItem = new MenuItem(securityKey.getAsymmetricPrivateKey().get(i));
            	String a = securityKey.getAsymmetricPrivateKey().get(i);
            	subMenuItem.setOnAction(new EventHandler<ActionEvent>() {
            		public void handle(ActionEvent t) {
            			AddPartSecurityMessage(a);
                    }
                });
            	menu.getItems().add(subMenuItem);       	
            }
            menuSecurityFunction.getItems().addAll(menu);
    	}
       	if (securityKey.getHashKey() !=null && !securityKey.getHashKey().isEmpty()) {
       		Menu menu = new Menu();
            prepareMenuItem(menu, "Hash", menuSecurityFunction);
            MenuItem subMenuItem;
            for (int i=0; i< securityKey.getHashKey().size(); i++) {
            	subMenuItem = new MenuItem(securityKey.getHashKey().get(i));
            	String a = securityKey.getHashKey().get(i);
            	subMenuItem.setOnAction(new EventHandler<ActionEvent>() {
            		public void handle(ActionEvent t) {
            			AddPartSecurityMessage(a);
                    }
                });
            	menu.getItems().add(subMenuItem);       	
            }
            menuSecurityFunction.getItems().addAll(menu);
    	}
       	
		txtPreview.getChildren().clear();
		textFlowSecurity.getChildren().clear();
		ceckPayloadField.setSelected(false);
		ceckPayloadField.setVisible(false);
		ceckPayloadField2.setSelected(false);
		ceckPayloadField2.setVisible(false);
		payloadField.getChildren().clear();
		payloadField2.getChildren().clear();
		payloadField.setVisible(false);
		payloadField2.setVisible(false);

    }

	private void AddPartSecurityMessage(String messaggioSecurity) {
		
		Node nodeLastSecurytyFunction = searchLastMsgSecurityFuncion();
		Node nodePedice = null;
		Node nodePedice2 = null;
		if (nodeLastSecurytyFunction != null) {
			for (Node node : ((TextFlow) nodeLastSecurytyFunction).getChildren()) {
				if (((Text) node).getTranslateY() > 0) {
					nodePedice = node;
				} else {
					nodePedice = null;
				}
			}
			for (Node node : ((TextFlow) textFlowSecurity).getChildren()) {
				if (((Text) node).getTranslateY() > 0) {
					nodePedice2 = node;
				} else {
					nodePedice2 = null;
				}
			}
			if (nodePedice != null) {
				messaggioSecurity = ((((Text) nodePedice).getText()) + "," + messaggioSecurity);
				((Text) nodePedice).setText(messaggioSecurity);
				((Text) nodePedice2).setText(messaggioSecurity);
			} else {
				Text normal = new Text("normal");
				Text sub = new Text(messaggioSecurity);
				sub.setTranslateY(normal.getFont().getSize() * 0.3);
				((TextFlow) nodeLastSecurytyFunction).getChildren().add(sub);
				Text sub2 = new Text(messaggioSecurity);
				sub2.setTranslateY(normal.getFont().getSize() * 0.3);
				((TextFlow) textFlowSecurity).getChildren().add(sub2);
			}
		}
	}
    private void prepareMenuItem(MenuItem menuItem, String text, MenuButton menuButton){
        Label label = new Label();
        label.prefWidthProperty().bind(menuButton.widthProperty());
        label.setText(text);
        label.setTextAlignment(TextAlignment.RIGHT);
        menuItem.setGraphic(label);
    }
    

    public String getActorTo() {
    	    	
    	if (actorTo.getValue()== null) {
    		return "";
    	}

    	return actorTo.getValue().toString();
    }
    public Boolean getEvesIntercept() {
 	
    	return evesIntercept.isSelected();
    }
    @FXML
    private void acotrToSelect() {
    	String actorFromAppo = actorFrom.getText();    	
    	message.setActorTo(actorTo.getValue().toString());
    	message.setActorFrom(actorFrom.getText());
    	message.setEvesIntercept(evesIntercept.isSelected());
    }
    
// metodo attivato quando si preme il button "+" presente nel "message Payload Filed
// vengono trasferiti i vari campi all'interno dell'elenco del "Security Functions"
    @FXML 
    public void piuTabeMessage(){
// ricerca il primo spazio vuoto della tabella "Security Functions"
    	Node nodeVuotoSecurityFuncion = cercaNodoVuotoSecurityFuncion();
    	boolean primoTesto= true;
    	String appMessage ="";

//  
    	NumNodiSecurityFunctions++;
    	numNodiMessagePayloadField = 0;
		if (ceckPayloadField.isSelected()) {
			oldMessagePayloadField[NumNodiSecurityFunctions][numNodiMessagePayloadField]= ("(payloadField)");
			primoTesto = false;
			inserisciOldMesage(nodeVuotoSecurityFuncion,payloadField,numNodiMessagePayloadField);
			numNodiMessagePayloadField ++;
		}
		if (ceckPayloadField2.isSelected()) {
			oldMessagePayloadField[NumNodiSecurityFunctions][numNodiMessagePayloadField]= ("(payloadField2)");
			primoTesto = false;
			inserisciOldMesage(nodeVuotoSecurityFuncion,payloadField2,numNodiMessagePayloadField);
			numNodiMessagePayloadField ++;
		}
    	
    	for (Node node : tabeMessage.getChildren()) {
    		if (node !=null && node instanceof TextField && !((TextField) node).getText().isEmpty()) {
     			oldMessagePayloadField[NumNodiSecurityFunctions][numNodiMessagePayloadField]= ((TextField) node).getText().replaceAll(" ","");
    			numNodiMessagePayloadField ++;
    			if (primoTesto) {
    				primoTesto = false;
    				appMessage =  "{" + ((TextField) node).getText().replaceAll(" ","");
    			}else {
    				appMessage =  ","+ ((TextField) node).getText().replaceAll(" ","");
    			}
    			inserisciInSecurityFuncion(nodeVuotoSecurityFuncion,appMessage);
    		}
		}
    	if (!primoTesto){
    		appMessage =  "} ";
    		inserisciInSecurityFuncion(nodeVuotoSecurityFuncion,appMessage);
    		cleanTabeMessage();
    		piuTabeMessage.setVisible(false);
    		doneButton.setVisible(true);
    		menuSecurityFunction.setVisible(true);
    		textFlowSecurity.setVisible(true);
    		
    	}
    	System.out.println("----------elenco valori tabella----------" + NumNodiSecurityFunctions);
    	for (int i=0; i<oldMessagePayloadField[NumNodiSecurityFunctions].length; i++) {
    		System.out.println(oldMessagePayloadField[NumNodiSecurityFunctions] [i]);
    	}
    }
    
    private Node cercaNodoVuotoSecurityFuncion() {
    	for (Node node : tabeSecurityFunction.getChildren()) {
    		
	        if (node !=null && node instanceof TextFlow && ((TextFlow) node).getChildren().isEmpty()) {
	        	return node;
	        }
	    }
    	return null;
    	
    }
    private void inserisciOldMesage(Node node1, TextFlow appayloadField, int numNodiMessagePayloadField) {
 
    	inserisciInSecurityFuncion(node1,"{");
    	for (Node node : appayloadField.getChildren()) {
			if (node !=null && node instanceof Text && !((Text) node).getText().isEmpty()) {
				if (((Text)node).getTranslateY() > 0){
					Text normal = new Text("normal");
					Text sub = new Text (((Text) node).getText().toString());
					Text sub2 = new Text (((Text) node).getText().toString());
					sub.setTranslateY(normal.getFont().getSize() * 0.3);
					sub2.setTranslateY(normal.getFont().getSize() * 0.3);
					((TextFlow)node1).getChildren().add(sub);
					textFlowSecurity.getChildren().add(sub2);
	    			oldMessagePayloadField[NumNodiSecurityFunctions][numNodiMessagePayloadField] = oldMessagePayloadField[NumNodiSecurityFunctions][numNodiMessagePayloadField] + " - " + (((Text) node).getText()) +  " - ";
	    		} else {
	    			Text sub = new Text (((Text) node).getText().toString());
	    			Text sub2 = new Text (((Text) node).getText().toString());
					((TextFlow)node1).getChildren().add(sub);
					textFlowSecurity.getChildren().add(sub2);
	    			oldMessagePayloadField[NumNodiSecurityFunctions][numNodiMessagePayloadField] = oldMessagePayloadField[NumNodiSecurityFunctions][numNodiMessagePayloadField]  + (((Text) node).getText());
	    		}
			}
		}
    }
    private void inserisciInSecurityFuncion(Node node, String appMessage) {

    	if (node == null) {
    		return;
    	}
    	Text normal = new Text(appMessage);
    	Text normal2 = new Text(appMessage);
     	((TextFlow)node).getChildren().add(normal);
     	textFlowSecurity.getChildren().add(normal2);
    }
    private void inserisciInSecurityFuncionPedice(Node node1, String appMessage) {
    	if (node1 == null) {
    		return;     	}
    	
    	Text normal = new Text(appMessage);
    	boolean pedice = false;
    	boolean primoTrattino = true;
    	int str = appMessage.length();
    	String stringOut = "";
    	
		for(int i= 0; i < str; i++){
			if(appMessage.charAt(i) != '-') {
				stringOut = stringOut + appMessage.charAt(i);
			}
			if(appMessage.charAt(i) == '-') {
				if (primoTrattino) {
					inserisciInSecurityFuncion(node1,stringOut.replaceAll(" ",""));
					primoTrattino=false;
					stringOut="";
				} else {
					primoTrattino=true;
			    	Text sub = new Text(stringOut.replaceAll(" ",""));
			    	sub.setTranslateY(normal.getFont().getSize() * 0.3);
			    	((TextFlow)node1).getChildren().addAll(sub);
					stringOut="";
				}
			}
		}
		if (!stringOut.isEmpty()) {
			inserisciInSecurityFuncion(node1,stringOut.replaceAll(" ",""));
		}
    }  
	private void cleanTabeMessage() {
		ceckPayloadField.setSelected(false);
		ceckPayloadField.setVisible(false);
		ceckPayloadField2.setSelected(false);
		ceckPayloadField2.setVisible(false);
		payloadField.getChildren().clear();
		payloadField2.getChildren().clear();
		payloadField.setVisible(false);
		payloadField2.setVisible(false);
		for (Node node : tabeMessage.getChildren()) {
			if (node !=null && node instanceof TextField && !((TextField) node).getText().isEmpty()) {
				((TextField) node).setText("");
			}
		}
	}
	@FXML
	private void menoSecurityFunction() {
	piuTabeMessage.setVisible(true);
		doneButton.setVisible(false);
		menuSecurityFunction.setVisible(false);
		numNodiMessagePayloadField = -1;
		textFlowSecurity.getChildren().clear();
		if (NumNodiSecurityFunctions >= 0) {
			cleanTabeMessage();
			int i = 0;
			if (oldMessagePayloadField[NumNodiSecurityFunctions][i] != null && oldMessagePayloadField[NumNodiSecurityFunctions][i].contains("(payloadField)")) {
				Text str = new Text(oldMessagePayloadField[NumNodiSecurityFunctions][i].replaceAll("(payloadField)", ""));
				payloadField.getChildren().add(str);
				ceckPayloadField.setSelected(true);
				ceckPayloadField.setVisible(true);
				ceckPayloadField2.setSelected(false);
				ceckPayloadField2.setVisible(true);
				oldMessagePayloadField[NumNodiSecurityFunctions][i]="";
				numNodiMessagePayloadField++;
				i=1;
			}
			if (oldMessagePayloadField[NumNodiSecurityFunctions][i] != null && oldMessagePayloadField[NumNodiSecurityFunctions][i].contains("(payloadField2)")) {
				Text str = new Text(oldMessagePayloadField[NumNodiSecurityFunctions][i].replaceAll("(payloadField2)", ""));
				payloadField2.getChildren().add(str);
				ceckPayloadField.setSelected(false);
				ceckPayloadField.setVisible(true);
				ceckPayloadField2.setSelected(true);
				ceckPayloadField2.setVisible(true);
				oldMessagePayloadField[NumNodiSecurityFunctions][i]="";
				numNodiMessagePayloadField++;
				i=1;
			}
			for (Node node1 : tabeMessage.getChildren()) {
				if (i < 16 && oldMessagePayloadField[NumNodiSecurityFunctions][i] != null
						&& !oldMessagePayloadField[NumNodiSecurityFunctions][i].isEmpty()) {
					if (node1 != null && node1 instanceof TextField) {
						((TextField) node1).setText(oldMessagePayloadField[NumNodiSecurityFunctions][i]);
						oldMessagePayloadField[NumNodiSecurityFunctions][i]="";
						i++;
						numNodiMessagePayloadField++;
					}
				}
			}
			Node nodeLastSecurytyFunction = searchLastSecurityFuncion(NumNodiSecurityFunctions);
			if (nodeLastSecurytyFunction != null) {
				message.remSecurityFunctionsPartMessage();
				((TextFlow) nodeLastSecurytyFunction).getChildren().clear();
				NumNodiSecurityFunctions--;
				if (NumNodiSecurityFunctions >= 0) {
					
					ceckPayloadField.setVisible(true);
					ceckPayloadField2.setVisible(true);
					payloadField.getChildren().clear();
					payloadField2.getChildren().clear();
					payloadField.setVisible(true);
					payloadField2.setVisible(true);
					writeTxtPreview(createPreviewField());
					message.setPayload(createPreviewField());
					nodeLastSecurytyFunction = searchLastSecurityFuncion(NumNodiSecurityFunctions);
		 			writeTextField(nodeLastSecurytyFunction);
				} else {
					message.setPayload("");
					
					txtPreview.getChildren().clear();
					ceckPayloadField.setSelected(false);
					ceckPayloadField.setVisible(false);
					ceckPayloadField2.setSelected(false);
					ceckPayloadField2.setVisible(false);
					payloadField.getChildren().clear();
					payloadField2.getChildren().clear();
					payloadField.setVisible(false);
					payloadField2.setVisible(false);
				}
			}
		}
	}

    public Node searchLastMsgSecurityFuncion() {
    	Node nodeAppo = null;
    	appRow=0;
    	appColumn=0;
    	for (Node node : tabeSecurityFunction.getChildren()) {
			if (node !=null && node instanceof TextFlow && !((TextFlow) node).getChildren().isEmpty()) {
				nodeAppo = node;
				if (tabeSecurityFunction.getRowIndex(node) != null) {appRow = tabeSecurityFunction.getRowIndex(node);}
				if (tabeSecurityFunction.getColumnIndex(node) != null) {appColumn = tabeSecurityFunction.getColumnIndex(node);}
			}
		}
    	return nodeAppo;
    }
    public Node searchLastSecurityFuncion(int row) {
    	
      	int stoRow=0;
    	for (Node node : tabeSecurityFunction.getChildren()) {
    		
			if (tabeSecurityFunction.getRowIndex(node) != null) {stoRow = tabeSecurityFunction.getRowIndex(node);} else {stoRow =0;}
			
			if (node !=null && node instanceof TextFlow && row==stoRow) {
				return node;
			}
		}
    	return null;
    }    
    
    private String  setComboBoxpayloadFieldList(Node nodeLastSecurytyFunction) {
    	
    	String msgSecurityFunction ="";
    	for (Node node : ((TextFlow)nodeLastSecurytyFunction).getChildren()) {
    		if (((Text)node).getTranslateY() > 0){
    			msgSecurityFunction = msgSecurityFunction + " - " + (((Text) node).getText()) +  " - ";
    		} else {
    			msgSecurityFunction = msgSecurityFunction  + (((Text) node).getText());
    		}
    	}
    		
		return msgSecurityFunction;
    }
    @FXML 
    public void closeWindows(ActionEvent e){
    	boolean riempito = false;
    	for (Node node : tabeMessage.getChildren()) {
    		if (node !=null && node instanceof TextField && !((TextField) node).getText().isEmpty()) {
    			System.out.println("campo riempito" + ((TextField) node).getText().toString());
    			riempito = true;
    			break;
    		}
    	}
    	if (actorTo.getValue() !="" && actorTo.getValue() != null  && !riempito) {
        	message.setActorTo(actorTo.getValue().toString());
        	message.setActorFrom(actorFrom.getText());
        	message.setEvesIntercept(evesIntercept.isSelected());
    		dialogStage.close();
    		return;
    	}
    	
    	Stage stage = (Stage) dialogStage.getScene().getWindow();
    	Alert.AlertType type =  Alert.AlertType.CONFIRMATION;
    	Alert alert = new Alert(type, "");
    	alert.initModality(Modality.APPLICATION_MODAL);
    	alert.initOwner(stage);
    	
    	alert.getDialogPane().setContentText("Confirm Exit?");
		if ((actorTo.getValue() == "" || actorTo.getValue() == null) && (riempito)) {
			alert.getDialogPane()
					.setHeaderText("*- Attenction!! ActorTo not Selected -* \n *- Attenction!! Message Payload Fields not saved -*");
		} else {
			if ((actorTo.getValue() == "" || actorTo.getValue() == null)) {
				alert.getDialogPane().setHeaderText("*- Attenction!! ActorTo not Selected -*");
			} else {
				if (riempito) {
					alert.getDialogPane().setHeaderText("*- Attenction!! Message Payload Fields not saved -*");
				}
			}
		}
    	Optional<ButtonType> result  = alert.showAndWait();
    	if (result.get()== ButtonType.OK) {
    	    	dialogStage.close();
    	}
    }
    
    @FXML 
    public void doneButton(ActionEvent e){
    	
    	doneButton.setVisible(false);
    	piuTabeMessage.setVisible(true);
    	textSecurityFunction.setText("");
    	menuSecurityFunction.setVisible(false);
    	
		Node nodeLastSecurytyFunction = searchLastSecurityFuncion(NumNodiSecurityFunctions);
		String compactMessage="";
		if (nodeLastSecurytyFunction != null) {
			
			ceckPayloadField.setVisible(true);
			ceckPayloadField2.setVisible(true);
			payloadField.setVisible(true);
			payloadField2.setVisible(true);
			compactMessage = setComboBoxpayloadFieldList(nodeLastSecurytyFunction);
			System.out.println("----------> compactMessage " +compactMessage);
			message.addSecurityFunctionsPartMessage(compactMessage);
			setTabMessageListPartMessage();

		}
		
		if (NumNodiSecurityFunctions>=0) {
			
			message.setPayload(createPreviewField());
			writeTxtPreview(createPreviewField());
			nodeLastSecurytyFunction = searchLastSecurityFuncion(NumNodiSecurityFunctions);
 			writeTextField(nodeLastSecurytyFunction);
		}else {
			
			txtPreview.getChildren().clear();
			payloadField2.getChildren().clear();
			payloadField.getChildren().clear();
		}
		textFlowSecurity.getChildren().clear();
		textFlowSecurity.setVisible(false);
    }
    
    private void setTabMessageListPartMessage() {
    	for (int i=0; i<16; i++) {
    		if  (numNodiMessagePayloadField > i) {
    			message.addListPartMessage(oldMessagePayloadField[NumNodiSecurityFunctions][i], i);  
    		} else {
    			message.addListPartMessage("", i);
    		}
      	}
    }

	private String createPreviewField() {
		String compactMessageSuc = "";
		String compactMessagePrec = "";
		String compactMessageFinale = "";
		Node nodeLastSecurytyFunction;
		for (int i = 0; i <= NumNodiSecurityFunctions; i++) {
			nodeLastSecurytyFunction = searchLastSecurityFuncion(i);
			compactMessageSuc = setComboBoxpayloadFieldList(nodeLastSecurytyFunction).replaceAll(" ", "");
			compactMessageFinale = confrontaPreviewField(compactMessageFinale, compactMessageSuc, compactMessagePrec).replaceAll(" ", "");
			compactMessagePrec = compactMessageSuc;
		}
		return compactMessageFinale;
	}
	
    private String confrontaPreviewField(String compactMessageFinale, String compactMessageSuc, String compactMessagePrec) {
    	if (compactMessageSuc.contains(compactMessagePrec) && !compactMessagePrec.isEmpty() ) {
     		int partenza = compactMessageFinale.indexOf(compactMessagePrec);
    		String compactMessageAppo = compactMessageFinale.substring(0,partenza);
    		compactMessageFinale = compactMessageAppo +  compactMessageSuc;
     	} else {
    		if (compactMessageFinale.isEmpty()) {
    		compactMessageFinale = compactMessageFinale +  compactMessageSuc;
    		} else
    		{
    			compactMessageFinale = compactMessageFinale + "," + compactMessageSuc;
    		}
    	}
    	return compactMessageFinale;
    }
    private void writeTxtPreview(String compactMessageFinale) {
    	txtPreview.getChildren().clear();
    	payloadField2.getChildren().clear();
    	int endDash = compactMessageFinale.indexOf("-");
    	int startDash = 0;
    	boolean pedice = false;
    	Text normal = new Text("sub");
    	Text normal2 = new Text("sub");
    	while (endDash >0) {
    		if (pedice) {
    			Text sub = new Text(compactMessageFinale.substring(startDash+1, endDash));
		    	sub.setTranslateY(normal.getFont().getSize() * 0.3);
		    	payloadField2.getChildren().addAll(sub);
		    	Text sub2 = new Text(compactMessageFinale.substring(startDash+1, endDash));
		    	sub2.setTranslateY(normal.getFont().getSize() * 0.3);
		    	txtPreview.getChildren().addAll(sub2);
		    	startDash = endDash +1;
		    	pedice = false;
    		} else {
    			normal = new Text(compactMessageFinale.substring(startDash, endDash));
    			payloadField2.getChildren().addAll(normal);
    			normal2 = new Text(compactMessageFinale.substring(startDash, endDash));
    			txtPreview.getChildren().addAll(normal2);
    			pedice=true;
    			startDash = endDash;
    		}
    		
    		endDash = compactMessageFinale.indexOf("-", startDash+1);
    	}
    	if (startDash == 0 || !pedice) {
			normal = new Text(compactMessageFinale.substring(startDash,compactMessageFinale.length()));
			payloadField2.getChildren().addAll(normal);
			normal = new Text(compactMessageFinale.substring(startDash,compactMessageFinale.length()));
			txtPreview.getChildren().addAll(normal);
		}
    }
    
    private void writeTextField(Node node1) {

    	if (node1!=null && node1 instanceof TextFlow) {
    		int i=0;
    		String[] nodeAppo = new String[30];
    		for (Node node : ((TextFlow)node1).getChildren()) {
    			if (((Text)node).getTranslateY() > 0){
    				nodeAppo[i] = " -  " + ((Text)node).getText().toString() + " - ";
        		} else {
        			nodeAppo[i] = ((Text)node).getText().toString();
        		}
    			i++;
    		}
    		Text normal = new Text("sub");
    		for (int j=0; j<i ; j++) {
    			if (nodeAppo[j].contains(" - ")) {
    				nodeAppo[j] = nodeAppo[j].replaceAll(" - ", "");
    				Text sub = new Text(nodeAppo[j].replaceAll(" ", ""));
    		    	sub.setTranslateY(normal.getFont().getSize() * 0.3);
    		    	payloadField.getChildren().addAll(sub);
    			} else{
    				normal = new Text(nodeAppo[j].replaceAll(" ", ""));
        			payloadField.getChildren().addAll(normal);
    			}
    		}
    	}
    }
    @FXML
    public void menuSecurityFunction(MouseEvent event) {
    }
    @FXML
    public void ceckPayloadField() {
    	ceckPayloadField2.setSelected(false);
    }
    @FXML
    public void ceckPayloadField2() {
    	ceckPayloadField.setSelected(false);
    }
	//nasconde messaggio help 
	@FXML
	private void relasedHelp(MouseEvent e) throws Exception {
		msgPayload.setVisible(false);
		msgPayloadAncorPane.setVisible(false);
	}
	//messaggio help sul campo ActorTo
	@FXML
	private void helpActorToMEssage() {
		
		if (helpFlag) {

		//	msgPayloadAncorPane.setLayoutX(400);
		//	msgPayloadAncorPane.setLayoutY(70);
			
			msgPayload.setText("Selects the Target Actor of the Message");
			//writeTxtPreview("Select X for close"  );
			
			msgPayload.setVisible(true);
			msgPayloadAncorPane.setVisible(true);
		}
	}
	//messaggio help sul campo Payload
	@FXML
	private void helpPayloadMessage() {
		
		if (helpFlag) {

		//	msgPayloadAncorPane.setLayoutX(400);
		//	msgPayloadAncorPane.setLayoutY(70);
			
			msgPayload.setText("Field with the Payload Value");
			//writeTxtPreview("Select X for close"  );
			
			msgPayload.setVisible(true);
			msgPayloadAncorPane.setVisible(true);
		}
	}
	//messaggio help sul pulsante + dell'area Message Payload Fields
	@FXML
	private void helpPiuPayloadField() {
		
		if (helpFlag) {

		//	msgPayloadAncorPane.setLayoutX(400);
		//	msgPayloadAncorPane.setLayoutY(70);
			
			msgPayload.setText("Selects + for insert value to Security Function Area");
			//writeTxtPreview("Select X for close"  );
			
			msgPayload.setVisible(true);
			msgPayloadAncorPane.setVisible(true);
		}
	}
	//messaggio help sul pulsante - dell'area Security Functions
	@FXML
	private void helpMenoSecurityFunctions() {
		
		if (helpFlag) {

		//	msgPayloadAncorPane.setLayoutX(400);
		//	msgPayloadAncorPane.setLayoutY(70);
			
			msgPayload.setText("Selects - for return value to Message Payload Fields");
			//writeTxtPreview("Select X for close"  );
			
			msgPayload.setVisible(true);
			msgPayloadAncorPane.setVisible(true);
		}
	}
	//messaggio help sul pulsante - dell'area Security Functions
	@FXML
	private void helpUpdateMessage() {
		
		if (helpFlag) {

		//	msgPayloadAncorPane.setLayoutX(400);
		//	msgPayloadAncorPane.setLayoutY(70);
			
			msgPayload.setText("Selects to Store the part of the Message");
			//writeTxtPreview("Select X for close"  );
			
			msgPayload.setVisible(true);
			msgPayloadAncorPane.setVisible(true);
		}
	}
		//messaggio help sul pulsante - dell'area Security Functions
		@FXML
		private void helpFinishMessage() {
			
			if (helpFlag) {

			//	msgPayloadAncorPane.setLayoutX(400);
			//	msgPayloadAncorPane.setLayoutY(70);
				
				msgPayload.setText("Selects to Close Page");
				//writeTxtPreview("Select X for close"  );
				
				msgPayload.setVisible(true);
				msgPayloadAncorPane.setVisible(true);
			}
	}
}
