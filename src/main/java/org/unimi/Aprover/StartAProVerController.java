package org.unimi.Aprover;

import java.awt.Desktop;
//import java.awt.Desktop;
import java.io.File;
import java.io.IOException;
import java.net.URL;
import java.util.ArrayList;
import java.util.List;

import javafx.fxml.FXML;
import javafx.fxml.FXMLLoader;
import javafx.scene.Scene;
import javafx.scene.control.Button;
import javafx.scene.control.ComboBox;
import javafx.scene.control.ContentDisplay;
import javafx.scene.control.Label;
import javafx.scene.control.MenuItem;
import javafx.scene.control.TitledPane;
import javafx.scene.image.Image;
import javafx.scene.image.ImageView;
import javafx.scene.layout.AnchorPane;
import javafx.scene.layout.HBox;
import javafx.scene.text.Text;
import javafx.stage.FileChooser;
import javafx.stage.FileChooser.ExtensionFilter;
import javafx.stage.Modality;
import javafx.stage.Stage;

public class StartAProVerController {

	// private Sicurezza sicurezza = new Sicurezza();

	private MainApp main;

	private List<String> listFiles;

	@FXML
	private Text singleFile;

	@FXML
	private TitledPane titledAlice, titledEve, titledBob, titledServer;
	@FXML
	private Button buttonNew, buttonOld;

	@FXML
	private MenuItem tool;

	@FXML
	private Label aliceAsymmetricPublicKey, aliceAsymmetricPrivateKey, aliceSymmetricKey, aliceHash;

	@FXML

	private void selectBox2() throws Exception {

		FileChooser fc = new FileChooser();
		fc.getExtensionFilters().add(new ExtensionFilter("AProVer File", listFiles));
		File f = fc.showOpenDialog(null);
		//singleFile.setText("xxxxxxxxxxxxxxxxxxxx");

		if (f != null) {
			singleFile.setText(f.getAbsolutePath());
			selectBox1();
		}

	}

	@FXML

	private void toolSet() {
		if (tool.getText().contains("Disable")) {
			tool.setText("Enable Server");
		} else {
			tool.setText("Disable Server");
		}
	}

	@FXML

	private void selectBox1() throws Exception {

		FXMLLoader loader = new FXMLLoader();
		
		System.out.println(getClass().getResource("/fxml/SelectAProVer.fxml").toExternalForm());
		System.out.println("1");
		loader.setLocation(getClass().getResource("/fxml/SelectAProVer.fxml"));
		System.out.println("2");
        AnchorPane page = (AnchorPane) loader.load();
        System.out.println("3");
        Stage dialogStage = new Stage();
        System.out.println("4");
        dialogStage.initModality(Modality.WINDOW_MODAL);
        System.out.println("5");
        Scene scene = new Scene(page);
        System.out.println("6");
        dialogStage.setScene(scene);
        System.out.println("7");
        
        SelectAProVerController controller = loader.getController();
        System.out.println("8");
         controller.setToolStart(tool.getText());
        System.out.println("9");
         controller.setFileStart(singleFile.getText());
        dialogStage.setMaximized(true);
        //dialogStage.showAndWait();
        dialogStage.show();
        final Stage stage = (Stage) buttonOld.getScene().getWindow();
        stage.close();
        
		/*  versione del 21-03-2022
		Parent root = FXMLLoader.load(getClass().getResource("SelectAProVer.fxml"));
		Stage windows = (Stage) buttonOld.getScene().getWindow();
		windows.setScene(new Scene(root, 1400, 700));
		// windows.setFullScreen(true);
		windows.setMaximized(true);
		 */
		
		
		
		// windows.setResizable(true);
		/*
		 * Parent blah = FXMLLoader.load(getClass().getResource("StartAProVer2.fxml"));
		 * Scene scene = new Scene(blah); Stage appStage = (Stage) ((Node)
		 * event.getSource()).getScene().getWindow(); appStage.setScene(scene);
		 * appStage.show();
		 */
	}

	@FXML
	private ComboBox comboBox;

	@FXML

	private void selectClose() {
        final Stage stage = (Stage) buttonOld.getScene().getWindow();
        stage.close();
	}

	@FXML
	public void initialize() throws IOException {
		// comboBox.setValue("Alice");
		listFiles = new ArrayList<>();
		listFiles.add("*.avr");
		//listFiles.add("*.docx");
		//listFiles.add("*.DOC");
		//listFiles.add("*.DOCX");
		toolSet();
		System.out.println("a");
		HBox titleBoxAlice = new HBox();
//		ImageView immageAlice = new ImageView(new Image("../resources/styles/images/alicepiccola1.png", 0, 24, true, true));
		
		ImageView immageAlice = new ImageView(new Image(getClass().getResource("/styles/images/alicepiccola1.png").toExternalForm(),0, 24, true, true));

		titleBoxAlice.getChildren().add(immageAlice);
		titledAlice.setGraphic(titleBoxAlice);
		titledAlice.setContentDisplay(ContentDisplay.RIGHT);
		System.out.println("b");
		HBox titleBoxBob = new HBox();
		//ImageView immageBob = new ImageView(new Image("/styles/images/bobpiccola1.png", 0, 24, true, true));
		ImageView immageBob = new ImageView(new Image(getClass().getResource("/styles/images/bobpiccola1.png").toExternalForm(),0, 24, true, true));
		titleBoxBob.getChildren().add(immageBob);
		titledBob.setGraphic(titleBoxBob);
		titledBob.setContentDisplay(ContentDisplay.RIGHT);
		System.out.println("c");
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
	}

	// se viene cliccato dal men� l'opzione about si visualizza il file PdF 
	@FXML
	public void about() throws IOException {
		File file = new File("src\\main\\resources\\ConfigurationFile\\Help.pdf");
	 	Desktop.getDesktop().open(file);
	}

}
