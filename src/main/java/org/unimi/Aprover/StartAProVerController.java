package org.unimi.Aprover;

import java.awt.Desktop;
import java.io.File;
import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

import javafx.collections.FXCollections;
import javafx.collections.ObservableList;
import javafx.fxml.FXML;
import javafx.fxml.FXMLLoader;
import javafx.scene.Parent;
import javafx.scene.Scene;
import javafx.scene.control.ComboBox;
import javafx.scene.control.ContentDisplay;
import javafx.scene.control.Label;
import javafx.scene.control.MenuItem;
import javafx.scene.text.Text;
import javafx.scene.control.Button;
import javafx.scene.control.TitledPane;
import javafx.scene.image.Image;
import javafx.scene.image.ImageView;
import javafx.scene.layout.AnchorPane;
import javafx.scene.layout.BorderPane;
import javafx.scene.layout.HBox;
import javafx.stage.FileChooser;
import javafx.stage.Modality;
import javafx.stage.FileChooser.ExtensionFilter;
import javafx.stage.Stage;

import org.unimi.Aprover.MainApp;

public class StartAProVerController {

	// private Sicurezza sicurezza = new Sicurezza();

	private MainApp main;

	private List<String> listFiles;

	@FXML
	private Text singleFile;

	@FXML
	private TitledPane titledAlice, titledEye, titledBob, titledServer;
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
			titledServer.setVisible(false);
		} else {
			tool.setText("Disable Server");
			titledServer.setVisible(true);
		}
	}

	@FXML

	private void selectBox1() throws Exception {

		FXMLLoader loader = new FXMLLoader();
        loader.setLocation(getClass().getResource("/fxml/SelectAProVer.fxml"));
        AnchorPane page = (AnchorPane) loader.load();
        Stage dialogStage = new Stage();
        
        dialogStage.initModality(Modality.WINDOW_MODAL);
        
        Scene scene = new Scene(page);
        
        dialogStage.setScene(scene);

        
        SelectAProVerController controller = loader.getController();
        controller.setToolStart(tool.getText());
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
	public void initialize() {
		// comboBox.setValue("Alice");
		listFiles = new ArrayList<>();
		listFiles.add("*.avr");
		//listFiles.add("*.docx");
		//listFiles.add("*.DOC");
		//listFiles.add("*.DOCX");
		System.out.println("a");
		HBox titleBoxAlice = new HBox();
		ImageView immageAlice = new ImageView(new Image("/styles/alicepiccola1.png", 0, 24, true, true));
		titleBoxAlice.getChildren().add(immageAlice);
		titledAlice.setGraphic(titleBoxAlice);
		titledAlice.setContentDisplay(ContentDisplay.RIGHT);
		System.out.println("b");
		HBox titleBoxBob = new HBox();
		ImageView immageBob = new ImageView(new Image("/styles/bobpiccola1.png", 0, 24, true, true));
		titleBoxBob.getChildren().add(immageBob);
		titledBob.setGraphic(titleBoxBob);
		titledBob.setContentDisplay(ContentDisplay.RIGHT);
		System.out.println("c");
		HBox titleBoxEye = new HBox();
		ImageView immageEye = new ImageView(new Image("/styles/eyepiccola1.png", 0, 24, true, true));
		titleBoxEye.getChildren().add(immageEye);
		titledEye.setGraphic(titleBoxEye);
		titledEye.setContentDisplay(ContentDisplay.RIGHT);

		HBox titleBoxServer = new HBox();
		ImageView immageServer = new ImageView(new Image("/styles/serverpiccola1.png", 0, 24, true, true));
		titleBoxServer.getChildren().add(immageServer);
		titledServer.setGraphic(titleBoxServer);
		titledServer.setContentDisplay(ContentDisplay.RIGHT);
	}

	// se viene cliccato dal men� l'opzione about si visualizza il file PdF 
	@FXML
	public void about() throws IOException {
		File file = new File("ConfigurationFile\\Help.pdf");
		Desktop.getDesktop().open(file);
	}

}
