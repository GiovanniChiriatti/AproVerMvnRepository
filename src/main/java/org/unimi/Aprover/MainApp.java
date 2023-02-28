package org.unimi.Aprover;

import java.io.IOException;


import javafx.fxml.FXML;
import javafx.fxml.FXMLLoader;
import javafx.scene.Parent;
import javafx.scene.Scene;
import javafx.stage.Stage;
import javafx.collections.FXCollections;
import javafx.collections.ObservableList;
import org.unimi.model.*;
import javafx.application.Application;

public class MainApp extends Application {

    
	@Override
    public void start(Stage primaryStage) throws Exception{
    	
    	Parent root = FXMLLoader.load(getClass().getResource("/fxml/StartAProVer.fxml"));
    	primaryStage.setTitle("AProVer");
    	primaryStage.setScene(new Scene(root, 1400, 650));
    	primaryStage.setMaximized(true);
    	primaryStage.show();

    }

    public static void main(String[] args) {
        launch(args);
    }
}
