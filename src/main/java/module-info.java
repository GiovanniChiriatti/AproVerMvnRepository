module org.unimi {
    requires javafx.controls;
    requires javafx.fxml;
    requires javafx.media;
	requires org.controlsfx.controls;
	requires java.desktop;
    opens org.unimi.Aprover to javafx.fxml;
    exports org.unimi.Aprover;
}