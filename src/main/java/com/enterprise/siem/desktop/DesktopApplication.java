package com.enterprise.siem.desktop;

import javafx.application.Application;
import javafx.application.Platform;
import javafx.scene.layout.AnchorPane;
import javafx.scene.Scene;
import javafx.scene.web.WebView;
import javafx.stage.Stage;
import javafx.stage.StageStyle;
import javafx.embed.swing.SwingFXUtils;
import java.awt.Color;
import java.awt.Graphics2D;
import java.awt.RenderingHints;
import java.awt.image.BufferedImage;

import java.util.Objects;

/**
 * Native desktop shell for the local SOC dashboard; it never delegates to a
 * system browser.
 */
public final class DesktopApplication extends Application {
    private static String dashboardUrl;
    private static String applicationTitle;
    private static Runnable shutdownAction;

    public static void configure(String dashboardUrl, Runnable shutdownAction, String applicationTitle) {
        DesktopApplication.dashboardUrl = Objects.requireNonNull(dashboardUrl);
        DesktopApplication.shutdownAction = Objects.requireNonNull(shutdownAction);
        DesktopApplication.applicationTitle = Objects.requireNonNull(applicationTitle);
    }

    public static void launchApplication() {
        Application.launch(DesktopApplication.class);
    }

    @Override
    public void start(Stage stage) {
        WebView webView = new WebView();
        webView.setContextMenuEnabled(false);
        webView.getEngine().setJavaScriptEnabled(true);
        webView.getEngine().load(dashboardUrl);
        AnchorPane root = new AnchorPane(webView);
        AnchorPane.setTopAnchor(webView, 0.0);
        AnchorPane.setRightAnchor(webView, 0.0);
        AnchorPane.setBottomAnchor(webView, 0.0);
        AnchorPane.setLeftAnchor(webView, 0.0);
        Scene scene = new Scene(root);
        stage.initStyle(StageStyle.UNDECORATED);
        stage.setTitle(applicationTitle);
        stage.getIcons().add(SwingFXUtils.toFXImage(icon(), null));
        stage.setScene(scene);
        stage.setResizable(false);
        stage.setOnCloseRequest(event -> shutdown());
        stage.show();
        stage.setFullScreen(true);
    }

    @Override
    public void stop() {
        shutdown();
    }

    private void shutdown() {
        Runnable action = shutdownAction;
        if (action != null) {
            shutdownAction = null;
            action.run();
        }
        Platform.exit();
    }

    private static BufferedImage icon() {
        BufferedImage image = new BufferedImage(256, 256, BufferedImage.TYPE_INT_ARGB);
        Graphics2D graphics = image.createGraphics();
        graphics.setRenderingHint(RenderingHints.KEY_ANTIALIASING, RenderingHints.VALUE_ANTIALIAS_ON);
        graphics.setColor(Color.decode("#13222b"));
        int[] shieldX = { 128, 226, 226, 128, 30, 30 };
        int[] shieldY = { 12, 48, 118, 244, 118, 48 };
        graphics.fillPolygon(shieldX, shieldY, shieldX.length);
        graphics.setColor(Color.decode("#2e9d98"));
        graphics.fillRoundRect(64, 55, 128, 130, 28, 28);
        graphics.setColor(Color.decode("#d9f1ee"));
        graphics.fillOval(82, 116, 18, 18);
        graphics.fillOval(156, 86, 18, 18);
        graphics.setColor(Color.decode("#de7a4d"));
        graphics.setStroke(
                new java.awt.BasicStroke(10, java.awt.BasicStroke.CAP_ROUND, java.awt.BasicStroke.JOIN_ROUND));
        graphics.drawLine(91, 125, 115, 149);
        graphics.drawLine(115, 149, 165, 94);
        graphics.dispose();
        return image;
    }
}
