package br.com.analisador.gui;

import com.formdev.flatlaf.FlatDarkLaf;
import com.formdev.flatlaf.FlatLaf;

import javax.swing.*;
import java.util.Map;

/**
 * Visual da janela: tema escuro do FlatLaf, cor de destaque e cantos arredondados.
 * Deve ser aplicado antes de criar qualquer componente Swing.
 */
public final class Tema {

    /** Ciano usado como cor de destaque (seleção, foco, botão principal). */
    public static final String DESTAQUE = "#22B8CF";

    private Tema() { }

    public static void aplicar() {
        FlatLaf.setGlobalExtraDefaults(Map.of("@accentColor", DESTAQUE));
        FlatDarkLaf.setup();

        UIManager.put("Component.arc", 10);
        UIManager.put("Button.arc", 10);
        UIManager.put("TextComponent.arc", 10);
        UIManager.put("CheckBox.arc", 6);
        UIManager.put("ScrollBar.thumbArc", 999);
        UIManager.put("ScrollBar.thumbInsets", new java.awt.Insets(2, 2, 2, 2));
        UIManager.put("ScrollBar.width", 12);
        UIManager.put("TitlePane.unifiedBackground", true);
    }
}
