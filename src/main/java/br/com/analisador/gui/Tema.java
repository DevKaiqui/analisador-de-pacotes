package br.com.analisador.gui;

import br.com.analisador.detector.Severidade;
import com.formdev.flatlaf.FlatClientProperties;
import com.formdev.flatlaf.FlatDarkLaf;
import com.formdev.flatlaf.FlatLaf;
import com.formdev.flatlaf.util.ColorFunctions;

import javax.swing.*;
import java.awt.*;
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

        // zebra das tabelas derivada do fundo do tema (funciona no claro e no escuro)
        Color fundoTabela = UIManager.getColor("Table.background");
        UIManager.put("Table.alternateRowColor", FlatLaf.isLafDark()
                ? ColorFunctions.lighten(fundoTabela, 0.03f)
                : ColorFunctions.darken(fundoTabela, 0.03f));
        UIManager.put("Table.showHorizontalLines", false);
        UIManager.put("Table.showVerticalLines", false);
        UIManager.put("Table.intercellSpacing", new Dimension(0, 0));

        // cores de severidade, legíveis sobre fundo escuro
        UIManager.put(chave(Severidade.CRITICA), new Color(0xFF3B4E));
        UIManager.put(chave(Severidade.ALTA), new Color(0xFF6B6B));
        UIManager.put(chave(Severidade.MEDIA), new Color(0xFFB020));
        UIManager.put(chave(Severidade.BAIXA), new Color(0x3BC9DB));
    }

    private static String chave(Severidade s) {
        return "Analisador.severidade." + s.name();
    }

    public static Color corSeveridade(Severidade s) {
        return UIManager.getColor(chave(s));
    }

    /** Verde do tema (captura ativa). */
    public static Color corAtivo() {
        return UIManager.getColor("Actions.Green");
    }

    /** Cinza do tema para estados inativos. */
    public static Color corInativo() {
        return UIManager.getColor("Label.disabledForeground");
    }

    /**
     * Botão de ação principal, com a cor de fundo vinda de uma chave do tema (ex.: "Actions.Green")
     * ou da cor de destaque; o FlatLaf deriva sozinho as cores de hover e pressionado.
     */
    public static void botaoPrimario(JButton botao, String corDeFundo, String corDoTexto) {
        botao.putClientProperty(FlatClientProperties.STYLE,
                "background:" + corDeFundo + "; foreground:" + corDoTexto
                        + "; borderWidth:0; focusWidth:0; innerFocusWidth:0; font:bold");
    }
}
