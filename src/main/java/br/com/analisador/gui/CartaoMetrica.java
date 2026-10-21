package br.com.analisador.gui;

import com.formdev.flatlaf.FlatClientProperties;
import com.formdev.flatlaf.util.ColorFunctions;
import com.formdev.flatlaf.util.UIScale;

import javax.swing.*;
import java.awt.*;

/** Cartão do painel com um título pequeno e um número grande, com uma faixa colorida à esquerda. */
public final class CartaoMetrica extends JPanel {

    private static final int ARCO = 12;
    private static final int FAIXA = 4;

    private final JLabel valor = new JLabel("0");
    private final Color cor;

    public CartaoMetrica(String titulo, Color cor) {
        super(new BorderLayout(0, 2));
        this.cor = cor;
        setOpaque(false);
        setBorder(BorderFactory.createEmptyBorder(10, 16 + FAIXA, 10, 16));

        JLabel rotulo = new JLabel(titulo.toUpperCase());
        rotulo.putClientProperty(FlatClientProperties.STYLE, "font: -1 bold; foreground: $Label.disabledForeground");
        valor.putClientProperty(FlatClientProperties.STYLE, "font: bold +14");
        valor.setForeground(cor);

        add(rotulo, BorderLayout.NORTH);
        add(valor, BorderLayout.CENTER);
    }

    public void setValor(int n) {
        valor.setText(String.format("%,d", n).replace(',', '.'));
    }

    @Override
    protected void paintComponent(Graphics g) {
        Graphics2D g2 = (Graphics2D) g.create();
        try {
            g2.setRenderingHint(RenderingHints.KEY_ANTIALIASING, RenderingHints.VALUE_ANTIALIAS_ON);
            int arco = UIScale.scale(ARCO);
            Color fundo = UIManager.getColor("Panel.background");
            g2.setColor(ColorFunctions.lighten(fundo, 0.04f));
            g2.fillRoundRect(0, 0, getWidth(), getHeight(), arco, arco);

            // faixa de cor da métrica, recortada pelo mesmo arredondamento do cartão
            g2.setClip(new java.awt.geom.RoundRectangle2D.Float(0, 0, getWidth(), getHeight(), arco, arco));
            g2.setColor(cor);
            g2.fillRect(0, 0, UIScale.scale(FAIXA), getHeight());
        } finally {
            g2.dispose();
        }
        super.paintComponent(g);
    }
}
