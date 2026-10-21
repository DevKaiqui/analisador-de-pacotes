package br.com.analisador.gui;

import br.com.analisador.detector.Severidade;
import com.formdev.flatlaf.util.ColorFunctions;
import com.formdev.flatlaf.util.UIScale;

import javax.swing.*;
import javax.swing.table.TableCellRenderer;
import java.awt.*;
import java.awt.geom.RoundRectangle2D;

/**
 * Selo (pílula) colorido com o nome da severidade.
 * Serve tanto de renderizador da coluna Severidade quanto de componente avulso (painel de detalhes).
 */
public final class SeloSeveridade extends JComponent implements TableCellRenderer {

    private Severidade severidade;
    private Color fundoDaCelula;

    public SeloSeveridade() {
        setFont(UIManager.getFont("Label.font").deriveFont(Font.BOLD, UIManager.getFont("Label.font").getSize2D() - 1));
    }

    public void setSeveridade(Severidade severidade) {
        this.severidade = severidade;
        fundoDaCelula = null;
        revalidate();
        repaint();
    }

    static String rotulo(Severidade s) {
        return switch (s) {
            case CRITICA -> "CRÍTICA";
            case ALTA -> "ALTA";
            case MEDIA -> "MÉDIA";
            case BAIXA -> "BAIXA";
        };
    }

    @Override
    public Component getTableCellRendererComponent(JTable tabela, Object valor, boolean selecionado,
            boolean foco, int linha, int coluna) {
        severidade = valor instanceof Severidade s ? s : null;
        // mesmo fundo das outras colunas, para a linha ficar uniforme
        fundoDaCelula = selecionado ? tabela.getSelectionBackground() : RenderizadorSeveridade.fundoDaLinha(tabela, linha);
        return this;
    }

    @Override
    public Dimension getPreferredSize() {
        FontMetrics fm = getFontMetrics(getFont());
        return new Dimension(fm.stringWidth("CRÍTICA") + UIScale.scale(28), fm.getHeight() + UIScale.scale(8));
    }

    @Override
    protected void paintComponent(Graphics g) {
        Graphics2D g2 = (Graphics2D) g.create();
        try {
            if (fundoDaCelula != null) {
                g2.setColor(fundoDaCelula);
                g2.fillRect(0, 0, getWidth(), getHeight());
            }
            if (severidade == null) return;

            g2.setRenderingHint(RenderingHints.KEY_ANTIALIASING, RenderingHints.VALUE_ANTIALIAS_ON);
            g2.setRenderingHint(RenderingHints.KEY_TEXT_ANTIALIASING, RenderingHints.VALUE_TEXT_ANTIALIAS_ON);
            g2.setFont(getFont());
            FontMetrics fm = g2.getFontMetrics();
            String texto = rotulo(severidade);
            Color cor = Tema.corSeveridade(severidade);

            int padH = UIScale.scale(10), padV = UIScale.scale(2);
            int w = fm.stringWidth(texto) + 2 * padH;
            int h = Math.min(fm.getHeight() + 2 * padV, getHeight() - UIScale.scale(2));
            int x = fundoDaCelula != null ? UIScale.scale(6) : 0;
            int y = (getHeight() - h) / 2;
            RoundRectangle2D pilula = new RoundRectangle2D.Float(x, y, w, h, h, h);

            // crítica em vermelho sólido; as demais em tom translúcido com texto na cor da severidade
            boolean solido = severidade == Severidade.CRITICA;
            Color base = fundoDaCelula != null ? fundoDaCelula : UIManager.getColor("Panel.background");
            g2.setColor(solido ? cor : ColorFunctions.mix(cor, base, 0.22f));
            g2.fill(pilula);
            g2.setColor(solido ? Color.WHITE : cor);
            g2.drawString(texto, x + padH, y + (h - fm.getHeight()) / 2 + fm.getAscent());
        } finally {
            g2.dispose();
        }
    }
}
