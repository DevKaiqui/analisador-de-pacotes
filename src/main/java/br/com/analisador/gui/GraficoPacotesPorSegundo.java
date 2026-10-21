package br.com.analisador.gui;

import com.formdev.flatlaf.util.ColorFunctions;
import com.formdev.flatlaf.util.UIScale;

import javax.swing.*;
import java.awt.*;
import java.awt.geom.Path2D;
import java.util.function.LongSupplier;

/**
 * Gráfico de área com os pacotes por segundo do último minuto, desenhado com Graphics2D.
 * Um javax.swing.Timer lê o total a cada segundo; como o Timer dispara na thread da interface,
 * a série e o desenho nunca são tocados por outra thread.
 */
public final class GraficoPacotesPorSegundo extends JComponent {

    private static final int SEGUNDOS = 60;
    private static final int ARCO = 12;

    private final SerieTaxa serie = new SerieTaxa(SEGUNDOS);
    private final LongSupplier totalDePacotes;
    private final Timer relogio;

    public GraficoPacotesPorSegundo(LongSupplier totalDePacotes) {
        this.totalDePacotes = totalDePacotes;
        relogio = new Timer(1000, e -> {
            serie.registrar(totalDePacotes.getAsLong());
            repaint();
        });
        setPreferredSize(new Dimension(UIScale.scale(420), UIScale.scale(120)));
        setMinimumSize(new Dimension(UIScale.scale(240), UIScale.scale(100)));
    }

    /** Chamado pelo botão Limpar (na thread da interface). */
    public void limpar() {
        serie.limpar(totalDePacotes.getAsLong());
        repaint();
    }

    @Override public void addNotify() { super.addNotify(); relogio.start(); }
    @Override public void removeNotify() { relogio.stop(); super.removeNotify(); }

    @Override
    protected void paintComponent(Graphics g) {
        Graphics2D g2 = (Graphics2D) g.create();
        try {
            g2.setRenderingHint(RenderingHints.KEY_ANTIALIASING, RenderingHints.VALUE_ANTIALIAS_ON);
            g2.setRenderingHint(RenderingHints.KEY_TEXT_ANTIALIASING, RenderingHints.VALUE_TEXT_ANTIALIAS_ON);
            int w = getWidth(), h = getHeight();
            Color fundo = UIManager.getColor("Panel.background");
            Color destaque = UIManager.getColor("Component.accentColor");
            Color textoFraco = UIManager.getColor("Label.disabledForeground");

            int arco = UIScale.scale(ARCO);
            g2.setColor(ColorFunctions.lighten(fundo, 0.04f));
            g2.fillRoundRect(0, 0, w, h, arco, arco);

            // cabeçalho: título à esquerda, valor atual à direita
            int margem = UIScale.scale(14);
            Font base = UIManager.getFont("Label.font");
            Font fonteTitulo = base.deriveFont(Font.BOLD, base.getSize2D() - 1);
            Font fonteValor = base.deriveFont(Font.BOLD, base.getSize2D() + 4);
            Font fonteEixo = base.deriveFont(base.getSize2D() - 2);
            g2.setFont(fonteTitulo);
            int yTitulo = margem + g2.getFontMetrics().getAscent();
            g2.setColor(textoFraco);
            g2.drawString("PACOTES POR SEGUNDO", margem, yTitulo);

            String atual = serie.atual() + " pkt/s";
            g2.setFont(fonteValor);
            FontMetrics fmValor = g2.getFontMetrics();
            g2.setColor(destaque);
            g2.drawString(atual, w - margem - fmValor.stringWidth(atual), yTitulo + UIScale.scale(2));

            // área do gráfico
            g2.setFont(fonteEixo);
            FontMetrics fmEixo = g2.getFontMetrics();
            int[] valores = serie.valores();
            int maximo = escalaBonita(serie.maximo());
            int larguraEixo = fmEixo.stringWidth(String.valueOf(maximo)) + UIScale.scale(6);
            int x0 = margem + larguraEixo;
            int x1 = w - margem;
            int y0 = yTitulo + UIScale.scale(12);
            int y1 = h - margem - fmEixo.getHeight();
            if (x1 - x0 < 20 || y1 - y0 < 20) return;

            // grade horizontal com rótulos (0, metade, máximo)
            for (int i = 0; i <= 2; i++) {
                int y = y1 - (y1 - y0) * i / 2;
                g2.setColor(ColorFunctions.lighten(fundo, 0.10f));
                g2.drawLine(x0, y, x1, y);
                String rotulo = String.valueOf(maximo * i / 2);
                g2.setColor(textoFraco);
                g2.drawString(rotulo, x0 - UIScale.scale(6) - fmEixo.stringWidth(rotulo), y + fmEixo.getAscent() / 2 - 1);
            }
            g2.setColor(textoFraco);
            g2.drawString("-" + SEGUNDOS + "s", x0, h - margem);
            String agora = "agora";
            g2.drawString(agora, x1 - fmEixo.stringWidth(agora), h - margem);

            // linha e área preenchida com degradê
            Path2D.Float linha = new Path2D.Float();
            for (int i = 0; i < valores.length; i++) {
                float x = x0 + (x1 - x0) * i / (float) (valores.length - 1);
                float y = y1 - (y1 - y0) * Math.min(valores[i], maximo) / (float) maximo;
                if (i == 0) linha.moveTo(x, y); else linha.lineTo(x, y);
            }
            Path2D.Float area = new Path2D.Float(linha);
            area.lineTo(x1, y1);
            area.lineTo(x0, y1);
            area.closePath();
            g2.setPaint(new GradientPaint(0, y0, ColorFunctions.fade(destaque, 0.45f), 0, y1, ColorFunctions.fade(destaque, 0.02f)));
            g2.fill(area);
            g2.setColor(destaque);
            g2.setStroke(new BasicStroke(UIScale.scale(2f), BasicStroke.CAP_ROUND, BasicStroke.JOIN_ROUND));
            g2.draw(linha);
        } finally {
            g2.dispose();
        }
    }

    /** Arredonda o topo do eixo para um número "redondo" (10, 20, 50, 100, ...), nunca menor que 10. */
    static int escalaBonita(int maximo) {
        int alvo = Math.max(10, maximo);
        int potencia = 1;
        while (potencia * 10 < alvo) potencia *= 10;
        for (int passo : new int[]{1, 2, 5, 10}) {
            if (passo * potencia >= alvo) return passo * potencia;
        }
        return 10 * potencia;
    }
}
