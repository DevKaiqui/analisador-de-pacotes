package br.com.analisador.gui;

import br.com.analisador.detector.Severidade;

import javax.swing.*;
import javax.swing.table.DefaultTableCellRenderer;
import java.awt.*;

/** Pinta cada linha da tabela de alertas conforme a severidade. */
public final class RenderizadorSeveridade extends DefaultTableCellRenderer {

    @Override
    public Component getTableCellRendererComponent(JTable tabela, Object valor,
            boolean selecionado, boolean foco, int linha, int coluna) {
        Component c = super.getTableCellRendererComponent(tabela, valor, selecionado, foco, linha, coluna);
        Object sev = tabela.getValueAt(linha, 1);
        Color fundo = Color.WHITE, frente = Color.BLACK;
        if (sev instanceof Severidade s) {
            switch (s) {
                case CRITICA -> { fundo = new Color(0xB0, 0x00, 0x20); frente = Color.WHITE; }
                case ALTA ->    { fundo = new Color(0xFF, 0xCD, 0xD2); }
                case MEDIA ->   { fundo = new Color(0xFF, 0xF3, 0xCD); }
                case BAIXA ->   { fundo = new Color(0xD1, 0xEC, 0xF1); }
            }
        }
        if (!selecionado) {
            c.setBackground(fundo);
            c.setForeground(frente);
        }
        return c;
    }
}
