package br.com.analisador.gui;

import br.com.analisador.detector.Severidade;
import com.formdev.flatlaf.util.ColorFunctions;

import javax.swing.*;
import javax.swing.table.DefaultTableCellRenderer;
import java.awt.*;

/**
 * Tabela de alertas sobre as cores do tema: a coluna Severidade sai na cor da severidade
 * e linhas críticas ganham um leve fundo avermelhado para chamar atenção.
 */
public final class RenderizadorSeveridade extends DefaultTableCellRenderer {

    static final int COLUNA_SEVERIDADE = 1;

    @Override
    public Component getTableCellRendererComponent(JTable tabela, Object valor,
            boolean selecionado, boolean foco, int linha, int coluna) {
        Component c = super.getTableCellRendererComponent(tabela, valor, selecionado, foco, linha, coluna);
        setBorder(BorderFactory.createEmptyBorder(0, 8, 0, 8));
        if (selecionado) return c;

        Object sev = tabela.getValueAt(linha, COLUNA_SEVERIDADE);
        Color fundo = fundoDaLinha(tabela, linha);
        if (sev == Severidade.CRITICA) {
            fundo = ColorFunctions.mix(Tema.corSeveridade(Severidade.CRITICA), fundo, 0.14f);
        }
        c.setBackground(fundo);
        c.setForeground(tabela.getForeground());
        if (coluna == COLUNA_SEVERIDADE && sev instanceof Severidade s) {
            c.setForeground(Tema.corSeveridade(s));
            c.setFont(c.getFont().deriveFont(Font.BOLD));
        }
        return c;
    }

    /** Fundo normal da linha, respeitando a zebra do tema. */
    static Color fundoDaLinha(JTable tabela, int linha) {
        Color alternada = UIManager.getColor("Table.alternateRowColor");
        return linha % 2 == 1 && alternada != null ? alternada : tabela.getBackground();
    }
}
