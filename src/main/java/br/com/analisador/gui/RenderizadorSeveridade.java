package br.com.analisador.gui;

import br.com.analisador.detector.Severidade;
import com.formdev.flatlaf.util.ColorFunctions;

import javax.swing.*;
import javax.swing.table.DefaultTableCellRenderer;
import java.awt.*;

/**
 * Tabela de alertas sobre as cores do tema: linhas críticas ganham um leve fundo avermelhado
 * para chamar atenção. A coluna Severidade em si é desenhada pelo {@link SeloSeveridade}.
 */
public final class RenderizadorSeveridade extends DefaultTableCellRenderer {

    static final int COLUNA_SEVERIDADE = 1;

    public RenderizadorSeveridade() {
        // a descrição pode trazer dados da rede: nunca interpretar como HTML
        putClientProperty("html.disable", Boolean.TRUE);
    }

    @Override
    public Component getTableCellRendererComponent(JTable tabela, Object valor,
            boolean selecionado, boolean foco, int linha, int coluna) {
        Component c = super.getTableCellRendererComponent(tabela, valor, selecionado, foco, linha, coluna);
        setBorder(BorderFactory.createEmptyBorder(0, 8, 0, 8));
        if (!selecionado) {
            c.setBackground(fundoDaLinha(tabela, linha));
            c.setForeground(tabela.getForeground());
        }
        return c;
    }

    /** Fundo da linha: zebra do tema, com um toque de vermelho quando o alerta é crítico. */
    static Color fundoDaLinha(JTable tabela, int linha) {
        Color alternada = UIManager.getColor("Table.alternateRowColor");
        Color fundo = linha % 2 == 1 && alternada != null ? alternada : tabela.getBackground();
        return tabela.getValueAt(linha, COLUNA_SEVERIDADE) == Severidade.CRITICA
                ? ColorFunctions.mix(Tema.corSeveridade(Severidade.CRITICA), fundo, 0.14f)
                : fundo;
    }
}
