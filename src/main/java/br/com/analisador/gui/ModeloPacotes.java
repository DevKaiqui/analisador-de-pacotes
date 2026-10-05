package br.com.analisador.gui;

import javax.swing.table.AbstractTableModel;
import java.util.ArrayDeque;
import java.util.Deque;

/**
 * Guarda as linhas de pacotes já descritas pelo PacketAnalyzer.
 * Mantém no máximo um limite de linhas, para a memória não explodir
 * numa captura longa (as mais antigas são descartadas).
 */
public final class ModeloPacotes extends AbstractTableModel {

    private static final String[] COLUNAS = {"#", "Descrição"};
    private final Deque<Object[]> linhas = new ArrayDeque<>();
    private final int maximo;

    public ModeloPacotes(int maximo) {
        this.maximo = maximo;
    }

    public void adicionar(int numero, String descricao) {
        linhas.addFirst(new Object[]{numero, descricao});
        if (linhas.size() > maximo) linhas.removeLast();
        fireTableDataChanged();
    }

    public void limpar() {
        linhas.clear();
        fireTableDataChanged();
    }

    @Override public int getRowCount() { return linhas.size(); }
    @Override public int getColumnCount() { return COLUNAS.length; }
    @Override public String getColumnName(int c) { return COLUNAS[c]; }

    @Override
    public Object getValueAt(int linha, int coluna) {
        int i = 0;
        for (Object[] dados : linhas) {
            if (i++ == linha) return dados[coluna];
        }
        return "";
    }
}
