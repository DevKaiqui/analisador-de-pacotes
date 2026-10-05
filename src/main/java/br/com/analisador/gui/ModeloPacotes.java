package br.com.analisador.gui;

import br.com.analisador.PacketAnalyzer.LinhaPacote;

import javax.swing.table.AbstractTableModel;
import java.util.ArrayDeque;
import java.util.Deque;

/**
 * Guarda as linhas de pacotes já separadas em colunas pelo PacketAnalyzer.
 * Mantém no máximo um limite de linhas, para a memória não explodir
 * numa captura longa (as mais antigas são descartadas).
 */
public final class ModeloPacotes extends AbstractTableModel {

    private static final String[] COLUNAS =
            {"Nº", "Protocolo", "Origem", "Destino", "Porta origem", "Porta destino", "Tamanho"};
    private final Deque<LinhaPacote> linhas = new ArrayDeque<>();
    private final int maximo;

    public ModeloPacotes(int maximo) {
        this.maximo = maximo;
    }

    public void adicionar(LinhaPacote linha) {
        linhas.addFirst(linha);
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
        for (LinhaPacote l : linhas) {
            if (i++ != linha) continue;
            return switch (coluna) {
                case 0 -> l.numero();
                case 1 -> l.protocolo();
                case 2 -> l.origem();
                case 3 -> l.destino();
                case 4 -> l.portaOrigem();
                case 5 -> l.portaDestino();
                case 6 -> l.tamanho();
                default -> "";
            };
        }
        return "";
    }
}
