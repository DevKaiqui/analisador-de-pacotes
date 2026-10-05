package br.com.analisador.gui;

import br.com.analisador.detector.Alerta;

import javax.swing.table.AbstractTableModel;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.List;

/** Guarda os alertas e alimenta a tabela de alertas da janela. */
public final class ModeloAlertas extends AbstractTableModel {

    private static final String[] COLUNAS = {"Hora", "Severidade", "Tipo", "Descrição"};
    private static final DateTimeFormatter HORA = DateTimeFormatter.ofPattern("HH:mm:ss");

    private final List<Alerta> alertas = new ArrayList<>();

    /** Adiciona no topo (mais recente primeiro). */
    public void adicionar(Alerta a) {
        alertas.add(0, a);
        fireTableRowsInserted(0, 0);
    }

    public Alerta get(int linha) {
        return alertas.get(linha);
    }

    public void limpar() {
        int n = alertas.size();
        if (n > 0) {
            alertas.clear();
            fireTableRowsDeleted(0, n - 1);
        }
    }

    @Override public int getRowCount() { return alertas.size(); }
    @Override public int getColumnCount() { return COLUNAS.length; }
    @Override public String getColumnName(int c) { return COLUNAS[c]; }

    @Override
    public Object getValueAt(int linha, int coluna) {
        Alerta a = alertas.get(linha);
        return switch (coluna) {
            case 0 -> a.momento().format(HORA);
            case 1 -> a.severidade();
            case 2 -> a.tipo();
            case 3 -> a.descricao();
            default -> "";
        };
    }
}
