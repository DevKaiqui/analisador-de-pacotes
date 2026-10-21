package br.com.analisador.gui;

import java.util.Arrays;

/**
 * Histórico de "pacotes por segundo" dos últimos N segundos, calculado a partir do total acumulado.
 * Sem Swing, para ser testado direto; o gráfico só a desenha.
 */
public final class SerieTaxa {

    private final int[] valores;
    private int inicio;          // posição do valor mais antigo no buffer circular
    private long ultimoTotal;

    public SerieTaxa(int segundos) {
        valores = new int[segundos];
    }

    /** Registra mais um segundo, dado o total de pacotes acumulado até agora. */
    public void registrar(long totalAtual) {
        // o total volta a zero quando o usuário clica em Limpar; aí conta só o que veio depois
        long diferenca = totalAtual >= ultimoTotal ? totalAtual - ultimoTotal : totalAtual;
        ultimoTotal = totalAtual;
        valores[inicio] = (int) Math.min(Integer.MAX_VALUE, diferenca);
        inicio = (inicio + 1) % valores.length;
    }

    /** Zera o histórico (botão Limpar). */
    public void limpar(long totalAtual) {
        Arrays.fill(valores, 0);
        inicio = 0;
        ultimoTotal = totalAtual;
    }

    /** Valores do mais antigo para o mais recente. */
    public int[] valores() {
        int[] copia = new int[valores.length];
        for (int i = 0; i < valores.length; i++) copia[i] = valores[(inicio + i) % valores.length];
        return copia;
    }

    public int atual() {
        return valores[(inicio - 1 + valores.length) % valores.length];
    }

    public int maximo() {
        return Arrays.stream(valores).max().orElse(0);
    }

    public int tamanho() {
        return valores.length;
    }
}
