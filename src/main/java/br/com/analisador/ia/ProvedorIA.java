package br.com.analisador.ia;

import java.util.Locale;

/**
 * Qual IA explica os alertas, escolhida pela variável de ambiente ANALISADOR_IA:
 * "local" usa o Ollama no próprio computador; qualquer outro valor (ou ausência) usa o Claude.
 */
public enum ProvedorIA {

    CLAUDE("Claude (API)", true),
    LOCAL("IA local (Ollama)", false);

    public static final String VARIAVEL = "ANALISADOR_IA";

    private final String nomeExibicao;
    private final boolean enviaParaInternet;

    ProvedorIA(String nomeExibicao, boolean enviaParaInternet) {
        this.nomeExibicao = nomeExibicao;
        this.enviaParaInternet = enviaParaInternet;
    }

    /** Lido do ambiente a cada chamada; o programa precisa ser reaberto para trocar (como a chave). */
    public static ProvedorIA doAmbiente() {
        return escolher(System.getenv(VARIAVEL));
    }

    /** Separado de {@link #doAmbiente()} para ser testado sem mexer em variáveis do sistema. */
    static ProvedorIA escolher(String valor) {
        return valor != null && valor.strip().toLowerCase(Locale.ROOT).equals("local") ? LOCAL : CLAUDE;
    }

    public String nomeExibicao() {
        return nomeExibicao;
    }

    /** Se o texto do alerta sai do computador (e, portanto, precisa de confirmação do usuário). */
    public boolean enviaParaInternet() {
        return enviaParaInternet;
    }
}
