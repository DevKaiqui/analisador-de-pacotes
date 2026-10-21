package br.com.analisador.ia;

import java.io.IOException;

/**
 * Qualquer serviço que responde a uma pergunta em texto.
 * Existe como interface para o resto do programa (e os testes) não depender
 * da rede nem de um provedor específico.
 */
@FunctionalInterface
public interface ModeloDeLinguagem {

    /**
     * @param instrucoes regras fixas de comportamento (papel e formato da resposta)
     * @param pergunta   o conteúdo variável a ser analisado
     * @return texto simples da resposta
     */
    String perguntar(String instrucoes, String pergunta) throws IOException, InterruptedException;
}
