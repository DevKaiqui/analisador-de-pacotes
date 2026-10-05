package br.com.analisador.detector;

import java.time.LocalDateTime;

/**
 * Um alerta gerado por uma regra de detecção.
 * "alvo" já vem mascarado; "chave" é interna, usada só para evitar alertas repetidos.
 */
public record Alerta(
        LocalDateTime momento,
        Severidade severidade,
        String tipo,
        String alvo,
        String descricao,
        String chave) {

    public static Alerta agora(Severidade severidade, String tipo, String alvo,
                               String descricao, String chave) {
        return new Alerta(LocalDateTime.now(), severidade, tipo, alvo, descricao, chave);
    }
}
