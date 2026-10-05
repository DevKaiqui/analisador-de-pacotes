package br.com.analisador.detector;

import java.util.function.UnaryOperator;

/**
 * Como IPs e MACs aparecem nos alertas. Permite reaproveitar o
 * SensitiveDataMasker do projeto, para que os alertas respeitem a mesma
 * política de privacidade da saída normal.
 */
public record Mascara(UnaryOperator<String> ip, UnaryOperator<String> mac) {

    /** Sem mascaramento (útil em testes). */
    public static Mascara nenhuma() {
        return new Mascara(s -> s, s -> s);
    }
}
