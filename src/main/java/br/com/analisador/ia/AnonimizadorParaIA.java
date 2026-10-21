package br.com.analisador.ia;

import java.util.regex.Pattern;

/**
 * Última barreira de privacidade antes de enviar qualquer texto para a IA:
 * mesmo que o usuário tenha marcado "Mostrar dados sensíveis" na janela,
 * IPs e MACs completos nunca saem do computador.
 *
 * Mantém só o suficiente para a IA raciocinar (faixa do IP, fabricante do MAC).
 */
public final class AnonimizadorParaIA {

    private static final Pattern IPV4 =
            Pattern.compile("\\b(\\d{1,3})\\.(\\d{1,3})\\.\\d{1,3}\\.\\d{1,3}\\b");
    private static final Pattern MAC =
            Pattern.compile("\\b([0-9A-Fa-f]{2}[:-][0-9A-Fa-f]{2}[:-][0-9A-Fa-f]{2})([:-][0-9A-Fa-f]{2}){3}\\b");

    private AnonimizadorParaIA() { }

    public static String anonimizar(String texto) {
        if (texto == null) return "";
        String resultado = IPV4.matcher(texto).replaceAll("$1.$2.x.x");
        // normaliza o separador para ":" (estilo do resto do projeto) e esconde os 3 últimos bytes
        return MAC.matcher(resultado).replaceAll(m -> m.group(1).replace('-', ':') + ":**:**:**");
    }
}
