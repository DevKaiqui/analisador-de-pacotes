package br.com.analisador.detector;

import java.io.PrintStream;
import java.time.format.DateTimeFormatter;
import java.util.function.Consumer;

/** Mostra os alertas no terminal, com cor por severidade. */
public final class ImpressoraDeAlertas implements Consumer<Alerta> {

    private static final String RESET = "\u001B[0m";
    private static final DateTimeFormatter HORA = DateTimeFormatter.ofPattern("HH:mm:ss");

    private final PrintStream saida;
    private final boolean usarCores;

    public ImpressoraDeAlertas(PrintStream saida, boolean usarCores) {
        this.saida = saida;
        this.usarCores = usarCores;
    }

    public ImpressoraDeAlertas(boolean usarCores) {
        this(System.out, usarCores);
    }

    @Override
    public synchronized void accept(Alerta a) {
        String linha = String.format("[ALERTA %s] %s | %s | %s",
                a.severidade(), a.momento().format(HORA), a.tipo(), a.descricao());
        saida.println(usarCores ? cor(a.severidade()) + linha + RESET : linha);
    }

    private static String cor(Severidade s) {
        return switch (s) {
            case CRITICA -> "\u001B[1;97;41m"; // branco em fundo vermelho
            case ALTA -> "\u001B[1;31m";       // vermelho
            case MEDIA -> "\u001B[1;33m";      // amarelo
            case BAIXA -> "\u001B[36m";        // ciano
        };
    }
}
