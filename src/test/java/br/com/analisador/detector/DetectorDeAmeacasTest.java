package br.com.analisador.detector;

import org.junit.jupiter.api.Test;
import org.pcap4j.packet.Packet;
import org.pcap4j.packet.UnknownPacket;

import java.util.ArrayList;
import java.util.List;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.*;

class DetectorDeAmeacasTest {

    private static final Packet PACOTE_QUALQUER =
            UnknownPacket.newPacket(new byte[]{1, 2, 3}, 0, 3);

    /** Regra falsa que sempre alerta, para testar o motor isoladamente. */
    private static RegraDeteccao regraQueSempreAlerta() {
        return new RegraDeteccao() {
            public String nome() { return "Teste"; }
            public Optional<Alerta> analisar(Packet p, long agora) {
                return Optional.of(Alerta.agora(Severidade.ALTA, "Teste", "1.2.3.4", "teste", "Teste|1.2.3.4"));
            }
        };
    }

    @Test
    void naoRepeteOMesmoAlertaDentroDoCooldown() {
        DetectorDeAmeacas detector = new DetectorDeAmeacas(30_000);
        detector.adicionarRegra(regraQueSempreAlerta());
        List<Alerta> recebidos = new ArrayList<>();
        detector.aoDetectar(recebidos::add);

        detector.processar(PACOTE_QUALQUER, 1_000);
        detector.processar(PACOTE_QUALQUER, 5_000);   // dentro do cooldown
        detector.processar(PACOTE_QUALQUER, 40_000);  // cooldown já passou

        assertEquals(2, recebidos.size());
    }

    @Test
    void regraComErroNaoDerrubaAsOutras() {
        DetectorDeAmeacas detector = new DetectorDeAmeacas(30_000);
        detector.adicionarRegra(new RegraDeteccao() {
            public String nome() { return "Quebrada"; }
            public Optional<Alerta> analisar(Packet p, long agora) { throw new IllegalStateException(); }
        });
        detector.adicionarRegra(regraQueSempreAlerta());
        List<Alerta> recebidos = new ArrayList<>();
        detector.aoDetectar(recebidos::add);

        assertDoesNotThrow(() -> detector.processar(PACOTE_QUALQUER, 1_000));
        assertEquals(1, recebidos.size());
    }

    @Test
    void dominiosNormaisNaoSaoSuspeitos() {
        assertFalse(DetectorDnsSuspeito.eSuspeito("www.google.com"));
        assertFalse(DetectorDnsSuspeito.eSuspeito("github.com"));
    }

    @Test
    void dominioAleatorioELongoESuspeito() {
        assertTrue(DetectorDnsSuspeito.eSuspeito("a8f3k2j9x7q1m5n4b6v8c0z2l4p6r8t0.exemplo.com"));
    }

    @Test
    void entropiaDeTextoRepetidoEZero() {
        assertEquals(0.0, DetectorDnsSuspeito.entropia("aaaaaaaa"), 0.0001);
    }
}
