package br.com.analisador.detector;

import org.pcap4j.packet.IpPacket;
import org.pcap4j.packet.Packet;
import org.pcap4j.packet.TcpPacket;

import java.util.*;

/**
 * Detecta SYN flood: volume muito alto de SYN para o mesmo alvo (IP:porta)
 * em pouco tempo, o que pode indicar tentativa de negação de serviço (DoS).
 */
public final class DetectorSynFlood implements RegraDeteccao {

    private final Mascara mascara;
    private final int limiteSyns;
    private final long janelaMs;
    private final Map<String, Deque<Long>> historico = new HashMap<>();

    public DetectorSynFlood(Mascara mascara, int limiteSyns, long janelaMs) {
        this.mascara = mascara;
        this.limiteSyns = limiteSyns;
        this.janelaMs = janelaMs;
    }

    public DetectorSynFlood(Mascara mascara) {
        this(mascara, 200, 1_000); // 200 SYNs em 1 segundo
    }

    @Override
    public String nome() { return "SYN Flood"; }

    @Override
    public Optional<Alerta> analisar(Packet pacote, long agora) {
        IpPacket ip = pacote.get(IpPacket.class);
        TcpPacket tcp = pacote.get(TcpPacket.class);
        if (ip == null || tcp == null) return Optional.empty();
        if (!tcp.getHeader().getSyn() || tcp.getHeader().getAck()) return Optional.empty();

        String alvoIp = ip.getHeader().getDstAddr().getHostAddress();
        int porta = tcp.getHeader().getDstPort().valueAsInt();
        String alvo = alvoIp + ":" + porta;

        Deque<Long> tempos = historico.computeIfAbsent(alvo, k -> new ArrayDeque<>());
        tempos.addLast(agora);
        while (!tempos.isEmpty() && agora - tempos.peekFirst() > janelaMs) tempos.pollFirst();

        if (tempos.size() < limiteSyns) return Optional.empty();

        int total = tempos.size();
        tempos.clear();
        String alvoMascarado = mascara.ip().apply(alvoIp);
        return Optional.of(Alerta.agora(Severidade.CRITICA, nome(), alvoMascarado,
                String.format("%d pacotes SYN para %s:%d em %dms (possível DoS)",
                        total, alvoMascarado, porta, janelaMs),
                nome() + "|" + alvo));
    }

    @Override
    public void limpar(long agora) {
        historico.values().forEach(d -> {
            while (!d.isEmpty() && agora - d.peekFirst() > janelaMs) d.pollFirst();
        });
        historico.values().removeIf(Deque::isEmpty);
    }
}
