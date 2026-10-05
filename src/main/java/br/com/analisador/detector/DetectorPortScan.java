package br.com.analisador.detector;

import org.pcap4j.packet.IpPacket;
import org.pcap4j.packet.Packet;
import org.pcap4j.packet.TcpPacket;

import java.util.*;

/**
 * Detecta port scan: um mesmo IP enviando SYN para muitas portas
 * diferentes em pouco tempo (comportamento típico do nmap -sS).
 */
public final class DetectorPortScan implements RegraDeteccao {

    private final Mascara mascara;
    private final int limitePortas;
    private final long janelaMs;
    private final Map<String, Deque<long[]>> historico = new HashMap<>();

    public DetectorPortScan(Mascara mascara, int limitePortas, long janelaMs) {
        this.mascara = mascara;
        this.limitePortas = limitePortas;
        this.janelaMs = janelaMs;
    }

    public DetectorPortScan(Mascara mascara) {
        this(mascara, 20, 10_000); // 20 portas distintas em 10 segundos
    }

    @Override
    public String nome() { return "Port Scan"; }

    @Override
    public Optional<Alerta> analisar(Packet pacote, long agora) {
        IpPacket ip = pacote.get(IpPacket.class);
        TcpPacket tcp = pacote.get(TcpPacket.class);
        if (ip == null || tcp == null) return Optional.empty();
        if (!tcp.getHeader().getSyn() || tcp.getHeader().getAck()) return Optional.empty();

        String origem = ip.getHeader().getSrcAddr().getHostAddress();
        int porta = tcp.getHeader().getDstPort().valueAsInt();

        Deque<long[]> eventos = historico.computeIfAbsent(origem, k -> new ArrayDeque<>());
        eventos.addLast(new long[]{agora, porta});
        while (!eventos.isEmpty() && agora - eventos.peekFirst()[0] > janelaMs) eventos.pollFirst();

        long portasDistintas = eventos.stream().mapToLong(e -> e[1]).distinct().count();
        if (portasDistintas < limitePortas) return Optional.empty();

        eventos.clear();
        String origemMascarada = mascara.ip().apply(origem);
        String destino = mascara.ip().apply(ip.getHeader().getDstAddr().getHostAddress());
        return Optional.of(Alerta.agora(Severidade.ALTA, nome(), origemMascarada,
                String.format("%s tentou %d portas diferentes em %s em menos de %ds",
                        origemMascarada, portasDistintas, destino, janelaMs / 1000),
                nome() + "|" + origem));
    }

    @Override
    public void limpar(long agora) {
        historico.values().forEach(d -> {
            while (!d.isEmpty() && agora - d.peekFirst()[0] > janelaMs) d.pollFirst();
        });
        historico.values().removeIf(Deque::isEmpty);
    }
}
