package br.com.analisador.detector;

import org.pcap4j.packet.DnsPacket;
import org.pcap4j.packet.DnsQuestion;
import org.pcap4j.packet.IpPacket;
import org.pcap4j.packet.Packet;

import java.util.*;

/**
 * Detecta consultas DNS suspeitas: subdomínios muito longos ou com aparência
 * aleatória (alta entropia), padrão de DNS tunneling e de malware com DGA.
 * Requer a dependência pcap4j-packetfactory-static para decodificar DNS.
 */
public final class DetectorDnsSuspeito implements RegraDeteccao {

    static final int TAMANHO_SUSPEITO = 40;
    static final int TAMANHO_MINIMO_ENTROPIA = 20;
    static final double ENTROPIA_SUSPEITA = 3.8;

    private final Mascara mascara;

    public DetectorDnsSuspeito(Mascara mascara) {
        this.mascara = mascara;
    }

    @Override
    public String nome() { return "DNS Suspeito"; }

    @Override
    public Optional<Alerta> analisar(Packet pacote, long agora) {
        DnsPacket dns = pacote.get(DnsPacket.class);
        if (dns == null || dns.getHeader().isResponse()) return Optional.empty();

        IpPacket ip = pacote.get(IpPacket.class);
        String origem = ip != null ? ip.getHeader().getSrcAddr().getHostAddress() : "?";

        for (DnsQuestion pergunta : dns.getHeader().getQuestions()) {
            String dominio = pergunta.getQName().getName();
            if (!eSuspeito(dominio)) continue;

            String rotulo = maiorRotulo(dominio);
            String origemMascarada = mascara.ip().apply(origem);
            return Optional.of(Alerta.agora(Severidade.MEDIA, nome(), origemMascarada,
                    String.format("%s consultou \"%s\" (rótulo com %d caracteres, entropia %.2f)",
                            origemMascarada, dominio, rotulo.length(), entropia(rotulo)),
                    nome() + "|" + origem + "|" + dominio));
        }
        return Optional.empty();
    }

    static boolean eSuspeito(String dominio) {
        String rotulo = maiorRotulo(dominio);
        boolean longo = rotulo.length() >= TAMANHO_SUSPEITO;
        boolean aleatorio = rotulo.length() >= TAMANHO_MINIMO_ENTROPIA
                && entropia(rotulo) >= ENTROPIA_SUSPEITA;
        return longo || aleatorio;
    }

    static String maiorRotulo(String dominio) {
        return Arrays.stream(dominio.split("\\."))
                .max(Comparator.comparingInt(String::length))
                .orElse("");
    }

    /** Entropia de Shannon: quanto maior, mais "aleatório" é o texto. */
    static double entropia(String texto) {
        if (texto.isEmpty()) return 0;
        Map<Character, Integer> freq = new HashMap<>();
        for (char c : texto.toLowerCase().toCharArray()) freq.merge(c, 1, Integer::sum);
        double resultado = 0;
        for (int n : freq.values()) {
            double p = (double) n / texto.length();
            resultado -= p * (Math.log(p) / Math.log(2));
        }
        return resultado;
    }
}
