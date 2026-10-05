package br.com.analisador.detector;

import org.pcap4j.packet.Packet;

import java.util.Optional;

/** Contrato de toda regra. Para criar uma regra nova, implemente esta interface. */
public interface RegraDeteccao {

    String nome();

    /** Analisa um pacote e devolve um alerta, se houver. */
    Optional<Alerta> analisar(Packet pacote, long agoraMs);

    /** Remove dados antigos para a memória não crescer sem limite. */
    default void limpar(long agoraMs) { }
}
