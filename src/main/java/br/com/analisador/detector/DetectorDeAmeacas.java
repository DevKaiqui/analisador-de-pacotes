package br.com.analisador.detector;

import org.pcap4j.packet.Packet;

import java.util.*;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.function.Consumer;

/**
 * Motor central: recebe cada pacote, roda todas as regras e avisa os ouvintes
 * (o console, uma futura interface gráfica, um log...) quando algo é detectado.
 */
public final class DetectorDeAmeacas {

    private final List<RegraDeteccao> regras = new ArrayList<>();
    private final List<Consumer<Alerta>> ouvintes = new CopyOnWriteArrayList<>();
    private final Map<String, Long> ultimoAlerta = new HashMap<>();
    private final Map<Severidade, Long> contagem = new EnumMap<>(Severidade.class);
    private final long cooldownMs;
    private long ultimaLimpeza = 0;

    /** @param cooldownMs tempo mínimo entre alertas iguais */
    public DetectorDeAmeacas(long cooldownMs) {
        this.cooldownMs = cooldownMs;
    }

    /** Detector com todas as regras padrão, respeitando a máscara informada. */
    public static DetectorDeAmeacas padrao(Mascara mascara) {
        DetectorDeAmeacas d = new DetectorDeAmeacas(30_000);
        d.adicionarRegra(new DetectorPortScan(mascara));
        d.adicionarRegra(new DetectorSynFlood(mascara));
        d.adicionarRegra(new DetectorArpSpoofing(mascara));
        d.adicionarRegra(new DetectorDnsSuspeito(mascara));
        return d;
    }

    public void adicionarRegra(RegraDeteccao regra) {
        regras.add(regra);
    }

    public void aoDetectar(Consumer<Alerta> ouvinte) {
        ouvintes.add(ouvinte);
    }

    public void processar(Packet pacote) {
        processar(pacote, System.currentTimeMillis());
    }

    /** Versão com timestamp explícito (útil para arquivos .pcap e testes). */
    public synchronized void processar(Packet pacote, long agoraMs) {
        for (RegraDeteccao regra : regras) {
            try {
                regra.analisar(pacote, agoraMs).ifPresent(a -> emitir(a, agoraMs));
            } catch (RuntimeException e) {
                // Pacote malformado não pode derrubar a captura
            }
        }
        if (agoraMs - ultimaLimpeza > 30_000) {
            regras.forEach(r -> r.limpar(agoraMs));
            ultimoAlerta.values().removeIf(t -> agoraMs - t > cooldownMs);
            ultimaLimpeza = agoraMs;
        }
    }

    private void emitir(Alerta alerta, long agoraMs) {
        Long anterior = ultimoAlerta.get(alerta.chave());
        if (anterior != null && agoraMs - anterior < cooldownMs) return; // evita spam

        ultimoAlerta.put(alerta.chave(), agoraMs);
        contagem.merge(alerta.severidade(), 1L, Long::sum);
        for (Consumer<Alerta> ouvinte : ouvintes) ouvinte.accept(alerta);
    }

    /** Resumo para mostrar ao encerrar a captura. */
    public synchronized String resumo() {
        long total = contagem.values().stream().mapToLong(Long::longValue).sum();
        if (total == 0) return "Nenhuma ameaça detectada.";
        StringBuilder sb = new StringBuilder("Alertas: ").append(total).append(" (");
        StringJoiner partes = new StringJoiner(", ");
        contagem.forEach((sev, n) -> partes.add(sev + "=" + n));
        return sb.append(partes).append(")").toString();
    }
}
