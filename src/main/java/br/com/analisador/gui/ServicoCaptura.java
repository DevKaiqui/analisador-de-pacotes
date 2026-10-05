package br.com.analisador.gui;

import org.pcap4j.core.*;
import org.pcap4j.core.BpfProgram.BpfCompileMode;
import org.pcap4j.core.PcapNetworkInterface.PromiscuousMode;
import org.pcap4j.packet.Packet;

import java.util.List;
import java.util.function.Consumer;

/**
 * Cuida da captura em si, numa thread separada da interface.
 * Converte as chamadas do Pcap4J em callbacks simples que a janela consome.
 */
public final class ServicoCaptura {

    private volatile PcapHandle handle;
    private Thread thread;

    /** Lista as placas de rede disponíveis. */
    public static List<PcapNetworkInterface> listarInterfaces() throws PcapNativeException {
        return Pcaps.findAllDevs();
    }

    public boolean estaCapturando() {
        return handle != null && handle.isOpen();
    }

    /**
     * Inicia a captura.
     * @param filtro filtro BPF (ex.: "tcp", "udp port 53"); vazio = tudo
     * @param aoReceber chamado para cada pacote (fora da thread da interface)
     * @param aoFalhar chamado se a captura quebrar
     */
    public void iniciar(PcapNetworkInterface nif, String filtro,
                        Consumer<Packet> aoReceber, Consumer<String> aoFalhar) throws PcapNativeException, NotOpenException {
        handle = nif.openLive(65536, PromiscuousMode.PROMISCUOUS, 10);
        if (filtro != null && !filtro.isBlank()) {
            handle.setFilter(filtro.trim(), BpfCompileMode.OPTIMIZE);
        }

        PacketListener listener = aoReceber::accept;
        thread = new Thread(() -> {
            try {
                handle.loop(-1, listener);
            } catch (InterruptedException e) {
                // parada normal pelo botão
            } catch (Exception e) {
                aoFalhar.accept(e.getMessage());
            }
        }, "captura-pcap");
        thread.setDaemon(true);
        thread.start();
    }

    public void parar() {
        try {
            if (handle != null && handle.isOpen()) {
                handle.breakLoop();
                handle.close();
            }
        } catch (Exception ignored) {
        } finally {
            handle = null;
        }
    }
}
