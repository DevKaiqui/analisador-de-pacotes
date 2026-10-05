package br.com.analisador;

import br.com.analisador.detector.DetectorDeAmeacas;
import br.com.analisador.detector.ImpressoraDeAlertas;
import org.pcap4j.core.*;
import org.pcap4j.core.PcapNetworkInterface.PromiscuousMode;

import java.io.EOFException;
import java.util.List;
import java.util.concurrent.TimeoutException;
import java.util.concurrent.atomic.AtomicLong;

public final class AnalisadorDePacotes {

    private static final String USO = """
            Uso: java -jar analisador-de-pacotes.jar [opções]
              -l                 lista as interfaces de rede e sai
              -i <número>        captura na interface indicada (padrão: primeira com IPv4)
              -r <arquivo.pcap>  analisa um arquivo .pcap em vez da rede ao vivo
              -f <filtro BPF>    filtro de captura, ex.: "tcp or arp or udp port 53"
              --sem-mascara      mostra IPs e MACs completos nos alertas
              --sem-cores        desativa cores no terminal
              -h                 mostra esta ajuda
            """;

    public static void main(String[] args) throws Exception {
        Npcap.configurar();
        Integer indice = null;
        String arquivo = null;
        String filtro = null;
        boolean mascarar = true;
        boolean cores = System.console() != null;

        for (int i = 0; i < args.length; i++) {
            switch (args[i]) {
                case "-l" -> { listarInterfaces(); return; }
                case "-i" -> indice = Integer.parseInt(valor(args, ++i));
                case "-r" -> arquivo = valor(args, ++i);
                case "-f" -> filtro = valor(args, ++i);
                case "--sem-mascara" -> mascarar = false;
                case "--sem-cores" -> cores = false;
                case "-h", "--help" -> { System.out.print(USO); return; }
                default -> { System.err.println("Opção desconhecida: " + args[i]); System.err.print(USO); System.exit(2); }
            }
        }

        DetectorDeAmeacas detector = DetectorDeAmeacas.padrao(new SensitiveDataMasker().comoMascara(!mascarar));
        detector.aoDetectar(new ImpressoraDeAlertas(cores));

        if (arquivo != null) {
            analisarArquivo(arquivo, filtro, detector);
        } else {
            capturarAoVivo(indice, filtro, detector);
        }
    }

    private static String valor(String[] args, int i) {
        if (i >= args.length) {
            System.err.println("Faltou o valor da opção " + args[i - 1]);
            System.exit(2);
        }
        return args[i];
    }

    private static void listarInterfaces() throws PcapNativeException {
        List<PcapNetworkInterface> interfaces = Pcaps.findAllDevs();
        for (int i = 0; i < interfaces.size(); i++) {
            PcapNetworkInterface nif = interfaces.get(i);
            System.out.printf("[%d] %s%n    %s%n", i,
                    nif.getDescription() != null ? nif.getDescription() : nif.getName(),
                    nif.getAddresses().stream().map(a -> a.getAddress().getHostAddress()).toList());
        }
    }

    private static PcapNetworkInterface escolherInterface(Integer indice) throws PcapNativeException {
        List<PcapNetworkInterface> interfaces = Pcaps.findAllDevs();
        if (interfaces.isEmpty()) {
            throw new IllegalStateException("Nenhuma interface encontrada. O Npcap está instalado e você executou como administrador?");
        }
        return indice != null ? interfaces.get(indice) : Placas.escolherPadrao(interfaces);
    }

    private static void capturarAoVivo(Integer indice, String filtro, DetectorDeAmeacas detector) throws Exception {
        PcapNetworkInterface nif = escolherInterface(indice);
        PcapHandle handle = nif.openLive(65536, PromiscuousMode.PROMISCUOUS, 100);
        if (filtro != null) handle.setFilter(filtro, BpfProgram.BpfCompileMode.OPTIMIZE);

        AtomicLong pacotes = new AtomicLong();
        Runtime.getRuntime().addShutdownHook(new Thread(() -> {
            System.out.println();
            System.out.println("Pacotes analisados: " + pacotes.get());
            System.out.println(detector.resumo());
        }));

        System.out.println("Capturando em: " + (nif.getDescription() != null ? nif.getDescription() : nif.getName()));
        System.out.println("Pressione Ctrl+C para encerrar.");
        handle.loop(-1, (PacketListener) pacote -> {
            pacotes.incrementAndGet();
            detector.processar(pacote);
        });
    }

    private static void analisarArquivo(String arquivo, String filtro, DetectorDeAmeacas detector) throws Exception {
        long pacotes = 0;
        try (PcapHandle handle = Pcaps.openOffline(arquivo)) {
            if (filtro != null) handle.setFilter(filtro, BpfProgram.BpfCompileMode.OPTIMIZE);
            while (true) {
                try {
                    var pacote = handle.getNextPacketEx();
                    pacotes++;
                    detector.processar(pacote, handle.getTimestamp().getTime());
                } catch (TimeoutException e) {
                    // sem pacote neste instante, segue lendo
                } catch (EOFException e) {
                    break;
                }
            }
        }
        System.out.println("Pacotes analisados: " + pacotes);
        System.out.println(detector.resumo());
    }
}
