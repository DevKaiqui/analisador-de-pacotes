import java.io.File;
import java.net.InetAddress;
import java.util.List;

import org.pcap4j.core.BpfProgram;
import org.pcap4j.core.NotOpenException;
import org.pcap4j.core.PcapHandle;
import org.pcap4j.core.PcapNativeException;
import org.pcap4j.core.PcapNetworkInterface;
import org.pcap4j.core.Pcaps;
import org.pcap4j.packet.ArpPacket;
import org.pcap4j.packet.EthernetPacket;
import org.pcap4j.packet.IcmpV4CommonPacket;
import org.pcap4j.packet.IpPacket;
import org.pcap4j.packet.Packet;
import org.pcap4j.packet.TcpPacket;
import org.pcap4j.packet.UdpPacket;

public class Main {
    private static final int SNAPSHOT_LENGTH = 256;
    private static final int READ_TIMEOUT_MILLIS = 10;
    private static final int DEFAULT_MAX_PACKETS = 200;
    private static final int DEFAULT_DURATION_SECONDS = 60;
    private static final int MAX_FILTER_LENGTH = 120;
    private static final String WINDOWS_NPCAP_PATH = "C:\\Windows\\System32\\Npcap";
    private static final String DEFAULT_FILTER = "ip or arp";

    public static void main(String[] args) {
        try {
            configureNativePcapPath();

            List<PcapNetworkInterface> interfaces = Pcaps.findAllDevs();
            if (interfaces == null || interfaces.isEmpty()) {
                System.out.println("Nenhuma interface de rede foi encontrada.");
                return;
            }

            CaptureConfig config = CaptureConfig.parse(args);
            if (config.help) {
                printUsage();
                return;
            }

            if (config.listInterfaces) {
                printInterfaces(interfaces);
                return;
            }

            PcapNetworkInterface networkInterface = selectInterface(interfaces, config.interfaceArgument);
            if (networkInterface == null) {
                printInterfaces(interfaces);
                return;
            }

            System.out.println("Interface selecionada: " + describeInterface(networkInterface));
            System.out.println("Modo promiscuo: " + (config.promiscuous ? "ativado" : "desativado"));
            System.out.println("Filtro seguro: " + config.filter);
            System.out.println("Dados sensiveis: " + (config.showSensitiveData ? "visiveis" : "mascarados"));
            System.out.println("Limites: " + config.maxPackets + " pacotes ou " + config.durationSeconds + " segundos.");
            System.out.println("Capturando somente metadados. Pressione Ctrl+C para parar.");

            PcapHandle handle = networkInterface.openLive(
                    SNAPSHOT_LENGTH,
                    config.promiscuous
                            ? PcapNetworkInterface.PromiscuousMode.PROMISCUOUS
                            : PcapNetworkInterface.PromiscuousMode.NONPROMISCUOUS,
                    READ_TIMEOUT_MILLIS
            );

            try {
                handle.setFilter(config.filter, BpfProgram.BpfCompileMode.OPTIMIZE);

                int capturedPackets = 0;
                long deadlineMillis = System.currentTimeMillis() + (config.durationSeconds * 1000L);

                while (capturedPackets < config.maxPackets && System.currentTimeMillis() < deadlineMillis) {
                    Packet packet = handle.getNextPacket();
                    if (packet != null) {
                        capturedPackets++;
                        analyzePacket(packet, capturedPackets, config.showSensitiveData);
                    }
                }

                System.out.println("Captura finalizada com seguranca. Pacotes processados: " + capturedPackets);
            } finally {
                handle.close();
            }
        } catch (IllegalArgumentException e) {
            System.err.println("Parametro invalido: " + e.getMessage());
            printUsage();
        } catch (PcapNativeException e) {
            System.err.println("Erro ao acessar o capturador de pacotes: " + e.getMessage());
            System.err.println("No Windows, verifique se o Npcap esta instalado e execute como administrador.");
        } catch (NotOpenException e) {
            System.err.println("A captura foi encerrada antes da leitura do pacote.");
        } catch (UnsatisfiedLinkError e) {
            System.err.println("Nao foi possivel carregar a biblioteca nativa do Npcap/WinPcap.");
            System.err.println("Verifique se o Npcap esta instalado e se existe: " + WINDOWS_NPCAP_PATH + "\\wpcap.dll");
            System.err.println("Detalhe tecnico: " + e.getMessage());
        }
    }

    private static void configureNativePcapPath() {
        if (System.getProperty("jna.library.path") != null) {
            return;
        }

        File npcapDirectory = new File(WINDOWS_NPCAP_PATH);
        if (npcapDirectory.isDirectory()) {
            System.setProperty("jna.library.path", npcapDirectory.getAbsolutePath());
        }
    }

    private static PcapNetworkInterface selectInterface(List<PcapNetworkInterface> interfaces, String interfaceArgument) {
        if (interfaceArgument != null) {
            PcapNetworkInterface selected = findInterfaceByArgument(interfaces, interfaceArgument);
            if (selected != null) {
                return selected;
            }

            System.err.println("Interface nao encontrada: " + sanitize(interfaceArgument));
            return null;
        }

        for (PcapNetworkInterface networkInterface : interfaces) {
            if (!networkInterface.isLoopBack()
                    && networkInterface.isUp()
                    && !networkInterface.getAddresses().isEmpty()) {
                return networkInterface;
            }
        }

        for (PcapNetworkInterface networkInterface : interfaces) {
            if (!networkInterface.isLoopBack() && networkInterface.isUp()) {
                return networkInterface;
            }
        }

        return interfaces.get(0);
    }

    private static PcapNetworkInterface findInterfaceByArgument(
            List<PcapNetworkInterface> interfaces,
            String argument
    ) {
        if (argument == null || argument.trim().isEmpty()) {
            return null;
        }

        try {
            int index = Integer.parseInt(argument);
            if (index >= 0 && index < interfaces.size()) {
                return interfaces.get(index);
            }
        } catch (NumberFormatException ignored) {
            // The argument may be an interface name instead of a numeric index.
        }

        for (PcapNetworkInterface networkInterface : interfaces) {
            if (argument.equalsIgnoreCase(networkInterface.getName())
                    || argument.equalsIgnoreCase(networkInterface.getDescription())) {
                return networkInterface;
            }
        }

        return null;
    }

    private static void printInterfaces(List<PcapNetworkInterface> interfaces) {
        System.out.println("Interfaces disponiveis:");
        for (int i = 0; i < interfaces.size(); i++) {
            System.out.println(i + " - " + describeInterface(interfaces.get(i)));
        }
        System.out.println("Execute novamente informando --interface INDICE.");
    }

    private static String describeInterface(PcapNetworkInterface networkInterface) {
        String description = sanitize(networkInterface.getDescription());
        if (description == null || description.trim().isEmpty()) {
            description = "sem descricao";
        }

        return sanitize(networkInterface.getName()) + " (" + description + ")";
    }

    private static void analyzePacket(Packet packet, int packetNumber, boolean showSensitiveData) {
        try {
            EthernetPacket ethernet = packet.get(EthernetPacket.class);
            IpPacket ip = packet.get(IpPacket.class);
            TcpPacket tcp = packet.get(TcpPacket.class);
            UdpPacket udp = packet.get(UdpPacket.class);
            IcmpV4CommonPacket icmp = packet.get(IcmpV4CommonPacket.class);
            ArpPacket arp = packet.get(ArpPacket.class);

            StringBuilder output = new StringBuilder();
            output.append("#").append(packetNumber);
            output.append(" | tamanho=").append(packet.length()).append(" bytes");

            if (ethernet != null) {
                output.append(" | macOrigem=").append(formatSensitiveValue(
                        ethernet.getHeader().getSrcAddr().toString(),
                        showSensitiveData,
                        ValueKind.MAC
                ));
                output.append(" | macDestino=").append(formatSensitiveValue(
                        ethernet.getHeader().getDstAddr().toString(),
                        showSensitiveData,
                        ValueKind.MAC
                ));
            }

            if (ip != null) {
                InetAddress source = ip.getHeader().getSrcAddr();
                InetAddress destination = ip.getHeader().getDstAddr();
                output.append(" | ipOrigem=").append(formatSensitiveValue(
                        source.getHostAddress(),
                        showSensitiveData,
                        ValueKind.IP
                ));
                output.append(" | ipDestino=").append(formatSensitiveValue(
                        destination.getHostAddress(),
                        showSensitiveData,
                        ValueKind.IP
                ));
                output.append(" | protocolo=").append(ip.getHeader().getProtocol());
            }

            if (tcp != null) {
                output.append(" | tcp=").append(tcp.getHeader().getSrcPort())
                        .append(" -> ").append(tcp.getHeader().getDstPort());
            } else if (udp != null) {
                output.append(" | udp=").append(udp.getHeader().getSrcPort())
                        .append(" -> ").append(udp.getHeader().getDstPort());
            } else if (icmp != null) {
                output.append(" | icmp=").append(icmp.getHeader().getType());
            } else if (arp != null) {
                output.append(" | arp=").append(arp.getHeader().getOperation());
            }

            System.out.println(output.toString());
        } catch (RuntimeException e) {
            System.err.println("Pacote ignorado por falha de leitura segura: " + sanitize(e.getMessage()));
        }
    }

    private enum ValueKind {
        IP,
        MAC
    }

    private static String formatSensitiveValue(String value, boolean showSensitiveData, ValueKind kind) {
        if (showSensitiveData) {
            return sanitize(value);
        }

        if (value == null || value.trim().isEmpty()) {
            return "mascarado";
        }

        String sanitized = sanitize(value);
        int hash = sanitized.hashCode() & 0x7fffffff;
        String prefix = kind == ValueKind.IP ? "ip" : "mac";
        return prefix + "-mascarado-" + Integer.toHexString(hash);
    }

    private static String sanitize(String value) {
        if (value == null) {
            return null;
        }

        return value.replace('\r', ' ')
                .replace('\n', ' ')
                .replace('\t', ' ')
                .trim();
    }

    private static void printUsage() {
        System.out.println("Uso:");
        System.out.println("  java Main --list");
        System.out.println("  java Main --interface 3");
        System.out.println("  java Main --interface 3 --max-packets 100 --duration-seconds 30");
        System.out.println("  java Main --interface 3 --filter \"tcp or udp\"");
        System.out.println("Opcoes:");
        System.out.println("  --list                 Lista interfaces e sai.");
        System.out.println("  --interface VALOR      Indice, nome ou descricao da interface.");
        System.out.println("  --max-packets NUM      Limite de pacotes entre 1 e 10000. Padrao: 200.");
        System.out.println("  --duration-seconds NUM Limite de tempo entre 1 e 3600. Padrao: 60.");
        System.out.println("  --filter TEXTO         Filtro BPF seguro. Padrao: ip or arp.");
        System.out.println("  --promiscuous          Ativa modo promiscuo manualmente.");
        System.out.println("  --show-sensitive       Mostra IPs e MACs reais no terminal.");
        System.out.println("  --help                 Mostra esta ajuda.");
    }

    private static class CaptureConfig {
        private boolean help;
        private boolean listInterfaces;
        private boolean promiscuous;
        private boolean showSensitiveData;
        private String interfaceArgument;
        private String filter = DEFAULT_FILTER;
        private int maxPackets = DEFAULT_MAX_PACKETS;
        private int durationSeconds = DEFAULT_DURATION_SECONDS;

        private static CaptureConfig parse(String[] args) {
            CaptureConfig config = new CaptureConfig();

            for (int i = 0; i < args.length; i++) {
                String arg = args[i];

                if ("--help".equals(arg) || "-h".equals(arg)) {
                    config.help = true;
                } else if ("--list".equals(arg)) {
                    config.listInterfaces = true;
                } else if ("--promiscuous".equals(arg)) {
                    config.promiscuous = true;
                } else if ("--show-sensitive".equals(arg)) {
                    config.showSensitiveData = true;
                } else if ("--interface".equals(arg) || "-i".equals(arg)) {
                    config.interfaceArgument = requiredValue(args, ++i, arg);
                } else if ("--max-packets".equals(arg)) {
                    config.maxPackets = parseInt(requiredValue(args, ++i, arg), 1, 10000, arg);
                } else if ("--duration-seconds".equals(arg)) {
                    config.durationSeconds = parseInt(requiredValue(args, ++i, arg), 1, 3600, arg);
                } else if ("--filter".equals(arg)) {
                    config.filter = validateFilter(requiredValue(args, ++i, arg));
                } else if (!arg.startsWith("--") && config.interfaceArgument == null) {
                    config.interfaceArgument = arg;
                } else {
                    throw new IllegalArgumentException("opcao desconhecida: " + sanitize(arg));
                }
            }

            return config;
        }

        private static String requiredValue(String[] args, int index, String option) {
            if (index >= args.length || args[index].trim().isEmpty()) {
                throw new IllegalArgumentException("faltou valor para " + option);
            }

            return args[index].trim();
        }

        private static int parseInt(String value, int minimum, int maximum, String option) {
            try {
                int parsed = Integer.parseInt(value);
                if (parsed < minimum || parsed > maximum) {
                    throw new IllegalArgumentException(option + " deve ficar entre " + minimum + " e " + maximum);
                }
                return parsed;
            } catch (NumberFormatException e) {
                throw new IllegalArgumentException(option + " precisa ser numero inteiro");
            }
        }

        private static String validateFilter(String filter) {
            if (filter.length() > MAX_FILTER_LENGTH) {
                throw new IllegalArgumentException("--filter muito grande");
            }

            if (!filter.matches("[A-Za-z0-9_ .()!&|<>=:/-]+")) {
                throw new IllegalArgumentException("--filter contem caracteres nao permitidos");
            }

            return filter;
        }
    }
}
