package br.com.analisador.gui;

import br.com.analisador.Npcap;
import br.com.analisador.PacketAnalyzer;
import br.com.analisador.Placas;
import br.com.analisador.SensitiveDataMasker;
import br.com.analisador.detector.DetectorDeAmeacas;
import br.com.analisador.detector.Mascara;

import org.pcap4j.core.PcapNetworkInterface;
import org.pcap4j.packet.Packet;

import javax.swing.*;
import java.awt.*;
import java.util.List;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * Janela principal do analisador de pacotes.
 * Permite escolher a placa de rede, aplicar um filtro, iniciar/parar a captura
 * e acompanhar pacotes e alertas de segurança, tudo sem usar o terminal.
 */
public final class JanelaPrincipal extends JFrame {

    private final JComboBox<ItemInterface> comboInterfaces = new JComboBox<>();
    private final JTextField campoFiltro = new JTextField(18);
    private final JCheckBox checkSensivel = new JCheckBox("Mostrar dados sensíveis");
    private final JButton botaoIniciar = new JButton("Iniciar");
    private final JButton botaoParar = new JButton("Parar");
    private final JButton botaoLimpar = new JButton("Limpar");
    private final JLabel status = new JLabel("Pronto.");

    private final ModeloPacotes modeloPacotes = new ModeloPacotes(5000);
    private final ModeloAlertas modeloAlertas = new ModeloAlertas();

    private final ServicoCaptura servico = new ServicoCaptura();
    private final SensitiveDataMasker masker = new SensitiveDataMasker();
    private final PacketAnalyzer analyzer = new PacketAnalyzer(masker);
    private final AtomicInteger contador = new AtomicInteger();
    private DetectorDeAmeacas detector;

    public JanelaPrincipal() {
        super("Analisador de Pacotes");
        setDefaultCloseOperation(EXIT_ON_CLOSE);
        setSize(1000, 640);
        setLocationRelativeTo(null);
        montarLayout();
        carregarInterfaces();
        botaoParar.setEnabled(false);
    }

    private void montarLayout() {
        JPanel topo = new JPanel(new FlowLayout(FlowLayout.LEFT));
        topo.add(new JLabel("Placa:"));
        topo.add(comboInterfaces);
        topo.add(new JLabel("Filtro:"));
        topo.add(campoFiltro);
        topo.add(checkSensivel);
        topo.add(botaoIniciar);
        topo.add(botaoParar);
        topo.add(botaoLimpar);

        JTable tabelaPacotes = new JTable(modeloPacotes);
        tabelaPacotes.getColumnModel().getColumn(0).setMaxWidth(60);

        JTable tabelaAlertas = new JTable(modeloAlertas);
        tabelaAlertas.setDefaultRenderer(Object.class, new RenderizadorSeveridade());
        tabelaAlertas.getColumnModel().getColumn(0).setMaxWidth(70);
        tabelaAlertas.getColumnModel().getColumn(1).setMaxWidth(90);

        JScrollPane painelPacotes = new JScrollPane(tabelaPacotes);
        painelPacotes.setBorder(BorderFactory.createTitledBorder("Pacotes"));
        JScrollPane painelAlertas = new JScrollPane(tabelaAlertas);
        painelAlertas.setBorder(BorderFactory.createTitledBorder("Alertas de segurança"));

        JSplitPane divisao = new JSplitPane(JSplitPane.VERTICAL_SPLIT, painelPacotes, painelAlertas);
        divisao.setResizeWeight(0.6);

        setLayout(new BorderLayout(6, 6));
        add(topo, BorderLayout.NORTH);
        add(divisao, BorderLayout.CENTER);
        add(status, BorderLayout.SOUTH);

        botaoIniciar.addActionListener(e -> iniciar());
        botaoParar.addActionListener(e -> {
            parar();
            // invokeLater: roda depois das atualizações de pacotes que ainda estão na fila, para não ser sobrescrito
            SwingUtilities.invokeLater(() -> status.setText("Captura parada.   |   Pacotes: " + contador.get()
                    + "   |   " + detector.resumo()));
        });
        botaoLimpar.addActionListener(e -> {
            modeloPacotes.limpar();
            modeloAlertas.limpar();
            contador.set(0);
        });
    }

    private void carregarInterfaces() {
        try {
            List<PcapNetworkInterface> nifs = ServicoCaptura.listarInterfaces();
            if (nifs.isEmpty()) {
                status.setText("Nenhuma placa encontrada. Abra como administrador e confira o Npcap.");
                botaoIniciar.setEnabled(false);
                return;
            }
            ItemInterface padrao = new ItemInterface(Placas.escolherPadrao(nifs));
            for (PcapNetworkInterface nif : nifs) comboInterfaces.addItem(new ItemInterface(nif));
            comboInterfaces.setSelectedItem(padrao);
        } catch (Exception e) {
            status.setText("Erro ao listar placas: " + e.getMessage()
                    + " (rode como administrador e verifique o Npcap)");
            botaoIniciar.setEnabled(false);
        }
    }

    private void iniciar() {
        ItemInterface item = (ItemInterface) comboInterfaces.getSelectedItem();
        if (item == null) return;

        boolean mostrarSensivel = checkSensivel.isSelected();
        detector = DetectorDeAmeacas.padrao(new Mascara(
                ip -> masker.maskIp(ip, mostrarSensivel),
                mac -> masker.maskMac(mac, mostrarSensivel)));
        detector.aoDetectar(alerta -> SwingUtilities.invokeLater(() -> modeloAlertas.adicionar(alerta)));

        try {
            servico.iniciar(item.nif, campoFiltro.getText(),
                    pacote -> processar(pacote, mostrarSensivel),
                    msg -> SwingUtilities.invokeLater(() -> {
                        status.setText("Captura interrompida: " + msg);
                        parar();
                    }));
            botaoIniciar.setEnabled(false);
            botaoParar.setEnabled(true);
            comboInterfaces.setEnabled(false);
            status.setText("Capturando em " + item + " ...");
        } catch (Exception e) {
            JOptionPane.showMessageDialog(this,
                    "Não foi possível iniciar a captura:\n" + e.getMessage()
                            + "\n\nDicas: rode como administrador; confira o filtro BPF.",
                    "Erro", JOptionPane.ERROR_MESSAGE);
        }
    }

    private void processar(Packet pacote, boolean mostrarSensivel) {
        int numero = contador.incrementAndGet();
        String descricao = analyzer.describe(pacote, numero, mostrarSensivel);
        detector.processar(pacote);
        SwingUtilities.invokeLater(() -> {
            modeloPacotes.adicionar(numero, descricao);
            status.setText("Pacotes: " + numero + "   |   " + detector.resumo());
        });
    }

    private void parar() {
        servico.parar();
        botaoIniciar.setEnabled(true);
        botaoParar.setEnabled(false);
        comboInterfaces.setEnabled(true);
    }

    /** Embrulha a placa para mostrar um nome legível no combo. */
    private record ItemInterface(PcapNetworkInterface nif) {
        @Override public String toString() {
            String desc = nif.getDescription();
            return (desc != null && !desc.isBlank()) ? desc : nif.getName();
        }
    }

    public static void main(String[] args) {
        Npcap.configurar();
        try {
            UIManager.setLookAndFeel(UIManager.getSystemLookAndFeelClassName());
        } catch (Exception ignored) { }
        SwingUtilities.invokeLater(() -> new JanelaPrincipal().setVisible(true));
    }
}
