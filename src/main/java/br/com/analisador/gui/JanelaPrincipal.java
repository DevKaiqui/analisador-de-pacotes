package br.com.analisador.gui;

import br.com.analisador.Npcap;
import br.com.analisador.PacketAnalyzer;
import br.com.analisador.PacketAnalyzer.LinhaPacote;
import br.com.analisador.Placas;
import br.com.analisador.SensitiveDataMasker;
import br.com.analisador.detector.Alerta;
import br.com.analisador.detector.DetectorDeAmeacas;
import br.com.analisador.detector.Mascara;
import br.com.analisador.detector.Severidade;

import org.pcap4j.core.PcapNetworkInterface;
import org.pcap4j.packet.Packet;

import javax.swing.*;
import javax.swing.border.TitledBorder;
import javax.swing.table.DefaultTableCellRenderer;
import java.awt.*;
import java.util.EnumMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * Janela principal do analisador de pacotes.
 * Permite escolher a placa de rede, aplicar um filtro, iniciar/parar a captura
 * e acompanhar pacotes e alertas de segurança, tudo sem usar o terminal.
 */
public final class JanelaPrincipal extends JFrame {

    private static final Color VERDE = new Color(0x2E, 0x7D, 0x32);
    private static final Color VERMELHO = new Color(0xC6, 0x28, 0x28);
    private static final Color CINZA = new Color(0x9E, 0x9E, 0x9E);
    private static final Color ZEBRA = new Color(0xF2, 0xF4, 0xF7);

    /** Filtro BPF pronto para o combo de filtros rápidos. */
    private record FiltroRapido(String nome, String filtro) {
        @Override public String toString() { return nome; }
    }

    private final JComboBox<ItemInterface> comboInterfaces = new JComboBox<>();
    private final JTextField campoFiltro = new JTextField(16);
    private final JComboBox<FiltroRapido> comboFiltrosRapidos = new JComboBox<>(new FiltroRapido[]{
            new FiltroRapido("Tudo", ""),
            new FiltroRapido("TCP", "tcp"),
            new FiltroRapido("DNS (udp port 53)", "udp port 53"),
            new FiltroRapido("ARP", "arp"),
    });
    private final JCheckBox checkSensivel = new JCheckBox("Mostrar dados sensíveis");
    private final JButton botaoIniciar = new JButton("Iniciar");
    private final JButton botaoParar = new JButton("Parar");
    private final JButton botaoLimpar = new JButton("Limpar");
    private final JLabel bolinhaStatus = new JLabel("●");
    private final JLabel textoStatusCaptura = new JLabel("Parado");
    private final JLabel status = new JLabel("Pronto.");

    private final JLabel lblPacotes = new JLabel("Pacotes: 0");
    private final Map<Severidade, JLabel> lblAlertasPorSeveridade = new EnumMap<>(Severidade.class);
    private final Map<Severidade, Integer> contagemAlertas = new EnumMap<>(Severidade.class);

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
        for (Severidade s : Severidade.values()) contagemAlertas.put(s, 0);
        montarLayout();
        carregarInterfaces();
        botaoParar.setEnabled(false);
    }

    private void montarLayout() {
        JPanel painelCaptura = new JPanel(new FlowLayout(FlowLayout.LEFT, 6, 4));
        painelCaptura.setBorder(tituloSecao("Captura"));
        painelCaptura.add(new JLabel("Placa:"));
        painelCaptura.add(comboInterfaces);
        painelCaptura.add(botaoIniciar);
        painelCaptura.add(botaoParar);

        JPanel painelFiltro = new JPanel(new FlowLayout(FlowLayout.LEFT, 6, 4));
        painelFiltro.setBorder(tituloSecao("Filtro"));
        painelFiltro.add(new JLabel("BPF:"));
        painelFiltro.add(campoFiltro);
        painelFiltro.add(new JLabel("Rápidos:"));
        painelFiltro.add(comboFiltrosRapidos);

        JPanel painelExibicao = new JPanel(new FlowLayout(FlowLayout.LEFT, 6, 4));
        painelExibicao.setBorder(tituloSecao("Exibição"));
        painelExibicao.add(checkSensivel);
        painelExibicao.add(botaoLimpar);
        bolinhaStatus.setForeground(CINZA);
        painelExibicao.add(bolinhaStatus);
        painelExibicao.add(textoStatusCaptura);

        estilizarBotaoPrimario(botaoIniciar, VERDE);
        estilizarBotaoPrimario(botaoParar, VERMELHO);

        JPanel controles = new JPanel();
        controles.setLayout(new BoxLayout(controles, BoxLayout.Y_AXIS));
        JPanel linha1 = new JPanel(new FlowLayout(FlowLayout.LEFT, 8, 0));
        linha1.add(painelCaptura);
        linha1.add(painelFiltro);
        linha1.add(painelExibicao);
        controles.add(linha1);

        JPanel painelResumo = montarPainelResumo();

        JPanel topo = new JPanel(new BorderLayout(8, 4));
        topo.add(controles, BorderLayout.CENTER);
        topo.add(painelResumo, BorderLayout.EAST);

        JTable tabelaPacotes = new JTable(modeloPacotes);
        ajustarLargurasPacotes(tabelaPacotes);
        aplicarZebra(tabelaPacotes);
        deixarCabecalhoEmNegrito(tabelaPacotes);

        JTable tabelaAlertas = new JTable(modeloAlertas);
        tabelaAlertas.setDefaultRenderer(Object.class, new RenderizadorSeveridade());
        tabelaAlertas.getColumnModel().getColumn(0).setMaxWidth(70);
        tabelaAlertas.getColumnModel().getColumn(1).setMaxWidth(90);
        deixarCabecalhoEmNegrito(tabelaAlertas);

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

        comboFiltrosRapidos.addActionListener(e -> {
            FiltroRapido f = (FiltroRapido) comboFiltrosRapidos.getSelectedItem();
            if (f != null) campoFiltro.setText(f.filtro());
        });

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
            for (Severidade s : Severidade.values()) contagemAlertas.put(s, 0);
            atualizarResumo();
        });
    }

    private JPanel montarPainelResumo() {
        JPanel painel = new JPanel(new GridLayout(0, 1, 2, 2));
        painel.setBorder(tituloSecao("Resumo"));
        lblPacotes.setFont(lblPacotes.getFont().deriveFont(Font.BOLD));
        painel.add(lblPacotes);
        for (Severidade s : Severidade.values()) {
            JLabel lbl = new JLabel(s.name() + ": 0");
            lbl.setFont(lbl.getFont().deriveFont(Font.BOLD));
            lbl.setForeground(corResumo(s));
            lblAlertasPorSeveridade.put(s, lbl);
            painel.add(lbl);
        }
        return painel;
    }

    private static Color corResumo(Severidade s) {
        return switch (s) {
            case CRITICA -> new Color(0xB0, 0x00, 0x20);
            case ALTA -> new Color(0xC6, 0x28, 0x28);
            case MEDIA -> new Color(0x8A, 0x6D, 0x00);
            case BAIXA -> new Color(0x0C, 0x5A, 0x6E);
        };
    }

    private void atualizarResumo() {
        lblPacotes.setText("Pacotes: " + contador.get());
        for (Severidade s : Severidade.values()) {
            lblAlertasPorSeveridade.get(s).setText(s.name() + ": " + contagemAlertas.get(s));
        }
    }

    private static TitledBorder tituloSecao(String texto) {
        TitledBorder borda = BorderFactory.createTitledBorder(texto);
        borda.setTitleFont(borda.getTitleFont().deriveFont(Font.BOLD));
        return borda;
    }

    private static void estilizarBotaoPrimario(JButton botao, Color cor) {
        botao.setBackground(cor);
        botao.setForeground(Color.WHITE);
        botao.setOpaque(true);
        botao.setContentAreaFilled(true);
        botao.setBorderPainted(false);
        botao.setFocusPainted(false);
    }

    private static void aplicarZebra(JTable tabela) {
        tabela.setDefaultRenderer(Object.class, new DefaultTableCellRenderer() {
            @Override
            public Component getTableCellRendererComponent(JTable t, Object valor, boolean selecionado,
                    boolean foco, int linha, int coluna) {
                Component c = super.getTableCellRendererComponent(t, valor, selecionado, foco, linha, coluna);
                if (!selecionado) c.setBackground(linha % 2 == 0 ? Color.WHITE : ZEBRA);
                return c;
            }
        });
    }

    /** Nº e portas ficam estreitas; Origem/Destino, mais largas, concentram o espaço disponível. */
    private static void ajustarLargurasPacotes(JTable tabela) {
        var colunas = tabela.getColumnModel();
        colunas.getColumn(0).setMaxWidth(50);   // Nº
        colunas.getColumn(1).setMaxWidth(90);   // Protocolo
        colunas.getColumn(2).setPreferredWidth(220); // Origem
        colunas.getColumn(3).setPreferredWidth(220); // Destino
        colunas.getColumn(4).setMaxWidth(100);  // Porta origem
        colunas.getColumn(5).setMaxWidth(100);  // Porta destino
        colunas.getColumn(6).setMaxWidth(90);   // Tamanho
    }

    private static void deixarCabecalhoEmNegrito(JTable tabela) {
        Font fonte = tabela.getTableHeader().getFont();
        tabela.getTableHeader().setFont(fonte.deriveFont(Font.BOLD));
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
        detector.aoDetectar(this::registrarAlerta);

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
            bolinhaStatus.setForeground(VERDE);
            textoStatusCaptura.setText("Capturando...");
            status.setText("Capturando em " + item + " ...");
        } catch (Exception e) {
            JOptionPane.showMessageDialog(this,
                    "Não foi possível iniciar a captura:\n" + e.getMessage()
                            + "\n\nDicas: rode como administrador; confira o filtro BPF.",
                    "Erro", JOptionPane.ERROR_MESSAGE);
        }
    }

    private void registrarAlerta(Alerta alerta) {
        SwingUtilities.invokeLater(() -> {
            modeloAlertas.adicionar(alerta);
            contagemAlertas.merge(alerta.severidade(), 1, Integer::sum);
            atualizarResumo();
        });
    }

    private void processar(Packet pacote, boolean mostrarSensivel) {
        int numero = contador.incrementAndGet();
        LinhaPacote linha = analyzer.analisar(pacote, numero, mostrarSensivel);
        detector.processar(pacote);
        SwingUtilities.invokeLater(() -> {
            modeloPacotes.adicionar(linha);
            atualizarResumo();
        });
    }

    private void parar() {
        servico.parar();
        botaoIniciar.setEnabled(true);
        botaoParar.setEnabled(false);
        comboInterfaces.setEnabled(true);
        bolinhaStatus.setForeground(CINZA);
        textoStatusCaptura.setText("Parado");
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
