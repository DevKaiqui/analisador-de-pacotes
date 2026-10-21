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
import br.com.analisador.ia.ClienteClaude;
import br.com.analisador.ia.ClienteOllama;
import br.com.analisador.ia.ExplicadorDeAlertas;
import br.com.analisador.ia.ModeloDeLinguagem;
import br.com.analisador.ia.ProvedorIA;

import org.pcap4j.core.PcapNetworkInterface;
import org.pcap4j.packet.Packet;

import javax.swing.*;
import javax.swing.border.TitledBorder;
import java.awt.*;
import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;
import java.util.EnumMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * Janela principal do analisador de pacotes.
 * Permite escolher a placa de rede, aplicar um filtro, iniciar/parar a captura
 * e acompanhar pacotes e alertas de segurança, tudo sem usar o terminal.
 */
public final class JanelaPrincipal extends JFrame {

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
    private final JButton botaoExplicarIA = new JButton("Explicar com IA");
    private final JLabel bolinhaStatus = new JLabel("●");
    private final JLabel textoStatusCaptura = new JLabel("Parado");
    private final JLabel status = new JLabel("Pronto.");

    private final CartaoMetrica cartaoPacotes = new CartaoMetrica("Pacotes capturados", UIManager.getColor("Component.accentColor"));
    private final Map<Severidade, CartaoMetrica> cartoesPorSeveridade = new EnumMap<>(Severidade.class);
    private final Map<Severidade, Integer> contagemAlertas = new EnumMap<>(Severidade.class);

    private final ModeloPacotes modeloPacotes = new ModeloPacotes(5000);
    private final ModeloAlertas modeloAlertas = new ModeloAlertas();

    private final ServicoCaptura servico = new ServicoCaptura();
    private final SensitiveDataMasker masker = new SensitiveDataMasker();
    private final PacketAnalyzer analyzer = new PacketAnalyzer(masker);
    private final AtomicInteger contador = new AtomicInteger();
    private DetectorDeAmeacas detector;

    /** Escolhido por ANALISADOR_IA ao abrir o programa. */
    private final ProvedorIA provedorIA = ProvedorIA.doAmbiente();
    /** Criado na primeira consulta à IA; guarda as respostas já recebidas. */
    private ExplicadorDeAlertas explicador;
    private boolean envioParaIAConfirmado = false;

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
        bolinhaStatus.setForeground(Tema.corInativo());
        painelExibicao.add(bolinhaStatus);
        painelExibicao.add(textoStatusCaptura);

        Tema.botaoPrimario(botaoIniciar, "$Actions.Green", "#ffffff");
        botaoIniciar.setIcon(Tema.icone("iniciar", Color.WHITE));
        Tema.botaoPrimario(botaoParar, "$Actions.Red", "#ffffff");
        botaoParar.setIcon(Tema.icone("parar", Color.WHITE));
        botaoLimpar.setIcon(Tema.icone("limpar", "Button.foreground"));

        JPanel controles = new JPanel();
        controles.setLayout(new BoxLayout(controles, BoxLayout.Y_AXIS));
        JPanel linha1 = new JPanel(new FlowLayout(FlowLayout.LEFT, 8, 0));
        linha1.add(painelCaptura);
        linha1.add(painelFiltro);
        linha1.add(painelExibicao);
        controles.add(linha1);

        JPanel topo = new JPanel(new BorderLayout(8, 8));
        topo.add(controles, BorderLayout.NORTH);
        topo.add(montarCartoes(), BorderLayout.CENTER);

        JTable tabelaPacotes = new JTable(modeloPacotes);
        ajustarLargurasPacotes(tabelaPacotes);
        deixarCabecalhoEmNegrito(tabelaPacotes);

        JTable tabelaAlertas = new JTable(modeloAlertas);
        tabelaAlertas.setDefaultRenderer(Object.class, new RenderizadorSeveridade());
        tabelaAlertas.getColumnModel().getColumn(0).setMaxWidth(80);
        tabelaAlertas.getColumnModel().getColumn(1).setCellRenderer(new SeloSeveridade());
        tabelaAlertas.getColumnModel().getColumn(1).setMinWidth(100);
        tabelaAlertas.getColumnModel().getColumn(1).setMaxWidth(110);
        tabelaAlertas.setRowHeight(Math.max(tabelaAlertas.getRowHeight(), new SeloSeveridade().getPreferredSize().height + 4));
        deixarCabecalhoEmNegrito(tabelaAlertas);

        JScrollPane painelPacotes = new JScrollPane(tabelaPacotes);
        painelPacotes.setBorder(BorderFactory.createTitledBorder("Pacotes"));
        JScrollPane rolagemAlertas = new JScrollPane(tabelaAlertas);

        Tema.botaoPrimario(botaoExplicarIA, Tema.DESTAQUE, "#0b1a1e");
        botaoExplicarIA.setIcon(Tema.icone("ia", new Color(0x0B1A1E)));
        botaoExplicarIA.setToolTipText("Pede à IA uma explicação em português do alerta selecionado (ou dê duplo clique no alerta)");
        botaoExplicarIA.addActionListener(e -> explicarComIA(tabelaAlertas));
        tabelaAlertas.addMouseListener(new MouseAdapter() {
            @Override public void mouseClicked(MouseEvent e) {
                if (e.getClickCount() == 2) explicarComIA(tabelaAlertas);
            }
        });
        JPanel barraAlertas = new JPanel(new FlowLayout(FlowLayout.LEFT, 6, 4));
        barraAlertas.add(botaoExplicarIA);
        barraAlertas.add(new JLabel("Selecione um alerta (ou dê duplo clique) para a IA explicar.   IA: "
                + provedorIA.nomeExibicao()));

        JPanel painelAlertas = new JPanel(new BorderLayout());
        painelAlertas.setBorder(BorderFactory.createTitledBorder("Alertas de segurança"));
        painelAlertas.add(rolagemAlertas, BorderLayout.CENTER);
        painelAlertas.add(barraAlertas, BorderLayout.SOUTH);

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

    /** Cartões do topo: total de pacotes e alertas por severidade, da mais grave para a mais leve. */
    private JPanel montarCartoes() {
        JPanel painel = new JPanel(new GridLayout(1, 0, 12, 0));
        painel.add(cartaoPacotes);
        Severidade[] ordem = {Severidade.CRITICA, Severidade.ALTA, Severidade.MEDIA, Severidade.BAIXA};
        for (Severidade s : ordem) {
            CartaoMetrica cartao = new CartaoMetrica("Alertas " + nomeSeveridade(s), Tema.corSeveridade(s));
            cartoesPorSeveridade.put(s, cartao);
            painel.add(cartao);
        }
        return painel;
    }

    private static String nomeSeveridade(Severidade s) {
        return switch (s) {
            case CRITICA -> "críticos";
            case ALTA -> "altos";
            case MEDIA -> "médios";
            case BAIXA -> "baixos";
        };
    }

    private void atualizarResumo() {
        cartaoPacotes.setValor(contador.get());
        for (Severidade s : Severidade.values()) {
            cartoesPorSeveridade.get(s).setValor(contagemAlertas.get(s));
        }
    }

    private static TitledBorder tituloSecao(String texto) {
        TitledBorder borda = BorderFactory.createTitledBorder(texto);
        borda.setTitleFont(borda.getTitleFont().deriveFont(Font.BOLD));
        return borda;
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
            bolinhaStatus.setForeground(Tema.corAtivo());
            textoStatusCaptura.setText("Capturando...");
            status.setText("Capturando em " + item + " ...");
        } catch (Exception e) {
            JOptionPane.showMessageDialog(this,
                    "Não foi possível iniciar a captura:\n" + e.getMessage()
                            + "\n\nDicas: rode como administrador; confira o filtro BPF.",
                    "Erro", JOptionPane.ERROR_MESSAGE);
        }
    }

    /** Pede à IA a explicação do alerta selecionado, sem travar a janela. */
    private void explicarComIA(JTable tabelaAlertas) {
        // a configuração é conferida antes da seleção: assim o botão já ensina a configurar mesmo sem alertas
        if (explicador == null) {
            Optional<ModeloDeLinguagem> modelo = criarModeloDeLinguagem();
            if (modelo.isEmpty()) return;
            explicador = new ExplicadorDeAlertas(modelo.get());
        }

        int linha = tabelaAlertas.getSelectedRow();
        if (linha < 0) {
            status.setText("Selecione um alerta na tabela para a IA explicar.");
            return;
        }
        Alerta alerta = modeloAlertas.get(tabelaAlertas.convertRowIndexToModel(linha));

        // no modo local nada sai do computador, então não há envio a confirmar
        if (provedorIA.enviaParaInternet() && !envioParaIAConfirmado) {
            int resposta = JOptionPane.showConfirmDialog(this,
                    "O texto do alerta será enviado à API da Anthropic para gerar a explicação.\n"
                            + "IPs e MACs são mascarados antes do envio, mesmo com \"Mostrar dados sensíveis\" ligado.\n\n"
                            + "Continuar?",
                    "Enviar alerta para a IA", JOptionPane.OK_CANCEL_OPTION, JOptionPane.QUESTION_MESSAGE);
            if (resposta != JOptionPane.OK_OPTION) return;
            envioParaIAConfirmado = true;
        }

        DialogoExplicacaoIA dialogo = new DialogoExplicacaoIA(this, alerta, provedorIA);
        dialogo.setVisible(true);
        ExplicadorDeAlertas usado = explicador;
        new SwingWorker<String, Void>() {
            @Override protected String doInBackground() throws Exception {
                return usado.explicar(alerta);
            }
            @Override protected void done() {
                try {
                    dialogo.mostrarExplicacao(get());
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                } catch (ExecutionException e) {
                    Throwable causa = e.getCause() != null ? e.getCause() : e;
                    dialogo.mostrarErro(causa.getMessage());
                }
            }
        }.execute();
    }

    /** Cria o cliente do provedor escolhido em ANALISADOR_IA; vazio (após explicar o motivo) se faltar configuração. */
    private Optional<ModeloDeLinguagem> criarModeloDeLinguagem() {
        if (provedorIA == ProvedorIA.LOCAL) {
            // sem chave nem internet; se o Ollama estiver parado, a própria janela de explicação ensina a iniciá-lo
            return Optional.of(ClienteOllama.doAmbiente());
        }
        Optional<ClienteClaude> cliente = ClienteClaude.doAmbiente();
        if (cliente.isEmpty()) {
            JOptionPane.showMessageDialog(this,
                    "Para usar a IA, defina a variável de ambiente " + ClienteClaude.VARIAVEL_CHAVE
                            + " com a sua chave da API da Anthropic\n(console.anthropic.com) e abra o programa de novo.\n\n"
                            + "No Windows (cmd):  setx " + ClienteClaude.VARIAVEL_CHAVE + " \"sua-chave\"\n\n"
                            + "A chave nunca é gravada no programa.\n\n"
                            + "Prefere uma IA 100% offline, sem chave? Instale o Ollama (ollama.com) e use:\n"
                            + "setx " + ProvedorIA.VARIAVEL + " local",
                    "IA não configurada", JOptionPane.INFORMATION_MESSAGE);
            return Optional.empty();
        }
        return Optional.of(cliente.get());
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
        bolinhaStatus.setForeground(Tema.corInativo());
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
        Tema.aplicar(); // antes de criar qualquer componente
        SwingUtilities.invokeLater(() -> new JanelaPrincipal().setVisible(true));
    }
}
