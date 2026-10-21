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

import com.formdev.flatlaf.FlatClientProperties;
import net.miginfocom.swing.MigLayout;

import javax.swing.*;
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

    private final CartaoMetrica cartaoPacotes = new CartaoMetrica("Pacotes", UIManager.getColor("Component.accentColor"));
    private final Map<Severidade, CartaoMetrica> cartoesPorSeveridade = new EnumMap<>(Severidade.class);
    private final Map<Severidade, Integer> contagemAlertas = new EnumMap<>(Severidade.class);

    private final ModeloPacotes modeloPacotes = new ModeloPacotes(5000);
    private final ModeloAlertas modeloAlertas = new ModeloAlertas();

    private final ServicoCaptura servico = new ServicoCaptura();
    private final SensitiveDataMasker masker = new SensitiveDataMasker();
    private final PacketAnalyzer analyzer = new PacketAnalyzer(masker);
    private final AtomicInteger contador = new AtomicInteger();
    private final GraficoPacotesPorSegundo grafico = new GraficoPacotesPorSegundo(contador::get);
    private DetectorDeAmeacas detector;

    /** Escolhido por ANALISADOR_IA ao abrir o programa. */
    private final ProvedorIA provedorIA = ProvedorIA.doAmbiente();
    /** Criado na primeira consulta à IA; guarda as respostas já recebidas. */
    private ExplicadorDeAlertas explicador;
    private boolean envioParaIAConfirmado = false;
    private final PainelDetalhesAlerta detalhes = new PainelDetalhesAlerta(provedorIA, botaoExplicarIA);

    public JanelaPrincipal() {
        super("Analisador de Pacotes");
        setDefaultCloseOperation(EXIT_ON_CLOSE);
        // ocupa até 90% da tela, sem passar de 1440x900, e não encolhe a ponto de quebrar o layout
        Rectangle tela = GraphicsEnvironment.getLocalGraphicsEnvironment().getMaximumWindowBounds();
        setSize(Math.min(1440, tela.width * 9 / 10), Math.min(900, tela.height * 9 / 10));
        setMinimumSize(new Dimension(1080, 680));
        setLocationRelativeTo(null);
        for (Severidade s : Severidade.values()) contagemAlertas.put(s, 0);
        montarLayout();
        carregarInterfaces();
        botaoParar.setEnabled(false);
    }

    private void montarLayout() {
        Tema.botaoPrimario(botaoIniciar, "$Actions.Green", "#ffffff");
        botaoIniciar.setIcon(Tema.icone("iniciar", Color.WHITE));
        Tema.botaoPrimario(botaoParar, "$Actions.Red", "#ffffff");
        botaoParar.setIcon(Tema.icone("parar", Color.WHITE));
        botaoLimpar.setIcon(Tema.icone("limpar", "Button.foreground"));
        botaoLimpar.setToolTipText("Apaga pacotes, alertas e contadores da tela");
        Tema.botaoPrimario(botaoExplicarIA, Tema.DESTAQUE, "#0b1a1e");
        botaoExplicarIA.setIcon(Tema.icone("ia", new Color(0x0B1A1E)));
        botaoExplicarIA.setToolTipText("Pede à IA uma explicação em português do alerta selecionado (ou dê duplo clique no alerta)");
        campoFiltro.putClientProperty(FlatClientProperties.PLACEHOLDER_TEXT, "ex.: tcp port 443");
        status.putClientProperty(FlatClientProperties.STYLE, "font: -1; foreground: $Label.disabledForeground");

        JTable tabelaPacotes = new JTable(modeloPacotes);
        ajustarLargurasPacotes(tabelaPacotes);
        deixarCabecalhoEmNegrito(tabelaPacotes);

        JTable tabelaAlertas = new JTable(modeloAlertas);
        tabelaAlertas.setDefaultRenderer(Object.class, new RenderizadorSeveridade());
        tabelaAlertas.getColumnModel().getColumn(0).setMinWidth(72);
        tabelaAlertas.getColumnModel().getColumn(0).setMaxWidth(80);
        tabelaAlertas.getColumnModel().getColumn(1).setCellRenderer(new SeloSeveridade());
        tabelaAlertas.getColumnModel().getColumn(1).setMinWidth(100);
        tabelaAlertas.getColumnModel().getColumn(1).setMaxWidth(110);
        tabelaAlertas.getColumnModel().getColumn(2).setPreferredWidth(130);
        tabelaAlertas.getColumnModel().getColumn(3).setPreferredWidth(420);
        tabelaAlertas.setRowHeight(Math.max(tabelaAlertas.getRowHeight(), new SeloSeveridade().getPreferredSize().height + 6));
        deixarCabecalhoEmNegrito(tabelaAlertas);

        botaoExplicarIA.addActionListener(e -> explicarComIA(tabelaAlertas));
        tabelaAlertas.addMouseListener(new MouseAdapter() {
            @Override public void mouseClicked(MouseEvent e) {
                if (e.getClickCount() == 2) explicarComIA(tabelaAlertas);
            }
        });
        tabelaAlertas.getSelectionModel().addListSelectionListener(e -> {
            if (!e.getValueIsAdjusting()) mostrarDetalhes(tabelaAlertas);
        });

        JSplitPane alertasEDetalhes = new JSplitPane(JSplitPane.HORIZONTAL_SPLIT,
                rolagemArredondada(tabelaAlertas), detalhes);
        alertasEDetalhes.setResizeWeight(0.6);
        alertasEDetalhes.setBorder(null);

        JSplitPane divisao = new JSplitPane(JSplitPane.VERTICAL_SPLIT,
                secao("Pacotes", "mais recentes no topo", rolagemArredondada(tabelaPacotes)),
                secao("Alertas de segurança", "selecione um alerta para ver os detalhes", alertasEDetalhes));
        divisao.setResizeWeight(0.34);
        divisao.setBorder(null);

        JPanel raiz = new JPanel(new MigLayout("fill, insets 14 18 8 18, gap 0 12", "[grow, fill]", "[][][][grow, fill][]"));
        raiz.add(montarCabecalho(), "wrap");
        raiz.add(montarControles(), "wrap");
        raiz.add(montarMetricas(), "wrap");
        raiz.add(divisao, "wrap");
        raiz.add(status);
        setContentPane(raiz);

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
            detalhes.limpar();
            contador.set(0);
            grafico.limpar();
            for (Severidade s : Severidade.values()) contagemAlertas.put(s, 0);
            atualizarResumo();
        });
    }

    /** Título do programa à esquerda; estado da captura e opções de exibição à direita. */
    private JPanel montarCabecalho() {
        JLabel titulo = new JLabel("Analisador de Pacotes");
        titulo.putClientProperty(FlatClientProperties.STYLE_CLASS, "h2");
        JLabel subtitulo = new JLabel("Captura de tráfego e detecção de ameaças em tempo real");
        subtitulo.putClientProperty(FlatClientProperties.STYLE, "foreground: $Label.disabledForeground");
        bolinhaStatus.setForeground(Tema.corInativo());
        textoStatusCaptura.putClientProperty(FlatClientProperties.STYLE, "font: bold");

        JPanel painel = new JPanel(new MigLayout("insets 0, gap 8 0", "[]push[]4[]24[]12[]", "[]2[]"));
        painel.add(titulo);
        painel.add(bolinhaStatus, "spany 2, aligny center");
        painel.add(textoStatusCaptura, "spany 2, aligny center");
        painel.add(checkSensivel, "spany 2, aligny center");
        painel.add(botaoLimpar, "spany 2, aligny center, wrap");
        painel.add(subtitulo);
        return painel;
    }

    /** Barra de captura e filtro, num cartão arredondado. */
    private JPanel montarControles() {
        JPanel painel = new JPanel(new MigLayout("insets 10 14, gap 8",
                "[][grow 30, fill, 150::360][][]24[][grow 70, fill, 90::][][110::, fill]", "[center]"));
        painel.putClientProperty(FlatClientProperties.STYLE, "arc: 14; background: lighten($Panel.background, 4%)");
        painel.add(rotuloCampo("Placa"));
        painel.add(comboInterfaces);
        painel.add(botaoIniciar);
        painel.add(botaoParar);
        painel.add(rotuloCampo("Filtro BPF"));
        painel.add(campoFiltro);
        painel.add(rotuloCampo("Rápidos"));
        painel.add(comboFiltrosRapidos);
        return painel;
    }

    /** Cartões do topo (pacotes e alertas por severidade, da mais grave para a mais leve) e o gráfico. */
    private JPanel montarMetricas() {
        JPanel painel = new JPanel(new MigLayout("insets 0, gap 12",
                "[sg cartao, grow, fill, 100::][sg cartao, grow, fill, 100::][sg cartao, grow, fill, 100::]"
                        + "[sg cartao, grow, fill, 100::][sg cartao, grow, fill, 100::][grow 300, fill, 240::]", "[118!, fill]"));
        painel.add(cartaoPacotes);
        Severidade[] ordem = {Severidade.CRITICA, Severidade.ALTA, Severidade.MEDIA, Severidade.BAIXA};
        for (Severidade s : ordem) {
            CartaoMetrica cartao = new CartaoMetrica(nomeSeveridade(s), Tema.corSeveridade(s));
            cartao.setToolTipText("Alertas de severidade " + SeloSeveridade.rotulo(s).toLowerCase());
            cartoesPorSeveridade.put(s, cartao);
            painel.add(cartao);
        }
        painel.add(grafico);
        return painel;
    }

    /** Bloco com título e dica acima do conteúdo (substitui as bordas com título). */
    private static JPanel secao(String titulo, String dica, JComponent conteudo) {
        JLabel rotulo = new JLabel(titulo);
        rotulo.putClientProperty(FlatClientProperties.STYLE_CLASS, "h4");
        JLabel subtitulo = new JLabel(dica);
        subtitulo.putClientProperty(FlatClientProperties.STYLE, "font: -1; foreground: $Label.disabledForeground");
        JPanel painel = new JPanel(new MigLayout("fill, insets 4 0 4 0, gap 8 6", "[][grow]", "[][grow, fill]"));
        painel.add(rotulo);
        painel.add(subtitulo, "wrap");
        painel.add(conteudo, "span, grow");
        return painel;
    }

    private static JScrollPane rolagemArredondada(JComponent conteudo) {
        JScrollPane rolagem = new JScrollPane(conteudo);
        rolagem.putClientProperty(FlatClientProperties.STYLE, "arc: 12");
        return rolagem;
    }

    private static JLabel rotuloCampo(String texto) {
        JLabel l = new JLabel(texto);
        l.putClientProperty(FlatClientProperties.STYLE, "foreground: $Label.disabledForeground");
        return l;
    }

    private static String nomeSeveridade(Severidade s) {
        return switch (s) {
            case CRITICA -> "Críticos";
            case ALTA -> "Altos";
            case MEDIA -> "Médios";
            case BAIXA -> "Baixos";
        };
    }

    private void atualizarResumo() {
        cartaoPacotes.setValor(contador.get());
        for (Severidade s : Severidade.values()) {
            cartoesPorSeveridade.get(s).setValor(contagemAlertas.get(s));
        }
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

    /** Atualiza o painel da direita com o alerta selecionado (e a explicação, se já foi pedida antes). */
    private void mostrarDetalhes(JTable tabelaAlertas) {
        int linha = tabelaAlertas.getSelectedRow();
        if (linha < 0) {
            detalhes.limpar();
            return;
        }
        Alerta alerta = modeloAlertas.get(tabelaAlertas.convertRowIndexToModel(linha));
        // alertas novos entram no topo e deslocam a seleção; se o alerta é o mesmo, nada muda
        if (alerta == detalhes.alertaAtual()) return;
        detalhes.mostrar(alerta);
        if (explicador != null) explicador.explicacaoGuardada(alerta).ifPresent(detalhes::mostrarExplicacao);
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

        if (detalhes.alertaAtual() != alerta) detalhes.mostrar(alerta);
        detalhes.mostrarCarregando();
        ExplicadorDeAlertas usado = explicador;
        new SwingWorker<String, Void>() {
            @Override protected String doInBackground() throws Exception {
                return usado.explicar(alerta);
            }
            @Override protected void done() {
                // o usuário pode ter selecionado outro alerta enquanto a IA respondia
                if (detalhes.alertaAtual() != alerta) return;
                try {
                    detalhes.mostrarExplicacao(get());
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                } catch (ExecutionException e) {
                    Throwable causa = e.getCause() != null ? e.getCause() : e;
                    detalhes.mostrarErro(causa.getMessage());
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
