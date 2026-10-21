package br.com.analisador.gui;

import br.com.analisador.detector.Alerta;
import br.com.analisador.ia.ProvedorIA;
import com.formdev.flatlaf.FlatClientProperties;

import javax.swing.*;
import java.awt.*;
import java.time.format.DateTimeFormatter;

/**
 * Painel à direita da tabela de alertas: dados completos do alerta selecionado e a explicação da IA.
 *
 * Tudo que vem do alerta é exibido como TEXTO PURO: os rótulos têm o HTML do Swing desligado,
 * porque a descrição pode conter dados da rede (um nome de DNS, por exemplo) controlados por quem ataca.
 * A anonimização do que vai para a IA continua no ExplicadorDeAlertas.
 */
public final class PainelDetalhesAlerta extends JPanel {

    private static final DateTimeFormatter DATA_HORA = DateTimeFormatter.ofPattern("dd/MM/yyyy HH:mm:ss");
    private static final String VAZIO = "vazio";
    private static final String DETALHES = "detalhes";

    private final CardLayout cartas = new CardLayout();
    private final JPanel conteudo = new JPanel(cartas);

    private final JLabel tipo = rotuloTexto();
    private final SeloSeveridade selo = new SeloSeveridade();
    private final JLabel hora = rotuloTexto();
    private final JLabel alvo = rotuloTexto();
    private final JTextArea descricao = areaTexto();
    private final JTextArea explicacao = areaTexto();
    private final JLabel rodapeIA = rotuloTexto();

    private final ProvedorIA provedor;
    private Alerta alertaAtual;

    public PainelDetalhesAlerta(ProvedorIA provedor, JButton botaoExplicar) {
        super(new BorderLayout());
        this.provedor = provedor;
        setMinimumSize(new Dimension(320, 0));
        setPreferredSize(new Dimension(420, 0));

        JLabel vazio = new JLabel("Selecione um alerta na tabela para ver os detalhes.", SwingConstants.CENTER);
        vazio.putClientProperty(FlatClientProperties.STYLE, "foreground: $Label.disabledForeground");
        conteudo.add(vazio, VAZIO);
        conteudo.add(montarDetalhes(botaoExplicar), DETALHES);
        conteudo.setBorder(BorderFactory.createEmptyBorder(12, 16, 12, 16));
        add(conteudo, BorderLayout.CENTER);
        limpar();
    }

    private JPanel montarDetalhes(JButton botaoExplicar) {
        tipo.putClientProperty(FlatClientProperties.STYLE_CLASS, "h3");
        rodapeIA.putClientProperty(FlatClientProperties.STYLE, "font: -2 italic; foreground: $Label.disabledForeground");
        explicacao.setRows(8);

        JPanel cabecalho = new JPanel(new FlowLayout(FlowLayout.LEFT, 0, 0));
        cabecalho.add(tipo);
        cabecalho.add(Box.createHorizontalStrut(10));
        cabecalho.add(selo);

        JPanel campos = new JPanel(new GridBagLayout());
        adicionarCampo(campos, 0, "Hora", hora);
        adicionarCampo(campos, 1, "Alvo", alvo);
        adicionarCampo(campos, 2, "Descrição", descricao);

        JPanel tituloIA = new JPanel(new BorderLayout(8, 0));
        tituloIA.add(titulo("Explicação da IA"), BorderLayout.WEST);
        tituloIA.add(botaoExplicar, BorderLayout.EAST);

        JScrollPane rolagem = new JScrollPane(explicacao);
        rolagem.putClientProperty(FlatClientProperties.STYLE, "arc: 10");

        JPanel ia = new JPanel(new BorderLayout(0, 8));
        ia.add(tituloIA, BorderLayout.NORTH);
        ia.add(rolagem, BorderLayout.CENTER);
        ia.add(rodapeIA, BorderLayout.SOUTH);

        JPanel topo = new JPanel(new BorderLayout(0, 12));
        topo.add(cabecalho, BorderLayout.NORTH);
        topo.add(campos, BorderLayout.CENTER);
        topo.add(new JSeparator(), BorderLayout.SOUTH);

        JPanel painel = new JPanel(new BorderLayout(0, 12));
        painel.add(topo, BorderLayout.NORTH);
        painel.add(ia, BorderLayout.CENTER);
        return painel;
    }

    private static void adicionarCampo(JPanel painel, int linha, String nome, JComponent valor) {
        GridBagConstraints c = new GridBagConstraints();
        c.gridy = linha;
        c.anchor = GridBagConstraints.NORTHWEST;
        c.insets = new Insets(4, 0, 4, 12);
        painel.add(titulo(nome), c);
        c.gridx = 1;
        c.weightx = 1;
        c.fill = GridBagConstraints.HORIZONTAL;
        c.insets = new Insets(4, 0, 4, 0);
        painel.add(valor, c);
    }

    private static JLabel titulo(String texto) {
        JLabel l = new JLabel(texto.toUpperCase());
        l.putClientProperty(FlatClientProperties.STYLE, "font: -1 bold; foreground: $Label.disabledForeground");
        return l;
    }

    /** JLabel que nunca interpreta HTML. */
    private static JLabel rotuloTexto() {
        JLabel l = new JLabel();
        l.putClientProperty("html.disable", Boolean.TRUE);
        return l;
    }

    private static JTextArea areaTexto() {
        JTextArea t = new JTextArea();
        t.setEditable(false);
        t.setLineWrap(true);
        t.setWrapStyleWord(true);
        t.setFocusable(true);
        t.setOpaque(false);
        t.setFont(UIManager.getFont("Label.font"));
        return t;
    }

    /** Alerta exibido agora (ou null). */
    public Alerta alertaAtual() {
        return alertaAtual;
    }

    public void limpar() {
        alertaAtual = null;
        cartas.show(conteudo, VAZIO);
    }

    /** Mostra os dados do alerta; a área da IA volta ao convite para explicar. */
    public void mostrar(Alerta alerta) {
        alertaAtual = alerta;
        tipo.setText(alerta.tipo());
        selo.setSeveridade(alerta.severidade());
        hora.setText(alerta.momento().format(DATA_HORA));
        alvo.setText(alerta.alvo());
        descricao.setText(alerta.descricao());
        explicacao.setText("Clique em \"Explicar com IA\" (ou dê duplo clique no alerta) para entender o que ele significa.");
        explicacao.setForeground(UIManager.getColor("Label.disabledForeground"));
        rodapeIA.setText("IA configurada: " + provedor.nomeExibicao());
        cartas.show(conteudo, DETALHES);
    }

    public void mostrarCarregando() {
        explicacao.setForeground(UIManager.getColor("Label.disabledForeground"));
        explicacao.setText(provedor == ProvedorIA.LOCAL
                ? "Consultando a IA local... (no computador, sem internet; pode levar alguns segundos)"
                : "Consultando a IA...");
    }

    public void mostrarExplicacao(String texto) {
        explicacao.setForeground(UIManager.getColor("TextArea.foreground"));
        explicacao.setText(texto);
        explicacao.setCaretPosition(0);
        rodapeIA.setText("Respondido por: " + provedor.nomeExibicao()
                + "  ·  Gerado por IA (IPs/MACs mascarados). Confira antes de agir.");
    }

    public void mostrarErro(String mensagem) {
        explicacao.setForeground(UIManager.getColor("Actions.Red"));
        explicacao.setText("Não foi possível obter a explicação.\n\n" + mensagem);
        explicacao.setCaretPosition(0);
    }
}
