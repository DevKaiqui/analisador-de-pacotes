package br.com.analisador.gui;

import br.com.analisador.detector.Alerta;
import br.com.analisador.ia.ProvedorIA;
import com.formdev.flatlaf.FlatClientProperties;
import net.miginfocom.swing.MigLayout;

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
        JScrollPane rolagemDetalhes = new JScrollPane(montarDetalhes(botaoExplicar),
                ScrollPaneConstants.VERTICAL_SCROLLBAR_AS_NEEDED, ScrollPaneConstants.HORIZONTAL_SCROLLBAR_NEVER);
        rolagemDetalhes.setBorder(null);
        rolagemDetalhes.getVerticalScrollBar().setUnitIncrement(16);
        conteudo.add(rolagemDetalhes, DETALHES);
        conteudo.setBorder(BorderFactory.createEmptyBorder(12, 16, 12, 16));
        add(conteudo, BorderLayout.CENTER);
        limpar();
    }

    private JPanel montarDetalhes(JButton botaoExplicar) {
        tipo.putClientProperty(FlatClientProperties.STYLE_CLASS, "h3");
        rodapeIA.putClientProperty(FlatClientProperties.STYLE, "font: -2 italic; foreground: $Label.disabledForeground");

        JScrollPane rolagem = new JScrollPane(explicacao);
        rolagem.putClientProperty(FlatClientProperties.STYLE, "arc: 10");

        // a explicação fica com o espaço que sobrar, mas nunca some (altura mínima)
        JPanel painel = new PainelRolavel(new MigLayout("fill, insets 0, gap 12 6, hidemode 3",
                "[][grow, fill]", "[]10[][][]8[]8[][grow, fill][]"));
        painel.add(tipo, "span 2, split 2");
        painel.add(selo, "gapleft 6, wrap");
        painel.add(titulo("Hora"));
        painel.add(hora, "wmin 0, wrap");
        painel.add(titulo("Alvo"));
        painel.add(alvo, "wmin 0, wrap");
        painel.add(titulo("Descrição"), "aligny top");
        painel.add(descricao, "wmin 0, wrap");
        painel.add(new JSeparator(), "span 2, growx, wrap");
        painel.add(titulo("Explicação da IA"), "span 2, split 2, aligny center");
        painel.add(botaoExplicar, "gapleft push, wrap");
        painel.add(rolagem, "span 2, grow, hmin 72, wmin 0, wrap");
        painel.add(rodapeIA, "span 2, wmin 0");
        return painel;
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
        t.setMargin(new Insets(0, 0, 0, 0));
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

    /**
     * Acompanha a largura da rolagem (para os textos quebrarem linha) e ocupa toda a altura
     * quando cabe; só rola quando a janela fica baixa demais.
     */
    private static final class PainelRolavel extends JPanel implements Scrollable {
        PainelRolavel(LayoutManager layout) { super(layout); }

        @Override public Dimension getPreferredScrollableViewportSize() { return getPreferredSize(); }
        @Override public int getScrollableUnitIncrement(Rectangle r, int o, int d) { return 16; }
        @Override public int getScrollableBlockIncrement(Rectangle r, int o, int d) { return r.height; }
        @Override public boolean getScrollableTracksViewportWidth() { return true; }

        @Override public boolean getScrollableTracksViewportHeight() {
            return getParent() instanceof JViewport v && v.getHeight() >= getMinimumSize().height;
        }
    }
}
