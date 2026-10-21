package br.com.analisador.gui;

import br.com.analisador.detector.Alerta;

import javax.swing.*;
import java.awt.*;

/** Janela (não bloqueante) que mostra a explicação da IA sobre um alerta. */
public final class DialogoExplicacaoIA extends JDialog {

    private final JTextArea texto = new JTextArea();

    public DialogoExplicacaoIA(Window pai, Alerta alerta) {
        super(pai, "Explicação da IA — " + alerta.tipo(), ModalityType.MODELESS);

        JLabel cabecalho = new JLabel("<html><b>" + escapar(alerta.severidade().name()) + "</b> · "
                + escapar(alerta.descricao()) + "</html>");
        cabecalho.setBorder(BorderFactory.createEmptyBorder(8, 10, 4, 10));

        texto.setEditable(false);
        texto.setLineWrap(true);
        texto.setWrapStyleWord(true);
        texto.setMargin(new Insets(8, 10, 8, 10));
        texto.setFont(texto.getFont().deriveFont(14f));

        JLabel aviso = new JLabel("Gerado por IA a partir do alerta (IPs/MACs mascarados). Confira antes de agir.");
        aviso.setFont(aviso.getFont().deriveFont(Font.ITALIC, 11f));
        aviso.setBorder(BorderFactory.createEmptyBorder(4, 10, 8, 10));

        setLayout(new BorderLayout());
        add(cabecalho, BorderLayout.NORTH);
        add(new JScrollPane(texto), BorderLayout.CENTER);
        add(aviso, BorderLayout.SOUTH);
        setSize(560, 420);
        setLocationRelativeTo(pai);
        mostrarCarregando();
    }

    public void mostrarCarregando() {
        texto.setText("Consultando a IA...");
    }

    public void mostrarExplicacao(String explicacao) {
        texto.setText(explicacao);
        texto.setCaretPosition(0);
    }

    public void mostrarErro(String mensagem) {
        texto.setText("Não foi possível obter a explicação.\n\n" + mensagem);
    }

    /** O cabeçalho usa HTML; o descritivo do alerta pode vir de dados da rede, então é escapado. */
    private static String escapar(String s) {
        return s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;");
    }
}
