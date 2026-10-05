package br.com.analisador;

import java.io.File;

public final class Npcap {

    private Npcap() { }

    /** Npcap instalado sem o modo compatível com WinPcap deixa a wpcap.dll fora do PATH padrão. Chamar antes de usar o pcap4j. */
    public static void configurar() {
        if (!System.getProperty("os.name").startsWith("Windows") || System.getProperty("jna.library.path") != null) return;
        String pasta = System.getenv("SystemRoot") + "\\System32\\Npcap";
        if (new File(pasta, "wpcap.dll").exists()) System.setProperty("jna.library.path", pasta);
    }
}
