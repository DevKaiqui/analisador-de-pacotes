package br.com.analisador.ia;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

class ProvedorIATest {

    @Test
    void localUsaOllamaIgnorandoMaiusculasEEspacos() {
        assertEquals(ProvedorIA.LOCAL, ProvedorIA.escolher("local"));
        assertEquals(ProvedorIA.LOCAL, ProvedorIA.escolher("LOCAL"));
        assertEquals(ProvedorIA.LOCAL, ProvedorIA.escolher("  Local "));
    }

    @Test
    void ausenteOuQualquerOutroValorUsaOClaude() {
        assertEquals(ProvedorIA.CLAUDE, ProvedorIA.escolher(null));
        assertEquals(ProvedorIA.CLAUDE, ProvedorIA.escolher(""));
        assertEquals(ProvedorIA.CLAUDE, ProvedorIA.escolher("claude"));
        assertEquals(ProvedorIA.CLAUDE, ProvedorIA.escolher("ollama"));
        assertEquals(ProvedorIA.CLAUDE, ProvedorIA.escolher("locall"));
    }

    @Test
    void soOClaudeEnviaParaAInternetEOsNomesAparecemNoRodape() {
        assertTrue(ProvedorIA.CLAUDE.enviaParaInternet());
        assertFalse(ProvedorIA.LOCAL.enviaParaInternet());
        assertEquals("Claude (API)", ProvedorIA.CLAUDE.nomeExibicao());
        assertEquals("IA local (Ollama)", ProvedorIA.LOCAL.nomeExibicao());
    }
}
