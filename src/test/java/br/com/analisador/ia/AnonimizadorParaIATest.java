package br.com.analisador.ia;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

class AnonimizadorParaIATest {

    @Test
    void mascaraOsDoisUltimosOctetosDoIp() {
        assertEquals("Scan de 192.168.x.x para 10.0.x.x",
                AnonimizadorParaIA.anonimizar("Scan de 192.168.1.50 para 10.0.3.7"));
    }

    @Test
    void mascaraOMacMantendoSoOFabricante() {
        assertEquals("MAC AA:BB:CC:**:**:**", AnonimizadorParaIA.anonimizar("MAC AA:BB:CC:11:22:33"));
        assertEquals("MAC aa:bb:cc:**:**:**", AnonimizadorParaIA.anonimizar("MAC aa-bb-cc-11-22-33"));
    }

    @Test
    void naoMexeEmTextoJaMascaradoNemEmTextoSemDados() {
        String jaMascarado = "IP 192.168.x.x com MAC AA:BB:CC:**:**:**";
        assertEquals(jaMascarado, AnonimizadorParaIA.anonimizar(jaMascarado));
        assertEquals("subdominio.exemplo.com", AnonimizadorParaIA.anonimizar("subdominio.exemplo.com"));
    }

    @Test
    void nuloViraTextoVazio() {
        assertEquals("", AnonimizadorParaIA.anonimizar(null));
    }
}
