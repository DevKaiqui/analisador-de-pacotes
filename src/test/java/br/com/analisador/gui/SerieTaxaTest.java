package br.com.analisador.gui;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

class SerieTaxaTest {

    @Test
    void calculaPacotesPorSegundoAPartirDoTotalAcumulado() {
        SerieTaxa serie = new SerieTaxa(4);
        serie.registrar(10);
        serie.registrar(25);
        serie.registrar(25);

        assertArrayEquals(new int[]{0, 10, 15, 0}, serie.valores());
        assertEquals(0, serie.atual());
        assertEquals(15, serie.maximo());
    }

    @Test
    void descartaOsValoresMaisAntigosQuandoEnche() {
        SerieTaxa serie = new SerieTaxa(3);
        for (long total : new long[]{1, 3, 6, 10, 15}) serie.registrar(total);

        assertArrayEquals(new int[]{3, 4, 5}, serie.valores());
        assertEquals(5, serie.atual());
    }

    @Test
    void totalZeradoPeloBotaoLimparNaoGeraValorNegativo() {
        SerieTaxa serie = new SerieTaxa(3);
        serie.registrar(500);
        serie.registrar(7); // contador voltou a zero e já chegou 7 pacotes

        assertEquals(7, serie.atual());
        assertTrue(serie.maximo() >= 0);
    }

    @Test
    void limparZeraOHistorico() {
        SerieTaxa serie = new SerieTaxa(3);
        serie.registrar(100);
        serie.limpar(100);
        serie.registrar(104);

        assertArrayEquals(new int[]{0, 0, 4}, serie.valores());
    }

    @Test
    void topoDoEixoDoGraficoEhUmNumeroRedondo() {
        assertEquals(10, GraficoPacotesPorSegundo.escalaBonita(0));
        assertEquals(10, GraficoPacotesPorSegundo.escalaBonita(7));
        assertEquals(20, GraficoPacotesPorSegundo.escalaBonita(13));
        assertEquals(50, GraficoPacotesPorSegundo.escalaBonita(41));
        assertEquals(100, GraficoPacotesPorSegundo.escalaBonita(100));
        assertEquals(500, GraficoPacotesPorSegundo.escalaBonita(273));
    }
}
