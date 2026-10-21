package br.com.analisador.ia;

import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import org.junit.jupiter.api.Test;

import java.io.IOException;

import static org.junit.jupiter.api.Assertions.*;

/** Testa só a montagem e a leitura do JSON; nada aqui usa a rede. */
class ClienteClaudeTest {

    @Test
    void corpoTemModeloSistemaEMensagemComAspasEscapadas() {
        String corpo = ClienteClaude.montarCorpo("modelo-x", "regras \"fixas\"", "linha1\nlinha2 com \"aspas\"");

        JsonObject json = JsonParser.parseString(corpo).getAsJsonObject();
        assertEquals("modelo-x", json.get("model").getAsString());
        assertEquals("regras \"fixas\"", json.get("system").getAsString());
        JsonObject msg = json.getAsJsonArray("messages").get(0).getAsJsonObject();
        assertEquals("user", msg.get("role").getAsString());
        assertEquals("linha1\nlinha2 com \"aspas\"", msg.get("content").getAsString());
        assertTrue(json.get("max_tokens").getAsInt() > 0);
    }

    @Test
    void extraiESomaOsBlocosDeTexto() throws IOException {
        String resposta = """
                {"id":"msg_1","content":[
                  {"type":"text","text":"Parte 1. "},
                  {"type":"text","text":"Parte 2."}
                ],"stop_reason":"end_turn"}""";

        assertEquals("Parte 1. Parte 2.", ClienteClaude.extrairTexto(resposta));
    }

    @Test
    void respostaVaziaOuMalFormadaViraErroClaro() {
        assertThrows(IOException.class, () -> ClienteClaude.extrairTexto("{\"content\":[]}"));
        assertThrows(IOException.class, () -> ClienteClaude.extrairTexto("isso não é json"));
    }

    @Test
    void mensagensDeErroSaoUteisEMencionamAVariavelDaChave() {
        assertTrue(ClienteClaude.mensagemDeErro(401, "{}").contains(ClienteClaude.VARIAVEL_CHAVE));
        assertTrue(ClienteClaude.mensagemDeErro(429, "{}").contains("429"));
        assertTrue(ClienteClaude.mensagemDeErro(500, "{\"error\":{\"message\":\"sobrecarregado\"}}")
                .contains("sobrecarregado"));
        assertTrue(ClienteClaude.mensagemDeErro(502, "<html>").contains("502"));
    }
}
