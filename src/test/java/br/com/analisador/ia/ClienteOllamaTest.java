package br.com.analisador.ia;

import com.google.gson.JsonArray;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import org.junit.jupiter.api.Test;

import java.io.IOException;

import static org.junit.jupiter.api.Assertions.*;

/** Testa só a montagem e a leitura do JSON; nada aqui usa a rede. */
class ClienteOllamaTest {

    @Test
    void corpoTemModeloSemStreamingEInstrucoesSeparadasDosDados() {
        String corpo = ClienteOllama.montarCorpo("llama3.2", "regras \"fixas\"", "linha1\nlinha2 com \"aspas\"");

        JsonObject json = JsonParser.parseString(corpo).getAsJsonObject();
        assertEquals("llama3.2", json.get("model").getAsString());
        assertFalse(json.get("stream").getAsBoolean());
        assertTrue(json.getAsJsonObject("options").get("num_predict").getAsInt() > 0);

        JsonArray msgs = json.getAsJsonArray("messages");
        assertEquals(2, msgs.size());
        // as regras vão como "system" e o alerta como "user": o conteúdo da rede nunca vira instrução
        assertEquals("system", msgs.get(0).getAsJsonObject().get("role").getAsString());
        assertEquals("regras \"fixas\"", msgs.get(0).getAsJsonObject().get("content").getAsString());
        assertEquals("user", msgs.get(1).getAsJsonObject().get("role").getAsString());
        assertEquals("linha1\nlinha2 com \"aspas\"", msgs.get(1).getAsJsonObject().get("content").getAsString());
    }

    @Test
    void extraiOConteudoDaMensagem() throws IOException {
        String resposta = """
                {"model":"llama3.2","created_at":"2026-10-21T12:00:00Z",
                 "message":{"role":"assistant","content":"O QUE SIGNIFICA: teste."},
                 "done":true}""";

        assertEquals("O QUE SIGNIFICA: teste.", ClienteOllama.extrairTexto(resposta));
    }

    @Test
    void respostaVaziaOuMalFormadaViraErroClaro() {
        assertThrows(IOException.class, () -> ClienteOllama.extrairTexto("{\"message\":{\"content\":\"  \"}}"));
        assertThrows(IOException.class, () -> ClienteOllama.extrairTexto("{\"done\":true}"));
        assertThrows(IOException.class, () -> ClienteOllama.extrairTexto("isso não é json"));
    }

    @Test
    void modeloVemDaVariavelOuUsaOPadrao() {
        assertEquals(ClienteOllama.MODELO_PADRAO, ClienteOllama.modeloDoAmbiente(null));
        assertEquals(ClienteOllama.MODELO_PADRAO, ClienteOllama.modeloDoAmbiente("  "));
        assertEquals("qwen2.5:3b", ClienteOllama.modeloDoAmbiente(" qwen2.5:3b "));
    }

    @Test
    void mensagensDeErroEnsinamComoResolver() {
        assertTrue(ClienteOllama.mensagemOllamaParado().contains("ollama serve"));

        String semModelo = ClienteOllama.mensagemDeErro(404,
                "{\"error\":\"model \\\"llama3.2\\\" not found, try pulling it first\"}", "llama3.2");
        assertTrue(semModelo.contains("ollama pull llama3.2"));

        assertTrue(ClienteOllama.mensagemDeErro(500, "{\"error\":\"sem memória\"}", "x").contains("sem memória"));
        assertTrue(ClienteOllama.mensagemDeErro(502, "<html>", "x").contains("502"));
    }
}
