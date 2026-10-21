package br.com.analisador.ia;

import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;

import java.io.IOException;
import java.net.ConnectException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpConnectTimeoutException;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.net.http.HttpTimeoutException;
import java.time.Duration;

/**
 * Cliente da IA local (Ollama), 100% offline: fala só com http://localhost:11434,
 * sem chave e sem internet. O modelo pode ser trocado com OLLAMA_MODELO (padrão: llama3.2).
 */
public final class ClienteOllama implements ModeloDeLinguagem {

    public static final String VARIAVEL_MODELO = "OLLAMA_MODELO";
    public static final String MODELO_PADRAO = "llama3.2";

    private static final URI ENDPOINT = URI.create("http://localhost:11434/api/chat");
    private static final int MAX_TOKENS = 700;

    private final String modelo;
    private final HttpClient http = HttpClient.newBuilder()
            .connectTimeout(Duration.ofSeconds(5))
            .build();

    public ClienteOllama(String modelo) {
        this.modelo = modelo;
    }

    /** Diferente do Claude, sempre existe: não há chave para configurar. */
    public static ClienteOllama doAmbiente() {
        return new ClienteOllama(modeloDoAmbiente(System.getenv(VARIAVEL_MODELO)));
    }

    static String modeloDoAmbiente(String valor) {
        return valor == null || valor.isBlank() ? MODELO_PADRAO : valor.strip();
    }

    @Override
    public String perguntar(String instrucoes, String pergunta) throws IOException, InterruptedException {
        HttpRequest requisicao = HttpRequest.newBuilder(ENDPOINT)
                // modelos locais rodam na CPU de muitos computadores e podem demorar bem mais que a API
                .timeout(Duration.ofSeconds(180))
                .header("content-type", "application/json")
                .POST(HttpRequest.BodyPublishers.ofString(montarCorpo(modelo, instrucoes, pergunta)))
                .build();

        HttpResponse<String> resposta;
        try {
            resposta = http.send(requisicao, HttpResponse.BodyHandlers.ofString());
        } catch (ConnectException | HttpConnectTimeoutException e) {
            throw new IOException(mensagemOllamaParado(), e);
        } catch (HttpTimeoutException e) {
            throw new IOException("A IA local demorou demais para responder. Tente um modelo menor "
                    + "(ex.: " + VARIAVEL_MODELO + "=llama3.2:1b) ou tente de novo.", e);
        }
        if (resposta.statusCode() != 200) {
            throw new IOException(mensagemDeErro(resposta.statusCode(), resposta.body(), modelo));
        }
        return extrairTexto(resposta.body());
    }

    /** Corpo JSON da requisição (visível ao pacote para ser testado sem rede). */
    static String montarCorpo(String modelo, String instrucoes, String pergunta) {
        JsonArray mensagens = new JsonArray();
        mensagens.add(mensagem("system", instrucoes));
        mensagens.add(mensagem("user", pergunta));

        JsonObject opcoes = new JsonObject();
        opcoes.addProperty("num_predict", MAX_TOKENS);

        JsonObject corpo = new JsonObject();
        corpo.addProperty("model", modelo);
        corpo.addProperty("stream", false);
        corpo.add("messages", mensagens);
        corpo.add("options", opcoes);
        return corpo.toString();
    }

    private static JsonObject mensagem(String papel, String conteudo) {
        JsonObject m = new JsonObject();
        m.addProperty("role", papel);
        m.addProperty("content", conteudo);
        return m;
    }

    /** Lê message.content da resposta (sem streaming, vem tudo num JSON só). */
    static String extrairTexto(String json) throws IOException {
        String texto;
        try {
            JsonObject mensagem = JsonParser.parseString(json).getAsJsonObject().getAsJsonObject("message");
            JsonElement conteudo = mensagem == null ? null : mensagem.get("content");
            texto = conteudo == null || conteudo.isJsonNull() ? "" : conteudo.getAsString();
        } catch (RuntimeException e) {
            throw new IOException("Resposta da IA local em formato inesperado.", e);
        }
        if (texto.isBlank()) throw new IOException("A IA local devolveu uma resposta vazia.");
        return texto;
    }

    static String mensagemOllamaParado() {
        return "A IA local (Ollama) não está rodando em localhost:11434.\n\n"
                + "Para iniciar:\n"
                + "  - Windows/macOS: abra o aplicativo Ollama (ícone perto do relógio), ou\n"
                + "  - em um terminal: ollama serve\n\n"
                + "Ainda não instalou? Baixe em https://ollama.com e depois rode: ollama pull " + MODELO_PADRAO;
    }

    static String mensagemDeErro(int status, String corpo, String modelo) {
        String detalhe = "";
        try {
            JsonObject json = JsonParser.parseString(corpo).getAsJsonObject();
            if (json.has("error")) detalhe = json.get("error").getAsString();
        } catch (RuntimeException ignorado) {
            // corpo não era JSON; fica só o código
        }
        if (status == 404 || detalhe.contains("not found")) {
            return "O modelo \"" + modelo + "\" não está baixado no Ollama.\n\n"
                    + "Baixe com:  ollama pull " + modelo + "\n"
                    + "(ou escolha outro com a variável " + VARIAVEL_MODELO + ")";
        }
        return "Erro da IA local (HTTP " + status + ")" + (detalhe.isEmpty() ? "" : ": " + detalhe);
    }
}
