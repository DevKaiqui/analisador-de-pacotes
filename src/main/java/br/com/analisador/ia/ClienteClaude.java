package br.com.analisador.ia;

import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;

import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;
import java.util.Optional;

/**
 * Cliente mínimo da API de mensagens do Claude (HTTPS direto, sem SDK).
 *
 * A chave NUNCA fica no código: é lida da variável de ambiente ANTHROPIC_API_KEY.
 * O modelo pode ser trocado com ANALISADOR_MODELO (padrão: um modelo rápido e barato,
 * suficiente para explicar alertas curtos).
 */
public final class ClienteClaude implements ModeloDeLinguagem {

    public static final String VARIAVEL_CHAVE = "ANTHROPIC_API_KEY";
    public static final String VARIAVEL_MODELO = "ANALISADOR_MODELO";
    public static final String MODELO_PADRAO = "claude-haiku-5-5";

    private static final URI ENDPOINT = URI.create("https://api.anthropic.com/v1/messages");
    private static final String VERSAO_API = "2023-06-01";
    private static final int MAX_TOKENS = 700;

    private final String chave;
    private final String modelo;
    private final HttpClient http = HttpClient.newBuilder()
            .connectTimeout(Duration.ofSeconds(10))
            .build();

    public ClienteClaude(String chave, String modelo) {
        this.chave = chave;
        this.modelo = modelo;
    }

    /** Cria o cliente se a chave estiver configurada no ambiente; senão, vazio. */
    public static Optional<ClienteClaude> doAmbiente() {
        String chave = System.getenv(VARIAVEL_CHAVE);
        if (chave == null || chave.isBlank()) return Optional.empty();
        String modelo = System.getenv(VARIAVEL_MODELO);
        if (modelo == null || modelo.isBlank()) modelo = MODELO_PADRAO;
        return Optional.of(new ClienteClaude(chave.trim(), modelo.trim()));
    }

    @Override
    public String perguntar(String instrucoes, String pergunta) throws IOException, InterruptedException {
        HttpRequest requisicao = HttpRequest.newBuilder(ENDPOINT)
                .timeout(Duration.ofSeconds(40))
                .header("x-api-key", chave)
                .header("anthropic-version", VERSAO_API)
                .header("content-type", "application/json")
                .POST(HttpRequest.BodyPublishers.ofString(montarCorpo(modelo, instrucoes, pergunta)))
                .build();

        HttpResponse<String> resposta = http.send(requisicao, HttpResponse.BodyHandlers.ofString());
        if (resposta.statusCode() != 200) {
            throw new IOException(mensagemDeErro(resposta.statusCode(), resposta.body()));
        }
        return extrairTexto(resposta.body());
    }

    /** Corpo JSON da requisição (visível ao pacote para ser testado sem rede). */
    static String montarCorpo(String modelo, String instrucoes, String pergunta) {
        JsonObject mensagem = new JsonObject();
        mensagem.addProperty("role", "user");
        mensagem.addProperty("content", pergunta);

        JsonArray mensagens = new JsonArray();
        mensagens.add(mensagem);

        JsonObject corpo = new JsonObject();
        corpo.addProperty("model", modelo);
        corpo.addProperty("max_tokens", MAX_TOKENS);
        corpo.addProperty("system", instrucoes);
        corpo.add("messages", mensagens);
        return corpo.toString();
    }

    /** Junta os blocos de texto da resposta. */
    static String extrairTexto(String json) throws IOException {
        StringBuilder texto = new StringBuilder();
        try {
            JsonArray conteudo = JsonParser.parseString(json).getAsJsonObject().getAsJsonArray("content");
            if (conteudo != null) {
                for (JsonElement bloco : conteudo) {
                    JsonObject o = bloco.getAsJsonObject();
                    if (o.has("type") && "text".equals(o.get("type").getAsString()) && o.has("text")) {
                        texto.append(o.get("text").getAsString());
                    }
                }
            }
        } catch (RuntimeException e) {
            throw new IOException("Resposta da IA em formato inesperado.", e);
        }
        if (texto.isEmpty()) throw new IOException("A IA devolveu uma resposta vazia.");
        return texto.toString();
    }

    static String mensagemDeErro(int status, String corpo) {
        if (status == 401) return "Chave da API inválida (401). Confira a variável " + VARIAVEL_CHAVE + ".";
        if (status == 403) return "Sem permissão para usar a API (403).";
        if (status == 429) return "Limite de uso da API atingido (429). Tente de novo em instantes.";
        String detalhe = "";
        try {
            JsonObject erro = JsonParser.parseString(corpo).getAsJsonObject().getAsJsonObject("error");
            if (erro != null && erro.has("message")) detalhe = ": " + erro.get("message").getAsString();
        } catch (RuntimeException ignorado) {
            // corpo não era JSON; fica só o código
        }
        return "Erro da API (HTTP " + status + ")" + detalhe;
    }
}
