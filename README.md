# Analisador de Pacotes

Aplicação Java com **interface gráfica (Swing)** — e também utilizável via terminal — que captura tráfego de rede (ou lê um arquivo `.pcap`) e alerta em tempo real sobre ameaças:

| Regra | Severidade | O que detecta |
|---|---|---|
| Port Scan | ALTA | 20+ portas distintas com SYN do mesmo IP em 10s |
| SYN Flood | CRÍTICA | 200+ SYN para o mesmo IP:porta em 1s |
| ARP Spoofing | ALTA | Mesmo IP anunciado por um MAC diferente (possível man-in-the-middle) |
| DNS Suspeito | MÉDIA | Subdomínios longos ou de aparência aleatória (DNS tunneling / DGA) |

IPs e MACs aparecem mascarados nos alertas e na lista de pacotes (ex.: `192.168.x.x`, `AA:BB:CC:**:**:**`), a menos que se marque "Mostrar dados sensíveis" na GUI ou se use `--sem-mascara` no terminal.

## Requisitos

- Java 17+ (ex.: `C:\Users\PMSL\.jdks\ms-21.0.11`)
- [Npcap](https://npcap.com) instalado
- Executar **como administrador** para captura ao vivo

## Compilar e testar

```
mvn package
```

Gera `target/analisador-de-pacotes-1.0.0.jar` (já com todas as dependências). A classe principal do jar é a interface gráfica (`br.com.analisador.gui.JanelaPrincipal`).

Para rodar só os testes automatizados (não dependem de captura real nem de administrador):

```
mvn test
```

## Interface gráfica

Clique duas vezes em `target/analisador-de-pacotes-1.0.0.jar` (ou `java -jar target/analisador-de-pacotes-1.0.0.jar`) para abrir a janela principal. Nela é possível:

- **Placa**: escolher a interface de rede (a placa física já vem selecionada por padrão).
- **Filtro**: digitar um filtro BPF opcional, ex. `tcp or arp or udp port 53`.
- **Mostrar dados sensíveis**: desmarcado por padrão (IPs/MACs mascarados); marque para ver os valores reais.
- **Iniciar / Parar / Limpar**: controlam a captura e permitem limpar as tabelas.
- Tabela **Pacotes**: lista cada pacote capturado, numerado e descrito.
- Tabela **Alertas de segurança**: mostra os alertas das 4 regras acima, com a severidade colorida por linha.
- Barra de status: exibe o total de pacotes e o resumo de alertas em tempo real.

## Terminal

```
set JAR=target/analisador-de-pacotes-1.0.0.jar
java -cp %JAR% br.com.analisador.AnalisadorDePacotes -l              # lista interfaces
java -cp %JAR% br.com.analisador.AnalisadorDePacotes                 # captura na placa física padrão
java -cp %JAR% br.com.analisador.AnalisadorDePacotes -i 4            # captura na interface 4
java -cp %JAR% br.com.analisador.AnalisadorDePacotes -r captura.pcap # analisa um arquivo
java -cp %JAR% br.com.analisador.AnalisadorDePacotes -f "tcp or arp or udp port 53"
java -cp %JAR% br.com.analisador.AnalisadorDePacotes --sem-mascara    # mostra IPs/MACs reais
java -cp %JAR% br.com.analisador.AnalisadorDePacotes --sem-cores      # desativa cores no terminal
java -cp %JAR% br.com.analisador.AnalisadorDePacotes -h               # mostra a ajuda
```

Ctrl+C encerra a captura e mostra o resumo dos alertas.

## Nova regra

Implemente `br.com.analisador.detector.RegraDeteccao` e registre com `detector.adicionarRegra(...)`.
