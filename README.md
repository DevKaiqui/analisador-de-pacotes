# Analisador de Pacotes

Captura tráfego de rede (ou lê um arquivo `.pcap`) e alerta sobre ameaças:

| Regra | Severidade | O que detecta |
|---|---|---|
| Port Scan | ALTA | 20+ portas distintas com SYN do mesmo IP em 10s |
| SYN Flood | CRÍTICA | 200+ SYN para o mesmo IP:porta em 1s |
| ARP Spoofing | ALTA | Mesmo IP anunciado por um MAC diferente |
| DNS Suspeito | MÉDIA | Subdomínios longos ou aleatórios (tunneling / DGA) |

IPs e MACs aparecem mascarados nos alertas (ex.: `192.168.x.x`), a menos que se use `--sem-mascara`.

## Requisitos

- Java 17+ (ex.: `C:\Users\PMSL\.jdks\ms-21.0.11`)
- [Npcap](https://npcap.com) instalado
- Terminal **como administrador** para captura ao vivo

## Compilar e testar

```
mvn package
```

Gera `target/analisador-de-pacotes-1.0.0.jar` (já com todas as dependências).

## Interface gráfica

Clique duas vezes em `target/analisador-de-pacotes-1.0.0.jar` (ou `java -jar target/analisador-de-pacotes-1.0.0.jar`).
A placa física já vem selecionada; escolha outra se quiser, opcionalmente digite um filtro BPF e clique em **Iniciar**.

## Terminal

```
set JAR=target/analisador-de-pacotes-1.0.0.jar
java -cp %JAR% br.com.analisador.AnalisadorDePacotes -l              # lista interfaces
java -cp %JAR% br.com.analisador.AnalisadorDePacotes                 # captura na placa física padrão
java -cp %JAR% br.com.analisador.AnalisadorDePacotes -i 4            # captura na interface 4
java -cp %JAR% br.com.analisador.AnalisadorDePacotes -r captura.pcap # analisa um arquivo
java -cp %JAR% br.com.analisador.AnalisadorDePacotes -f "tcp or arp or udp port 53"
```

Ctrl+C encerra a captura e mostra o resumo dos alertas.

## Nova regra

Implemente `br.com.analisador.detector.RegraDeteccao` e registre com `detector.adicionarRegra(...)`.
