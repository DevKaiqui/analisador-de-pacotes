# Analisador de Pacotes

Aplicacao Java simples para capturar e exibir informacoes basicas de pacotes de rede usando Pcap4J e Npcap.

## Como executar

No PowerShell, dentro da pasta do projeto:

```powershell
.\run.ps1
```

## Rodar com F5

### VS Code

1. Abra esta pasta no VS Code.
2. Instale a extensao **Extension Pack for Java**, se ainda nao tiver.
3. Pressione `F5`.
4. Escolha **Analisador de Pacotes**, se o VS Code perguntar.

### IntelliJ IDEA

1. Abra esta pasta no IntelliJ.
2. No topo da tela, selecione a configuracao **Analisador de Pacotes**.
3. Clique em Run/Debug.

No IntelliJ, `F5` normalmente nao e o atalho padrao para rodar Java. Se quiser que seja `F5`, va em **File > Settings > Keymap**, procure por **Run**, e atribua `F5`.

Para listar as interfaces disponiveis:

```powershell
.\run.ps1 -List
```

Para capturar em uma interface especifica, use o indice mostrado na listagem:

```powershell
.\run.ps1 -Interface 3
```

Para limitar ainda mais a captura:

```powershell
.\run.ps1 -Interface 3 -MaxPackets 50 -DurationSeconds 20
```

Por padrao, IPs e MACs sao mascarados na saida do terminal. Para diagnostico local, voce pode mostrar esses dados reais explicitamente:

```powershell
.\run.ps1 -Interface 3 -ShowSensitive
```

Pressione `Ctrl+C` para parar a captura.

## Camadas de seguranca aplicadas

1. **Captura minima por padrao**: o projeto captura apenas os primeiros 256 bytes de cada pacote, evitando coletar payload completo.
2. **Modo promiscuo desligado por padrao**: a aplicacao nao tenta enxergar trafego de outros dispositivos sem voce pedir explicitamente com `-Promiscuous`.
3. **Limite de execucao**: a captura para automaticamente por quantidade de pacotes ou por tempo.
4. **Filtro BPF validado**: o filtro padrao e `ip or arp`, e filtros personalizados passam por validacao simples antes de chegar ao Pcap4J.
5. **Saida sanitizada e sem payload**: o terminal mostra metadados, como protocolo e portas, sem imprimir conteudo bruto dos pacotes.
6. **IPs e MACs mascarados por padrao**: identificadores locais so aparecem se voce usar `-ShowSensitive`.
7. **Arquivos sensiveis ignorados no Git**: `.env`, chaves, logs e capturas `.pcap/.pcapng` ficam fora do repositorio.

## Requisitos

- Java/JDK. Se `javac` nao estiver no PATH, o script tenta usar o JDK incluido no IntelliJ IDEA.
- Maven. Se `mvn` nao estiver no PATH, o script tenta usar o Maven incluido no IntelliJ IDEA.
- Npcap instalado no Windows.
- Em algumas interfaces, execute o PowerShell como administrador.
