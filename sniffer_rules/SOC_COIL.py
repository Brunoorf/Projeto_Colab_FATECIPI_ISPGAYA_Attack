#!/usr/bin/env python3
# SOC_COIL.py
# Single-interface sniffer + flag detection (ISPGAYA{...})
# Dependências: scapy, colorama
# pip install scapy colorama

# Importação do módulo sys para operações do sistema (não usado diretamente, mas útil para saída)
import sys
# Importação do módulo time para operações temporais (não usado diretamente, mas pode ser útil)
import time
# Importação do módulo re para operações com expressões regulares (usado para detecção de padrões)
import re
# Importação do módulo urllib.parse para decodificação de URLs (usado para normalizar payloads URL-encoded)
import urllib.parse
# Importação de datetime para formatação de timestamps nos alertas e nomes de ficheiros
from datetime import datetime
# Importação das funções e classes essenciais do Scapy:
# - sniff: função principal para capturar pacotes de rede
# - Raw: camada que representa dados brutos (payload) dos pacotes
# - TCP: camada do protocolo TCP
# - IP: camada do protocolo IP
from scapy.all import sniff, Raw, TCP, IP
# Proteção para Pylance / ambientes sem scapy resolvível
# Tenta importar PcapWriter que é usado para gravar pacotes em ficheiros .pcap
try:
    from scapy.utils import PcapWriter
except Exception:
    # Se a importação falhar, define como None para evitar erros
    PcapWriter = None  # type: ignore

# Importação do colorama para colorir a saída no terminal
# - init: função de inicialização
# - Fore: cores para o texto (foreground)
# - Style: estilos de texto (RESET_ALL, etc.)
from colorama import init as colorama_init, Fore, Style
# Inicializa o colorama com autoreset=True para resetar automaticamente as cores após cada print
colorama_init(autoreset=True)

# ---------------------------
# Configuração e estado
# ---------------------------
# Define a interface de rede padrão para captura de pacotes
# Valor padrão: "wlan0" (interface wireless comum no Linux)
# Pode ser alterada em runtime usando o comando 'iface <nome>' (ex.: 'iface lo' para loopback)
INTERFACE = "wlan0"      # default, podes mudar com 'iface lo' por exemplo
# Variável global que armazena o objeto PcapWriter para gravar todos os pacotes capturados
# Inicializada como None e será criada quando o sniffing iniciar
pcap_writer = None
# Variável global que armazena o objeto PcapWriter específico para pacotes que contêm flags
# Inicializada como None e será criada quando o sniffing iniciar
flag_pcap_writer = None
# Flag booleana que indica se o sniffer está atualmente em execução
# Usada para evitar múltiplas instâncias simultâneas de sniffing
sniffing = False

# FLAG regex: captura ISPGAYA{ qualquer coisa até a próxima '}' }
# Compila uma expressão regular para detectar flags no formato ISPGAYA{...}
# - ISPGAYA\{ : procura literalmente "ISPGAYA{" (a chaveta é escapada porque é especial em regex)
# - ([^}]*) : captura qualquer sequência de caracteres que não seja '}' (grupo de captura 1)
# - \} : procura literalmente a chaveta de fecho "}"
# Case-sensitive por padrão; altere para re.I se quiser ignore-case
FLAG_REGEX = re.compile(r"ISPGAYA\{([^}]*)\}")  # case-sensitive; altere para re.I se quiser ignore-case

# SQLi simple heuristics (mantemos por enquanto, mas foco na FLAG)
# Lista de expressões regulares para detecção heurística de tentativas de SQL Injection
# Cada regex usa (?i) no início para tornar a busca case-insensitive
SQLI_REGEXES = [
    r"(?i)\b(or)\b\s+1\s*=\s*1",        # Detecta "OR 1=1" (tentativa de bypass de autenticação)
    r"(?i)union\s+select",               # Detecta "UNION SELECT" (tentativa de extração de dados)
    r"(?i)information_schema",           # Detecta referências ao information_schema (enumeração de BD)
    r"(?i)\bbenchmark\s*\(",            # Detecta chamadas à função BENCHMARK (time-based SQLi)
    r"(?i)\bsleep\s*\(",                # Detecta chamadas à função SLEEP (time-based SQLi)
    r"(?i)['\"]\s*--",                   # Detecta aspas seguidas de comentário SQL (-- ou #)
    r"(?i)drop\s+table",                 # Detecta tentativas de DROP TABLE (destrutivo)
    r"(?i)insert\s+into"                 # Detecta tentativas de INSERT INTO (inserção de dados)
]

# ---------------------------
# Utilitários
# ---------------------------
def ts_now():
    """
    Gera um timestamp formatado para uso em nomes de ficheiros.
    Formato: YYYYMMDD_HHMMSS (exemplo: 20241107_143025)
    Retorna: string com o timestamp atual
    """
    return datetime.now().strftime("%Y%m%d_%H%M%S")

def make_pcap_filename(prefix="soc_coil", iface=None):
    """
    Cria um nome de ficheiro .pcap único baseado em timestamp.
    
    Args:
        prefix: prefixo para o nome do ficheiro (padrão: "soc_coil")
        iface: nome da interface de rede (opcional, será incluído no nome se fornecido)
    
    Retorna:
        string com o nome do ficheiro no formato: prefix_interface_timestamp.pcap ou prefix_timestamp.pcap
    """
    # Obtém o timestamp atual formatado
    ts = ts_now()
    # Se a interface foi fornecida, inclui no nome do ficheiro
    if iface:
        return f"{prefix}_{iface}_{ts}.pcap"
    # Caso contrário, retorna apenas prefix_timestamp.pcap
    return f"{prefix}_{ts}.pcap"

def print_banner():
    """
    Imprime o banner ASCII art do SOC COIL no terminal.
    Usa cor ciano (CYAN) para destacar visualmente o banner.
    O Style.RESET_ALL garante que as cores não afetem o texto subsequente.
    """
    print(Fore.CYAN + """
  ____ ___   ____   ____   _____   ____  _  _ 
 / ___/ _ \\ / ___| / ___| | ____| / ___|| || |
| |  | | | | |     \\___ \\ |  _|   \\___ \\| || |_
| |__| |_| | |___   ___) || |___   ___) |__   _|
 \\____\\___/ \\____| |____/ |_____| |____/   |_|  
SOC COIL - Single-Interface Sniffer & Flag Detector
    """ + Style.RESET_ALL)

def pretty_alert(priority, src, dst, summary, payload_excerpt=""):
    """
    Imprime um alerta formatado e colorido no terminal.
    
    Args:
        priority: nível de prioridade do alerta ("HIGH", "MEDIUM", "LOW")
        src: endereço IP de origem do pacote
        dst: endereço IP de destino do pacote
        summary: resumo do alerta (descrição do que foi detectado)
        payload_excerpt: excerto do payload do pacote (opcional, máximo 300-600 caracteres)
    
    A cor do alerta varia conforme a prioridade:
    - HIGH: vermelho (Fore.RED) - usado para flags detectadas
    - MEDIUM: magenta (Fore.MAGENTA) - usado para SQLi heuristics
    - LOW: amarelo (Fore.YELLOW) - usado para outros alertas
    """
    # Obtém o timestamp atual formatado para exibição legível
    t = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    # Define a cor padrão como amarelo (LOW priority)
    color = Fore.YELLOW
    # Ajusta a cor conforme a prioridade do alerta
    if priority == "HIGH":
        color = Fore.RED
    elif priority == "MEDIUM":
        color = Fore.MAGENTA
    elif priority == "LOW":
        color = Fore.YELLOW
    # Imprime o cabeçalho do alerta com timestamp, prioridade e resumo
    print(color + f"[{t}] ALERT [{priority}] {summary}")
    # Imprime a direção do tráfego (origem -> destino)
    print(color + f"    {src} -> {dst}")
    # Se foi fornecido um excerto do payload, imprime-o também
    if payload_excerpt:
        print(color + f"    payload_excerpt: {payload_excerpt}")
    # Reseta as cores para não afetar o texto subsequente
    print(Style.RESET_ALL)

# ---------------------------
# Analyzer
# ---------------------------
def analyze_packet(pkt):
    """
    Função callback principal que analisa cada pacote capturado.
    Esta função é chamada pelo Scapy para cada pacote que corresponde ao filtro BPF.
    
    Processo de análise:
    1. Grava o pacote no ficheiro .pcap geral (se disponível)
    2. Extrai o payload (camada Raw) se existir
    3. Procura por flags no formato ISPGAYA{...} (prioridade máxima)
    4. Opcionalmente, procura por padrões de SQL Injection (prioridade média)
    
    Args:
        pkt: objeto Packet do Scapy contendo o pacote capturado
    """
    # Declara as variáveis globais que serão modificadas nesta função
    global pcap_writer, flag_pcap_writer
    try:
        # Sempre gravar pacote no pcap geral se estiver activo
        # Isto permite ter um registo completo de todo o tráfego capturado
        if pcap_writer is not None:
            try:
                # Escreve o pacote completo no ficheiro .pcap geral
                pcap_writer.write(pkt)
            except Exception as e:
                # Se houver erro ao escrever, imprime mas não interrompe o processamento
                print(Fore.RED + f"[pcap write error] {e}")

        # Verifica se o pacote contém dados brutos (payload) na camada Raw
        # A camada Raw contém o conteúdo real da aplicação (HTTP, SQL, etc.)
        if pkt.haslayer(Raw):
            # Extrai o payload como bytes da camada Raw
            raw = bytes(pkt[Raw].load)
            try:
                # Tenta decodificar o payload como UTF-8
                # errors='ignore' garante que caracteres inválidos não causem exceção
                s = raw.decode('utf-8', errors='ignore')
            except:
                # Se a decodificação falhar completamente, converte os bytes para string
                s = str(raw)

            # Normalizar URL-encoded: decodifica caracteres codificados em URL
            # Exemplo: %20 vira espaço, %7B vira '{', etc.
            # unquote_plus também converte '+' em espaços (comportamento de formulários HTML)
            s_unquoted = urllib.parse.unquote_plus(s)
            # Cria uma string combinada para verificar tanto o payload original quanto o decodificado
            # Isto é importante porque flags podem estar codificadas em URL
            to_check = s + "\n" + s_unquoted

            # 1) Procurar FLAG (não case-insensitive por defeito)
            # Procura o padrão ISPGAYA{...} na string combinada
            m = FLAG_REGEX.search(to_check)
            if m:
                # Se encontrou uma flag, extrai o conteúdo completo (ISPGAYA{...})
                flag_content = m.group(0)  # ISPGAYA{...}
                # Extrai apenas o conteúdo interno (sem as chavetas e o prefixo)
                inner = m.group(1)
                # Extrai o endereço IP de origem do pacote (se existir camada IP)
                src = pkt[IP].src if pkt.haslayer(IP) else "?"
                # Extrai o endereço IP de destino do pacote (se existir camada IP)
                dst = pkt[IP].dst if pkt.haslayer(IP) else "?"
                # Cria um excerto do payload (primeiros 600 caracteres) para exibição
                # Remove quebras de linha para facilitar a leitura
                excerpt = to_check[:600].replace("\n", " ").replace("\r", " ")
                # Gera um alerta de prioridade HIGH com a flag detectada
                pretty_alert("HIGH", src, dst, f"FLAG DETECTED: {flag_content}", f"inner={inner} | excerpt={excerpt}")
                # Gravar também no pcap de flags (ficheiro separado apenas com pacotes que contêm flags)
                if flag_pcap_writer is not None:
                    try:
                        # Escreve o pacote no ficheiro .pcap específico de flags
                        flag_pcap_writer.write(pkt)
                    except Exception as e:
                        # Se houver erro ao escrever, imprime mas não interrompe
                        print(Fore.RED + f"[flag pcap write error] {e}")
                # Retorna imediatamente após detectar uma flag
                # Isto evita processamento desnecessário e garante que flags têm prioridade
                return  # já encontrou a flag, não precisamos de mais processamento

            # 2) (opcional) Detecção simples SQLi — gera alerta mas não impede flag logic
            # Itera sobre todas as expressões regulares de SQL Injection
            for rx in SQLI_REGEXES:
                # Procura o padrão SQLi na string combinada (original + decodificada)
                if re.search(rx, to_check):
                    # Se encontrou um padrão SQLi, extrai informações do pacote
                    src = pkt[IP].src if pkt.haslayer(IP) else "?"
                    dst = pkt[IP].dst if pkt.haslayer(IP) else "?"
                    # Cria um excerto do payload decodificado (primeiros 300 caracteres)
                    excerpt = s_unquoted[:300].replace("\n", " ").replace("\r", " ")
                    # Gera um alerta de prioridade MEDIUM com o padrão SQLi detectado
                    pretty_alert("MEDIUM", src, dst, f"SQLI heuristic matched: {rx}", excerpt)
                    # Interrompe o loop após encontrar o primeiro padrão (evita múltiplos alertas por pacote)
                    break

    except Exception as e:
        # Captura qualquer exceção não prevista e imprime um erro
        # Isto garante que um pacote malformado não interrompa todo o sniffer
        print(Fore.RED + f"[analyzer error] {e}")

# ---------------------------
# Sniff control
# ---------------------------
def start_sniff(bpf_filter=None):
    """
    Inicia a captura de pacotes na interface de rede configurada.
    
    Esta função:
    1. Verifica se já existe um sniffer em execução
    2. Cria ficheiros .pcap para gravação (geral e específico de flags)
    3. Inicia a captura de pacotes usando o Scapy
    4. Processa cada pacote através da função analyze_packet
    5. Fecha os ficheiros .pcap quando o sniffing termina
    
    Args:
        bpf_filter: filtro BPF (Berkeley Packet Filter) opcional para limitar a captura
                    Exemplos: "tcp port 80", "host 192.168.1.1", None (captura tudo)
    
    O filtro BPF permite capturar apenas tráfego específico, reduzindo o processamento.
    Se None, captura todo o tráfego na interface especificada.
    """
    # Declara as variáveis globais que serão modificadas
    global sniffing, pcap_writer, flag_pcap_writer
    # Verifica se já existe um sniffer em execução
    if sniffing:
        print(Fore.YELLOW + "[!] Sniffer já está a correr.")
        return
    # Marca o sniffer como ativo
    sniffing = True

    # Criar pcap geral (ficheiro que armazena todos os pacotes capturados)
    if PcapWriter is not None:
        try:
            # Gera um nome único para o ficheiro .pcap geral
            name = make_pcap_filename(prefix="soc_coil", iface=INTERFACE)
            # Cria o objeto PcapWriter para escrever pacotes no ficheiro
            # append=False: sobrescreve o ficheiro se existir
            # sync=True: sincroniza escrita no disco (mais seguro, mas mais lento)
            pcap_writer = PcapWriter(name, append=False, sync=True)
            print(Fore.GREEN + f"[*] PCAP criado: {name}")
        except Exception as e:
            # Se falhar, define como None e continua sem gravação
            pcap_writer = None
            print(Fore.RED + f"[!] Não foi possível criar pcap geral: {e}")
    else:
        # Se PcapWriter não estiver disponível (importação falhou), define como None
        pcap_writer = None
        print(Fore.YELLOW + "[!] PcapWriter não disponível. A captura não será gravada em pcap.")

    # Criar pcap de flags (ficheiro separado apenas para pacotes que contêm flags)
    if PcapWriter is not None:
        try:
            # Gera um nome único para o ficheiro .pcap de flags
            flag_name = make_pcap_filename(prefix="soc_coil_flag_hits")
            # Cria o objeto PcapWriter para escrever apenas pacotes com flags
            flag_pcap_writer = PcapWriter(flag_name, append=False, sync=True)
            print(Fore.GREEN + f"[*] PCAP de FLAG hits criado: {flag_name}")
        except Exception as e:
            # Se falhar, define como None e continua sem gravação específica de flags
            flag_pcap_writer = None
            print(Fore.RED + f"[!] Não foi possível criar pcap de flags: {e}")
    else:
        # Se PcapWriter não estiver disponível, define como None
        flag_pcap_writer = None

    # Informa o utilizador que o sniffing está a iniciar
    print(Fore.CYAN + f"[*] Iniciando sniff na interface '{INTERFACE}' (Ctrl+C para parar).")
    try:
        # Inicia a captura de pacotes usando o Scapy
        # prn=analyze_packet: função callback chamada para cada pacote capturado
        # filter=bpf_filter: filtro BPF opcional (None = captura tudo)
        # store=0: não armazena pacotes em memória (apenas processa e descarta)
        # iface=INTERFACE: interface de rede onde capturar
        # Se bpf_filter for None -> captura tudo
        sniff(prn=analyze_packet, filter=bpf_filter, store=0, iface=INTERFACE)
    except KeyboardInterrupt:
        # Captura Ctrl+C do utilizador para parar o sniffing graciosamente
        print(Fore.CYAN + "\n[*] Sniffer parado pelo utilizador (Ctrl+C).")
    except Exception as e:
        # Captura outros erros durante o sniffing (ex: permissões insuficientes, interface inválida)
        print(Fore.RED + f"[!] Erro ao executar sniff: {e}")
    finally:
        # Bloco finally garante que o código de limpeza sempre executa, mesmo em caso de erro
        # Marca o sniffer como inativo
        sniffing = False
        # Fechar writers (garante que os ficheiros .pcap são fechados corretamente)
        if pcap_writer is not None:
            try:
                # Fecha o ficheiro .pcap geral e garante que todos os dados são escritos
                pcap_writer.close()
                print(Fore.CYAN + "[*] PCAP geral fechado e salvo.")
            except Exception as e:
                # Se houver erro ao fechar, imprime mas continua
                print(Fore.RED + f"[!] Erro ao fechar pcap geral: {e}")
            finally:
                # Garante que a variável é resetada mesmo se houver erro
                pcap_writer = None
        if flag_pcap_writer is not None:
            try:
                # Fecha o ficheiro .pcap de flags e garante que todos os dados são escritos
                flag_pcap_writer.close()
                print(Fore.CYAN + "[*] PCAP de FLAG hits fechado e salvo.")
            except Exception as e:
                # Se houver erro ao fechar, imprime mas continua
                print(Fore.RED + f"[!] Erro ao fechar pcap de flags: {e}")
            finally:
                # Garante que a variável é resetada mesmo se houver erro
                flag_pcap_writer = None

# ---------------------------
# UI / Menu
# ---------------------------
def show_menu():
    """
    Exibe o banner e o menu de comandos disponíveis no terminal.
    Esta função é chamada no início do programa e pode ser chamada novamente pelo utilizador.
    """
    # Imprime o banner ASCII art do SOC COIL
    print_banner()
    # Lista todos os comandos disponíveis com suas descrições
    print("Comandos disponíveis:")
    # Comando para iniciar captura sem filtro (captura todo o tráfego)
    print("  run             -> Iniciar captura na interface definida (captura tudo)")
    # Comando para iniciar captura com filtro BPF (permite limitar o tráfego capturado)
    print('  run "<bpf>"     -> Iniciar captura com filtro BPF (ex.: run "tcp port 8000")')
    # Comando para alterar a interface de rede onde capturar
    print("  iface <ifname>  -> Definir interface (ex.: iface lo)")
    # Comando para mostrar qual interface está atualmente configurada
    print("  show iface      -> Mostrar interface definida")
    # Comando para listar as regras de detecção (flags e SQLi)
    print("  rules           -> Mostrar regras/flag pattern")
    # Comando para sair do programa
    print("  exit            -> Sair")
    # Linha em branco para melhorar a legibilidade
    print("")

def list_rules():
    """
    Exibe as regras de detecção configuradas no sistema.
    Mostra o padrão de flag e todas as expressões regulares de SQL Injection.
    """
    print("Regras / padrões:")
    # Exibe o padrão de detecção de flags
    print(" - Detect FLAG: pattern ISPGAYA{QUALQUER_COISA_AQUI} (regex: ISPGAYA{...})")
    # Exibe todas as expressões regulares de SQL Injection separadas por vírgula
    print(" - SQLi heuristics:", ", ".join([r for r in SQLI_REGEXES]))

def main_loop():
    """
    Loop principal do programa que processa comandos do utilizador.
    
    Este loop interativo permite ao utilizador:
    - Iniciar captura de pacotes (com ou sem filtro BPF)
    - Alterar a interface de rede
    - Ver a interface atual
    - Listar regras de detecção
    - Sair do programa
    
    O loop continua até que o utilizador digite 'exit' ou 'quit', ou pressione Ctrl+C.
    """
    # Declara a variável global INTERFACE que pode ser modificada
    global INTERFACE
    # Imprime o banner no início do programa
    print_banner()
    # Avisa o utilizador que precisa de privilégios elevados para capturar pacotes
    print("Nota: executa com privilégios elevados (sudo / Administrator).")
    # Exibe o menu de comandos disponíveis
    show_menu()
    # Loop infinito que processa comandos até o utilizador sair
    while True:
        try:
            # Solicita um comando do utilizador e remove espaços em branco no início/fim
            cmd = input("SOC_COIL> ").strip()
        except (KeyboardInterrupt, EOFError):
            # Captura Ctrl+C ou EOF (Ctrl+D) e sai graciosamente
            print("\nSaindo...")
            break

        # Processa o comando "run" (iniciar captura)
        if cmd.lower().startswith("run"):
            # Divide o comando em partes para extrair o filtro BPF opcional
            parts = cmd.split(" ", 1)
            # Inicializa o filtro BPF como None (sem filtro)
            bpf = None
            # Se o comando tiver uma segunda parte (filtro BPF), extrai-a
            if len(parts) == 2 and parts[1].strip() != "":
                # Remove aspas simples e duplas do filtro BPF (permite usar com ou sem aspas)
                bpf = parts[1].strip().strip('"').strip("'")
                # Informa o utilizador que está a usar um filtro BPF
                print(Fore.CYAN + f"[*] Usando filtro BPF: {bpf}")
            # Inicia a captura de pacotes com o filtro BPF especificado (ou None)
            start_sniff(bpf_filter=bpf)

        # Processa o comando "iface" (alterar interface de rede)
        elif cmd.lower().startswith("iface"):
            # Divide o comando em partes para extrair o nome da interface
            parts = cmd.split(" ", 1)
            # Se o comando tiver uma segunda parte (nome da interface), atualiza a variável global
            if len(parts) == 2 and parts[1].strip():
                # Atualiza a interface global com o nome fornecido
                INTERFACE = parts[1].strip()
                # Confirma a alteração da interface
                print(Fore.GREEN + f"Interface definida: {INTERFACE}")
            else:
                # Se não foi fornecido um nome de interface, mostra a sintaxe correta
                print("Uso: iface <ifname>  (ex.: iface lo)")

        # Processa o comando "show iface" (mostrar interface atual)
        elif cmd.lower() == "show iface":
            # Exibe a interface de rede atualmente configurada
            print(f"Interface actual: {INTERFACE}")

        # Processa o comando "rules" (listar regras de detecção)
        elif cmd.lower() == "rules":
            # Chama a função que lista todas as regras de detecção
            list_rules()

        # Processa os comandos "exit" ou "quit" (sair do programa)
        elif cmd.lower() in ("exit", "quit"):
            # Verifica se há um sniffer em execução
            if sniffing:
                # Avisa o utilizador que precisa parar o sniffing manualmente (Ctrl+C)
                print(Fore.CYAN + "[*] A terminar sniff antes de sair...")
                # Nota: parar sniffing definindo sniffing=False não funciona aqui porque sniff é blocking
                # O utilizador precisa pressionar Ctrl+C para parar o sniffing, depois pode sair
            # Mensagem de despedida
            print("Saindo...")
            # Sai do loop principal
            break

        # Processa comandos vazios (apenas Enter pressionado)
        elif cmd.strip() == "":
            # Ignora comandos vazios e continua o loop
            continue

        # Processa comandos desconhecidos
        else:
            # Informa o utilizador que o comando não foi reconhecido e lista os comandos válidos
            print("Comando desconhecido. Use 'run', 'iface', 'show iface', 'rules' ou 'exit'.")

# Ponto de entrada do programa
# Este bloco só executa se o script for executado diretamente (não quando importado como módulo)
if __name__ == "__main__":
    # Inicia o loop principal do programa
    main_loop()
