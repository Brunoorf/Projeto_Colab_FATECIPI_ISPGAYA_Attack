# COIL — SQL Injection Demo (Tema NASA Retro)

Ambiente didático mínimo em PHP + SQLite para estudar e demonstrar SQL Injection, com um tema visual inspirado na NASA e conteúdo sobre o cometa interestelar 3I/ATLAS.

Autores: Miguel Magalhães e Alexandre Marques  
Projeto: COIL — ISPGAYA (2025)

Importante: Esta aplicação é intencionalmente vulnerável e destina‑se apenas a fins educativos em ambiente controlado. Não utilize este código em produção.

## Estrutura do repositório

```
COIL_site_SQL_Injection/
├─ README.md                     # Este guia
└─ COIL - site/
	 ├─ init_db.php               # Script que cria/reset à BD SQLite e injeta utilizador de teste
	 ├─ vuln_db.sqlite            # Base de dados SQLite (incluída para conveniência didática)
	 └─ public/                   # Document root do servidor web
			├─ index.php              # Página inicial; mostra conteúdo NASA/3I/ATLAS após login
			├─ login.php              # Página de autenticação — contém consulta vulnerável (propositado)
			├─ styles.css             # Estilos do tema NASA Retro (visual apenas)
			└─ assets/                # (opcional) Imagens estáticas usadas em index.php
```

### Descrição dos ficheiros

- `COIL - site/init_db.php`
	- Apaga a BD anterior (`vuln_db.sqlite`) se existir e cria uma nova.
	- Define a tabela `users (id, username UNIQUE, password)`.
	- Insere um utilizador de teste: `admin / password123` (plain‑text, intencional para a aula).
	- Saída no terminal indica a localização da BD e as credenciais de teste.

- `COIL - site/vuln_db.sqlite`
	- Ficheiro SQLite com a estrutura/dados para testes.
	- Mantido no repositório para simplificar a execução do exercício (não recomendado em produção).

- `COIL - site/public/login.php`
	- Formulário de login (método POST) e lógica de autenticação.
	- Inclui uma query SQL construída por concatenação de strings com inputs do utilizador — VULNERÁVEL (propositado), para exploração de SQLi.
	- Em caso de “login” obtido apenas pela query vulnerável (e não pela segura), envia um cabeçalho HTTP `Flag: ISPGAYA{SQL_Injection}` a indicar que ocorreu exploração (útil para o estudo).
	- Nota: Existe também uma verificação com `prepared statements` como contraste do método seguro.

- `COIL - site/public/index.php`
	- Página principal. Mostra saudação se existir sessão ativa.
	- Após login, apresenta um dossier organizado sobre o cometa 3I/ATLAS (texto + figura) num tema “NASA Retro”.
	- Se não estiver autenticado, mostra uma breve introdução e link para login.

- `COIL - site/public/styles.css`
	- Folha de estilos do tema visual “NASA Retro” (cores, gradientes, tipografia, cartões, figura, etc.).
	- Não altera a lógica de aplicação — apenas aparência.
	- Comentários no ficheiro explicam cada secção relevante (autoria: Miguel Magalhães e Alexandre Marques; COIL — ISPGAYA).

- `COIL - site/public/assets/`
	- Pasta opcional para imagens. Para o exemplo em `index.php`, coloque o ficheiro:
		- `Imagem-do-cometa-interestelar-3IATLAS-em-21-de-julho-de-2025-1-800x450.jpg`
	- Se a imagem não existir, a secção “Imagens” mostrará um espaço vazio no local do `<img>`.

## Como executar localmente

Pré‑requisitos: macOS com PHP instalado ou Docker.

### Opção A — Servidor embutido do PHP (recomendado)

1) (Opcional) Reset/seed da base de dados
```zsh
php "COIL - site/init_db.php"
```

2) Servir a pasta pública
```zsh
php -S 127.0.0.1:8000 -t "COIL - site/public"
```

3) Abrir no browser

http://127.0.0.1:8000

Credenciais de teste: `admin / password123`

Se não tiveres PHP instalado:
```zsh
brew install php
```

### Opção B — Docker (sem instalar PHP localmente)

```zsh
docker run --rm -it \
	-p 8000:8000 \
	-v "$(pwd)/COIL - site":/app \
	-w /app \
	php:8.2-cli \
	sh -c 'php init_db.php && php -S 0.0.0.0:8000 -t public'
```

Abrir: http://127.0.0.1:8000

### Opção C — MAMP/Valet/Apache

- Define o Document Root para `COIL - site/public`.
- Garante que a BD `vuln_db.sqlite` está um nível acima do DocRoot, tal como no repositório.

## Sobre o exercício de SQL Injection

- A página `login.php` contém uma consulta vulnerável de propósito para fins académicos.
- A exploração (por ex., com `' OR '1'='1' -- `) pode permitir “login” sem conhecermos a password.
- Se a query vulnerável retornar resultado mas a versão com `prepared statements` não, o servidor envia um header `Flag: ISPGAYA{SQL_Injection}` ao fazer o redirect — verifica na aba Network das DevTools.
- Reforço: não reutilizar este padrão em sistemas reais.

## Tema visual “NASA Retro”

- O tema foca-se em:
	- Paleta: azul NASA, vermelho de destaque, branco quase‑gelo.
	- Fundo com gradientes “nebula glow” e vinheta suave, evitando padrões repetitivos (sem moiré).
	- Cartões translúcidos e tipografia com contraste em fundo escuro.
- O ficheiro `styles.css` tem comentários detalhados por secções.

## Secção 3I/ATLAS (após login)

- Ao iniciar sessão, `index.php` mostra um resumo com subseções: Descoberta, Classificação/Órbita, Trajetória/Velocidade, Características físicas, Imagens, Observações, Contexto.
- A secção “Imagens” inclui uma figura com legenda profissional a explicar a coma em forma de gota e a orientação da cauda.
- Para aparecer a imagem, coloca o ficheiro referido em `public/assets/`.

## Troubleshooting

- Erro ao correr `npm run dev`: este projeto não usa Node/npm (não há `package.json`). Usa o servidor embutido do PHP ou Docker (ver acima).
- Erro "command not found: php": instala o PHP via Homebrew: `brew install php`.
- Imagem não aparece: confirma o caminho `COIL - site/public/assets/Imagem-do-cometa-interestelar-3IATLAS-em-21-de-julho-de-2025-1-800x450.jpg` e faz refresh forçado.

## Aviso legal

Este repositório é para fins educativos em ambiente controlado. O código vulnerável existe para demonstração. Não utilizar em produção.

