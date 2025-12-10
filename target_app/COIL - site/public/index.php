<?php
// public/index.php
session_start();
$user = isset($_SESSION['user']) ? $_SESSION['user'] : null;
?>
<!doctype html>
<html lang="pt">
<head>
  <meta charset="utf-8">
  <title>3I/ATLAS — Portal NASA Retro</title>
  <link rel="stylesheet" href="styles.css">
</head>
<body>
  <header>
    <div class="brand">
      <img class="logo" alt="NASA" src="https://www.nasa.gov/wp-content/themes/nasa/assets/images/nasa-logo.svg" />
      <div>
        <div class="title">3I/ATLAS — Cometa Interestelar</div>
        <div class="subtitle muted">COIL • Portal Retro inspirado na NASA</div>
      </div>
    </div>
    <?php if ($user): ?>
      <div class="user">Olá, <?php echo htmlspecialchars($user); ?></div>
    <?php else: ?>
      <div class="user"><a href="login.php">Login</a></div>
    <?php endif; ?>
  </header>

  <main>
    <?php if ($user): ?>
      <div class="nasa-ribbon card">
        <img alt="NASA" src="https://www.nasa.gov/wp-content/themes/nasa/assets/images/nasa-logo.svg" />
        <div>
          <strong>Portal inclusivo para cientistas da NASA</strong>
          <div class="muted">Acesso autorizado. Tema retro e paleta oficial inspirada na NASA.</div>
        </div>
      </div>
      <div class="prose stack">
        <section class="card">
          <div class="kicker">Resumo</div>
          <h2>Cometa interestelar 3I/ATLAS</h2>
          <p class="lead">Visitante interestelar observado em 2025. Este portal agrega apontamentos científicos e contexto didático do estudo.</p>
        </section>

        <section class="card">
          <h3>Descoberta</h3>
          <p>O 3I/ATLAS foi descoberto em 1º de julho de 2025 pelo telescópio ATLAS (Río Hurtado, Chile), financiado pela NASA. Inicialmente designado C/2025 N1 (ATLAS), recebeu a designação 3I/ATLAS ao confirmar-se a sua natureza interestelar — o terceiro visitante conhecido após 1I/ʻOumuamua e 2I/Borisov. Observações iniciais já mostravam atividade cometária (coma difusa ao redor de um núcleo gelado).</p>
        </section>

        <section class="card">
          <h3>Classificação e órbita</h3>
          <p>Os dados orbitais revelam uma trajetória hiperbólica (excentricidade &gt; 1), típica de objetos não ligados gravitacionalmente ao Sol. Assim, 3I/ATLAS atravessa o Sistema Solar e regressará ao meio interestelar após o periélio, sem orbitar o Sol como cometas comuns.</p>
        </section>

        <section class="card">
          <h3>Trajetória e velocidade</h3>
          <p>O cometa cruza o Sistema Solar interno a ~58 km/s (~210 mil km/h). Passou no periélio em 29 de outubro de 2025, a ~1,36 AU do Sol, dentro da órbita de Marte, sem aproximação perigosa à Terra. A inclinação elevada (~175°) indica origem fora do plano planetário.</p>
        </section>

        <section class="card">
          <h3>Características físicas</h3>
          <ul>
            <li><strong>Núcleo:</strong> estimado &lt; ~5,6 km (Hubble); encoberto por coma de poeira.</li>
            <li><strong>Coma e cauda:</strong> atividade típica por sublimação, com coma evidente e cauda desenvolvida.</li>
            <li><strong>Composição:</strong> JWST/NIRSpec detetou H₂O, CO e CO₂; razão CO₂/H₂O elevada sugere ambientes muito frios ou história de radiação intensa.</li>
          </ul>
        </section>

        <section class="card">
          <h3>Imagens da NASA do 3I/ATLAS</h3>
          <p>Registos de Hubble e de observatórios terrestres (ex.: Gemini North/NOIRLab) confirmam a coma assimétrica e a dinâmica da cauda, consistentes com atividade cometária.</p>
          <figure class="figure">
            <img loading="lazy" alt="Cometa 3I/ATLAS em 21 de julho de 2025, coma difusa em forma de gota captada por observação astronómica." src="https://aventurasnahistoria.com.br/wp-content/uploads/2025/10/Imagem-do-cometa-interestelar-3IATLAS-em-21-de-julho-de-2025-1-800x450.jpg">
            <figcaption><span class="label">Figura.</span> 3I/ATLAS observado em 21 de julho de 2025. A imagem evidencia uma <em>coma</em> difusa em forma de gota e o início de cauda, produzidas pela sublimação de gelos sob aquecimento solar. O brilho assimétrico e a morfologia do envelope gasoso reforçam a atividade do núcleo e a orientação da cauda em relação ao vento solar.</figcaption>
          </figure>
        </section>

        <section class="card">
          <h3>Observações e análise</h3>
          <p>A NASA utilizou Hubble, JWST e outros instrumentos (incl. SPHEREx) para caracterizar velocidade, composição e dimensões. Estudos liderados por equipas do GSFC destacam a riqueza de CO₂ e consolidam o estatuto de terceiro objeto interestelar conhecido.</p>
        </section>

        <section class="card">
          <h3>Contexto</h3>
          <p>Tal como 1I/ʻOumuamua e 2I/Borisov, 3I/ATLAS oferece uma oportunidade rara para investigar material formado noutros sistemas planetários, informando modelos de formação e evolução de cometas.</p>
          <p class="footnote">Fontes: comunicações da NASA/JPL, NASA Science (Goddard), GSFC Science Nuggets e APOD.</p>
        </section>
      </div>
    <?php else: ?>
      <h2>Bem‑vindo</h2>
      <p>Este é um ambiente educativo para aprender sobre segurança web — exercício de SQL Injection (em ambiente isolado).</p>
      <p>Tema: <strong>3I/ATLAS</strong>, o novo cometa interestelar. Faça <a href="login.php">login</a> para ver o dossier NASA em modo retro.</p>
    <?php endif; ?>
  </main>
</body>
</html>
