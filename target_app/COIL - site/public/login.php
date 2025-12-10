<?php
session_start();

$dbFile = __DIR__ . '/../vuln_db.sqlite';
$db = new PDO('sqlite:' . $dbFile);
$db->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);

$message = '';

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $username = isset($_POST['username']) ? $_POST['username'] : '';
    $password = isset($_POST['password']) ? $_POST['password'] : '';

    // === VULNERÁVEL: query construída por concatenação (INTENCIONAL) ===
    $sql = "SELECT * FROM users WHERE username='$username' AND password='$password'";

    // Executa a query vulnerável (intencional)
    try {
        $stmt = $db->query($sql);
        $user = $stmt ? $stmt->fetch(PDO::FETCH_ASSOC) : false;
    } catch (Exception $e) {
        $user = false;
    }

    if ($user) {
        // Executa a mesma verificação usando prepared statement (seguro)
        $safeStmt = $db->prepare("SELECT * FROM users WHERE username = ? AND password = ?");
        $safeStmt->execute([$username, $password]);
        $safeUser = $safeStmt->fetch(PDO::FETCH_ASSOC);

        if ($safeUser) {
            // Login normal (credenciais válidas) — sem flag
            $_SESSION['user'] = $safeUser['username'];
            header('Location: index.php');
            exit;
        } else {
            // A query vulnerável devolveu um utilizador, mas a query segura não:
            // indicativo de SQL Injection — envia a flag no header
            header('Flag: ISPGAYA{SQL_Injection}');
            $_SESSION['user'] = $user['username'];
            header('Location: index.php');
            exit;
        }
    } else {
        $message = 'Credenciais inválidas.';
    }
}
?>
<!doctype html>
<html lang="pt">
<head>
  <meta charset="utf-8">
  <title>NASA Official Access — 3I/ATLAS</title>
  <link rel="stylesheet" href="styles.css">
</head>
<body>
  <header>
    <div class="brand">
      <img class="logo" alt="NASA" src="https://www.nasa.gov/wp-content/themes/nasa/assets/images/nasa-logo.svg" />
      <div>
        <div class="title">NASA Official Access Portal</div>
        <div class="subtitle muted">Projeto COIL — 3I/ATLAS</div>
      </div>
    </div>
    <span class="badge"><span class="dot"></span> Acesso Autenticado</span>
  </header>

  <div class="hero">
    <div class="lockup twinkle">
      <img alt="NASA" src="https://www.nasa.gov/wp-content/themes/nasa/assets/images/nasa-logo.svg" />
      <div class="eyebrow">Astrophysics Sandbox</div>
      <h1>3I/ATLAS — Portal Retro</h1>
      <p class="muted">Acesso para investigadores e cientistas convidados. Ambiente educativo de cibersegurança.</p>
    </div>
  </div>

  <div class="login-box retro-grid">
    <h2>Login</h2>
    <?php if ($message): ?><p class="error"><?php echo htmlspecialchars($message); ?></p><?php endif; ?>
    <form method="post">
      <label>Username<br><input name="username" required></label><br>
      <label>Password<br><input name="password" type="password" required></label><br>
      <button type="submit">Entrar</button>
    </form>
    <p class="footnote">Ao autenticar, confirma que compreende que este ambiente é apenas para estudo. NASA theme para fins educativos.</p>
  </div>
</body>
</html>
