<?php
declare(strict_types=1);

$config = require __DIR__ . '/config.php';
$secure = isset($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off';
session_name('imtiho_setup');
session_set_cookie_params(['httponly' => true, 'secure' => $secure, 'samesite' => 'Strict', 'path' => '/']);
session_start();
$_SESSION['csrf'] = $_SESSION['csrf'] ?? bin2hex(random_bytes(32));
$message = '';
$complete = false;

try {
    $pdo = new PDO(
        'mysql:host=' . $config['db_host'] . ';dbname=' . $config['db_name'] . ';charset=utf8mb4',
        $config['db_user'],
        $config['db_password'],
        [PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION, PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC]
    );
    $complete = (int)$pdo->query("SELECT COUNT(*) FROM app_users WHERE role='admin'")->fetchColumn() > 0;
} catch (Throwable $error) {
    $message = 'Пайваст ба пойгоҳи дода нашуд. Маълумоти config.php ва воридоти schema.sql-ро санҷед.';
}

if ($_SERVER['REQUEST_METHOD'] === 'POST' && !$complete && $message === '') {
    $token = (string)($_POST['csrf'] ?? '');
    $setupKey = (string)($_POST['setup_key'] ?? '');
    $username = trim((string)($_POST['username'] ?? ''));
    $fullName = trim((string)($_POST['full_name'] ?? ''));
    $password = (string)($_POST['password'] ?? '');

    if (!hash_equals($_SESSION['csrf'], $token)) {
        $message = 'Дархост тасдиқ нашуд. Саҳифаро нав кунед.';
    } elseif (strlen($config['setup_key']) < 48 || str_contains($config['setup_key'], 'REPLACE_WITH')) {
        $message = 'Аввал setup_key-и дарозу тасодуфиро дар config.php гузоред.';
    } elseif (!hash_equals($config['setup_key'], $setupKey)) {
        $message = 'Калиди насб нодуруст аст.';
    } elseif (!preg_match('/^[a-zA-Z0-9._-]{3,64}$/', $username) || $fullName === '' || strlen($password) < 12) {
        $message = 'Логинро дуруст пур кунед ва рамзи на кам аз 12 аломат интихоб намоед.';
    } else {
        try {
            $pdo->beginTransaction();
            if ((int)$pdo->query("SELECT COUNT(*) FROM app_users WHERE role='admin'")->fetchColumn() > 0) {
                $pdo->rollBack();
                $complete = true;
            } else {
                $statement = $pdo->prepare("INSERT INTO app_users (username,password_hash,full_name,role) VALUES (:username,:hash,:name,'admin')");
                $statement->execute(['username' => $username, 'hash' => password_hash($password, PASSWORD_DEFAULT), 'name' => $fullName]);
                $pdo->commit();
                $complete = true;
            }
        } catch (Throwable $error) {
            if ($pdo->inTransaction()) $pdo->rollBack();
            $message = 'Ҳисоби администратор сохта нашуд. Логини такрорӣ ё пайвасти пойгоҳи додаҳоро санҷед.';
        }
    }
}

function h(string $value): string { return htmlspecialchars($value, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8'); }
?>
<!doctype html>
<html lang="tg">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<meta name="referrer" content="no-referrer">
<title>Насби администратор</title>
<style>
body{margin:0;background:#f4f6f3;color:#1f2b27;font:15px/1.5 Arial,sans-serif;min-height:100vh;display:grid;place-items:center;padding:20px;box-sizing:border-box}.box{width:min(100%,460px);background:white;border-top:3px solid #174c3e;padding:25px;box-shadow:0 12px 40px #173d3218}h1{font-size:23px;margin:0 0 7px;color:#174c3e}p{color:#66736b;font-size:13px;margin:0 0 20px}.field{display:grid;gap:6px;margin:14px 0}.field label{font-weight:bold;font-size:12px}.field input{padding:11px;border:1px solid #d6ded8;border-radius:3px;font:inherit}.btn{padding:11px 16px;border:0;border-radius:3px;background:#174c3e;color:white;font-weight:bold;cursor:pointer}.note{padding:11px;background:#edf4ef;color:#285b46;font-size:12px}.error{padding:11px;background:#f8ecea;color:#8d342e;font-size:12px;margin:14px 0}.footer{margin-top:18px;font-size:11px;color:#78857d}
</style>
</head>
<body><main class="box"><h1>Насби администратор</h1><p>Ин қадамро як бор, баъди насби MySQL иҷро кунед.</p>
<?php if ($complete): ?><div class="note">Ҳисоби администратор аллакай сохта шудааст. Ин саҳифаро ҳоло аз сервер пок кунед.</div>
<?php else: ?>
<?php if ($message !== ''): ?><div class="error"><?= h($message) ?></div><?php endif; ?>
<form method="post" autocomplete="off">
<input type="hidden" name="csrf" value="<?= h($_SESSION['csrf']) ?>">
<div class="field"><label for="setup_key">Калиди насб</label><input id="setup_key" name="setup_key" required autocomplete="off"></div>
<div class="field"><label for="full_name">Номи пурра</label><input id="full_name" name="full_name" required maxlength="160"></div>
<div class="field"><label for="username">Логини администратор</label><input id="username" name="username" required minlength="3" maxlength="64" pattern="[A-Za-z0-9._-]+"></div>
<div class="field"><label for="password">Рамз (камаш 12 аломат)</label><input id="password" name="password" type="password" required minlength="12" autocomplete="new-password"></div>
<button class="btn" type="submit">Сохтани ҳисоби администратор</button>
</form><div class="footer">Пас аз насб setup_admin.php-ро аз сервер пок кунед ва калиди насбро иваз намоед.</div>
<?php endif; ?></main></body></html>
