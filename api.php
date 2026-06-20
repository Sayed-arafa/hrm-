<?php
header('Content-Type: application/json');
// CORS restricted to localhost in development; update for production domain
$allowedOrigins = ['http://localhost', 'http://127.0.0.1'];
$origin = $_SERVER['HTTP_ORIGIN'] ?? '';
if (in_array($origin, $allowedOrigins)) {
    header('Access-Control-Allow-Origin: ' . $origin);
} else {
    header('Access-Control-Allow-Origin: http://localhost');
}
header('Access-Control-Allow-Methods: POST, GET, OPTIONS');
header('Access-Control-Allow-Headers: Content-Type, Authorization');

// API Authentication - change this in production via environment variable
// Auto-generate .env on first run
$envFile = __DIR__ . '/.env';
if (!file_exists($envFile)) {
    $secret = bin2hex(openssl_random_pseudo_bytes(32));
    file_put_contents($envFile, "HRM_API_KEY=$secret
");
    chmod($envFile, 0600);
}
$env = @parse_ini_file($envFile);
$apiSecret = $env && isset($env['HRM_API_KEY']) ? $env['HRM_API_KEY'] : 'hrm-secret-key-2026-change-me';
define('API_SECRET', $apiSecret);

function checkAuth() {
    $headers = getallheaders();
    $auth = $headers['Authorization'] ?? '';
    $token = (strpos($auth, 'Bearer ') === 0) ? substr($auth, 7) : '';

    // Allow local dev key for localhost/127.0.0.1 (development only)
    $remoteAddr = $_SERVER['REMOTE_ADDR'] ?? '';
    $isLocal = in_array($remoteAddr, ['127.0.0.1', '::1']);

    if ($token === API_SECRET || ($isLocal && $token === 'hrm-local-dev-key')) {
        return;
    }
    http_response_code(401);
    echo json_encode(['error' => 'Unauthorized']);
    exit;
}

$dbFile = __DIR__ . '/hrm.db';
$backupDir = __DIR__ . '/backups';

try {
    $pdo = new PDO('sqlite:' . $dbFile);
    $pdo->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
    $pdo->setAttribute(PDO::ATTR_DEFAULT_FETCH_MODE, PDO::FETCH_ASSOC);
} catch (PDOException $e) {
    http_response_code(500);
    echo json_encode(['error' => 'Database failed: ' . $e->getMessage()]);
    exit;
}

// Create table if not exists
$pdo->exec("CREATE TABLE IF NOT EXISTS audit_log (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    action TEXT NOT NULL,
    details TEXT,
    user_ip TEXT,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
)");

$pdo->exec("CREATE TABLE IF NOT EXISTS data_store (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    key TEXT UNIQUE NOT NULL,
    value TEXT NOT NULL,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
)");

function autoBackup($dbFile, $backupDir) {
    if (!is_dir($backupDir)) {
        mkdir($backupDir, 0777, true);
    }
    // Daily backup only (one per day)
    $backupFile = $backupDir . '/hrm_backup_' . date('Y-m-d') . '.db';
    if (!file_exists($backupFile) && file_exists($dbFile)) {
        copy($dbFile, $backupFile);
    }
    // Keep only last 20 backups
    $backups = glob($backupDir . '/*.db');
    if (count($backups) > 20) {
        usort($backups, function($a, $b) { return filemtime($a) - filemtime($b); });
        $toDelete = array_slice($backups, 0, count($backups) - 20);
        foreach ($toDelete as $f) @unlink($f);
    }
    return $backupFile;
}

$action = $_GET['action'] ?? '';

if ($_SERVER['REQUEST_METHOD'] === 'OPTIONS') {
    http_response_code(200);
    exit;
}

if ($action === 'save' && $_SERVER['REQUEST_METHOD'] === 'POST') {
    checkAuth();

    // Validate Content-Type
    $contentType = $_SERVER['CONTENT_TYPE'] ?? '';
    if (strpos($contentType, 'application/json') === false) {
        http_response_code(415);
        echo json_encode(['error' => 'Content-Type must be application/json']);
        exit;
    }

    // Rate limiting: max 30 saves per minute per IP
    $ip = $_SERVER['REMOTE_ADDR'] ?? 'unknown';
    $rateKey = 'rate_' . $ip;
    $now = time();
    $stmt = $pdo->prepare("SELECT value FROM data_store WHERE key = :key");
    $stmt->execute([':key' => $rateKey]);
    $rateRow = $stmt->fetch();
    $rateData = $rateRow ? json_decode($rateRow['value'], true) : ['count' => 0, 'window' => $now];
    if ($now - $rateData['window'] > 60) {
        $rateData = ['count' => 0, 'window' => $now];
    }
    $rateData['count']++;
    if ($rateData['count'] > 30) {
        http_response_code(429);
        echo json_encode(['error' => 'Rate limit exceeded. Max 30 requests/minute.']);
        exit;
    }
    $pdo->prepare("INSERT INTO data_store (key, value) VALUES (:key, :value) ON CONFLICT(key) DO UPDATE SET value=:value, updated_at=CURRENT_TIMESTAMP")
        ->execute([':key' => $rateKey, ':value' => json_encode($rateData)]);
    $input = json_decode(file_get_contents('php://input'), true);
    if (!$input || !isset($input['key']) || !isset($input['value'])) {
        echo json_encode(['success' => false, 'error' => 'Missing key or value']);
        exit;
    }

    // Validate key format (alphanumeric, underscore, hyphen, dot only)
    $key = $input['key'];
    if (!preg_match('/^[a-zA-Z0-9_.\-]+$/', $key) || strlen($key) > 128) {
        echo json_encode(['success' => false, 'error' => 'Invalid key format']);
        exit;
    }

    // Validate value size (max 10MB)
    $valueJson = json_encode($input['value'], JSON_UNESCAPED_UNICODE);
    if (strlen($valueJson) > 10 * 1024 * 1024) {
        echo json_encode(['success' => false, 'error' => 'Value exceeds 10MB limit']);
        exit;
    }

    $stmt = $pdo->prepare("INSERT INTO data_store (key, value) VALUES (:key, :value) 
                          ON CONFLICT(key) DO UPDATE SET value=:value, updated_at=CURRENT_TIMESTAMP");
    $stmt->execute([
        ':key' => $input['key'], 
        ':value' => $valueJson
    ]);

    // Audit log
    $pdo->prepare("INSERT INTO audit_log (action, details, user_ip) VALUES (:action, :details, :ip)")
        ->execute([':action' => 'SAVE', ':details' => substr($input['key'], 0, 100), ':ip' => $_SERVER['REMOTE_ADDR'] ?? 'unknown']);

    // Auto-backup on every save (daily only)
    $backupFile = autoBackup($dbFile, $backupDir);

    echo json_encode(['success' => true, 'message' => 'Saved to server', 'backup' => basename($backupFile)]);

} elseif ($action === 'load' && $_SERVER['REQUEST_METHOD'] === 'GET') {
    $key = $_GET['key'] ?? '';
    if (!$key) {
        echo json_encode(['success' => false, 'error' => 'Missing key']);
        exit;
    }
    $stmt = $pdo->prepare("SELECT value FROM data_store WHERE key = :key");
    $stmt->execute([':key' => $key]);
    $row = $stmt->fetch();
    if ($row) {
        echo json_encode(['success' => true, 'value' => json_decode($row['value'], true)], JSON_UNESCAPED_UNICODE);
    } else {
        echo json_encode(['success' => false, 'value' => null]);
    }

} elseif ($action === 'list' && $_SERVER['REQUEST_METHOD'] === 'GET') {
    $stmt = $pdo->query("SELECT key, value FROM data_store");
    $result = [];
    while ($row = $stmt->fetch()) {
        $result[$row['key']] = json_decode($row['value'], true);
    }
    echo json_encode(['success' => true, 'data' => $result], JSON_UNESCAPED_UNICODE);

} elseif ($action === 'delete' && $_SERVER['REQUEST_METHOD'] === 'POST') {
    checkAuth();
    $input = json_decode(file_get_contents('php://input'), true);
    $key = $input['key'] ?? '';
    if ($key) {
        $stmt = $pdo->prepare("DELETE FROM data_store WHERE key = :key");
        $stmt->execute([':key' => $key]);
    }
    // Audit log
    $pdo->prepare("INSERT INTO audit_log (action, details, user_ip) VALUES (:action, :details, :ip)")
        ->execute([':action' => 'DELETE', ':details' => substr($key, 0, 100), ':ip' => $_SERVER['REMOTE_ADDR'] ?? 'unknown']);

    echo json_encode(['success' => true]);

} elseif ($action === 'audit' && $_SERVER['REQUEST_METHOD'] === 'GET') {
    checkAuth();
    $limit = min(1000, intval($_GET['limit'] ?? 100));
    $stmt = $pdo->query("SELECT * FROM audit_log ORDER BY created_at DESC LIMIT $limit");
    $logs = $stmt->fetchAll();
    echo json_encode(['success' => true, 'logs' => $logs], JSON_UNESCAPED_UNICODE);
    exit;

} elseif ($action === 'backup' && $_SERVER['REQUEST_METHOD'] === 'GET') {
    checkAuth();
    $backupFile = autoBackup($dbFile, $backupDir);
    header('Content-Type: application/octet-stream');
    header('Content-Disposition: attachment; filename="' . basename($backupFile) . '"');
    readfile($backupFile);
    exit;

} else {
    echo json_encode(['success' => false, 'error' => 'Unknown action']);
}
?>
