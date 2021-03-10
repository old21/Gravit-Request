<?php
$login = str_replace(' ', '', $_GET['login']);
$passB = password_hash(str_replace(' ', '', $_GET['password']), PASSWORD_DEFAULT); // Новый DLE и XenForo
$passM = md5(str_replace(' ', '', $_GET['password'])); // У кого просто md5
$passDM = md5(md5(str_replace(' ', '', $_GET['password']))); // Старый DLE double md5
$passA = md5(str_replace(' ', '', $_GET['password'])); // Здесь можно написать альтернативную логику с солью. Ещё не реализовано
$key = str_replace(' ', '', $_GET['key']);
$ipA = str_replace(' ', '', $_GET['ip']);
$ipO = $_SERVER['REMOTE_ADDR'];
$ip = '';
$type = str_replace(' ', '', $_GET['type']);
$size = str_replace(' ', '', $_GET['size']);

class config
{
    static $settings = array(
        "db_host" => '', // 127.0.0.1 или localhost или IP
        "db_port" => '', // порт к БД
        "db_user" => '', // Имя пользователя БД
        "db_pass" => '', // Пароль БД
        "db_db" => '', // Имя базы данных сайта 
        "cms_type" => 0, // Тип CMS [0 - DLE DB, 1 - DLE API, 2 - XenForo DB]
        "key_request" => '', // Секрет-Ключ скрипта для взаимодействия с авторизацией
        "un_tpl" => '([a-zA-Z0-9\_\-]+)', // Проверка на Regexp
        "un_key" => '([a-zA-Z0-9\_\-\%\*\(\)\{\}\?\@\#\$\~]+)', // Проверка на Regexp для ключа, дополнительно %*(){}?@#$
        "skin_path" => "../путь до/skins/",
        "cloak_path" => "../путь до/cloaks/",
        "avatar_path" => "faces/",
        "auth_limiter_path" => "al/",
        "auth_cooldown" => 3,
        // Далее идут base64 скина, плаща и аватара Стива
        "b64s" => "iVBORw0KGgoAAAANSUhEUgAAAEAAAAAgCAMAAACVQ462AAAAWlBMVEVHcEwsHg51Ri9qQC+HVTgjIyNOLyK7inGrfWaWb1udZkj///9SPYmAUjaWX0FWScwoKCgAzMwAXl4AqKgAaGgwKHImIVtGOqU6MYkAf38AmpoAr68/Pz9ra2t3xPtNAAAAAXRSTlMAQObYZgAAAZJJREFUeNrUzLUBwDAUA9EPMsmw/7jhNljl9Xdy0J3t5CndmcOBT4Mw8/8P4pfB6sNg9yA892wQvwzSIr8f5JRzSeS7AaiptpxazUq8GPQB5uSe2DH644GTsDFsNrqB9CcDgOCAmffegWWwAExnBrljqowsFBuGYShY5oakgOXs/39zF6voDG9r+wLvTCVUcL+uV4m6uXG/L3Ut691697tgnZgJavinQHOB7DD8awmaLWEmaNuu7YGf6XcIITRm19P1ahbARCRGEc8x/UZ4CroXAQTVIGL0YySrREBADFGicS8XtG8CTS+IGU2F6EgSE34VNKoNz8348mzoXGDxpxkQBpg2bWobjgZSm+uiKDYH2BAO8C4YBmbgAjpq5jUl4yGJC46HQ7HJBfkeTAImIEmgmtpINi44JsHx+CKA/BTuArISXeBTR4AI5gK4C2JqRfPs0HNBkQnG8S4Yxw8IGoIZfXEBOW1D4YJDAdNSXgRevP+ylK6fGBCwsWywmA19EtBkJr8K2t4N5pnAVwH0jptsBp+2gUFj4tL5ywAAAABJRU5ErkJggg==",
        "b64c" => "iVBORw0KGgoAAAANSUhEUgAAAEAAAAAgAQMAAACYU+zHAAAAA1BMVEVHcEyC+tLSAAAAAXRSTlMAQObYZgAAAAxJREFUeAFjGAV4AQABIAABL3HDQQAAAABJRU5ErkJggg==",
        "b64a" => "iVBORw0KGgoAAAANSUhEUgAAAFAAAABQCAIAAAABc2X6AAAACXBIWXMAAA7EAAAOxAGVKw4bAAABP0lEQVR42u3ZPUtCYRjGcU8ecAglD2JKcEDBrc8gGg3RFk5ODoIurY4Frg622eTgJmQ4BI0NfQkXLdAhMDm+hAVNfoNrOGA+4f9aLx64f9wON0fr1I0E9ikHgT0LYMCAAQMGDHh3sc0cKx2NifZtPmPDgAEDBgwYMOB/f2ndXZcNHHrxtRZtvdNlw4ABAwYMGDBgE2I93FREfRQ+9H3x6Hyu1NvMSVy04+GADQMGDBgwYMCAzY+tb6nzWlO0hWxDtMXcyPctdf+UEO3jq5qqd1tlw4ABAwYMGDBgE2K1Kxeijhy7otVXWv/5xfdYV5dnotXftCYzjw0DBgwYMGDAgI24tFqlvO/H7x/eToZOJR3RTuV/mvykAQMGDBgwYMB/FltfS+tf9TjuhLY0ViioNrH8/mHDgAEDBgwYMGDzswFXWTZaG7TM4wAAAABJRU5ErkJggg==",
        "avatar_cooldown" => 60, // Кэш аватаров в файловой системе в секундах, если не было затребовано другое разрешение
        "logs" => true,
        "tech_work" => false,
        "salt" => false // Пока не реализовано
    );
}

class messages
{
    static $msg = array(
        "need_key" => "Проверьте секрет-ключ скрипта.\nДля обработки запроса",
        "err" => "Ошибка ",
        "player_not_found" => "Пользователь не найден",
        "pass_not_found" => "Пароль не найден",
        "incorrect_pass" => "Пароль неверный",
        "invalid" => "Введите правильные параметры",
        "tech_work" => "Проводятся тех. работы",
        "rgx_err" => "Проверка на Regexp выявила несоответствие",
        "not_impl" => "Не реализовано",
        "player_null" => "Пользователь не может быть пустым",
        "pass_null" => "Пароль не может быть пустым",
        "auth_limiter" => "Превышен лимит авторизаций",
        "other_limiret" => "Превышен лимит запросов",
        "php_old" => "Используйте версию PHP 5.4 и выше"
    );
}

if (strnatcmp(phpversion(), '5.4') >= 0) {
    if (exists($login)) {
        exists_ip();
        if (exists($key) && !exists($type)) {
            if (rgxp_valid($login, 0) && rgxp_valid($key, 1)) {
                auth_limiter($ip);
                auth($login);
            }
        }
        if (exists($type) && !exists($key)) {
            texture($login, $type, $size);
        }
    } else {
        echo messages::$msg['player_null'];
        die;
    }
} else {
    echo messages::$msg['php_old'];
    echo phpversion();
    die;
}

function logs($what)
{
    if (config::$settings['logs'] == true) {
        file_put_contents("log.log", date('d.m.Y H:i:s - ') . $what . "\n", FILE_APPEND);
    }
}
function texture($login, $type, $size)
{
    $path = '';
    $ext = '.png';
    $type_num = 0;
    switch ($type) {
        case 'skin':
            $default = config::$settings['b64s'];
            $path = config::$settings['skin_path'];
            $type_num = 1;
            break;
        case 'cloak':
            $default = config::$settings['b64c'];
            $path = config::$settings['cloak_path'];
            $type_num = 2;
            break;
        case 'avatar':
            $default = config::$settings['b64a'];
            $path = config::$settings['avatar_path'];
            $type_num = 3;
            break;
        default:
            echo messages::$msg['invalid'];
            die;
            break;
    }
    if ($type_num == 3) {
        $thumb = $path . strtolower($login) . $ext;
        if (is_numeric($size) == FALSE || $size <= 0) {
            $size = 80;
        }
        list($w, $h) = getimagesize($thumb);
        if ((file_exists($thumb) && (filemtime($thumb) >= time() - 1 * config::$settings['avatar_cooldown'])) && $size == $w) {
            header("Content-type: image/png");
            echo file_get_contents($thumb);
        } else {
            $loadskin = ci_find_file(config::$settings['skin_path'] . $login . $ext);  // чтение файла скина
            if ($loadskin) {
                $newFile = $thumb;
                list($width, $height) = getimagesize($loadskin); // взятие оригинальных размеров картинки в пикселях
                $width = $width / 8; // 1/8 матрицы
                ini_set('gd.png_ignore_warning', 0); //отключение отладочной информации
                $canvas = imagecreatetruecolor($size, $size); // новое canvas поле
                $image = imagecreatefrompng($loadskin); // создание png из файла для дальнейшего взаимодействия с ним
                imagecopyresized($canvas, $image, 0, 0, $width, $width, $size, $size, $width, $width); // голова
                imagecopyresized($canvas, $image, 0, 0, $width * 5, $width, $size, $size, $width, $width); // второй слой
                imagecolortransparent($image, imagecolorat($image, 63, 0)); // получение индекса цвета пикселя и определение цвета как прозрачный
                imagepng($canvas, $newFile, 9); // сохранение по пути изображения, степень сжатия пакета zlib 9 - максимальный
            } else {
                default_texture($default);
            }
            header("Content-type: image/png");
            echo file_get_contents($thumb);
            remove_old_files(config::$settings['avatar_path'], config::$settings['avatar_cooldown']);
        }
    } else {
        $thumb = $path . $login . $ext;
        if (file_exists($thumb)) {
            header("Content-type: image/png");
            readfile($thumb);
        } else {
            default_texture($default);
        }
    }
}
function default_texture($default)
{
    header("Content-type: image/png");
    echo base64_decode($default);
}

function ci_find_file($filename)
{
    if (file_exists($filename))
        return $filename;
    $directoryName = dirname($filename);
    $fileArray = glob($directoryName . '/*', GLOB_NOSORT);
    $fileNameLowerCase = strtolower($filename);
    foreach ($fileArray as $file) {
        if (strtolower($file) == $fileNameLowerCase) {
            return $file;
        }
    }
    return false;
}

function auth_limiter($ip)
{
    $newName = config::$settings['auth_limiter_path'] . strtolower($ip) . '.txt';
    remove_old_files(config::$settings['auth_limiter_path'], config::$settings['auth_cooldown']);
    if (time() - filectime($newName) < 1 * config::$settings['auth_cooldown']) {
        echo messages::$msg['auth_limiter'];
        file_put_contents($newName, '');
        die;
    }
    file_put_contents($newName, '');
    return true;
}

function remove_old_files($path, $cooldown)
{
    foreach (glob($path . "*") as $file) {
        if (time() - filectime($file) > $cooldown) {
            unlink($file);
        }
    }
}

function rgxp_valid($var, $type)
{
    switch ($type) {
        case '0':
            if (preg_match("/^" . config::$settings['un_tpl'] . "/", $var, $varR) === true) {
                return true;
            } else {
                echo messages::$msg['rgx_err'];
                die;
            }
            break;
        case '1':
            if (!empty($var)) {
                if (preg_match("/^" . config::$settings['un_key'] . "/", $var, $varR) === true) {
                    if ($var == config::$settings['key_request']) {
                        return true;
                    } else {
                        echo messages::$msg['need_key'];
                        die;
                    }
                } else {
                    echo messages::$msg['rgx_err'];
                    die;
                }
            } else {
                echo messages::$msg['need_key'];
                return false;
            }
            break;
        default:
            echo messages::$msg['err'];
            die;
            break;
    }
}

function auth($login)
{
    switch (config::$settings['cms_type']) {
        case '0':
            echo messages::$msg['not_impl'];
            die;
            break;
        case '1':
            echo messages::$msg['not_impl'];
            die;
            break;
        case '2':
            $link = mysqli_connect(config::$settings['db_host'], config::$settings['db_user'], config::$settings['db_pass'], config::$settings['db_db'], config::$settings['db_port'])
                or die("Ошибка " . mysqli_connect_error());
            $login = $link->real_escape_string($login);
            $qr = mysqli_query($link, "SELECT `user_id`,`username` FROM xf_user WHERE `username` = '$login' LIMIT 1")->fetch_assoc();
            if (!isset($qr['username']) || !isset($qr['user_id'])) {
                die(messages::$msg['player_not_found']);
                //die('Пользователь не найден');
            }
            $user_id = $qr['user_id'];
            $qr1 = mysqli_query($link, "SELECT `data` FROM xf_user_authenticate WHERE `user_id` = '$user_id' LIMIT 1")->fetch_assoc();
            if (!isset($qr1['data'])) {
                die(messages::$msg['pass_not_found']);
                //die('Пароль не найден');
            }
            pass_valid(mb_strimwidth($qr1['data'], 22, 60));
        default:
            echo messages::$msg['not_impl'];
            die;
            break;
    }
}
function pass_valid($pass)
{
    global $passB;
    global $passM;
    global $passA;
    global $login;

    if (empty($passB) || empty($passM) || empty($passA)) {
        echo messages::$msg['pass_null'];
        die;
    }
    if (password_verify($passB, $pass)) {
        echo 'OK:' . $login . ':0';
        exit;
    } else {
        die(messages::$msg['incorrect_pass']);
    }
}

function exists($var)
{
    if (!empty($var) && isset($var)) return true;
    else return false;
}
function exists_ip()
{
    global $ipA;
    global $ipO;
    global $ip;
    if (exists($ipA)) {
        $ip = $ipA;
    } else if (exists($ipO)) {
        $ip = $ipO;
    } else {
        $ip = '127.0.0.1';
    }
    return true;
}
