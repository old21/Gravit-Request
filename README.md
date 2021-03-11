# Gravit-Request

## СТАТУС - РЕЛИЗ!!!

![PHP 5.6.0](https://img.shields.io/badge/PHP-5.6.0-blue)
![Gravit Launcher](https://img.shields.io/badge/Gravit%20Launcher-5.1.10-brightgreen)

## Представляю вам скрипт Request метода. На языке PHP.

✔ DLE авторизация через MySQL, есть возможность передавать permissions

✔ WebMCR авторизация через MySQL, есть возможность передавать permissions

✔ XenForo авторизация через MySQL, есть возможность передавать permissions

✔ Выдача скинов из папки. При отсутствии, выдаёт стива

✔ Выдача плащей из папки. При отсутсвиии, выдаёт стива

✔ Выдача аватара скина, с стандартизированным размером для Discord Embed 80x80, можно задавать кеширование в папку на определённое время. Можно задать в запросе нужный размер аватара. Поддержка старых и новых типов скинов

### НАСТРОЙКА
- **Размещение скрипта**
`Создайте для его свою папку в корне сайта. Не забывайте что нужно будет эту папку вписать в запрос`

- **Подключение к БД и выбор типа CMS**
```php
class config
{
    static $settings = array(
        "db_host" => '', // 127.0.0.1 или localhost или IP
        "db_port" => '3306', // порт к БД
        "db_user" => '', // Имя пользователя БД
        "db_pass" => '', // Пароль БД
        "db_db" => '', // Имя базы данных сайта
        "cms_type" => 0, // Тип CMS [0 - DLE, 1 - WebMCR, 2 - XenForo]
```

- **Создание колонки permissions на примере DLE**
```sql
ALTER TABLE `dle_users` ADD `permissions` TINYINT NOT NULL DEFAULT '0';
```

- **Секрет-ключ для авторизий**
`Никому не передавайте ключ, либо ссылку с ним`
`Создать ключ можно через сайт:` [ССЫЛКА](http://www.onlinepasswordgenerator.ru/)
```php
"key_request" => '',
```

- **Настройка пути к скинам и плащам**
`../ - одна директория вверх`
`minecraft папка указана для примера`
```php
        "skin_path" => "../minecraft/skins/", // Сюда вписать путь до skins/
        "cloak_path" => "../minecraft/cloaks/", // Сюда вписать путь до cloaks/
```

### Формирование запросов
- **AuthProvider GravitLauncher** `Способ request`
```css
request.php?login=%login%&key=************&password=%password%&ip=%ip%
```
`key=************` - ключ, который вы укажите в скрипте `"key_request" => '******ЗДЕСЬ******', // Секрет-Ключ скрипта для взаимодействия с авторизацией`

`ip=%ip%` - необходимо передавать для работы cooldown'a в скрипте. По умолчанию: 5 секунд, можно изменить в `"auth_cooldown" => 5,`
Принцип: С 1 IP пользователь не может совершать авторизацию чаще, чем 5 секунд. Если у вас не будет передаваться этот параметр, проверка не будет работать.

- **AuthProvider GravitLauncher & Gravit-Request**
```yml
  "auth": [
    {
      "provider": {
        "type": "request",
        "usePermission": true,
        "flagsEnabled": false,
        "url": "http://example.com/папка_с_скриптом/request.php?login=%login%&key=СЮДА_КЛЮЧ&password=%password%&ip=%ip%",
        "response": "OK:(?<username>.+):(?<permissions>.+)"
      }
    }
  ]
```

- **Выдача скина**
```css
request.php?login=%login%&type=skin
```
`%username%` - заменяется в зависимости от скрипта, откуда запрос

- **Выдача плаща**
```css
request.php?login=%login%&type=cloak
```

- **Два варианта выдачи аватара**
```css
request.php?login=%login%&type=avatar
```
`либо`
```css
request.php?login=%login%&type=avatar&size=100
```
`size=100` - указание в пикселях ширины и высоты
