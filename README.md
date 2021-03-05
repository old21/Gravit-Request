# Gravit-Request

## СТАТУС - НЕ ЗАВЕРШЕНО!!!

![PHP 5.5.0](https://img.shields.io/badge/PHP-5.5.0-blue)
![Gravit Launcher](https://img.shields.io/badge/Gravit%20Launcher-5.1.10-brightgreen)

## Представлю вам скрипт Request метода. На языке PHP.

✔ DLE авторизация через MySQL, на BCrypt хэше паролей, есть возможность передавать permissions

✔ DLE авторизация через API. Работает с любым хэшем, не передаёт permissions

✔ XenForo авторизация через MySQL, есть возможность передавать permissions

✔ Выдача скинов из папки, при отсутствии, выдаёт стива

✔ Выдача плащей из папки, при отсутсвиии, выдаёт стива

✔ Выдача аватара скина, с стандартизированным размером для Discord Embed 80x80, можно задавать кеширование в папку на определённое время. Можно задать в запросе нужный размер аватара.

### Формирование запросов

- **Выдача скина**
```css
request.php?login=%username%&type=skin
```
`%username%` - заменяется в зависимости от скрипта, откуда запрос

- **Выдача плаща**
```css
request.php?login=%username%&type=cloak
```

- **Два варианта выдачи аватара**
```css
request.php?login=%username%&type=avatar
```
`либо`
```css
request.php?login=%username%&type=avatar&size=100
```
`size=100` - указание в пикселях ширины и высоты

- **Ссылка для AuthProvider GravitLauncher** `Способ request`
```css
request.php?login=%login%&key=************&password=%password%&ip=%ip%
```
`key=************` - ключ, который вы укажите в скрипте `"key_request" => '******ЗДЕСЬ******', // Секрет-Ключ скрипта для взаимодействия с авторизацией`
`ip=%ip%` - необходимо передавать для работы cooldown'a в скрипте. По умолчанию: 3 секунды, можно изменить в `"auth_cooldown" => 3,`
Принцип: С 1 IP пользователь не может совершать авторизацию чаще, чем 3 секунды. Если у вас не будет передаваться этот параметр, либо в случае его неуказания в ссылке, либо если у вас LaunchServer не видит реальные IP (проверить командой `clients`) - следует выставить на большее время в конфигурации, так как cooldown будет дейстовать не на пользователя, а на весь LaunchServer.

- **AuthProvider GravitLauncher & Gravit-Request**
```yml
  "auth": [
    {
      "provider": {
        "type": "request",
        "usePermission": true,
        "flagsEnabled": false,
        "url": "http://example.com/request.php?login=%login%&password=%password%&ip=%ip%",
        "response": "OK:(?<username>.+):(?<permissions>.+)"
      }
    }
  ]
```
