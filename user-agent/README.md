# User Agent

Фоновое GUI-приложение на Go для Windows 10/11, работающее в сессии залогиненного пользователя.

## Возможности

- Локальный HTTP API для управляющего сервера
- Показ окон с сообщениями, кликабельными ссылками и кнопками
- Запуск программ из сетевой папки от имени текущего пользователя или с переданными креденшелами
- IP-фильтрация и опциональная токен-авторизация

## Требования

- Go 1.22+
- Windows 10/11 (x64)

## Сборка

```powershell
# Скачивание зависимостей
go mod tidy

# Сборка с GUI-режимом (без консольного окна)
go build -ldflags="-H windowsgui" -o agent.exe ./cmd/agent
```

## Конфигурация

Создайте файл `agent.toml` рядом с бинарником:

```toml
[server]
port = 8080
bind = "0.0.0.0"

[security]
allowed_ips = [
    "127.0.0.1",
    "192.168.1.100",
    "10.0.0.0/8"
]
auth_token = ""

[storage]
dir = "C:\\ProgramData\\UserAgent\\Storage"
max_file_size_mb = 500
allowed_extensions = [".exe", ".bat", ".cmd", ".msi"]

[logging]
level = "info"
file = "C:\\ProgramData\\UserAgent\\agent.log"
max_size_mb = 10
max_backups = 5

[gui]
default_title = "Сообщение"
font_family = "Segoe UI"
font_size = 12
```

## Запуск

```powershell
# Запуск агента
.\agent.exe

# С указанием конфига
.\agent.exe -config custom.toml
```

## Безопасность

При первом запуске агент генерирует пару ключей ECDSA P-256 (или RSA-3072). Приватный ключ сохраняется в файл с правами 600.

### Шифрование креденшелов

Эндпоинт `/api/run-as` требует передачи креденшелов в зашифрованном виде:

1. Получите публичный ключ: `GET /api/pubkey`
2. Зашифруйте JSON с креденшелами публичным ключом (ECIES для ECDSA, RSA-OAEP+AES-GCM для RSA)
3. Отправьте base64-encoded зашифрованные данные в поле `credentials_encrypted`

### Токен для /api/run-as

Эндпоинт `/api/run-as` требует заголовок `X-Run-As-Token`. Если токен не настроен — эндпоинт отключён (503).

## HTTP API

### GET /api/health

Проверка живости (без IP-фильтра и токена).

### GET /api/pubkey

Получение публичного ключа агента (защищено IP-фильтром):

```json
{
  "algorithm": "ECDSA-P256",
  "public_key_pem": "-----BEGIN PUBLIC KEY-----\n...\n-----END PUBLIC KEY-----"
}
```

### POST /api/message

Показать окно с сообщением:

```json
{
  "title": "Уведомление",
  "body": "Ознакомьтесь с инструкцией.",
  "links": [{"text": "Инструкция", "url": "https://intranet/docs"}],
  "buttons": [{"text": "Прочитано", "callback": "https://control/ack/123"}]
}
```

### POST /api/run

Скопировать файл из сетевой папки и запустить:

```json
{
  "source": "\\\\server\\share\\installer.msi",
  "args": "/quiet",
  "run_as_current_user": true
}
```

### POST /api/run-as

Запустить с зашифрованными креденшелами. Требует заголовок `X-Run-As-Token`.

Тело запроса (креденшелы должны быть зашифрованы публичным ключом агента):

```json
{
  "source": "\\\\server\\share\\tool.exe",
  "args": "--mode=test",
  "credentials_encrypted": "base64-encoded-encrypted-data"
}
```

**Важно:** Поле `credentials` (открытый текст) запрещено — запрос будет отклонён с 400.

## Структура проекта

```
user-agent/
├── cmd/agent/main.go           # Точка входа
├── internal/
│   ├── config/config.go        # Загрузка конфигурации
│   ├── crypto/
│   │   ├── keys.go             # Генерация и загрузка ключей
│   │   └── decrypt.go          # Расшифровка ECIES/RSA
│   ├── server/
│   │   ├── server.go           # HTTP-сервер
│   │   ├── middleware.go       # IP-фильтр и токен-авторизация
│   │   └── handlers.go         # Обработчики эндпоинтов
│   ├── gui/
│   │   ├── message.go          # Окна сообщений
│   │   └── browser.go          # Открытие браузера
│   ├── executor/
│   │   ├── copy.go             # Копирование из UNC
│   │   ├── run.go              # Запуск от текущего пользователя
│   │   └── runas.go            # Запуск с креденшелами
│   └── winapi/process.go       # CreateProcessWithLogonW
├── go.mod
├── agent.toml
└── README.md
```

## Безопасность

- Все запросы (кроме /api/health) проверяются по IP-беллисту
- Опциональный токен в заголовке X-Auth-Token
- Валидация путей: запрет path traversal, проверка расширений файлов
- Пароли никогда не логируются
- Ограничение размера файлов при копировании