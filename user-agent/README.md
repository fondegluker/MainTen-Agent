# MainTen User Agent

Фоновое GUI-приложение на Go для Windows 10/11, работающее в сессии
залогиненного пользователя. Предоставляет локальный HTTPS API управляющему
серверу: показ окон с сообщениями, запуск программ из сетевых папок от имени
текущего пользователя или переданных (зашифрованных) креденшелов.

## Возможности

- Локальный **HTTPS** API (TLS 1.2+) для управляющего сервера
- Показ окон с сообщениями, кликабельными ссылками и кнопками
- Запуск `.exe/.bat/.cmd/.msi` из сетевой папки от имени текущего пользователя
  или с переданными креденшелами (`CreateProcessWithLogonW`)
- IP-фильтрация, токен-авторизация, отдельный токен для `/api/run-as`
- Двухслойная защита креденшелов: HTTPS-транспорт + прикладное шифрование
  поля `credentials` публичным ключом агента

## Требования

- Go 1.22+ (сборка)
- Windows 10 или новее (x64)

## Компоненты (cmd/)

| Утилита      | Назначение |
|--------------|------------|
| `agent`      | Сам агент (GUI-приложение без консоли) |
| `certgen`    | Генерация TLS-ключей и сертификатов (CA + серверный) для dev/test |
| `agent-test` | Автотест всех режимов агента (HTTPS, run, run-as, message) |
| `installer`  | Установщик: проверка ОС, установка, автозагрузка, брандмауэр, проверки |

## Сборка

```powershell
go mod tidy

# Агент — GUI-режим (без консольного окна)
go build -ldflags="-H windowsgui" -o agent.exe ./cmd/agent

# Утилиты — консольные
go build -o certgen.exe    ./cmd/certgen
go build -o agent-test.exe ./cmd/agent-test
go build -o installer.exe  ./cmd/installer
```

## Быстрый старт (dev)

```powershell
# 1) Сгенерировать CA и серверный сертификат
.\certgen.exe -out certs

# 2) Запустить агент (использует agent.toml рядом с бинарником)
.\agent.exe

# 3) Прогнать полный автотест (нужны права администратора)
.\agent-test.exe
```

## HTTPS / TLS

Весь трафик между сервером и агентом идёт по HTTPS. Модель доверия —
собственный CA:

- `certgen` создаёт `ca.pem`/`ca.key` (CA, ~10 лет) и `server.pem`/`server.key`
  (серверный сертификат агента, подписанный CA, ~825 дней).
- Агент слушает HTTPS с `server.*`. Клиент (сервер, `agent-test`) доверяет
  `ca.pem`. Один CA покрывает много агентов; ротация — через `-reuse-ca`.
- SAN серверного сертификата: `127.0.0.1`, `::1`, `localhost`, hostname машины
  плюс произвольные через `-san IP:...` / `-san DNS:...`.

```powershell
.\certgen.exe -out certs -san IP:192.168.0.100 -san DNS:agent.corp.local
.\certgen.exe -out certs -reuse-ca -force   # новый серверный серт тем же CA
```

Шифрование пары логин-пароль остаётся **вторым слоем** поверх TLS.

## Конфигурация агента (agent.toml)

```toml
[server]
port = 50513
bind = "0.0.0.0"

[tls]
# HTTPS transport. If false, the agent serves plain HTTP (dev only).
enabled = true
cert_file = "certs\\server.pem"
key_file = "certs\\server.key"

[security]
allowed_ips = ["127.0.0.1", "192.168.0.100", "10.0.0.0/8"]
auth_token = ""
# Токен для /api/run-as. Если пусто — эндпоинт отключён (503).
run_as_token = ""

[crypto]
private_key_path = "C:\\ProgramData\\UserAgent\\agent_key.pem"
algorithm = "rsa-3072"   # или ecdsa-p256

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

## HTTP API

Все эндпоинты, кроме `/api/health` и `/api/pubkey`, защищены IP-фильтром.
`/api/run-as` дополнительно требует токен.

### GET /api/health
Проверка живости (без IP-фильтра и токена).

### GET /api/pubkey
Публичный ключ агента (защищён IP-фильтром, без токена):

```json
{ "algorithm": "rsa-3072", "public_key_pem": "-----BEGIN PUBLIC KEY-----\n...\n-----END PUBLIC KEY-----" }
```

### POST /api/message
```json
{
  "title": "Уведомление",
  "body": "Ознакомьтесь с инструкцией.",
  "links": [{"text": "Инструкция", "url": "https://intranet/docs"}],
  "buttons": [{"text": "Прочитано", "callback": "https://control/ack/123"}]
}
```

### POST /api/run
```json
{ "source": "\\\\server\\share\\installer.msi", "args": "/quiet", "run_as_current_user": true }
```

### POST /api/run-as
Требует заголовок `X-Run-As-Token`. Креденшелы должны быть зашифрованы
публичным ключом агента и переданы в `credentials_encrypted` (base64):

```json
{ "source": "\\\\server\\share\\tool.exe", "args": "--mode=test", "credentials_encrypted": "base64..." }
```

Поле `credentials` (открытый текст) запрещено — запрос отклоняется с 400.

**Схема шифрования креденшелов:**
1. `GET /api/pubkey` — получить публичный ключ.
2. Зашифровать JSON `{username, domain, password}`:
   - RSA-3072: `RSA-OAEP(SHA-256, AES-ключ) || nonce(12) || AES-256-GCM(payload)`, затем base64.
   - ECDSA P-256: ECIES.
3. Отправить в `credentials_encrypted`.

## Установщик (installer)

`installer.exe` выполняет полный цикл установки:

1. Проверка системы (Windows 10+ и x64).
2. Проверка исходных файлов (`agent.exe`, `agent.toml`).
3. Копирование агента, конфига и `certs/*` в `%LOCALAPPDATA%\MainTenAgent`.
4. Правка `agent.toml`: пути к сертификатам делаются абсолютными.
5. Автозагрузка через `HKCU\...\Run` (userspace, без админа).
6. Правило брандмауэра для порта из `agent.toml`, **ограниченное профилями
   сетей из `installer.toml`** (требует прав администратора — установщик
   поднимает изолированный elevated под-процесс только для этого шага).
7. Запуск агента и локальная проверка `/api/health` по HTTPS с валидацией CA.
8. Проверка сетевой доступности по hostname (best-effort).

### Конфигурация установщика (installer.toml)

```toml
[firewall]
enabled = true
# Профили сетей для правила: "domain", "private", "public".
# Пусто/отсутствует => "private".
profiles = ["domain", "private"]

[install]
# Переопределение каталога установки. Пусто => %LOCALAPPDATA%\MainTenAgent.
dir = ""
```

### Флаги установщика

| Флаг            | Описание |
|-----------------|----------|
| `-config PATH`  | Путь к `installer.toml` (по умолчанию рядом с exe) |
| `-src DIR`      | Каталог с исходными файлами (по умолчанию каталог установщика) |
| `-dest DIR`     | Каталог установки (перекрывает `installer.toml`) |
| `-no-firewall`  | Пропустить правило брандмауэра |
| `-no-start`     | Не запускать агент и не проверять |
| `-no-pause`     | Не ждать нажатия клавиши в конце |
| `-silent`       | Тихий режим: без ожидания, окно консоли скрыто |
| `-uninstall`    | Удалить автозагрузку, правило брандмауэра и файлы |

По умолчанию (интерактивный запуск) установщик выводит цветной пошаговый лог и
ждёт нажатия Enter перед закрытием.

```powershell
# Обычная установка
.\installer.exe

# Тихая установка без брандмауэра (например, из средства развёртывания)
.\installer.exe -silent -no-firewall

# Удаление
.\installer.exe -uninstall
```

## Автотест (agent-test)

Автоматически поднимает SMB-шару с тестовыми файлами, при необходимости
генерирует `run_as_token`, создаёт временную учётку, прогоняет все режимы и
убирает за собой. Требует прав администратора (создание шары/учётки/правил);
при запуске без прав сам запрашивает повышение через UAC.

Проверяет: TLS-транспорт (доверие к CA, отказ без доверия, отказ plain HTTP на
TLS-порту), `health`/`pubkey`, `run` для всех расширений, `run-as` (позитив с
шифрованием + негативы), `message`.

```powershell
.\agent-test.exe            # полный прогон (UAC)
.\agent-test.exe -no-pause  # без паузы (для CI)
```

Полезные флаги: `-url`, `-ca`, `-skip-runas`, `-skip-message`, `-no-elevate`,
`-no-pause`.

## Структура проекта

```
user-agent/
├── cmd/
│   ├── agent/            # агент (main, GUI-приложение)
│   ├── certgen/          # генерация CA + серверного сертификата
│   ├── agent-test/       # автотест всех режимов
│   └── installer/        # установщик
├── internal/
│   ├── config/           # загрузка/валидация agent.toml (+ секция [tls])
│   ├── crypto/           # ключи агента и расшифровка креденшелов
│   ├── server/           # HTTP(S)-сервер, middleware, handlers
│   ├── gui/              # окна сообщений, браузер
│   ├── executor/         # копирование из UNC, запуск, run-as
│   └── winapi/           # CreateProcessWithLogonW
├── agent.toml            # конфиг агента
├── installer.toml        # конфиг установщика
├── go.mod
└── README.md
```

## Безопасность

- **HTTPS (TLS 1.2+)** на весь трафик; доверие через собственный CA.
- Все запросы, кроме `/api/health` и `/api/pubkey`, проверяются по IP-беллисту.
- Опциональный `X-Auth-Token`; отдельный `X-Run-As-Token` для `/api/run-as`
  (сравнение через `crypto/subtle.ConstantTimeCompare`).
- Креденшелы `/api/run-as` шифруются публичным ключом агента (второй слой
  поверх TLS); открытый `credentials` запрещён.
- Пароль обнуляется в памяти после использования и никогда не логируется.
- Валидация путей: только UNC-источники, запрет path traversal, белый список
  расширений, ограничение размера файла.

> Примечание: приватные ключи (`*.key`, `agent_key.pem`) на Windows создаются с
> режимом `0600`, который в NTFS не даёт полноценного ограничения ACL — файл
> наследует права каталога. Для продакшена храните ключи в каталоге с
> ограниченным доступом (например, отдельный ACL на `C:\ProgramData\UserAgent`).
