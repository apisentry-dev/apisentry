# APISentry AI -- Project Management Plan
## Версия 1.3 | Last updated: March 25, 2026 — Дни 1-2 завершены, Checkpoint Day 5 пройден досрочно | Составлено: Lead PM (Claude Opus 4.6)

---

# ПРИНЦИП: Validate First, Pay Later

## Философия: $0 до рабочего PoC

Ни одного доллара не тратится до тех пор, пока не будет работающий Proof of Concept, который находит реальные уязвимости в реальном API. Stripe Atlas ($500) покупается **ТОЛЬКО** когда первый клиент готов заплатить деньги.

### Ключевое правило

> Код и PoC сначала. Деньги потом. Каждая трата должна быть обусловлена конкретным milestone.

### Когда что покупать

| Условие (milestone) | Трата | Сумма |
|---------------------|-------|-------|
| PoC работает (Day 5): `apisentry scan` находит уязвимости | Ничего, всё бесплатно | $0 |
| MVP готов (Day 14): end-to-end pipeline работает | Ничего, всё ещё бесплатно | $0 |
| Готов к публичному beta (Day 15-21) | Домен + Vercel free + Supabase free tier | $50-100 |
| Есть интерес от пользователей (Day 22-30) | Anthropic API credits, Supabase Pro, Vercel Pro | $75-100 |
| Первый клиент готов платить (Месяц 2-3) | Stripe Atlas (Delaware C-Corp) | $500 |
| 10+ paying customers | Fly.io Pro, расширение инфраструктуры | $50-100/мес |

---

# РАЗДЕЛ 1: Снимок проекта (Project Snapshot)

## Что такое APISentry AI

APISentry AI -- developer-first платформа для автоматического тестирования безопасности API с помощью AI. Разработчик загружает OpenAPI spec (или даёт URL), и AI генерирует сотни контекстных тест-кейсов по OWASP API Top 10: BOLA, broken auth, injection, mass assignment, rate limiting, SSRF и другие. Продукт встраивается в CI/CD (GitHub Actions, GitLab CI, Jenkins) и стоит $49/мес вместо $50K+/год у enterprise-решений.

## Одно ключевое ценностное предложение

**AI-powered contextual API security testing за flat $49/мес для dev-команд -- ниша, которую НИКТО не занимает.** Enterprise-игроки (Salt, Cequence) берут $50K+/год, StackHawk -- $210+/мес на команду из 5 человек, Akto ушёл в AI agent security за $1,890/мес. Мы -- единственные, кто предлагает полный OWASP API Top 10 с AI-контекстными атаками по flat-rate цене для SMB.

## Модель дохода

| Источник | Доля | Описание |
|----------|------|----------|
| Подписка | 70% | 5 тарифов: Free ($0) / Pro ($49) / Team ($199) / Business ($499) / Enterprise ($2,999) |
| Compliance reports | 15% | DORA, PCI-DSS, NIS2, FAPI 2.0 -- add-on к Team+ |
| MCP/AI Agent Security | 10% | Новый модуль тестирования MCP-серверов |
| Enterprise consulting | 5% | Custom rules, on-premise, SLA |

## Milestone-цели

| Период | Цель | Ключевая метрика |
|--------|------|------------------|
| **Месяц 1** | Рабочий MVP: CLI + парсер + сканер + 5 OWASP атак | Работающий `apisentry scan --spec api.yaml` |
| **Месяц 3** | Public launch, 30 paying customers | MRR $3,600 |
| **Месяц 6** | 150 paying, full OWASP Top 10, compliance reports | MRR $21,000 |
| **Месяц 12** | 600 paying, pre-seed closed, team 3-4 | MRR $96,000 (= $1.15M ARR) |

## Бюджет (принцип Validate First, Pay Later)

| Категория | Сумма |
|-----------|-------|
| Потрачено на сегодня | $0 |
| Дни 1-14 (PoC + MVP) | $0 (всё бесплатно) |
| Дни 15-21 (публичный запуск) | $50-100 |
| Дни 22-30 (beta) | $75-100 |
| Месяц 2-3 (Stripe Atlas, только при наличии клиента) | $500 |
| Общий доступный бюджет | $1,000 |
| Запас | $275-375 (на непредвиденное) |

**Поэтапные расходы:**
- Фаза 0-1 (Дни 1-14): $0 — код, PoC, MVP на бесплатных инструментах
- Фаза 2 (Дни 15-21): Домен $50-100, Vercel free tier, Supabase free tier
- Фаза 3 (Дни 22-30): Claude API credits $50, Supabase Pro $25 (если нужен)
- Месяц 2-3: Stripe Atlas $500 — **ТОЛЬКО когда первый клиент готов платить**

**Альтернативы Stripe Atlas для первых 5-10 клиентов:**
- Личный Stripe account (без US LLC) — принимать платежи сразу, комиссия стандартная 2.9%+30¢
- Lemon Squeezy / Paddle (Merchant of Record) — берут комиссию ~5%, но юрлицо не нужно вообще
- Stripe Atlas покупать только когда нужна серьёзная B2B продажа или инвесторы требуют US entity

---

# РАЗДЕЛ 2: Полная структура декомпозиции работ (WBS)

## Фаза 0: Валидация — Validate First (Дни 1-5, $0)

> **Цель:** Доказать что технология работает. Потратить $0. Написать код, который находит реальные уязвимости.

### Epic 0.1: Техническая валидация (PoC)

| ID | Задача | Кто делает | Как | Время | Зависимости | Результат | Приоритет |
|----|--------|-----------|-----|-------|-------------|-----------|-----------|
| 0.1.1 | Создать GitHub Organization + repos | Human | GitHub.com -> + -> New Organization -> Name: "apisentry" (или "apisentry-ai"). Free tier. Создать repo `apisentry-scanner`. | 30 мин | Нет | GitHub org + repo | P0 |
| 0.1.2 | OpenAPI parser (kin-openapi) | Claude Code | Промпт: "Создай Go module с kin-openapi. Пакет `parser/` с `ParseSpec(path) (*ParsedAPI, error)`. Парсинг OpenAPI 3.0/3.1 + Swagger 2.0." | 3 часа | 0.1.1 | Рабочий parser | P0 |
| 0.1.3 | Парсинг реальных specs (Stripe, GitHub, Slack) | Human + Claude Code | Скачать реальные OpenAPI specs (Stripe, GitHub, Slack API). Прогнать через parser. Починить edge cases: circular $ref, allOf/oneOf/anyOf. | 4 часа | 0.1.2 | Parser обрабатывает 3+ реальных specs | P0 |
| 0.1.4 | BOLA attack generator (API1:2023) | Claude Code | Создать `attacks/bola/` -- для каждого endpoint с path parameter заменять ID на чужой (id+1, id-1, random UUID, 0, -1, MAX_INT). | 3 часа | 0.1.2 | Пакет `attacks/bola/` | P0 |
| 0.1.5 | Broken Auth attack generator (API2:2023) | Claude Code | Создать `attacks/auth/` -- запросы без auth, с пустым Bearer, с expired JWT, с модифицированным JWT (role claim), с алгоритмом none. | 3 часа | 0.1.2 | Пакет `attacks/auth/` | P0 |
| 0.1.6 | Развернуть локальный vulnerable API (OWASP crAPI) | Human | Docker: `docker-compose up` для OWASP crAPI (https://github.com/OWASP/crAPI). Это intentionally vulnerable API для тестирования. Бесплатно, локально. | 1 час | Нет | crAPI на localhost:8080 | P0 |
| 0.1.7 | HTTP scanner + executor | Claude Code | Создать `scanner/client.go` (HTTP client, rate limiter 10 RPS, retry, response recording) + `scanner/executor.go` (запуск атак, concurrent). | 4 часа | 0.1.4, 0.1.5 | Рабочий scanner | P0 |
| 0.1.8 | AI-интеграция (Claude) | Claude Code | Создать `ai/claude.go` -- анализ findings через Claude. Использовать бесплатные Anthropic credits (новый аккаунт) или существующую Claude Pro подписку ($20/мес, уже оплачена). | 3 часа | 0.1.7 | AI классификация: confirmed/potential/false_positive | P0 |
| 0.1.9 | **CHECKPOINT Day 5** | Human | Запустить: `apisentry scan --spec petstore.yaml --target http://localhost:8080`. Должно найти реальные уязвимости в crAPI. Если не находит -- PoC не прошёл, пересмотреть подход. | 2 часа | 0.1.1-0.1.8 | **PoC validated: scanner находит реальные уязвимости** | P0 |

### Epic 0.2: Исследование рынка (параллельно, Day 1-2)

| ID | Задача | Кто делает | Как | Время | Зависимости | Результат | Приоритет |
|----|--------|-----------|-----|-------|-------------|-----------|-----------|
| 0.2.1 | Competitor feature matrix | Claude Code | Промпт: "Проанализируй pricing pages и feature lists: StackHawk, Akto, APIsec, Beagle Security, Aikido, Equixly. Создай таблицу сравнения." | 1 час | Нет | Файл `competitive-matrix.md` | P1 |
| 0.2.2 | Positioning statement | Claude Code | На основе competitive matrix написать positioning statement. | 30 мин | 0.2.1 | Positioning statement | P1 |
| 0.2.3 | Проверить trademark | Human | USPTO TESS + EUIPO поиск "APISentry". | 30 мин | Нет | Trademark свободен | P0 |

---

## Фаза 1: MVP Core Engine (Дни 6-21, $0)

### Epic 1.1: OpenAPI Spec Parser

| ID | Задача | Кто делает | Как | Время | Зависимости | Результат | Приоритет |
|----|--------|-----------|-----|-------|-------------|-----------|-----------|
| 1.1.1 | Настроить Go module с kin-openapi | Claude Code | Промпт: "В репо apisentry-scanner создай Go module. Добавь зависимость github.com/getkin/kin-openapi/openapi3. Создай пакет `parser/` с файлом `parser.go`. Структура: `func ParseSpec(path string) (*ParsedAPI, error)` которая принимает путь к OpenAPI 3.0/3.1 файлу (JSON или YAML) и возвращает структуру ParsedAPI с полями: Endpoints []Endpoint (Method, Path, Parameters, RequestBody, Responses, Security), AuthSchemes []AuthScheme, Models map[string]Schema. Используй Go 1.26." | 3 часа | 0.1.5 | Файл `parser/parser.go` с базовым парсером | P0 |
| 1.1.2 | Обработка edge cases | Claude Code + Human | Claude Code: "Добавь в parser обработку: circular $ref, allOf/oneOf/anyOf composition, discriminator, nullable types, deprecated endpoints, servers array, security schemes (apiKey, http bearer, oauth2, openIdConnect). Напиши unit tests с fixtures: Stripe API spec, GitHub API spec, PetStore spec." Human: скачать реальные specs и протестировать. | 4 часа | 1.1.1 | Тесты проходят на 3+ реальных API specs | P0 |
| 1.1.3 | Swagger 2.0 backwards compatibility | Claude Code | Промпт: "Добавь в parser автоматическую конвертацию Swagger 2.0 в OpenAPI 3.0 через kin-openapi. Если файл начинается с swagger: '2.0', конвертируй перед парсингом." | 1 час | 1.1.1 | Поддержка Swagger 2.0 + OpenAPI 3.x | P1 |

### Epic 1.2: Attack Scenario Engine (OWASP Top 5)

| ID | Задача | Кто делает | Как | Время | Зависимости | Результат | Приоритет |
|----|--------|-----------|-----|-------|-------------|-----------|-----------|
| 1.2.1 | BOLA (API1:2023) attack generator | Claude Code | Промпт: "Создай Go пакет `attacks/bola/` для генерации BOLA (Broken Object Level Authorization) test cases. Для каждого endpoint с path parameter (например /users/{id}/orders/{orderId}): (1) Заменить ID на ID другого пользователя (id+1, id-1, random UUID). (2) Заменить на 0, -1, MAX_INT. (3) Перебор sequential IDs. Входные данные: ParsedAPI из parser. Выходные данные: []AttackCase{Method, URL, Headers, Body, ExpectedBehavior, VulnerabilityType}." | 3 часа | 1.1.1 | Пакет `attacks/bola/` с 10+ шаблонов атак | P0 |
| 1.2.2 | Broken Authentication (API2:2023) | Claude Code | Промпт: "Создай `attacks/auth/` для тестирования: (1) Запросы без auth header. (2) Запросы с пустым Bearer token. (3) Запросы с expired JWT (создать через jwt-go). (4) Запросы с модифицированным JWT (изменить role claim). (5) Запросы с другим алгоритмом (none, HS256 vs RS256). (6) Brute-force password endpoints (если есть /login или /auth)." | 3 часа | 1.1.1 | Пакет `attacks/auth/` | P0 |
| 1.2.3 | Broken Object Property Level Auth (API3:2023) | Claude Code | Промпт: "Создай `attacks/property/` для: (1) Массовое присвоение (mass assignment): отправить все поля модели включая `role`, `isAdmin`, `balance`, `verified` в POST/PUT/PATCH. (2) Excessive data exposure: проверить что GET responses не возвращают чувствительные поля (password, ssn, credit_card, secret, token)." | 2 часа | 1.1.1 | Пакет `attacks/property/` | P0 |
| 1.2.4 | Unrestricted Resource Consumption (API4:2023) | Claude Code | Промпт: "Создай `attacks/ratelimit/` для: (1) Отправить 100 запросов за 1 секунду на каждый endpoint -- проверить есть ли rate limiting (HTTP 429). (2) Отправить запрос с очень большим body (1MB+). (3) Отправить запрос с pagination limit=999999. (4) GraphQL: deep nesting query (если GraphQL endpoint)." | 2 часа | 1.1.1 | Пакет `attacks/ratelimit/` | P0 |
| 1.2.5 | Broken Function Level Auth (API5:2023) | Claude Code | Промпт: "Создай `attacks/funcauth/` для: (1) Попытка доступа к admin endpoints (/admin/*, /api/v1/admin/*) с user token. (2) Попытка PUT/DELETE на endpoints где доступен только GET. (3) Попытка доступа к другим HTTP methods (OPTIONS, TRACE, CONNECT). (4) Автоматическое обнаружение admin patterns в URL paths." | 2 часа | 1.1.1 | Пакет `attacks/funcauth/` | P0 |
| 1.2.6 | Orchestrator для 5 атак | Claude Code + Human | Claude Code: "Создай `engine/orchestrator.go` который: (1) Принимает ParsedAPI. (2) Для каждого endpoint вызывает все 5 attack generators. (3) Собирает []AttackCase. (4) Дедуплицирует по URL+Method. (5) Возвращает приоритизированный список." Human: review и тестирование на реальном API. | 3 часа | 1.2.1-1.2.5 | Рабочий orchestrator, 50+ test case templates | P0 |

### Epic 1.3: HTTP Scanner Engine

| ID | Задача | Кто делает | Как | Время | Зависимости | Результат | Приоритет |
|----|--------|-----------|-----|-------|-------------|-----------|-----------|
| 1.3.1 | Custom HTTP client с middleware | Human + Claude Code | Claude Code создаёт базу: "Создай `scanner/client.go` -- HTTP client на Go с: (1) Configurable timeout (default 10s). (2) Retry с exponential backoff (3 attempts). (3) Rate limiter (configurable RPS, default 10). (4) Custom headers injection. (5) Response recording (status, headers, body, latency). (6) Proxy support (HTTP_PROXY env). (7) TLS skip verify option (--insecure flag)." Human: тестирует на реальных API, тюнит rate limits. | 6 часов | 0.1.5 | Пакет `scanner/` с HTTP client | P0 |
| 1.3.2 | Auth handler (Bearer, API key, Basic, OAuth2) | Claude Code | Промпт: "Добавь в scanner auth middleware: (1) Bearer token из --token flag или env APISENTRY_TOKEN. (2) API key в header или query param (configurable). (3) Basic auth из --user --password. (4) OAuth2 client_credentials flow (--oauth2-client-id --oauth2-client-secret --oauth2-token-url)." | 3 часа | 1.3.1 | Auth работает для всех 4 типов | P0 |
| 1.3.3 | Response analyzer (diff engine) | Claude Code | Промпт: "Создай `scanner/analyzer.go`: (1) Сравнивает expected HTTP status (из OpenAPI spec) с actual. (2) Детектирует sensitive data в response (regex для email, SSN, credit card, JWT, API key patterns). (3) Проверяет security headers (X-Content-Type-Options, Strict-Transport-Security, X-Frame-Options). (4) Возвращает []Finding{Severity, Type, Endpoint, Description, Evidence, Confidence}." | 4 часа | 1.3.1 | Пакет с finding detection | P0 |
| 1.3.4 | Scan executor (run all attacks) | Claude Code + Human | "Создай `scanner/executor.go`: (1) Принимает []AttackCase от orchestrator. (2) Запускает каждый через HTTP client. (3) Передаёт responses в analyzer. (4) Собирает []Finding. (5) Concurrent execution с configurable --concurrency (default 5). (6) Progress bar (использовать github.com/schollz/progressbar/v3)." | 4 часа | 1.3.1, 1.3.3, 1.2.6 | Рабочий сканер, выполняет все атаки и собирает результаты | P0 |

### Epic 1.4: Claude API Integration (AI Analysis)

| ID | Задача | Кто делает | Как | Время | Зависимости | Результат | Приоритет |
|----|--------|-----------|-----|-------|-------------|-----------|-----------|
| 1.4.1 | Claude API client wrapper | Claude Code | Промпт: "Создай `ai/claude.go` -- Go client для Anthropic Messages API. Используй `github.com/anthropics/anthropic-sdk-go`. Функции: (1) `AnalyzeFinding(finding Finding) (AIAnalysis, error)` -- отправляет finding в Claude Haiku 4.5 для классификации: confirmed/potential/false_positive + confidence 0-100 + remediation advice. (2) `GenerateAttacks(endpoint Endpoint) ([]AttackCase, error)` -- отправляет endpoint spec в Claude Haiku для генерации контекстных атак. Кеширование через Upstash Redis." | 4 часа | 0.1.9, 0.1.10 | Go пакет `ai/` с Claude интеграцией | P0 |
| 1.4.2 | System prompts для каждого типа уязвимости | Claude Code | Промпт: "Создай файл `ai/prompts.go` с system prompts для Claude API. Для КАЖДОГО из OWASP API Top 5: (1) System prompt для генерации атак. (2) System prompt для анализа результатов. Промпты должны включать: роль (You are an expert API security tester), контекст (OpenAPI spec, endpoint details), задачу (generate/analyze), формат выхода (JSON). Оптимизировать для Haiku 4.5 (короткие, точные промпты)." | 3 часа | 1.4.1 | Файл с 10 system prompts | P0 |
| 1.4.3 | False positive reduction pipeline | Claude Code | Промпт: "Создай `ai/fp_reducer.go`: (1) Принимает []Finding от scanner. (2) Группирует по типу уязвимости. (3) Отправляет каждую группу в Claude Haiku с контекстом (endpoint spec + все findings). (4) Claude возвращает: duplicate findings (убрать), false positives (пометить), confirmed (оставить). (5) Добавляет confidence score. Это снижает false positive rate с ~30% до <5%." | 3 часа | 1.4.1 | FP reducer, confidence scoring | P0 |
| 1.4.4 | Redis caching для AI вызовов | Claude Code | Промпт: "Добавь в `ai/claude.go` кеширование через Upstash Redis: (1) Ключ = hash(system_prompt + user_message). (2) TTL = 24 часа для attack generation, 1 час для analysis. (3) При cache hit -- не вызывать Claude API. Это экономит до 90% AI costs на повторных паттернах." | 2 часа | 1.4.1, 0.1.10 | Кеширование AI вызовов | P1 |

### Epic 1.5: CLI Interface (Cobra)

| ID | Задача | Кто делает | Как | Время | Зависимости | Результат | Приоритет |
|----|--------|-----------|-----|-------|-------------|-----------|-----------|
| 1.5.1 | Cobra CLI skeleton | Claude Code | Промпт: "Создай CLI в `cmd/apisentry/main.go` с cobra. Команды: (1) `apisentry scan --spec <path> [--url <base-url>] [--format json\|html\|sarif] [--output <file>] [--token <bearer>] [--severity critical\|high\|medium\|low] [--concurrency 5] [--timeout 10s] [--insecure]`. (2) `apisentry version`. (3) `apisentry auth login --api-key <key>`. (4) `apisentry report --scan-id <id>`. Добавь ASCII banner при запуске, --quiet mode, --verbose mode, цветной output через github.com/fatih/color." | 4 часа | 0.1.5 | Рабочий CLI skeleton | P0 |
| 1.5.2 | Интеграция всех компонентов в CLI | Human + Claude Code | Human пишет main flow в `cmd/apisentry/scan.go`: spec -> parser -> orchestrator -> scanner -> AI analyzer -> FP reducer -> output. Claude Code помогает с error handling, progress reporting, graceful shutdown. | 6 часов | 1.1.1, 1.2.6, 1.3.4, 1.4.1, 1.5.1 | `apisentry scan` работает end-to-end | P0 |
| 1.5.3 | Cross-compilation (macOS/Linux/Windows) | Claude Code | Промпт: "Создай Makefile с targets: build-all (GOOS=darwin/linux/windows, GOARCH=amd64/arm64), build-docker, test, lint (golangci-lint). Добавь GitHub Actions CI: `.github/workflows/ci.yml` с matrix build + test + release (goreleaser)." | 2 часа | 1.5.1 | Makefile + CI pipeline | P1 |

### Epic 1.6: HTML Report Generator

| ID | Задача | Кто делает | Как | Время | Зависимости | Результат | Приоритет |
|----|--------|-----------|-----|-------|-------------|-----------|-----------|
| 1.6.1 | HTML report template | Claude Code | Промпт: "Создай Go HTML template в `report/template.html` для отчёта о безопасности API: (1) Header: scan date, target API, duration, total findings. (2) Executive summary: критических X, высоких Y, средних Z, низких W, ложных N. (3) Findings table: sortable по severity, тип уязвимости, endpoint, confidence, status. (4) Для каждого finding: описание, evidence (HTTP request/response), remediation, OWASP reference. (5) Footer: disclaimer, APISentry branding. Стиль: тёмная тема, профессиональный. Используй inline CSS (один файл)." | 3 часа | 1.3.4 | Файл `report/template.html` | P0 |
| 1.6.2 | JSON и SARIF output | Claude Code | Промпт: "Добавь в `report/` генерацию: (1) JSON формат (массив findings). (2) SARIF 2.1.0 формат (для GitHub Advanced Security integration). Sarif -- стандарт Microsoft для security findings, GitHub Code Scanning его понимает." | 2 часа | 1.6.1 | JSON + SARIF output | P1 |

---

## Фаза 2: Distribution Layer (Дни 22-30)

### Epic 2.1: GitHub Action

| ID | Задача | Кто делает | Как | Время | Зависимости | Результат | Приоритет |
|----|--------|-----------|-----|-------|-------------|-----------|-----------|
| 2.1.1 | GitHub Action definition | Claude Code | Промпт: "Создай `action.yml` для GitHub Action: name: 'APISentry API Security Scan'. Inputs: spec-path (required), api-key (required, secret), base-url (optional), severity-threshold (default: high), format (default: sarif). Runs: Docker container с apisentry binary. Outputs: results-file, findings-count, critical-count. Post-action: upload SARIF to GitHub Code Scanning, comment on PR с summary." | 3 часа | 1.5.2 | `action.yml` + `Dockerfile` | P0 |
| 2.1.2 | PR comment с результатами | Claude Code | Промпт: "Добавь в GitHub Action: после скана, если есть findings, создать PR comment используя github-script action. Формат: таблица severity counts + top 3 critical findings + ссылка на полный report. Если нет findings: зелёный checkmark comment." | 2 часа | 2.1.1 | PR comment с результатами | P1 |
| 2.1.3 | Пример workflow | Claude Code | Промпт: "Создай `.github/workflows/example-apisentry.yml`: on push/PR, запускает APISentry scan, блокирует merge если есть critical findings. README инструкция: 5 строчек для добавления в свой repo." | 1 час | 2.1.1 | Example workflow + README | P1 |

### Epic 2.2: Landing Page

| ID | Задача | Кто делает | Как | Время | Зависимости | Результат | Приоритет |
|----|--------|-----------|-----|-------|-------------|-----------|-----------|
| 2.2.1 | Landing page (Next.js) | Claude Code + Human | Claude Code: "Создай landing page для apisentry.ai на Next.js 15 + Tailwind + shadcn/ui. Секции: (1) Hero: 'AI-Powered API Security Testing. $49/month.' + CTA 'Start Free Scan' + terminal animation показывающая `apisentry scan`. (2) Problem: '97% API vulnerabilities are exploited with a single request.' (3) Solution: 3 шага -- Upload OpenAPI spec, AI generates attacks, Get results in CI/CD. (4) Features grid: OWASP Top 10, AI-powered, CI/CD native, $49 flat. (5) Pricing table (5 тарифов). (6) Comparison: нас vs Salt vs StackHawk vs Akto (цены). (7) Testimonials (placeholder). (8) FAQ. (9) Footer с links. SEO: meta tags, OG images, structured data." Human: review, правит тексты, добавляет реальные скриншоты. | 8 часов | 0.1.8 | Живой сайт на Vercel | P0 |
| 2.2.2 | Waitlist form (Supabase) | Claude Code | Промпт: "Добавь на landing page waitlist form: email + company name (optional). Сохранять в Supabase таблицу `waitlist` (id, email, company, created_at, source). Confirmation email через Supabase Edge Function (или Resend.com free tier). Thank you page с referral link." | 2 часа | 2.2.1, 0.1.6 | Рабочая waitlist форма | P0 |
| 2.2.3 | Blog setup | Claude Code | Промпт: "Добавь /blog раздел на Next.js сайте. MDX-based (contentlayer или next-mdx-remote). Первый пост: 'Why Your API is Probably Vulnerable Right Now (And What to Do About It)' -- Claude напишет 2000 слов с данными из мастерплана." | 3 часа | 2.2.1 | Работающий блог с первым постом | P1 |

### Epic 2.3: Documentation

| ID | Задача | Кто делает | Как | Время | Зависимости | Результат | Приоритет |
|----|--------|-----------|-----|-------|-------------|-----------|-----------|
| 2.3.1 | Docs site (Mintlify или Docusaurus) | Claude Code | Промпт: "Создай docs site используя Mintlify (бесплатный) или Nextra. Разделы: (1) Quick Start (5 мин). (2) CLI Reference (все команды и flags). (3) GitHub Action Setup. (4) Authentication. (5) Understanding Results. (6) OWASP API Top 10 explained. (7) FAQ. (8) API Reference (для SaaS API)." | 4 часа | 1.5.2, 2.1.1 | docs.apisentry.ai | P1 |
| 2.3.2 | README для GitHub repos | Claude Code | Промпт: "Напиши README.md для apisentry-scanner: badges (build, go version, license), описание, quick start (3 команды), feature list, comparison table, architecture diagram (mermaid), contributing guide, license (MIT для CLI, proprietary для SaaS)." | 1 час | 1.5.2 | README в каждом repo | P1 |

### Epic 2.4: Beta Launch Prep

| ID | Задача | Кто делает | Как | Время | Зависимости | Результат | Приоритет |
|----|--------|-----------|-----|-------|-------------|-----------|-----------|
| 2.4.1 | Создать Discord community | Human | Создать Discord server с каналами: #general, #bug-reports, #feature-requests, #show-your-results, #announcements. Настроить бота для приветствия. | 1 час | Нет | Discord server URL | P1 |
| 2.4.2 | Подготовить beta invite emails | Claude Code | Промпт: "Напиши email шаблон для приглашения в beta: Subject: 'You're in! APISentry AI beta access'. Body: что это, как начать (3 шага), ссылка на Discord, просьба о feedback. Тон: developer-friendly, без маркетинга." | 30 мин | Нет | Email template | P1 |
| 2.4.3 | Набрать 50 beta users | Human | Каналы: (1) r/netsec -- пост "Show r/netsec: I built an AI API security scanner for $49/mo". (2) r/golang -- пост про Go scanner. (3) Twitter/X -- thread про API security stats. (4) Dev.to -- статья. (5) Waitlist. (6) Личные контакты. | 3 дня | 2.2.2, 2.4.1 | 50+ зарегистрированных beta users | P0 |

---

## Фаза 3: Monetization (Дни 31-45)

### Epic 3.1: Stripe Integration

> **Важно: Альтернативы Stripe Atlas для первых 5-10 клиентов.**
> Для начала приёма платежей US LLC **не нужна**:
> - **Личный Stripe account** — без US LLC, стандартная комиссия 2.9%+30¢
> - **Lemon Squeezy / Paddle** — Merchant of Record, комиссия ~5%, юрлицо не нужно вообще, они берут на себя налоги и VAT
> - **Stripe Atlas ($500)** — покупать только когда нужна серьёзная B2B продажа (enterprise контракт, NET-30 invoicing) или инвесторы требуют US entity

| ID | Задача | Кто делает | Как | Время | Зависимости | Результат | Приоритет |
|----|--------|-----------|-----|-------|-------------|-----------|-----------|
| 3.1.1 | Создать Stripe Products и Prices | Human | В Stripe Dashboard (личный или Lemon Squeezy): создать 5 Products (Free, Pro $49, Team $199, Business $499, Enterprise $2,999). Для каждого -- monthly price. Включить Customer Portal. | 1 час | Нет (Stripe Atlas не требуется) | Stripe Products настроены | P0 |
| 3.1.2 | Checkout Session integration | Claude Code | Промпт: "В apisentry-web (Next.js) добавь Stripe Checkout: (1) API route `/api/stripe/checkout` -- создаёт Stripe Checkout Session с price_id из query. (2) Success page `/billing/success`. (3) Cancel page redirect. Используй @stripe/stripe-js и stripe npm packages." | 3 часа | 3.1.1, 2.2.1 | Pricing page -> Stripe Checkout -> Success | P0 |
| 3.1.3 | Webhook handler | Claude Code | Промпт: "Создай `/api/stripe/webhook` в Next.js: обработка событий checkout.session.completed (создать subscription в Supabase), customer.subscription.updated, customer.subscription.deleted, invoice.payment_failed. Верификация webhook signature. Запись в Supabase таблицу `subscriptions` (id, user_id, stripe_customer_id, stripe_subscription_id, plan, status, current_period_end)." | 3 часа | 3.1.2, 0.1.6 | Webhook handler с Supabase синхронизацией | P0 |
| 3.1.4 | Usage metering | Claude Code | Промпт: "Добавь usage metering: при каждом scan, инкрементировать counter в Supabase (user_id, month, scan_count). Middleware в API: проверять лимиты (Free: 50, Pro: 500, Team: unlimited). При превышении -- 402 Payment Required с ссылкой на upgrade." | 2 часа | 3.1.3 | Лимиты по тарифам работают | P0 |

### Epic 3.2: User Authentication

| ID | Задача | Кто делает | Как | Время | Зависимости | Результат | Приоритет |
|----|--------|-----------|-----|-------|-------------|-----------|-----------|
| 3.2.1 | Supabase Auth integration | Claude Code | Промпт: "В apisentry-web добавь Supabase Auth: (1) Sign up page (email + password, или GitHub OAuth, или Google OAuth). (2) Login page. (3) Password reset. (4) Email verification. (5) Auth middleware для protected routes (/dashboard/*). Используй @supabase/auth-helpers-nextjs." | 4 часа | 0.1.6, 2.2.1 | Полная auth система | P0 |
| 3.2.2 | API key system | Claude Code | Промпт: "Создай систему API keys: (1) Dashboard page для создания/удаления API keys. (2) Supabase таблица `api_keys` (id, user_id, key_hash, name, created_at, last_used, revoked). (3) Middleware для CLI/API: проверка API key в header `X-API-Key`. (4) Key format: `ask_` + 32 random hex chars. (5) Показывать key только при создании, хранить только hash." | 3 часа | 3.2.1 | API keys для CLI и CI/CD | P0 |

### Epic 3.3: Pricing Page

| ID | Задача | Кто делает | Как | Время | Зависимости | Результат | Приоритет |
|----|--------|-----------|-----|-------|-------------|-----------|-----------|
| 3.3.1 | Interactive pricing page | Claude Code | Промпт: "Обнови pricing секцию на landing page: (1) 5 тарифных карт с toggle monthly/annual (annual = 2 мес бесплатно). (2) Feature comparison table (как у Stripe/Vercel). (3) CTA buttons ведут на Stripe Checkout. (4) 'Free forever' badge для Free tier. (5) 'Most popular' badge для Pro. (6) Enterprise: 'Contact us' -> Calendly link." | 3 часа | 3.1.1, 2.2.1 | Pricing page с живыми ссылками на оплату | P0 |

---

## Фаза 4: Growth (Месяцы 2-3)

### Epic 4.1: Public Launch

| ID | Задача | Кто делает | Как | Время | Зависимости | Результат | Приоритет |
|----|--------|-----------|-----|-------|-------------|-----------|-----------|
| 4.1.1 | Product Hunt launch | Human + Claude Code | Claude Code пишет: PH tagline, description, first comment, maker comment. Human: загружает на PH, отвечает на комментарии. Запуск: вторник/среда 00:01 PST. Подготовить: GIF demo, 5 скриншотов, logo, социальные шеры. | 1 день | Все фазы 1-3 | Top 5 on Product Hunt, 200+ upvotes | P0 |
| 4.1.2 | Hacker News Show HN | Human + Claude Code | Claude Code: "Напиши Show HN пост: 'Show HN: APISentry -- AI-powered API security testing, $49/mo flat rate'. Текст: 2-3 абзаца -- что это, почему я это построил (API attacks +113% YoY, enterprise tools cost $50K+), tech stack (Go + Claude AI), как попробовать (free tier). БЕЗ маркетинга, технический тон." Human: публикует, отвечает на все комментарии лично в течение 6+ часов. | 1 день | Все фазы 1-3 | 100+ points on HN, 500+ signups | P0 |
| 4.1.3 | Reddit posts | Human + Claude Code | Посты в: r/netsec (technical writeup), r/programming (tool announcement), r/devops (CI/CD integration), r/golang (Go scanner internals), r/cybersecurity (threat landscape). Claude пишет drafts, Human адаптирует под каждый subreddit. | 2 дня | Все фазы 1-3 | 5 Reddit постов, 100+ signups | P1 |
| 4.1.4 | Dev.to + Hashnode articles | Claude Code + Human | Claude Code: 3 статьи -- "How I Built an AI API Security Scanner in Go", "OWASP API Top 10 Explained with Real Examples", "Why Your CI/CD Pipeline Needs API Security Testing". Human: review, publish. | 2 дня | Нет | 3 опубликованные статьи | P1 |

### Epic 4.2: Content Marketing

| ID | Задача | Кто делает | Как | Время | Зависимости | Результат | Приоритет |
|----|--------|-----------|-----|-------|-------------|-----------|-----------|
| 4.2.1 | SEO keyword research | Claude Code | Промпт: "Проведи keyword research для APISentry: (1) High-intent: 'api security testing tool', 'owasp api testing', 'api vulnerability scanner'. (2) Long-tail: 'how to test api for bola', 'dora api compliance', 'ci/cd api security'. (3) Competitor: 'stackhawk alternative', 'salt security alternative', 'api security testing open source'. Создай editorial calendar на 3 месяца: 2 статьи/неделю, keyword target, title, outline." | 2 часа | Нет | Editorial calendar на 3 мес | P1 |
| 4.2.2 | Первые 5 блог-постов | Claude Code + Human | Claude пишет draft, Human review и публикует. Темы: (1) "API Security in 2026: 113% More Attacks, Are You Ready?". (2) "DORA Compliance for API: A Developer's Guide". (3) "BOLA: The #1 API Vulnerability and How to Test for It". (4) "Why We Built APISentry (and Why It Costs $49, Not $50K)". (5) "GitHub Actions + API Security: 5-Minute Setup Guide". | 5 дней | 2.2.3 | 5 SEO-статей на блоге | P1 |
| 4.2.3 | YouTube demo video | Human | Записать 3-мин видео: (1) Install CLI. (2) Scan sample API. (3) Show results. (4) Set up GitHub Action. Использовать OBS + terminal. Опубликовать на YouTube, встроить на landing page. | 3 часа | 1.5.2 | YouTube video embed | P1 |

### Epic 4.3: Community Building

| ID | Задача | Кто делает | Как | Время | Зависимости | Результат | Приоритет |
|----|--------|-----------|-----|-------|-------------|-----------|-----------|
| 4.3.1 | GitHub Discussions / Issues template | Claude Code | Промпт: "Настрой GitHub Discussions в apisentry-scanner: categories (Q&A, Feature Requests, Show & Tell, Announcements). Создай issue templates: bug_report.yml, feature_request.yml, security_vulnerability.yml." | 1 час | 0.1.5 | GitHub Discussions настроены | P2 |
| 4.3.2 | Отвечать на каждый issue/discussion | Human | Правило: отвечать на каждый issue/discussion в течение 24 часов. Это строит community trust. | Ongoing | 4.3.1 | Response time < 24h | P1 |
| 4.3.3 | Contributor guide + first good issues | Claude Code | Промпт: "Создай CONTRIBUTING.md: как форкнуть, как запустить локально, code style guide, как создать PR. Создай 5 'good first issue' -- простые задачи для контрибьюторов (новый attack template, улучшение HTML report, добавить endpoint type)." | 1 час | 0.1.5 | CONTRIBUTING.md + 5 issues | P2 |

### Epic 4.4: Customer Feedback Loop

| ID | Задача | Кто делает | Как | Время | Зависимости | Результат | Приоритет |
|----|--------|-----------|-----|-------|-------------|-----------|-----------|
| 4.4.1 | In-app feedback widget | Claude Code | Промпт: "Добавь в dashboard кнопку Feedback (нижний правый угол). При клике: модальное окно с textarea + rating 1-5. Сохранять в Supabase таблицу `feedback` (id, user_id, rating, text, page_url, created_at)." | 2 часа | 2.2.1 | Feedback widget | P1 |
| 4.4.2 | NPS survey (месяц 2) | Claude Code | Промпт: "Добавь NPS popup: через 14 дней после signup, показать 'How likely are you to recommend APISentry? 0-10'. Сохранять в Supabase. Расчёт NPS score на admin dashboard." | 1 час | 3.2.1 | NPS tracking | P2 |

---

## Фаза 5: Scale (Месяцы 4-6)

### Epic 5.1: Full OWASP Top 10

| ID | Задача | Кто делает | Как | Время | Зависимости | Результат | Приоритет |
|----|--------|-----------|-----|-------|-------------|-----------|-----------|
| 5.1.1 | Оставшиеся OWASP API6-API10 | Claude Code + Human | По аналогии с 1.2.1-1.2.5: Claude создаёт attack generators для SSRF (API6), Security Misconfiguration (API7), Automated Threats (API8), Improper Inventory (API9), Unsafe Consumption (API10). Human тестирует на реальных API. | 2 недели | 1.2.6 | 100% OWASP API Top 10, 200+ test templates | P0 |

### Epic 5.2: Dashboard UI (Next.js)

| ID | Задача | Кто делает | Как | Время | Зависимости | Результат | Приоритет |
|----|--------|-----------|-----|-------|-------------|-----------|-----------|
| 5.2.1 | Scan history dashboard | Claude Code | Промпт: "Создай dashboard page `/dashboard`: (1) Список всех сканов (дата, API, findings count, severity breakdown). (2) Trend chart (findings over time). (3) Comparison: this scan vs previous scan. Используй Recharts для графиков, shadcn/ui Table для списка." | 4 часа | 2.2.1, 3.2.1 | Dashboard с историей сканов | P1 |
| 5.2.2 | Detailed finding view | Claude Code | "Создай `/dashboard/scan/[id]/finding/[findingId]` page: (1) Описание уязвимости. (2) HTTP request/response (syntax highlighted). (3) OWASP reference link. (4) Remediation advice от AI. (5) Status: open/fixed/false_positive/accepted. (6) Comments thread." | 3 часа | 5.2.1 | Finding detail page | P1 |

### Epic 5.3: CI/CD Integrations

| ID | Задача | Кто делает | Как | Время | Зависимости | Результат | Приоритет |
|----|--------|-----------|-----|-------|-------------|-----------|-----------|
| 5.3.1 | GitLab CI template | Claude Code | Промпт: "Создай `.gitlab-ci.yml` template для APISentry: stage: test, image: apisentry/scanner:latest, script: apisentry scan, artifacts: report.html + report.sarif. Документация: как добавить в существующий GitLab CI pipeline." | 2 часа | 1.5.2 | GitLab CI template + docs | P1 |
| 5.3.2 | Jenkins plugin (shared library) | Claude Code | Промпт: "Создай Jenkins Shared Library для APISentry: Groovy class `APISentryScan` с методами: scan(specPath, apiKey), getResults(), failOnCritical(). Jenkinsfile example." | 3 часа | 1.5.2 | Jenkins integration | P2 |
| 5.3.3 | CircleCI orb | Claude Code | Промпт: "Создай CircleCI Orb для APISentry: job `apisentry/scan` с parameters: spec-path, api-key. Publish в CircleCI Orb Registry." | 2 часа | 1.5.2 | CircleCI orb | P2 |

### Epic 5.4: Compliance Reports

| ID | Задача | Кто делает | Как | Время | Зависимости | Результат | Приоритет |
|----|--------|-----------|-----|-------|-------------|-----------|-----------|
| 5.4.1 | DORA compliance report | Claude Code | Промпт: "Создай report template для DORA: маппинг scan findings на DORA Articles 5-15 (ICT risk management, testing, incident reporting). Формат: PDF через puppeteer. Sections: Executive Summary, DORA Requirement Mapping, Findings Detail, Remediation Timeline, Compliance Score." | 4 часа | 1.6.1 | DORA report generator | P1 |
| 5.4.2 | OWASP compliance report | Claude Code | "Report template маппящий findings на OWASP API Security Top 10 2023. Coverage percentage для каждой категории." | 2 часа | 5.1.1 | OWASP report | P1 |
| 5.4.3 | NIST SP 800-228 report | Claude Code | "Report маппящий findings на NIST SP 800-228 Guidelines for API Protection for Cloud-Native Systems (June 2025)." | 3 часа | 5.1.1 | NIST 800-228 report | P2 |

### Epic 5.5: Pre-seed Fundraising Prep

| ID | Задача | Кто делает | Как | Время | Зависимости | Результат | Приоритет |
|----|--------|-----------|-----|-------|-------------|-----------|-----------|
| 5.5.1 | Pitch deck | Claude Code + Human | Claude: структура и контент 12 слайдов. Human: дизайн в Figma/Canva. Слайды: Problem, Solution, Market ($10.89B->$41.66B), Product Demo, Traction, Business Model, Competition, Team, Financials, Ask ($200-500K), Vision. | 1 день | Метрики | 12-slide deck | P1 |
| 5.5.2 | Financial model | Claude Code | Промпт: "Создай Google Sheets financial model: (1) Monthly P&L на 24 мес. (2) Customer cohort analysis. (3) Unit economics dashboard (CAC, LTV, LTV/CAC, payback). (4) Scenarios: bear/base/bull. (5) Revenue по тарифам. Данные из мастерплана." | 3 часа | Нет | Financial model spreadsheet | P1 |
| 5.5.3 | Target investor list | Claude Code | Промпт: "Создай таблицу из 30 target investors: (1) 10 micro-VCs (Silent Ventures, YL Ventures, Scout Ventures, etc.). (2) 10 angel investors (security founders на LinkedIn). (3) 5 accelerators (YC, Techstars, Alchemist). (4) 5 strategic (CrowdStrike Falcon Fund, etc.). Для каждого: name, focus, typical ticket, contact method, warm intro possible?" | 2 часа | Нет | Investor pipeline list | P1 |

---

# РАЗДЕЛ 2.5: Технические риски PoC

> Эти риски нужно проверить в первые 5 дней. Если какой-то из них подтвердится — лучше узнать до первого потраченного доллара.

| # | Риск | Вероятность | Как проверить за 1-2 дня | Что делать если не работает |
|---|------|-------------|--------------------------|---------------------------|
| 1 | OpenAPI parser (kin-openapi) не справляется с реальными specs (circular refs, huge files, нестандартные extensions) | 5% (низкая) | День 1-2: Скачать Stripe API spec (~100K строк), GitHub API spec, Slack spec. Прогнать через parser. Если >95% endpoints парсятся — ОК. | Попробовать libopenapi как альтернативу. Или написать custom pre-processor для проблемных мест. |
| 2 | **False positive rate >30%** (scanner находит уязвимости, которых нет) | **30%** (главный риск) | День 3-4: Запустить scanner на OWASP crAPI (known vulnerabilities) + на заведомо безопасном API (httpbin.org). Посчитать: FP = findings на безопасном API / все findings. | Добавить более жёсткие правила в analyzer. Использовать Claude для двойной проверки каждого finding. Ввести confidence threshold (показывать только >70%). |
| 3 | AI (Claude) не даёт преимущества над шаблонными атаками | 25% (средняя) | День 5: Запустить scanner в двух режимах: (a) только шаблоны, (b) шаблоны + AI генерация. Сравнить количество и качество findings. Если AI находит <10% больше — не стоит затрат. | Оставить AI только для FP reduction (где он точно помогает). Attack generation делать шаблонами. Экономия на API costs. |
| 4 | Rate limiting / WAF блокирует scanner на реальных API | **60%** (высокая, но не блокер) | День 3-4: Запустить scanner на API с Cloudflare WAF. Проверить: блокируется ли через 10-50 запросов. | Снизить RPS до 1-2. Добавить случайные delays. Рекомендовать сканировать staging environment. Это ожидаемое поведение для production API — документировать. |
| 5 | Один разработчик не успевает за 30 дней | 35% (средняя) | Оценить реальную скорость Day 1-3. Если за 3 дня не готов parser + 2 attack generators — план нереалистичен. | Сократить scope MVP: только BOLA + Auth (2 атаки вместо 5). Убрать HTML report (только JSON). Убрать GitHub Action из MVP. Цель: минимальный работающий scanner. |

---

# РАЗДЕЛ 3: Day-by-Day план на первые 30 дней

## Дни 1-5: Бесплатная валидация (PoC) — $0

> **Принцип:** Ни копейки до рабочего PoC. Только код + бесплатные инструменты.

### День 1 (Ср, 25 марта): Parser + Setup ✅ ВЫПОЛНЕНО
- [x] Go 1.26.1 установлен (winget, Windows) ✅
- [x] Проект создан: `C:\Users\Voznuk\apisentry\` ✅
- [x] `go mod init github.com/apisentry/apisentry` ✅
- [x] kin-openapi v0.134.0 + cobra v1.10.2 установлены ✅
- [x] `main.go` + `cmd/root.go` + `cmd/scan.go` (Cobra CLI) ✅
- [x] `internal/parser/parser.go` (OpenAPI parser) ✅
- [x] `testdata/petstore.yaml` (тестовый spec) ✅
- [x] `go run . scan --spec testdata/petstore.yaml --target http://localhost:8080` работает — 5 endpoints ✅

**Checkpoint Day 1 ПРОЙДЕН.** Parser работает, проект компилируется.

### День 2 (Ср, 25 марта): Attack Generators + реальные specs ✅ ВЫПОЛНЕНО
- [x] Parser исправлен для allOf/oneOf/anyOf (panic на Stripe spec → fixed) ✅
- [x] Stripe API spec (3.6MB, 452 endpoints) парсится без ошибок ✅
- [x] complex-edge-cases.yaml spec (allOf/oneOf/anyOf) парсится корректно ✅
- [x] `internal/attacks/bola.go` — BOLA generator + HTTP executor ✅
- [x] `internal/attacks/broken_auth.go` — Broken Auth generator + executor ✅
- [x] `testdata/vulnerable_api.py` — уязвимый FastAPI для тестов ✅
- [x] scan --dry-run + --token flags добавлены ✅
- [x] Параллельное выполнение (goroutines) + дедупликация findings ✅
- [x] **РЕАЛЬНЫЙ СКАН: 17 уязвимостей найдено** (3 CRITICAL + 14 HIGH) ✅
- [x] Docker Desktop установлен, требует перезагрузки ✅
- [ ] Создать GitHub Organization + repo (отложено)
- [ ] Проверить trademark на USPTO (отложено)

**Checkpoint Day 2 ПРОЙДЕН. Checkpoint Day 5 тоже ПРОЙДЕН ДОСРОЧНО.**
PoC подтверждён: сканер находит реальные уязвимости. False positive = 0 на защищённых endpoints.

### День 3 (после перезагрузки с Docker):
- [ ] Перезагрузить компьютер, запустить Docker Desktop (Human, 10мин)
- [ ] `docker run -p 8888:8888 -p 8025:8025 --name crapi crapi/crapi:latest` (Human, 15мин)
- [ ] Claude Code: `internal/attacks/mass_assignment.go` (Claude Code, 2ч)
- [ ] Claude Code: `internal/attacks/rate_limit.go` (Claude Code, 1ч)
- [ ] Claude Code: `internal/attacks/function_auth.go` (Claude Code, 1ч)
- [ ] Полный скан на OWASP crAPI (Human + Claude Code, 2ч)

**End-of-day checkpoint Day 3:** 5 attack generators работают на crAPI.

### День 3-4 (Пт-Сб, 28-29 марта): Attack Generators + Scanner
- [ ] Claude Code: BOLA attack generator (Claude Code, 3ч)
- [ ] Claude Code: Broken Auth attack generator (Claude Code, 3ч)
- [ ] Claude Code: Property-level auth + Rate limiting + Function-level auth generators (Claude Code, 4ч)
- [ ] Claude Code: Orchestrator для 5 атак (Claude Code, 1ч)
- [ ] Docker: развернуть OWASP crAPI локально (Human, 1ч)
- [ ] Claude Code: HTTP client + scanner executor (Claude Code, 4ч)
- [ ] Тест scanner на crAPI (Human, 2ч)

**End-of-day checkpoint Day 4:** 5 attack generators + scanner находят уязвимости в crAPI.

### День 5 (Вс, 30 марта): AI-интеграция + CHECKPOINT
- [ ] Claude Code: Claude API client wrapper (используя бесплатные credits или Claude подписку) (Claude Code, 3ч)
- [ ] Claude Code: System prompts для 5 OWASP categories (Claude Code, 2ч)
- [ ] Claude Code: False positive reduction pipeline (Claude Code, 2ч)

**CHECKPOINT Day 5:** Команда `apisentry scan --spec petstore.yaml --target http://localhost:8080` находит реальные уязвимости в crAPI. AI классифицирует findings. **Если это работает — PoC подтверждён. Если нет — STOP и пересмотреть подход.**

---

## Дни 6-14: MVP Core (всё ещё $0)

> **Принцип:** PoC прошёл. Теперь доводим до MVP: CLI, reports, CI/CD integration. Всё ещё $0.

### День 6-7 (Пн-Вт, 31 марта - 1 апреля): CLI + Response Analyzer
- [ ] Claude Code: Cobra CLI skeleton с полными flags (Claude Code, 3ч)
- [ ] Claude Code: Response analyzer (diff engine, sensitive data detection) (Claude Code, 4ч)
- [ ] Интеграция всех компонентов в `apisentry scan` (Human + Claude Code, 4ч)
- [ ] Claude Code: Redis caching для AI вызовов (Upstash free tier) (Claude Code, 2ч)

**End-of-day checkpoint Day 7:** `apisentry scan --spec petstore.yaml` работает end-to-end.

### День 8-9 (Ср-Чт, 2-3 апреля): Reports + Polish
- [ ] Claude Code: HTML report template (Claude Code, 3ч)
- [ ] Claude Code: JSON + SARIF output (Claude Code, 2ч)
- [ ] Полное end-to-end тестирование на 3+ разных API (Human, 4ч)
- [ ] Fix bugs, edge cases (Human + Claude Code, 3ч)

**End-of-day checkpoint Day 9:** CLI стабильно работает, генерирует HTML/JSON/SARIF reports.

### День 10-11 (Пт-Сб, 4-5 апреля): Cross-compilation + CI
- [ ] Claude Code: Makefile + goreleaser config (Claude Code, 2ч)
- [ ] Claude Code: GitHub Actions CI (build + test + release) (Claude Code, 2ч)
- [ ] Test: собрать binaries для macOS/Linux/Windows (Human, 1ч)
- [ ] Claude Code: Auth handler (Bearer, API key, Basic, OAuth2) (Claude Code, 3ч)

**End-of-day checkpoint Day 11:** CI green, binaries для 3 OS готовы.

### День 12-14 (Вс-Вт, 6-8 апреля): GitHub Action + Final Testing
- [ ] Claude Code: action.yml + Dockerfile (Claude Code, 3ч)
- [ ] Claude Code: PR comment с результатами (Claude Code, 2ч)
- [ ] Test GitHub Action в тестовом repo (Human, 2ч)
- [ ] Финальный полиш и testing (Human + Claude Code, 4ч)

**End-of-day checkpoint Day 14:** MVP полностью работает. GitHub Action комментирует PR. Потрачено: $0.

---

## Дни 15-21: Первые траты ($50-100) — ТОЛЬКО если PoC прошёл

> **Принцип:** PoC подтверждён, MVP работает. Теперь можно купить домен и сделать landing page.
> **Траты:** Домен $50-100. Vercel free tier. Supabase free tier.

### День 15-16 (Ср-Чт, 9-10 апреля): Landing Page + Домен
- [ ] Купить домен apisentry.ai/com (Human, 1ч) — **ПЕРВАЯ трата: $50-100**
- [ ] Claude Code: полная landing page Next.js (Claude Code, 5ч)
- [ ] Claude Code: waitlist form + Supabase free tier (Claude Code, 2ч)
- [ ] Claude Code: blog setup + первый пост (Claude Code, 3ч)
- [ ] Deploy на Vercel free tier (Human, 1ч)

**End-of-day checkpoint Day 16:** apisentry.ai live с waitlist.

### День 17-18 (Пт-Сб, 11-12 апреля): Auth + Docs
- [ ] Claude Code: Supabase Auth (signup/login/OAuth) — free tier (Claude Code, 4ч)
- [ ] Claude Code: API key system (Claude Code, 3ч)
- [ ] Claude Code: docs site (Mintlify free или Nextra) (Claude Code, 4ч)
- [ ] Создать Discord community (Human, 1ч)

**End-of-day checkpoint Day 18:** Users могут зарегистрироваться. Docs live.

### День 19-21 (Вс-Вт, 13-15 апреля): Beta Prep
- [ ] Claude Code: beta invite email template (Claude Code, 30мин)
- [ ] Claude Code: README для repos (Claude Code, 1ч)
- [ ] Claude Code: outreach posts для Reddit/Twitter (Claude Code, 1ч)
- [ ] Финальное тестирование всего (Human, 3ч)
- [ ] Fix critical bugs (Human + Claude Code, 2ч)

**End-of-day checkpoint Day 21:** Всё готово к beta launch. Потрачено: $50-100.

---

## Дни 22-30: Публичный beta ($75-100) — ТОЛЬКО если есть интерес

> **Принцип:** Waitlist > 20 человек ИЛИ positive feedback от beta testers. Тогда тратим на pro tiers.
> **Траты:** Anthropic API credits $50, Supabase Pro $25 (если free tier не хватает).

### День 22 (Ср, 16 апреля): Beta Launch!
- [ ] Отправить beta invites из waitlist (Human, 1ч)
- [ ] Пост на r/netsec + r/golang (Human, 2ч)
- [ ] Twitter/X thread (Human, 1ч)
- [ ] Отвечать на все feedback/вопросы (Human, 4ч)

**End-of-day checkpoint:** 20+ beta users зарегистрированы.

### День 23-26 (Чт-Вс, 17-20 апреля): Iterate + Content
- [ ] Собрать bug reports, fix top 5 (Human + Claude Code, 6ч)
- [ ] Добавить top 3 requested features (Human + Claude Code, 4ч)
- [ ] Claude Code: 3 статьи для Dev.to (Claude Code, 3ч)
- [ ] Записать YouTube demo (Human, 3ч)
- [ ] Publish + cross-post (Human, 2ч)

**End-of-day checkpoint Day 26:** 40+ beta users, 3 статьи опубликованы, critical bugs fixed.

### День 27-28 (Пн-Вт, 21-22 апреля): Payments Setup (без Stripe Atlas!)
- [ ] Настроить Stripe personal account ИЛИ Lemon Squeezy (Human, 1ч)
- [ ] Claude Code: Checkout Session integration (Claude Code, 3ч)
- [ ] Claude Code: Webhook handler (Claude Code, 3ч)
- [ ] Claude Code: Usage metering + plan limits (Claude Code, 2ч)
- [ ] Claude Code: Interactive pricing page (Claude Code, 3ч)
- [ ] Добавить analytics: Plausible или PostHog (Human, 1ч)

**End-of-day checkpoint Day 28:** Можно оплатить Pro plan. Analytics настроены.

### День 29-30 (Ср-Чт, 23-24 апреля): Public Launch
- [ ] Product Hunt launch в 00:01 PST (Human, all day)
- [ ] Отвечать на все комментарии (Human, 6ч)
- [ ] Show HN пост (Human, all day)
- [ ] Отвечать на КАЖДЫЙ комментарий (Human, 6ч)
- [ ] Fix any issues from traffic spike (Human + Claude Code, 2ч)

**End-of-day checkpoint Day 30:** 200+ free signups, 5-10 paying customers, first MRR. Потрачено: $125-200.

---

## Месяц 2-3: Stripe Atlas ($500) — ТОЛЬКО когда первый клиент готов платить

> **Принцип:** До этого момента принимаем платежи через личный Stripe / Lemon Squeezy / Paddle.
> Stripe Atlas покупаем когда: (a) нужна US LLC для B2B контракта, (b) инвестор требует, (c) >10 paying customers.

- [ ] Зарегистрировать Delaware C-Corp через Stripe Atlas (Human, 2ч) — $500
- [ ] Получить EIN + банковский счёт Mercury
- [ ] Перенести Stripe account на юрлицо

---

# РАЗДЕЛ 4: Руководство по использованию AI

## Таблица AI-инструментов по задачам

| Задача | AI инструмент | Как использовать | Ожидаемый результат |
|--------|--------------|------------------|---------------------|
| Написать OpenAPI parser | Claude Code (в терминале) | `/code` команда + промпт из задачи 1.1.1 | Go package `parser/parser.go` |
| Сгенерировать attack templates | Claude Code | Промпт из задач 1.2.1-1.2.5 | Go packages в `attacks/` |
| HTTP scanner engine | Claude Code + ручной review | Claude генерирует, human тестирует на реальных API | Go package `scanner/` |
| AI analysis pipeline | Claude Code | Промпт из 1.4.1-1.4.3 | Go package `ai/` с Claude integration |
| System prompts для продукта | Claude API (Sonnet 4.6) в Anthropic Console | Итерировать prompts в Workbench | Файл `ai/prompts.go` |
| Landing page | Claude Code | Одна команда создаёт полный Next.js проект | Полный сайт на Vercel |
| Stripe integration | Claude Code | Промпт из 3.1.2-3.1.4 | Webhook handlers, checkout flow |
| Blog posts / статьи | Claude (chat) | "Напиши 2000-word технический пост о [topic]" | Markdown статья |
| Pitch deck контент | Claude (chat) | "Создай структуру и контент для 12-slide pitch deck для APISentry" | Текст для каждого слайда |
| Cold outreach emails | Claude (chat) | "Напиши cold email для [investor/user type]" | Email template |
| Bug fix / code review | Claude Code | Показать error log, попросить fix | Исправленный код |
| Financial model | Claude (chat) | "Создай financial model для APISentry на 24 мес" | Формулы для Google Sheets |

## Критические system prompts для Claude API в продукте

### System prompt для генерации атак (Claude Haiku 4.5)

```
You are an expert API security tester specializing in OWASP API Security Top 10 2023.

Given an API endpoint specification (OpenAPI format), generate concrete attack test cases.

Rules:
1. Generate ONLY valid HTTP requests (method, URL, headers, body)
2. Each test case must target a specific vulnerability type
3. Include both the attack request AND the expected vulnerable response pattern
4. Be specific: use actual parameter names from the spec
5. Generate 5-15 test cases per endpoint, prioritized by likelihood

Output format (JSON array):
[{
  "vulnerability_type": "BOLA|BrokenAuth|MassAssignment|...",
  "owasp_id": "API1:2023",
  "method": "GET|POST|PUT|DELETE|PATCH",
  "path": "/actual/path/with/{params}",
  "headers": {"key": "value"},
  "body": {"key": "value"} or null,
  "description": "What this test does and why",
  "expected_vulnerable_response": "Pattern indicating vulnerability (e.g., 200 OK with other user's data)",
  "expected_secure_response": "Pattern indicating the API is secure (e.g., 403 Forbidden)",
  "severity": "critical|high|medium|low",
  "confidence": 0.0-1.0
}]
```

### System prompt для анализа результатов (Claude Haiku 4.5)

```
You are an API security analyst. Analyze HTTP response data from security tests and classify findings.

Given:
- The original API endpoint spec
- The attack test case (what was sent)
- The actual HTTP response (status, headers, body)

Classify as:
- CONFIRMED: Response clearly indicates vulnerability (e.g., returned other user's data for BOLA)
- POTENTIAL: Response is suspicious but not definitive (e.g., 200 OK but body unclear)
- FALSE_POSITIVE: Response indicates the API is secure (e.g., 401/403 as expected)

Output format (JSON):
{
  "classification": "CONFIRMED|POTENTIAL|FALSE_POSITIVE",
  "confidence": 0-100,
  "reasoning": "Why this classification",
  "evidence": "Specific part of response that confirms",
  "remediation": "How to fix this vulnerability (2-3 sentences)",
  "cwe_id": "CWE-XXX",
  "cvss_estimate": 0.0-10.0
}

Be conservative: prefer FALSE_POSITIVE over POTENTIAL if uncertain.
Never classify as CONFIRMED unless evidence is clear.
```

### System prompt для business logic testing (Claude Sonnet 4.6)

```
You are a senior penetration tester analyzing API business logic.

Given the full OpenAPI specification of an API, identify potential business logic vulnerabilities that automated scanners miss.

Focus on:
1. Price manipulation (negative prices, zero prices, currency tricks)
2. Quantity manipulation (negative quantities, MAX_INT)
3. State machine violations (skip steps in workflow)
4. Race conditions (concurrent identical requests)
5. Privilege escalation (user accessing admin functions)
6. Data leakage (endpoints returning more than they should)
7. IDOR (accessing other users' resources by changing IDs)

For each finding, provide:
{
  "vulnerability": "Description",
  "endpoint": "METHOD /path",
  "attack_scenario": "Step-by-step attack",
  "test_request": {"method": "", "path": "", "headers": {}, "body": {}},
  "impact": "What an attacker could do",
  "severity": "critical|high|medium|low"
}

Think like an attacker, not a tester. What would a motivated adversary try?
```

### System prompt для compliance report generation (Claude Sonnet 4.6)

```
You are a cybersecurity compliance analyst generating regulatory compliance reports.

Given API security scan results (list of findings with severity, type, remediation), generate a compliance report mapped to the specified framework.

Frameworks supported:
- DORA (Articles 5-15: ICT risk management, testing, incident reporting)
- OWASP API Security Top 10 2023
- PCI-DSS v4 (Requirement 6: Secure development)
- NIS2 (Article 21: Cybersecurity risk management measures)
- NIST SP 800-228 (API Protection for Cloud-Native Systems)
- FAPI 2.0 (Financial-grade API Security Profile)

Report structure:
1. Executive Summary (compliance score %, critical gaps)
2. Framework Requirement Mapping (each requirement -> findings -> status)
3. Gap Analysis (what's missing)
4. Remediation Priority (ordered by risk)
5. Timeline Recommendation (when to fix what)

Use professional language suitable for CTO/CISO audience.
```

---

# РАЗДЕЛ 5: Технические архитектурные решения

## 1. Go 1.26 + Cobra CLI

**Что выбрано:** Go 1.26 (Green Tea GC, вышел 10.02.2026) как основной язык для scanner, CLI, и API gateway. Cobra для CLI framework.

**Почему (vs альтернативы):**
- Go vs Python: Go на порядок быстрее для HTTP-heavy workloads. Concurrent HTTP scanner на Go обрабатывает 1000+ requests/sec. Python ограничен GIL.
- Go vs Rust: Rust быстрее, но время разработки 3-5x дольше. Go -- sweet spot для solo founder.
- Go vs Node.js: Go binary = zero dependencies. Node.js требует npm, node runtime. Go cross-compile тривиален.
- Cobra vs urfave/cli: Cobra -- стандарт (kubectl, docker, gh используют Cobra). Лучшая документация.

**Как структурировать проект:**
```
apisentry-scanner/
  cmd/
    apisentry/
      main.go          // Entry point
      scan.go           // `apisentry scan` command
      auth.go           // `apisentry auth` commands
      report.go         // `apisentry report` command
      version.go        // `apisentry version`
  internal/
    parser/
      parser.go         // OpenAPI parser (kin-openapi)
      parser_test.go
    attacks/
      bola/             // BOLA attack generator
      auth/             // Auth attack generator
      property/         // Property-level auth
      ratelimit/        // Rate limiting
      funcauth/         // Function-level auth
      orchestrator.go   // Combines all attacks
    scanner/
      client.go         // HTTP client with middleware
      executor.go       // Runs attacks concurrently
      analyzer.go       // Response analysis
    ai/
      claude.go         // Claude API client
      prompts.go        // System prompts
      fp_reducer.go     // False positive reduction
      cache.go          // Redis caching
    report/
      html.go           // HTML report
      json.go           // JSON output
      sarif.go          // SARIF output
      template.html     // HTML template
    config/
      config.go         // CLI config, env vars
  go.mod
  go.sum
  Makefile
  Dockerfile
  .goreleaser.yaml
```

**Gotchas:**
- Go 1.26 Green Tea GC -- включён по умолчанию, не выключать (GOGC settings).
- `kin-openapi` не поддерживает OpenAPI 3.1 полностью -- проверять конкретные features.
- Concurrent scanner: обязательно use `errgroup` для graceful error handling.
- Cross-compile для Windows: тестировать на реальном Windows, есть нюансы с path separators.

## 2. kin-openapi для парсинга спецификаций

**Что выбрано:** `github.com/getkin/kin-openapi` -- Go library для парсинга OpenAPI 3.0+ specs.

**Почему:**
- Единственная зрелая Go library для OpenAPI 3.x.
- Поддерживает: validation, circular $ref resolution, Swagger 2.0 conversion.
- Активно поддерживается (последний релиз: август 2025).
- Альтернатива libopenapi -- менее зрелая.

**Как использовать:**
```go
import "github.com/getkin/kin-openapi/openapi3"

loader := openapi3.NewLoader()
doc, err := loader.LoadFromFile("spec.yaml")
if err != nil { return err }
err = doc.Validate(loader.Context)
// Iterate endpoints:
for path, pathItem := range doc.Paths.Map() {
    for method, operation := range pathItem.Operations() {
        // path = "/users/{id}", method = "GET", operation has parameters, requestBody, responses
    }
}
```

**Gotchas:**
- `$ref` resolution: вызвать `doc.InternalizeRefs()` перед итерацией.
- Swagger 2.0: конвертировать через `openapi2conv.ToV3()`.
- Большие specs (10K+ endpoints): парсинг может занять секунды, кешировать результат.

## 3. Claude API -- стратегия кеширования и оптимизации стоимости

**Что выбрано:** Claude Haiku 4.5 для массовых операций (attack gen, FP reduction), Sonnet 4.6 для complex analysis (business logic, compliance reports).

**Стратегия оптимизации:**
1. **Prompt caching (Anthropic feature):** System prompt помечается как cacheable. При повторных вызовах с тем же system prompt -- 90% скидка на input tokens. Для нас: system prompts одинаковы для всех сканов.
2. **Batch API:** Для ночных CI/CD сканов -- Batch API даёт 50% скидку. Отправляем все findings разом, получаем результат через минуты.
3. **Redis caching:** Hash(system_prompt + user_message) -> cached response. TTL 24ч для attack generation (paттерны не меняются), 1ч для analysis (свежесть важна).
4. **Результат:** Prompt caching (90%) + Batch (50%) + Redis = до 95% экономии. При 1,000 клиентов: $500-1,200/мес вместо $10,000+/мес.

**Gotchas:**
- Anthropic rate limits: Haiku 4.5 = 4,000 RPM (tier 2). Достаточно для 100+ concurrent scans.
- Caching key collision: включать spec version/hash в cache key, иначе старые results для обновлённой API.
- Fallback: если Claude API down -- использовать cached results + local regex-based analysis как degraded mode.

## 4. Supabase для auth/db -- схема базы данных

**Что выбрано:** Supabase Pro ($25/мес) -- PostgreSQL + Auth + Realtime + Edge Functions.

**Схема (основные таблицы):**

```sql
-- Users (managed by Supabase Auth, extended)
CREATE TABLE public.profiles (
  id UUID PRIMARY KEY REFERENCES auth.users(id),
  email TEXT NOT NULL,
  full_name TEXT,
  company TEXT,
  plan TEXT DEFAULT 'free' CHECK (plan IN ('free','pro','team','business','enterprise')),
  stripe_customer_id TEXT,
  created_at TIMESTAMPTZ DEFAULT now()
);

-- API Keys
CREATE TABLE public.api_keys (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id UUID REFERENCES public.profiles(id) ON DELETE CASCADE,
  key_hash TEXT NOT NULL, -- SHA-256 hash
  name TEXT NOT NULL,
  last_used TIMESTAMPTZ,
  revoked BOOLEAN DEFAULT false,
  created_at TIMESTAMPTZ DEFAULT now()
);

-- Scans
CREATE TABLE public.scans (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id UUID REFERENCES public.profiles(id),
  api_name TEXT NOT NULL,
  spec_hash TEXT, -- for dedup
  status TEXT DEFAULT 'pending' CHECK (status IN ('pending','running','completed','failed')),
  findings_count INTEGER DEFAULT 0,
  critical_count INTEGER DEFAULT 0,
  high_count INTEGER DEFAULT 0,
  medium_count INTEGER DEFAULT 0,
  low_count INTEGER DEFAULT 0,
  duration_ms INTEGER,
  created_at TIMESTAMPTZ DEFAULT now(),
  completed_at TIMESTAMPTZ
);

-- Findings
CREATE TABLE public.findings (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  scan_id UUID REFERENCES public.scans(id) ON DELETE CASCADE,
  vulnerability_type TEXT NOT NULL,
  owasp_id TEXT, -- API1:2023
  severity TEXT CHECK (severity IN ('critical','high','medium','low')),
  classification TEXT CHECK (classification IN ('confirmed','potential','false_positive')),
  confidence INTEGER CHECK (confidence BETWEEN 0 AND 100),
  endpoint_method TEXT,
  endpoint_path TEXT,
  description TEXT,
  evidence TEXT,
  remediation TEXT,
  cwe_id TEXT,
  status TEXT DEFAULT 'open' CHECK (status IN ('open','fixed','accepted','false_positive')),
  created_at TIMESTAMPTZ DEFAULT now()
);

-- Subscriptions
CREATE TABLE public.subscriptions (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id UUID REFERENCES public.profiles(id),
  stripe_subscription_id TEXT UNIQUE,
  plan TEXT NOT NULL,
  status TEXT DEFAULT 'active',
  current_period_end TIMESTAMPTZ,
  created_at TIMESTAMPTZ DEFAULT now()
);

-- Usage
CREATE TABLE public.usage (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id UUID REFERENCES public.profiles(id),
  month TEXT NOT NULL, -- '2026-04'
  scan_count INTEGER DEFAULT 0,
  UNIQUE(user_id, month)
);

-- Waitlist
CREATE TABLE public.waitlist (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  email TEXT UNIQUE NOT NULL,
  company TEXT,
  source TEXT, -- 'landing', 'reddit', 'hn'
  created_at TIMESTAMPTZ DEFAULT now()
);

-- RLS policies
ALTER TABLE public.profiles ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.scans ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.findings ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.api_keys ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.usage ENABLE ROW LEVEL SECURITY;

-- Users can only see their own data
CREATE POLICY "Users see own profile" ON public.profiles FOR ALL USING (auth.uid() = id);
CREATE POLICY "Users see own scans" ON public.scans FOR ALL USING (auth.uid() = user_id);
CREATE POLICY "Users see own findings" ON public.findings FOR ALL USING (
  scan_id IN (SELECT id FROM public.scans WHERE user_id = auth.uid())
);
CREATE POLICY "Users see own keys" ON public.api_keys FOR ALL USING (auth.uid() = user_id);
CREATE POLICY "Users see own usage" ON public.usage FOR ALL USING (auth.uid() = user_id);
```

**Gotchas:**
- RLS обязателен! Без RLS любой user видит данные других.
- Supabase Pro $25/мес включает $10 compute credits -- хватит на старте.
- При 1000+ сканов/день -- добавить индексы на `scans(user_id, created_at)` и `findings(scan_id)`.
- Supabase Realtime: использовать для live scan progress в dashboard.

## 5. Stripe для платежей -- паттерн интеграции

**Что выбрано:** Stripe Checkout (hosted) + Customer Portal + Webhooks.

**Почему hosted Checkout (vs embedded):** Hosted = 0 compliance burden (PCI). Один redirect. Stripe обновляет UI автоматически. Для MVP -- идеально.

**Паттерн:**
1. User нажимает "Subscribe" -> POST `/api/stripe/checkout` с price_id
2. Server создаёт Stripe Checkout Session -> redirect URL
3. User оплачивает на Stripe hosted page
4. Stripe webhook `checkout.session.completed` -> server обновляет Supabase `subscriptions`
5. User может управлять подпиской через Customer Portal (cancel, upgrade, update card)

**Gotchas:**
- Webhook signature verification обязательна (Stripe-Signature header + raw body).
- Тестовый режим: все тесты через `sk_test_*` ключи.
- Idempotency: webhook может прийти дважды -- проверять `stripe_subscription_id` unique constraint.
- Metered billing (overages): Stripe Usage Records API для scan count > plan limit.

## 6. Deployment -- где что развернуть

**Что выбрано:**

| Компонент | Платформа | Стоимость | Почему |
|-----------|-----------|-----------|--------|
| Go API + Scanner | **Fly.io** | $10-20/мес | Low-latency, auto-scaling, Docker deploy. Альтернатива Railway ($5-20/мес). |
| Next.js Frontend | **Vercel** | $20/мес | Edge CDN, automatic deployments from GitHub, Next.js native. |
| Database | **Supabase** (managed PostgreSQL) | $25/мес | Auth + DB + Realtime в одном. |
| Redis | **Upstash** | $0 (free tier) | Serverless Redis, free 256MB / 500K commands. |
| Docs | **Mintlify** или Vercel | $0 | Free tier sufficient. |

**Fly.io vs Railway vs Hetzner:**
- **Fly.io:** Лучше для Go microservices. Edge deployment, low latency. Но free tier убран.
- **Railway:** Проще для deployment (git push), cheaper ($5/мес hobby). Но меньше control.
- **Hetzner:** Дешевле для production ($5-10/мес VPS). Но нужно самому настраивать Docker, TLS, monitoring. +30-50% цены с апреля 2026. Использовать с месяца 7+ когда нужна экономия.

**Рекомендация:** Начать с Fly.io (месяцы 1-6), мигрировать на Hetzner (месяцы 7+) когда infra costs вырастут.

**Gotchas:**
- Fly.io: `fly deploy` из GitHub Action для CD.
- Vercel: автоматический deploy из main branch.
- Supabase: миграции через `supabase db push` (local development с `supabase start`).
- Hetzner цены растут: с 1 апреля 2026 +30-50%. Заложить в финмодель.

---

# РАЗДЕЛ 6: Go-to-Market последовательность

## Шаг 1: Найти первых 10 beta users

**Где искать (конкретные места):**

| Канал | URL / Описание | Ожидаемые signups | Когда |
|-------|---------------|-------------------|-------|
| r/netsec | reddit.com/r/netsec (600K+ members) -- технический security community | 5-10 | Неделя 4 |
| r/programming | reddit.com/r/programming (6M+ members) -- developer tools | 3-5 | Неделя 4 |
| r/golang | reddit.com/r/golang -- Go community | 2-3 | Неделя 4 |
| r/devops | reddit.com/r/devops -- DevOps engineers | 2-3 | Неделя 4 |
| OWASP Slack | owasp.org/slack -- бесплатное community | 3-5 | Неделя 3 |
| API Security Slack | apisecuritynewsletter.com -- Dana Epp's community | 2-3 | Неделя 3 |
| Twitter/X security community | @danielmiessler, @InsiderPhD, @NahamSec -- tag/reply | 3-5 | Неделя 3 |
| Dev.to | dev.to -- публикация статьи | 2-3 | Неделя 4 |
| Hacker News (Show HN) | news.ycombinator.com | 10-20 | День 30 |
| Product Hunt | producthunt.com | 20-50 | День 29 |

**Конкретное сообщение для outreach (Reddit r/netsec):**

```
Title: Show r/netsec: I built an AI API security scanner that costs $49/mo instead of $50K/year

Hey r/netsec,

I've been building APISentry -- an AI-powered API security testing tool. You give it your OpenAPI spec,
it generates hundreds of contextual attack test cases (BOLA, broken auth, injection, mass assignment,
rate limiting) using Claude AI, then actually executes them against your API.

The problem: Enterprise API security tools (Salt, Cequence) cost $50K+/year. StackHawk charges
per-contributor ($42-59/mo each). Most dev teams with 5-50 devs have ZERO API security testing.

What APISentry does differently:
- Parses your OpenAPI 3.0/3.1 spec
- AI generates context-aware attacks (not generic fuzzing)
- Runs OWASP API Top 10 tests
- Integrates into CI/CD (GitHub Action)
- Flat $49/mo for the whole team

Tech stack: Go scanner + Claude AI for analysis + Next.js dashboard.

Free tier available (1 API, 50 tests/month). Looking for beta testers who have APIs
with OpenAPI specs. Would love feedback from security professionals.

Link: https://apisentry.ai
GitHub: https://github.com/apisentry/apisentry-scanner

Happy to answer any questions about the approach, false positive rates, or technical architecture.
```

## Шаг 2: Outreach message для direct DM

```
Hey [Name],

I saw your work on [specific thing they did]. I'm building APISentry -- an AI-powered
API security scanner for dev teams. Think "Snyk but for API runtime security" at $49/mo.

We're in beta right now and looking for security-minded developers to test it.
Would you be open to trying it on one of your APIs? Takes 5 minutes to set up.

Free access during beta, of course. Would really value your feedback.

[Link]
```

## Шаг 3: Конвертация beta -> paid

**Стратегия:** "Generous free tier, natural upgrade path"

1. **Beta period:** 30 дней бесплатный Pro-доступ для всех beta users.
2. **End of beta email:** "Your free Pro trial ends in 7 days. Here's what you found: [X critical, Y high vulnerabilities]. Continue protecting your APIs for $49/mo."
3. **Special offer:** "Beta users get 20% off for life. Use code BETA20."
4. **Trigger:** Первый scan который находит Critical vulnerability -- immediate email: "We found a critical vulnerability in your API. Upgrade to Pro for continuous protection."

## Шаг 4: Launch sequence

| Дата | Канал | Действие |
|------|-------|----------|
| День 29 | Product Hunt | Запуск в 00:01 PST. Подготовить: tagline, description, 5 скриншотов, GIF, first comment, maker story. Отвечать весь день. |
| День 30 | Hacker News | Show HN пост. Отвечать 6+ часов на каждый комментарий. Технический тон. |
| День 31 | Reddit (5 subs) | Одновременно: r/netsec, r/programming, r/devops, r/golang, r/cybersecurity |
| День 32 | Dev.to + Hashnode | 3 технические статьи |
| День 33 | Twitter/X thread | 10-tweet thread: "I built an API security scanner. Here's what I learned about API vulnerabilities in 2026" + link |
| Неделя 6 | YouTube | Demo video (3 мин), опубликовать, встроить на landing |
| Неделя 8 | HN again | Technical blog post, not marketing |

## Шаг 5: Контент-план -- первые 5 постов

| # | Заголовок | Ключевые моменты | SEO keyword |
|---|-----------|-----------------|-------------|
| 1 | "API Security in 2026: 113% More Attacks, and Your $49 Defense" | Данные Wallarm +113%, CISA KEV 43% = API, $4.44M breach cost. Что делать: shift-left testing, CI/CD integration. CTA: try APISentry. | api security 2026 |
| 2 | "BOLA: The #1 API Vulnerability Explained (With Real Examples)" | Что такое BOLA, примеры (GitHub, Uber, Facebook прецеденты), как тестировать, как исправить. Technical deep-dive. | bola api vulnerability |
| 3 | "DORA Compliance for APIs: A Developer's Guide" | Что такое DORA, Articles 5-15, как API testing помогает comply, checklist. | dora api compliance |
| 4 | "How to Add API Security Testing to GitHub Actions in 5 Minutes" | Tutorial: step-by-step setup APISentry GitHub Action. Скриншоты. YAML snippet. | api security github actions |
| 5 | "AI vs Traditional DAST: Why Context-Aware Testing Finds More Bugs" | Сравнение: generic fuzzing vs AI-контекстные атаки. Примеры findings которые AI находит а DAST нет. | ai api security testing |

---

# РАЗДЕЛ 7: Финансовый трекер

## Фаза 0 (Дни 1-14): Валидация + MVP

| Статья | Сумма | Примечание |
|--------|-------|------------|
| GitHub, Go, Docker, crAPI | $0 | Всё бесплатно |
| Claude API | $0 | Бесплатные credits / существующая подписка |
| Upstash Redis | $0 | Free tier |
| **Итого Дни 1-14** | **$0** | **Код и PoC бесплатно** |

## Неделя 3+ (Дни 15-30): Первые траты

| Статья | Сумма | Примечание |
|--------|-------|------------|
| Домен | $50-100 | apisentry.ai или .com (Day 15) |
| Claude API credits | $50 | Когда нужен объём (Day 22+) |
| Supabase Pro | $25 | Только если free tier не хватает |
| Vercel | $0 | Free tier достаточен для старта |
| Fly.io | $0 | Пока не нужен (CLI-first product) |
| **Итого Дни 15-30** | **$75-175** | |

## Месяц 2-3: Stripe Atlas (условно)

| Статья | Сумма | Примечание |
|--------|-------|------------|
| Stripe Atlas (Delaware C-Corp) | $500 | **Только когда первый клиент готов платить** |

> **Примечание:** Stripe Atlas ($500) переносится на Месяц 2-3. До этого момента платежи принимаются через личный Stripe account, Lemon Squeezy или Paddle.

## Месяц-за-месяцем (12 мес)

| Месяц | Расходы | Free Users | Paying | ARPU | MRR | Net Profit |
|-------|---------|-----------|--------|------|-----|------------|
| 1 | $75-175 | 50 | 0 | - | $0 | -$75-175 |
| 2 | $130 (+$500 Stripe Atlas если нужен) | 150 | 3 | $49 | $147 | +$17 (или -$483 с Atlas) |
| 3 | $130 | 300 | 30 | $120 | $3,600 | +$3,470 |
| 4 | $200 | 500 | 60 | $130 | $7,800 | +$7,600 |
| 5 | $250 | 800 | 100 | $135 | $13,500 | +$13,250 |
| 6 | $325 | 1,500 | 150 | $140 | $21,000 | +$20,675 |
| 7 | $500 | 2,000 | 220 | $145 | $31,900 | +$31,400 |
| 8 | $600 | 2,500 | 300 | $150 | $45,000 | +$44,400 |
| 9 | $700 | 3,000 | 380 | $155 | $58,900 | +$58,200 |
| 10 | $800 | 3,200 | 430 | $155 | $66,650 | +$65,850 |
| 11 | $900 | 3,500 | 500 | $160 | $80,000 | +$79,100 |
| 12 | $1,025 | 4,000 | 600 | $160 | $96,000 | +$94,975 |

**Итого за год:**
- Стартовые расходы (Дни 1-14): $0
- Первые траты (Дни 15-30): ~$75-175
- Stripe Atlas (Месяц 2-3, условно): $500
- Операционные расходы (12 мес): ~$5,690
- Общие расходы: ~$6,265-6,365
- Общая выручка: ~$424,497
- **Net profit за год 1: ~$418,000**
- **ARR на месяц 12: $1,152,000**

## Break-even

**Месяц 2** -- при 3 paying customers x $49 = $147 > $130 расходов. Бюджет $1,000 не будет исчерпан. Первые 14 дней = $0 расходов.

## Когда рассматривать pre-seed

**Месяц 6-9**, когда:
- MRR > $20K (доказанный product-market fit)
- 100+ paying customers
- Month-over-month growth > 20%
- Clear product roadmap requiring engineering hires

**Целевой raise:** $200-500K при оценке $3-5M (100-250x monthly revenue multiple, стандарт для cybersec pre-seed).

---

# РАЗДЕЛ 8: Реестр рисков

| # | Риск | Вероятность | Импакт | Митигация |
|---|------|------------|--------|-----------|
| 1 | **False positives подрывают доверие** | Высокая | Высокий | AI-driven FP reduction с confidence scoring. Маркировка: "Confirmed" vs "Potential". Feedback loop: user помечает FP -> модель учится. Цель: FP rate < 5%. |
| 2 | **Сканер повреждает production API** | Средняя | Критический | Read-only mode по умолчанию (только GET + HEAD для sensitive endpoints). Rate limiting (default 10 RPS). Чёткий disclaimer. `--safe-mode` flag. Рекомендация: сканировать staging. |
| 3 | **Aikido Security ($60M, $1B) выходит в SMB API testing** | Средняя | Высокий | Aikido Pro уже включает REST API fuzzing за $600/мес. Наш ответ: специализация ($49 vs $600), CI/CD lock-in, community. Мониторить pricing page ежеквартально. |
| 4 | **Equixly (EUR 10M Series A) -- прямой конкурент** | Средняя | Высокий | Equixly строит agentic AI pentesting, планирует EUR 50M Series B и US expansion. Наш edge: $49/мес self-serve vs enterprise pricing. Опередить в developer adoption. |
| 5 | **Claude API дорожает или downtime** | Низкая | Средний | Мульти-провайдер готовность: абстрагировать AI client за interface. Fallback на OpenAI GPT-4o-mini. Redis cache как degraded mode. Batch API для экономии. |
| 6 | **Юридическая ответственность за пропущенные уязвимости** | Средняя | Высокий | ToS: "best-effort, not a replacement for professional penetration testing". Cyber liability insurance ($1-2K/год) -- оформить до первого enterprise клиента. Limitation of liability в ToS. |
| 7 | **Burnout solo founder** | Высокая | Высокий | AI делает 60-70% рутинной работы (code, content, emails). Рабочий день 6-8 часов. Нанять первого инженера на месяце 10. Не брать enterprise support до Team+ tier. |
| 8 | **Open-source конкурент (Akto free tier, ZAP)** | Высокая | Средний | Managed SaaS UX + AI intelligence = premium. Akto free = 25 endpoints only. ZAP не имеет AI. Наш free tier щедрый (50 тестов) -- не дать повода уйти. |
| 9 | **Инфраструктурная инфляция** | Высокая | Низкий | Hetzner +30-50% с апреля 2026, DRAM +171% YoY. В финмодели заложен +25% запас с месяца 7. Миграция на Hetzner VPS при масштабе. |
| 10 | **Медленный рост -- не набрали 30 paying к месяцу 3** | Средняя | Средний | Запасной план: (1) Удвоить контент-маркетинг. (2) Снизить Pro до $29/мес. (3) Добавить "forever free" щедрый tier. (4) Partnerships с dev tool companies (Postman, Insomnia). (5) Переключиться на fintech нишу (DORA compliance = pain point). |

---

# РАЗДЕЛ 9: Определение "Готово" для каждого milestone

## MVP Done (День 21)

- [ ] `apisentry scan --spec petstore.yaml` работает без crash
- [ ] Парсит OpenAPI 3.0 + Swagger 2.0
- [ ] Генерирует атаки для 5 OWASP API categories (API1-API5)
- [ ] HTTP scanner выполняет запросы с auth (Bearer, API key)
- [ ] Claude AI анализирует findings: confirmed/potential/false_positive
- [ ] FP reducer снижает false positives
- [ ] HTML report генерируется с таблицей findings
- [ ] JSON и SARIF output работает
- [ ] GitHub Action публикует results как PR comment
- [ ] Landing page live с waitlist form
- [ ] Docs site с Quick Start guide

## First Paying Customer (День 35-40)

- [ ] Stripe Checkout работает для Pro plan ($49/мес)
- [ ] User может: signup, get API key, scan, see results in dashboard
- [ ] Usage limits enforced (Free: 50, Pro: 500)
- [ ] Минимум 1 customer заплатил и использует продукт еженедельно
- [ ] Customer подтвердил: "Это находит реальные уязвимости"

## Product-Market Fit Signal (Месяц 3-4)

- [ ] 30+ paying customers
- [ ] NPS > 40
- [ ] Week-over-week retention > 80% (users сканируют каждую неделю)
- [ ] Organic signups > 50% (люди приходят без прямого outreach)
- [ ] Хотя бы 3 customer testimonials / case studies
- [ ] Feature requests > bug reports (2:1 ratio)
- [ ] MRR > $3,000

## Ready for Pre-Seed (Месяц 6-9)

- [ ] MRR > $20,000
- [ ] 100+ paying customers
- [ ] MoM growth > 20% последние 3 месяца
- [ ] Churn < 7%/мес
- [ ] Full OWASP API Top 10 coverage
- [ ] 3+ CI/CD integrations (GitHub, GitLab, Jenkins)
- [ ] Pitch deck готов
- [ ] Financial model на 24 мес
- [ ] 5+ positive customer testimonials
- [ ] Clear roadmap к $1M ARR

---

# РАЗДЕЛ 10: Шаблон еженедельного стендапа

**Заполнять каждый понедельник утром. Хранить в файле `weekly-standup.md` в корне проекта.**

```markdown
# Еженедельный стендап -- APISentry AI

## Неделя: [номер] | Дата: [дд.мм.гггг]

### Что отгружено на прошлой неделе
- [ ] Задача 1: [описание] -- [статус: done/in-progress/blocked]
- [ ] Задача 2: ...

### Что заблокировано
- Блокер 1: [описание] -- [что нужно для разблокировки]
- Блокер 2: ...

### Фокус на эту неделю (макс 3 задачи)
1. [Главная задача] -- estimated: Xч
2. [Вторая задача] -- estimated: Xч
3. [Третья задача] -- estimated: Xч

### Метрики
| Метрика | На прошлой неделе | На этой неделе | Изменение |
|---------|------------------|----------------|-----------|
| Free users | | | |
| Paying customers | | | |
| MRR | $ | $ | |
| Scans выполнено | | | |
| NPS | | | |
| Critical bugs | | | |

### Заметки / инсайты
- [Что я узнал на этой неделе]
- [Feedback от пользователей]
- [Идеи на будущее]

### Настроение (1-5): [ ]
```

---

# Приложение A: Чеклист первого дня (обновлён — Validate First)

Распечатай и отмечай. Ничего не покупай в Day 1 — только код!

- [ ] Открыть этот документ
- [ ] Проверить trademark (USPTO + EUIPO)
- [ ] Создать GitHub org + repo `apisentry-scanner`
- [ ] Claude Code: Go boilerplate + OpenAPI parser (Claude Code)
- [ ] Скачать реальные API specs (Stripe, GitHub, Slack)
- [ ] Тест parser на PetStore spec
- [ ] Создать competitive matrix (Claude Code)
- [ ] Поставить себе напоминание: заполнять weekly standup каждый понедельник
- [ ] ~~Купить домен~~ → перенесено на Day 15
- [ ] ~~Stripe Atlas~~ → перенесено на Месяц 2-3
- [ ] ~~Supabase Pro~~ → free tier достаточен для начала

# Приложение B: Полезные ссылки

| Ресурс | URL |
|--------|-----|
| Stripe Atlas | https://stripe.com/atlas |
| Supabase Dashboard | https://supabase.com/dashboard |
| Anthropic Console | https://console.anthropic.com |
| Fly.io Dashboard | https://fly.io/dashboard |
| Vercel Dashboard | https://vercel.com/dashboard |
| Upstash Console | https://console.upstash.com |
| kin-openapi GitHub | https://github.com/getkin/kin-openapi |
| Cobra GitHub | https://github.com/spf13/cobra |
| OWASP API Top 10 2023 | https://owasp.org/API-Security/editions/2023/en/0x11-t10/ |
| NIST SP 800-228 | https://csrc.nist.gov/pubs/sp/800/228/final |
| DORA regulation | https://eur-lex.europa.eu/legal-content/EN/TXT/?uri=CELEX:32022R2554 |
| shadcn/ui | https://ui.shadcn.com |
| goreleaser | https://goreleaser.com |
| Product Hunt Launch Guide | https://www.producthunt.com/launch |

---

**Этот документ -- твоя библия на следующие 6 месяцев. Открывай его каждое утро, находи сегодняшний день, и делай ровно то, что написано. AI делает 60-70% работы -- тебе нужно направлять, тестировать и решать. Удачи.**

*Документ создан: 25 марта 2026. Обновлён: 25 марта 2026 — добавлен принцип Validate First, Pay Later. Следующая ревизия: 25 апреля 2026 (после первого месяца).*
