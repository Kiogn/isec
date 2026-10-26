# Отчет о ДЗ. Поиск уязвимостей с помощью SAST-сканера

## 1. Описание внедренной уязвимости

[Отчёт](../task1/task1.md)

- **Тип уязвимости:** OS command injection
- **CWE:** CWE-78
- **Файл и строки:** `main/java/nsu/security/demoapplication/controller/FileController.java`, строки <120–123>

Фрагмент уязвимого кода:

```java
String command = "convert " + filePath.toString() + " -resize " + resizeParam + " " + newPath;
Process process = new ProcessBuilder("/bin/sh", "-c", command).start();
```

Исправление:

```java
if (!resizeParam.matches("\\d+x\\d+[!<>^@%]*")) {
    return ResponseEntity.badRequest().build();
}

ProcessBuilder pb = new ProcessBuilder(
    "convert",
    filePath.toString(),
    "-resize", resizeParam,
    newPath
);

Process process = pb.start();
```

## 2. Параметры запуска

| Параметр | Значение |
| --- | --- |
| Сканер | semgrep |
| Наборы правил | p/java |

Команда запуска:

```bash
docker run --rm -v "${PWD}:/src" -e SEMGREP_APP_TOKEN=<token> semgrep/semgrep semgrep scan --config p/java --json --output /src/semgrep-report.json
```

Проверка покрытия: файл с уязвимостью присутствует в списке просканированных файлов, ошибок парсинга нет.

Приложенные отчеты сканера:

- Уязвимая/исправленная версия: [`semgrep-report-v.json`](./semgrep-report-v.json)

## 3. Результаты сканирования

| Версия | Результат | Правило |
| --- | --- | --- |
| Уязвимая | TP | `java.spring.security.injection.tainted-system-command.tainted-system-command` |
| Исправленная | FP | `java.spring.security.injection.tainted-system-command.tainted-system-command` |

### 3.1. Уязвимая версия

Фрагмент находки:

```java
Process process = new ProcessBuilder("/bin/sh", "-c", command).start();
```

| Поле | Значение |
| --- | --- |
| ID правила | `java.spring.security.injection.tainted-system-command.tainted-system-command` |
| CWE | 78 |
| Файл | `src/main/java/nsu/security/demoapplication/controller/FileController.java` |
| Строка | 123 |
| Сообщение сканера | Detected user input entering a method which executes a system command. This could result in a command injection vulnerability, which allows an attacker to inject an arbitrary system command onto the server. The attacker could download malware onto or steal data from the server. Instead, use ProcessBuilder, separating the command into individual arguments, like this: new ProcessBuilder("ls", "-al", targetDirectory). Further, make sure you hardcode or allowlist the actual command so that attackers can't run arbitrary commands. |

Обоснование классификации: **TP**, сканер выявил верно место OS command injection, где параметр вставлялся напрямую в оболочку

### 3.2. Исправленная версия

Фрагмент находки:

```java
Process process = pb.start();
```

| Поле | Значение |
| --- | --- |
| ID правила | `java.spring.security.injection.tainted-system-command.tainted-system-command` |
| CWE | 78 |
| Файл | `src/main/java/nsu/security/demoapplication/controller/FileController.java` |
| Строка | 179 |
| Сообщение сканера | Detected user input entering a method which executes a system command. This could result in a command injection vulnerability, which allows an attacker to inject an arbitrary system command onto the server. The attacker could download malware onto or steal data from the server. Instead, use ProcessBuilder, separating the command into individual arguments, like this: new ProcessBuilder("ls", "-al", targetDirectory). Further, make sure you hardcode or allowlist the actual command so that attackers can't run arbitrary commands. |

Обоснование классификации: FP, так как ProcessBuilder создаётся согласно рекомендациям, однако сканер всё равно нашёл уязвимость

## 4. Анализ результатов

### 4.1. Как сработало правило (для TP)

- **Источник в правиле:** 
`$METHODNAME(..., @$REQ(...) $TYPE $SOURCE,...)`
`- pattern: $X + $SOURCE`
`- pattern: $SOURCE + $Y`
- **Синк в правиле:** `new ProcessBuilder(...). ... .start(...);`
- **Соответствие коду:**

Источник - параметр  `filename` и `resizeParam`, вводимый пользователем и производная от него строка `command`
Синк - метод объекта `ProcessBuilder`, использующий данный параметр

```java
public ResponseEntity<Resource> resizeFile(@RequestParam String filename, @RequestParam String resizeParam) throws IOException {
...
String command = "convert " + filePath.toString() + " -resize " + resizeParam + " " + newPath;
...
Process process = new ProcessBuilder("/bin/sh", "-c", command).start();
...
}
```

### 4.3. Почему сканер не распознал исправление (для FP)

Правило не учитывает санитайзер, условие написанное в исправление и всё равно считает вызов `ProcessBuilder.start` уязвимостью. Исправление верно с точки зрения описания, предоставленого сканером: `ProcessBuilder` создаётся через несколько параметров, с указанием выполняемой программы и создан allowlist

## 5. Выводы

Сканирование Semgrep корректно обнаружило реальную OS command injection в уязвимой версии, но дало ложное срабатывание на исправленной версии, где инъекция уже устранена. Ограничения сканера проявились в том, что правило tainted-system-command не считает валидацию через String.matches(...) санитайзером, не различает вызов через sh -c и безопасный вызов ProcessBuilder со списком аргументов. Сканнеры может выдавать FP, поэтому результаты обязательно требуют ручной проверки,  также имеет смысл дополнять общие наборы правил кастомными паттернами под конкретное приложение.
