# Domushnik



DOM XSS Hunter

Инструмент для автоматизированного поиска потенциальных DOM XSS sink-ов в JavaScript-файлах.  
Скрипт комбинирует `waybackurls` и `katana` для поиска JS-ресурсов, загружает их и ищет опасные конструкции (например, `innerHTML`, `document.write`, `$.parseHTML` и другие).

Возможности
-  Поиск JS-файлов через **waybackurls** и **katana** (запускаются параллельно).
-  Асинхронная загрузка файлов для максимальной скорости.
-  Поиск по списку опасных функций/методов (DOM sinks).
-  Красивый вывод с подсветкой найденных совпадений.
-  Экспорт результатов в **JSON** и **CSV** для дальнейшего анализа.

Установка
1. Клонируй репозиторий:
  ```bash
   git clone https://github.com/Maksimqa322/Domushnik
   cd Domushnik
   ```

2. Установи зависимости Python:

   ```bash
   pip install -r requirements.txt
   ```

3. Убедись, что установлены внешние инструменты:

   * [waybackurls](https://github.com/tomnomnom/waybackurls)
   * [katana](https://github.com/projectdiscovery/katana)

   Пример для Linux:

   ```bash
   go install github.com/tomnomnom/waybackurls@latest
   go install github.com/projectdiscovery/katana/cmd/katana@latest
   ```

   После этого добавь `$HOME/go/bin` в `$PATH`.

## Использование

```bash
python3 dom_xss_hunter.py -u https://target.com
```

Или с файлом URL-ов:

```bash
python3 dom_xss_hunter.py -d urls.txt
```

### Аргументы

-u, --url — целевой URL.

-d, --dict — файл со списком URL.

--noaio — форсировать синхронный режим (не использовать aiohttp).

--nowayback — не запускать waybackurls.

--nokatana — не запускать katana.

--poc — генерировать простые PoC-шаблоны.

--json-out — сохранить JSON отчёт.

--csv-out — сохранить CSV.

--verbose — показать DEBUG-логи.

--max-per-source N — максимум уникальных паттернов для показа в одном source (по умолчанию 100).

--no-filter — отключить стандартную фильтрацию библиотечных/минифицированных файлов.

### Примеры

Сканирование одного домена:

```bash
python3 dom_xss_hunter.py -u https://example.com -o example_scan
```

Сканирование списка доменов:

```bash
python3 dom_xss_hunter.py -d targets.txt -o mass_scan
```

## Пример вывода

```
[+] URL: https://example.com/assets/main.js
    ⚠️ Найдено: innerHTML
    ⚠️ Найдено: document.write
```

## Экспорт

После завершения работы создаются файлы:

* `results.json` — полный отчет в JSON.
* `results.csv` — таблица для удобного анализа.



