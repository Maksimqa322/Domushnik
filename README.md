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
2.
  ```bash
   git clone https://github.com/yourname/dom-xss-hunter.git
   cd dom-xss-hunter
   ```

4. Установи зависимости Python:

   ```bash
   pip install -r requirements.txt
   ```

5. Убедись, что установлены внешние инструменты:

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

* `-u` — один URL-адрес для анализа.
* `-d` — файл со списком URL-ов.
* `-o` — указать базовое имя файла для экспорта (например, `results` создаст `results.json` и `results.csv`).

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



