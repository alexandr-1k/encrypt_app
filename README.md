# cpp-middle-project-sprint-1 <!-- omit in toc -->

- [Настройка переменных окружения](#настройка-переменных-окружения)
- [Начало работы](#начало-работы)
- [Сборка проекта и запуск тестов](#сборка-проекта-и-запуск-тестов)
  - [Команды для сборки проекта](#команды-для-сборки-проекта)
  - [Команды для запуска приложения](#команды-для-запуска-приложения)
  - [Команда для запуска тестов](#команда-для-запуска-тестов)
  - [Команда для запуска clang-format — обязательное требование перед сдачей работы на ревью](#команда-для-запуска-clang-format--обязательное-требование-перед-сдачей-работы-на-ревью)
  - [Команды для запуска отладчика](#команды-для-запуска-отладчика)
- [Дополнительно](#дополнительно)


Шаблон репозитория для практического задания 1-го спринта «Мидл разработчик С++»

## Настройка переменных окружения

Для корректной работы контейнера добавьте в ваш bash-профиль две переменные окружения `USER_UID` и `USER_GID` командой  `echo -e '\nexport USER_UID=$(id -u)\nexport USER_GID=$(id -g)' >> ~/.bashrc`.

После этого обновите настройки bash-профиля командой `source ~/.bashrc`.

## Начало работы

1. Нажмите зелёную кнопку `Use this template`, затем `Create a new repository`.
2. Назовите свой репозиторий.
3. Склонируйте созданный репозиторий командой `git clone your-repository-name`.
4. Создайте новую ветку командой `git switch -c development`.
5. Откройте проект в `Visual Studio Code`.
6. Нажмите `F1` и откройте проект в dev-контейнере командой `Dev Containers: Reopen in Container`.

## Сборка проекта и запуск тестов

Данный репозиторий использует три инструмента:

- **Conan** — свободный менеджер пакетов для C и C++ с открытым исходным кодом (MIT). Позволяет настраивать процесс сборки программ, скачивать и устанавливать сторонние зависимости и необходимые инструменты. Подробнее о Conan:
  - https://habr.com/ru/articles/884464
  - https://docs.conan.io/2.0/tutorial/consuming_packages/build_simple_cmake_project.html
  - https://docs.conan.io/2.0/tutorial/consuming_packages/the_flexibility_of_conanfile_py.html

- **cmake** — генератор систем сборки для C и C++. Позволяет создавать проекты, которые могут компилироваться на различных платформах и с различными компиляторами. Подробнее о cmake:
  - https://dzen.ru/a/ZzZGUm-4o0u-IQlb
  - https://neerc.ifmo.ru/wiki/index.php?title=CMake_Tutorial
  - https://cmake.org/cmake/help/book/mastering-cmake/cmake/Help/guide/tutorial/index.html

- **VS Code Dev Docker container** - Docker контейнер, который содержит полностью настроенное окружение для выполнение задания. Подробнее об этой функциональности:
  - https://habr.com/ru/articles/822707/ - "Почти все, что вы хотели бы знать про Docker"
  - https://code.visualstudio.com/docs/devcontainers/containers - официальная документация VS Code
  - https://www.youtube.com/watch?v=p9L7YFqHGk4 - "Docker container for VS Code"
  - https://www.youtube.com/watch?v=pg19Z8LL06w&t=174s&pp=ygUPRG9ja2VyY29udGFpbmVy - "Docker in 1 hour"

### Команды для сборки проекта

Используйте `F5` для выполнения следующих шагов:
- Создание папки `build`
- Вызов `conan` команд для установки требуемых библиотек и запуска процесса сборки
- Запуска `lldb` отладчика

### Команды для запуска приложения

```bash
cd build
echo "Hello OpenSSL crypto world!" > input.txt

./CryptoGuard -i input.txt     -o encrypted.txt -p 1234 --command encrypt
./CryptoGuard -i encrypted.txt -o decrypted.txt -p 1234 --command decrypt

./CryptoGuard -i input.txt     --command checksum
./CryptoGuard -i decrypted.txt --command checksum
```

### Команда для запуска тестов

```bash
cd build
./CryptoGuard_tests
```

### Команда для запуска clang-format — обязательное требование перед сдачей работы на ревью

В этом репозитории настроен автоматический запуск clang-format (файл конфигурации — .vscode/settings.json) при сохранении любого файла с кодом.

Убедитесь, что эта функциональность работает:
- Добавьте несколько пустых линий в любой файл.
- Сохраните файл.
- Если пустые линии были удалены, всё работает, если нет — убедитесь, что clangd работает (при открытии файла с кодом в самом низу VS Code на голубой полоске должно быть написано clangd: idle). Для этого:
    - нажмите `F1` и выполните команду `clangd: Download language server`;
    - нажмите `F1` и выполните команду `clangd: Restart language server`;
    - внажмите `F1` и выполните команду `Developer: Reload Window`.

### Команды для запуска отладчика

В Visual Studio Code настройки параметров для запуска отладчика находятся в файле .vscode/launch.json. Поскольку в этом файле для запуска приложения, которое вычисляет контрольную сумму файла, уже есть одна конфигурация Launch GeometryApp, то для запуска отладчика достаточно нажать F5 или открыть окно Run and Debug комбинацией клавиш `Ctrl+Shift+D`.

## Дополнительно

Для настройки автодополнения `Ctrl + Space` нажмите `F1` и выполните команду `clangd: Download language server`. VS Code сам предложит установить подходящую версию clangd (всплывашка в правом нижнем углу). После завершения установки перезагрузите окно кнопкой перезапуска справа снизу или с помощью `F1` и выполните команду `Developer: Reload Window`.

Если всё сделали правильно, то после успешной сборки проекта вы сможете использовать автодополнение.
