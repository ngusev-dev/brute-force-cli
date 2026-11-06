import { search, type Statistics } from "./search.js";

function printStatistics(stats: Statistics): void {
  console.log(
    `Потоков: ${stats.threads} | Проверено: ${stats.attempts} | Время: ${stats.elapsedSeconds.toFixed(2)} с | Скорость: ${stats.hashesPerSecond.toFixed(0)} хэш/с`,
  );
}

async function main(): Promise<void> {
  const args = process.argv.slice(2);
  if (args.length === 0 || (args.length === 1 && args[0] === "--help")) {
    console.log("Запуск: npm start -- <md5|sha1|bcrypt|argon2> <хэш> [маска]");
    console.log("Пример: npm start -- md5 a1d0c6e83f027327d8461063f4ac58a6");
    console.log(
      "С маской: npm start -- md5 a1d0c6e83f027327d8461063f4ac58a6 '?d?d'",
    );
    console.log(
      "?l — a-z, ?u — A-Z, ?d — 0-9, ?s — знаки и пробел, ?a — все ASCII, ?h/?H — hex, ?? — знак вопроса.",
    );
    return;
  }
  if (args.length < 2 || args.length > 3)
    throw new Error("Укажите алгоритм, хэш и необязательную маску.");

  const algorithm = args[0]!.toLowerCase().replace("sha-1", "sha1");
  const mask = args[2];
  const controller = new AbortController();
  const stop = () => controller.abort();
  process.on("SIGINT", stop);

  console.log(
    `Алгоритм: ${algorithm}. ${mask === undefined ? "Многопоточный перебор без ограничения длины." : `Маска: ${JSON.stringify(mask)}.`}`,
  );
  console.log("Остановка: Ctrl+C.");

  try {
    const result = await search(
      algorithm,
      args[1]!,
      controller.signal,
      undefined,
      undefined,
      mask,
    );
    console.log(
      result.password !== null
        ? `Пароль найден: ${JSON.stringify(result.password)}`
        : result.cancelled
          ? "Поиск остановлен."
          : "Пароль по заданной маске не найден.",
    );
    printStatistics(result);
    if (result.cancelled) process.exitCode = 130;
  } finally {
    process.removeListener("SIGINT", stop);
  }
}

main().catch((error: unknown) => {
  console.error(
    `Ошибка: ${error instanceof Error ? error.message : String(error)}`,
  );
  process.exitCode = 1;
});
