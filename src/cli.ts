import { search, type Statistics } from "./search.js";

function printStatistics(stats: Statistics): void {
  console.log(
    `Потоков: ${stats.threads} | Проверено: ${stats.attempts} | Время: ${stats.elapsedSeconds.toFixed(2)} с | Скорость: ${stats.hashesPerSecond.toFixed(0)} хэш/с`,
  );
}

async function main(): Promise<void> {
  const args = process.argv.slice(2);
  if (args.length === 0 || (args.length === 1 && args[0] === "--help")) {
    console.log("Запуск: npm start -- <md5|sha1|bcrypt|argon2> <хэш>");
    console.log("Пример: npm start -- md5 a1d0c6e83f027327d8461063f4ac58a6");
    return;
  }
  if (args.length !== 2)
    throw new Error("Укажите два аргумента: алгоритм и хэш.");

  const algorithm = args[0]!.toLowerCase().replace("sha-1", "sha1");
  const controller = new AbortController();
  const stop = () => controller.abort();
  process.on("SIGINT", stop);

  console.log(
    `Алгоритм: ${algorithm}. Многопоточный перебор без ограничения длины.`,
  );
  console.log("Остановка: Ctrl+C.");
  console.log("Сначала словарь src/rockyou-75.txt, затем полный перебор.");
  console.log("Для каждой длины: цифры → буквы → буквы и цифры → варианты со знаками.");
  try {
    const result = await search(algorithm, args[1]!, controller.signal);
    console.log(
      result.password !== null
        ? `Пароль найден: ${JSON.stringify(result.password)}`
        : "Поиск остановлен.",
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
