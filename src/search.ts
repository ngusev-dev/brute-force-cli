import { performance } from "node:perf_hooks";
import { availableParallelism } from "node:os";
import { Worker } from "node:worker_threads";
import { readFile } from "node:fs/promises";
import { createVerifier } from "./hashing.js";
import { CHARSETS, parseMask, matchesMask, maskCandidates } from "./mask.js";

// Печатные ASCII-символы; длина кандидатов увеличивается без заданного предела.
const DIGITS = CHARSETS.d!;
const LETTERS = CHARSETS.l! + CHARSETS.u!;
const DICTIONARY_FILE = new URL("../../src/rockyou-75.txt", import.meta.url);

export async function readDictionary(
  file: string | URL | null,
): Promise<string[]> {
  if (file === null) return [];
  try {
    const text = await readFile(file, "utf8");
    // Удаляем только BOM и разделители строк. Пробелы могут быть частью пароля.
    return [
      ...new Set(
        text
          .replace(/^\uFEFF/, "")
          .split(/\r?\n/)
          .filter((password) => password.length > 0),
      ),
    ];
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === "ENOENT") return [];
    throw error;
  }
}
export const ALPHABET = DIGITS + LETTERS + CHARSETS.s!;

// Этапы повторяются для каждой длины, иначе бесконечный этап чисел не закончится.
export function* stages() {
  yield { length: 0, alphabet: DIGITS, accepts: (_password: string) => true };
  for (let length = 1; ; length++) {
    yield { length, alphabet: DIGITS, accepts: (_password: string) => true };
    yield { length, alphabet: LETTERS, accepts: (_password: string) => true };
    yield {
      length,
      alphabet: DIGITS + LETTERS,
      accepts: (password: string) =>
        /[0-9]/.test(password) && /[a-zA-Z]/.test(password),
    };
    yield {
      length,
      alphabet: ALPHABET,
      accepts: (password: string) => /[^a-zA-Z0-9]/.test(password),
    };
  }
}

export interface Statistics {
  attempts: bigint;
  elapsedSeconds: number;
  hashesPerSecond: number;
  threads: number;
}

export interface WorkerInput {
  algorithm: string;
  hash: string;
  id: number;
  threads: number;
  stopBuffer: SharedArrayBuffer;
  dictionary: string[];
  mask?: string[][];
}

export interface WorkerResult {
  attempts: bigint;
  password: string | null;
}

// На каждой длине поток id проверяет индексы id, id + threads, id + 2 * threads...
export function* candidates(
  alphabet: string,
  length: number,
  id = 0,
  threads = 1,
): Generator<string> {
  yield* maskCandidates(
    Array.from({ length }, () => Array.from(alphabet)),
    id,
    threads,
  );
}

// Все потоки заканчивают этап до начала следующего. Выполняется только в worker.
export function finishStage(state: Int32Array, threads: number): void {
  if (Atomics.load(state, 0) !== 0) return;
  const generation = Atomics.load(state, 2);
  if (Atomics.add(state, 1, 1) === threads - 1) {
    Atomics.store(state, 1, 0);
    Atomics.add(state, 2, 1);
    Atomics.notify(state, 2);
  } else {
    while (
      Atomics.load(state, 0) === 0 &&
      Atomics.load(state, 2) === generation
    ) {
      Atomics.wait(state, 2, generation);
    }
  }
}

export function stopSearch(state: Int32Array, reason: number): boolean {
  if (Atomics.compareExchange(state, 0, 0, reason) !== 0) return false;
  // Изменение поколения исключает потерю сигнала между проверкой и Atomics.wait.
  Atomics.add(state, 2, 1);
  Atomics.notify(state, 2);
  return true;
}

export function threadCount(algorithm: string): number {
  const cpus = availableParallelism();
  const poolSize = Number(process.env.UV_THREADPOOL_SIZE ?? 4);
  return algorithm === "argon2"
    ? Math.min(cpus, Number.isInteger(poolSize) && poolSize > 0 ? poolSize : 4)
    : cpus;
}

export async function search(
  algorithm: string,
  hash: string,
  signal: AbortSignal,
  threads = threadCount(algorithm),
  dictionaryFile: string | URL | null = DICTIONARY_FILE,
  mask?: string,
): Promise<Statistics & { password: string | null; cancelled: boolean }> {
  createVerifier(algorithm, hash); // Проверяем ввод до запуска потоков.
  const positions = mask === undefined ? undefined : parseMask(mask);

  if (!Number.isSafeInteger(threads) || threads < 1)
    throw new Error("Число потоков должно быть положительным целым.");

  const started = performance.now();
  const words = signal.aborted ? [] : await readDictionary(dictionaryFile);
  const dictionary =
    positions === undefined
      ? words
      : words.filter((password) => matchesMask(password, positions));

  const stopBuffer = new SharedArrayBuffer(12);
  const stop = new Int32Array(stopBuffer); // Причина остановки, число готовых потоков, поколение этапа.

  const reports: WorkerResult[] = [];
  const jobs: Promise<void>[] = [];
  const cancel = () => {
    stopSearch(stop, 2);
  };
  signal.addEventListener("abort", cancel, { once: true });

  try {
    if (signal.aborted) cancel();
    for (let id = 0; id < threads && Atomics.load(stop, 0) !== 2; id++) {
      const workerData: WorkerInput = {
        algorithm,
        hash,
        id,
        threads,
        stopBuffer,
        dictionary,
        mask: positions,
      };
      const worker = new Worker(new URL("./worker.js", import.meta.url), {
        workerData,
      });
      jobs.push(
        new Promise<void>((resolve, reject) => {
          worker.on("message", (report: WorkerResult) => {
            reports[id] = report;
          });
          worker.once("error", (error) => {
            cancel();
            reject(error);
          });
          worker.once("exit", (code) => {
            if (code === 0 && reports[id]) resolve();
            else {
              cancel();
              reject(
                new Error(
                  `Поток ${id} завершился без результата (код ${code}).`,
                ),
              );
            }
          });
        }),
      );
    }
    await Promise.all(jobs);
  } finally {
    cancel();
    // Ждём завершения начатых проверок, чтобы итоговый счётчик был точным.
    await Promise.allSettled(jobs);
    signal.removeEventListener("abort", cancel);
  }

  const attempts = reports.reduce((sum, report) => sum + report.attempts, 0n);
  const password =
    reports.find((report) => report.password !== null)?.password ?? null;
  const elapsedSeconds = (performance.now() - started) / 1000;
  return {
    password,
    cancelled: password === null && signal.aborted,
    attempts,
    elapsedSeconds,
    threads: jobs.length,
    hashesPerSecond: elapsedSeconds > 0 ? Number(attempts) / elapsedSeconds : 0,
  };
}
