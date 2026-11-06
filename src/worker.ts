import { parentPort, workerData } from 'node:worker_threads';
import { createVerifier } from './hashing.js';
import { stages, candidates, finishStage, stopSearch, type WorkerInput, type WorkerResult } from './search.js';

const input = workerData as WorkerInput;
const stop = new Int32Array(input.stopBuffer);
const matches = createVerifier(input.algorithm, input.hash);
const result: WorkerResult = { attempts: 0n, password: null };
const checkedDictionary = new Set(input.dictionary);

function* passwords(): Generator<string> {
  for (let index = input.id; index < input.dictionary.length; index += input.threads) {
    if (Atomics.load(stop, 0) !== 0) return;
    yield input.dictionary[index]!;
  }
  finishStage(stop, input.threads);

  for (const stage of stages()) {
    if (Atomics.load(stop, 0) !== 0) return;
    for (const password of candidates(stage.alphabet, stage.length, input.id, input.threads)) {
      if (Atomics.load(stop, 0) !== 0) return;
      if (stage.accepts(password) && !checkedDictionary.has(password)) yield password;
    }
    finishStage(stop, input.threads);
  }
}

for (const password of passwords()) {
  if (Atomics.load(stop, 0) !== 0) break;
  const check = matches(password);
  const found = typeof check === 'boolean' ? check : await check;
  result.attempts++;
  if (found) {
    if (stopSearch(stop, 1)) result.password = password;
    break;
  }
}

parentPort!.postMessage(result);
