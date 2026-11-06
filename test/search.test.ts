import test from 'node:test';
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { fileURLToPath } from 'node:url';
import { availableParallelism } from 'node:os';
import bcrypt from 'bcryptjs';
import * as argon2 from 'argon2';
import { createVerifier } from '../src/hashing.js';
import { ALPHABET, candidates, stages, search, threadCount } from '../src/search.js';

const signal = () => new AbortController().signal;

test('генератор перебирает все комбинации по длине', () => {
  const sequence = [0, 1, 2].flatMap(length => [...candidates('ab', length)]);
  assert.deepEqual(sequence, ['', 'a', 'b', 'aa', 'ab', 'ba', 'bb']);
});

test('диапазоны потоков покрывают все комбинации без пропусков и повторов', () => {
  for (const threads of [1, 2, 3, 7, 32]) {
    const combined: string[] = [];
    for (let id = 0; id < threads; id++) {
      for (let length = 0; length <= 4; length++) combined.push(...candidates('ab', length, id, threads));
    }
    const expected = [0, 1, 2, 3, 4].flatMap(length => [...candidates('ab', length)]);
    assert.equal(combined.length, 31);
    assert.deepEqual(combined.sort(), expected.sort());
  }
});

test('все четыре алгоритма восстанавливают пароль в нескольких потоках', async () => {
  const hashes = {
    md5: createHash('md5').update('2').digest('hex'),
    sha1: createHash('sha1').update('2').digest('hex'),
    bcrypt: bcrypt.hashSync('2', 4),
    argon2: await argon2.hash('2', { memoryCost: 1024, timeCost: 1, parallelism: 1 }),
  };
  for (const [algorithm, hash] of Object.entries(hashes)) {
    const result = await search(algorithm, hash, signal(), 3, null);
    assert.equal(result.password, '2', algorithm);
    assert.equal(await createVerifier(algorithm, hash)(result.password!), true);
    assert(result.attempts >= 1n);
    assert.equal(result.threads, 3);
    assert.equal(result.cancelled, false);
    assert(result.elapsedSeconds > 0 && result.hashesPerSecond > 0);
  }
});

test('один поток сохраняет последовательный порядок и точный счётчик', async () => {
  const result = await search('md5', 'a1d0c6e83f027327d8461063f4ac58a6', signal(), 1, null);
  assert.equal(result.password, '42');
  assert.equal(result.attempts, 139n);
});

test('отмена останавливает все потоки и возвращает общую статистику', async () => {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), 300);
  try {
    const hash = createHash('md5').update('Ж').digest('hex');
    const result = await search('md5', hash, controller.signal, 3, null);
    assert.equal(result.cancelled, true);
    assert.equal(result.password, null);
    assert(result.attempts >= 0n);
    assert.equal(result.threads, 3);
    assert.equal(result.hashesPerSecond, Number(result.attempts) / result.elapsedSeconds);
  } finally { clearTimeout(timer); }
});

test('предварительная отмена не запускает потоки', async () => {
  const controller = new AbortController();
  controller.abort();
  const result = await search('md5', 'a1d0c6e83f027327d8461063f4ac58a6', controller.signal, 3, null);
  assert.equal(result.cancelled, true);
  assert.equal(result.attempts, 0n);
  assert.equal(result.threads, 0);
});

test('генератор продолжает перебор после шести символов', () => {
  assert.deepEqual([...candidates('a', 8)], ['aaaaaaaa']);
  const sequence = stages();
  assert.equal(Array.from({ length: 33 }, () => sequence.next().value).at(-1)?.length, 8);
});

test('этапы идут в заданном порядке и не повторяют проверки', () => {
  const sequence = stages();
  const batches = Array.from({ length: 9 }, () => {
    const stage = sequence.next().value!;
    return [...candidates(stage.alphabet, stage.length)].filter(stage.accepts);
  });
  assert.deepEqual(batches.map(batch => batch.length), [1, 10, 52, 0, 33, 100, 2704, 1040, 5181]);
  assert.deepEqual(batches[1], [...'0123456789']);
  assert.equal(batches[5]![0], '00');
  assert.equal(batches[5]!.at(-1), '99');
  assert(batches[6]!.every(password => /^[a-zA-Z]+$/.test(password)));
  assert(batches[7]!.every(password => /[a-zA-Z]/.test(password) && /[0-9]/.test(password)));
  assert(batches[8]!.every(password => /[^a-zA-Z0-9]/.test(password)));
  const combined = batches.flat();
  assert.equal(combined.length, 1 + 95 + 95 ** 2);
  assert.equal(new Set(combined).size, combined.length);
});

test('потоки завершают предыдущие этапы перед буквами и смешанными паролями', async () => {
  for (const [password, completedBefore] of [['a', 11n], ['a0', 2900n], ['0 ', 3940n]] as const) {
    const hash = createHash('md5').update(password).digest('hex');
    const result = await search('md5', hash, signal(), 3, null);
    assert.equal(result.password, password);
    assert(result.attempts > completedBefore);
  }
});

test('пустой пароль находится при работе нескольких потоков', async () => {
  const hash = createHash('md5').update('').digest('hex');
  const result = await search('md5', hash, signal(), 3, null);
  assert.equal(result.password, '');
  assert(result.attempts >= 1n);
  assert.equal(result.cancelled, false);
});

test('ошибки ввода и ошибки внутри worker завершают поиск', async () => {
  await assert.rejects(search('md5', 'bad', signal(), 3, null));
  await assert.rejects(search('unknown', 'bad', signal(), 3, null));
  await assert.rejects(search('md5', 'a1d0c6e83f027327d8461063f4ac58a6', signal(), 0, null));
  // Формат PHC верен, но нативная библиотека отвергает нулевую память.
  await assert.rejects(search('argon2', '$argon2id$v=19$m=0,t=1,p=1$c2FsdHNhbHQ$AAAAAA', signal(), 3, null));
});

test('число потоков выбирается автоматически по ресурсам процессора', () => {
  for (const algorithm of ['md5', 'sha1', 'bcrypt', 'argon2']) {
    assert(threadCount(algorithm) >= 1);
    assert(threadCount(algorithm) <= availableParallelism());
  }
  assert.equal(ALPHABET.length, 95);
  assert.equal(new Set(ALPHABET).size, 95);
});

test('CLI принимает два аргумента и печатает статистику только один раз', async () => {
  const exec = promisify(execFile);
  const cli = fileURLToPath(new URL('../src/cli.js', import.meta.url));
  const { stdout } = await exec(process.execPath, [cli, 'md5', 'a1d0c6e83f027327d8461063f4ac58a6']);
  assert.match(stdout, /Пароль найден: "42"/);
  assert.equal(stdout.match(/Проверено:/g)?.length, 1);
  assert.match(stdout, /Потоков: \d+/);
  assert.match(stdout, /Скорость:/);
  await assert.rejects(exec(process.execPath, [cli, 'md5', 'bad']), /Ошибка/);
});
