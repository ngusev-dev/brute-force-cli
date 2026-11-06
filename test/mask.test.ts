import test from 'node:test';
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { fileURLToPath } from 'node:url';
import { mkdtemp, writeFile, unlink, rmdir } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import bcrypt from 'bcryptjs';
import * as argon2 from 'argon2';
import { parseMask, matchesMask, maskCandidates } from '../src/mask.js';
import { search } from '../src/search.js';

const signal = () => new AbortController().signal;
const md5 = (password: string) => createHash('md5').update(password).digest('hex');

test('встроенные обозначения, фиксированные символы и ?? разбираются правильно', () => {
  const positions = parseMask('?l?u?d?s?a?h?H??X');
  assert.deepEqual(positions.map(choices => choices.length), [26, 26, 10, 33, 95, 16, 16, 1, 1]);
  assert.deepEqual(positions[7], ['?']);
  assert.deepEqual(positions[8], ['X']);
  assert.equal(new Set(positions[4]).size, 95);
  assert(matchesMask('pow12', parseMask('?l?l?l?d?d')));
  assert(matchesMask('pow12', parseMask('pow?d?d')));
  assert(!matchesMask('Pow12', parseMask('?l?l?l?d?d')));
  assert(!matchesMask('pow123', parseMask('?l?l?l?d?d')));
  assert(matchesMask('aF', parseMask('?h?H')));
  assert(!matchesMask('Af', parseMask('?h?H')));
  assert(matchesMask(' ?', parseMask('?s??')));
});

test('ошибочная маска отклоняется', () => {
  for (const mask of ['?', 'abc?', '?x', '?1', '?b']) assert.throws(() => parseMask(mask), /Некорректная маска/);
});

test('разные основания позиций распределяются между потоками без пропусков', () => {
  const positions = parseMask('?dX?d');
  const expected = [...maskCandidates(positions)];
  assert.equal(expected.length, 100);
  assert.equal(expected[0], '0X0');
  assert.equal(expected.at(-1), '9X9');
  for (const threads of [1, 2, 3, 20, 128]) {
    const combined = Array.from({ length: threads }, (_, id) => [...maskCandidates(positions, id, threads)]).flat();
    assert.equal(new Set(combined).size, 100);
    assert.deepEqual(combined.sort(), [...expected].sort());
  }
});

test('литералы Unicode, пустая маска и длинные маски работают без ограничения длины', () => {
  assert.deepEqual([...maskCandidates(parseMask('🔑?d'))], Array.from({ length: 10 }, (_, i) => `🔑${i}`));
  assert.deepEqual([...maskCandidates(parseMask(''))], ['']);
  assert.deepEqual([...maskCandidates(parseMask('fixed'), 1, 3)], []);
  const password = 'a'.repeat(80) + '?';
  assert.deepEqual([...maskCandidates(parseMask('a'.repeat(80) + '??'))], [password]);
});

test('поиск по маске восстанавливает пароль для всех четырёх алгоритмов', async () => {
  const hashes = {
    md5: md5('b2'),
    sha1: createHash('sha1').update('b2').digest('hex'),
    bcrypt: bcrypt.hashSync('b2', 4),
    argon2: await argon2.hash('b2', { memoryCost: 1024, timeCost: 1, parallelism: 1 }),
  };
  for (const [algorithm, hash] of Object.entries(hashes)) {
    const result = await search(algorithm, hash, signal(), 3, null, '?l?d');
    assert.equal(result.password, 'b2', algorithm);
    assert.equal(result.cancelled, false);
    assert(result.attempts >= 1n && result.attempts <= 260n);
  }
});

test('неподходящий пароль заканчивает конечный поиск со всеми проверенными комбинациями', async () => {
  const result = await search('md5', md5('outside'), signal(), 7, null, '?d?d');
  assert.equal(result.password, null);
  assert.equal(result.cancelled, false);
  assert.equal(result.attempts, 100n);
});

test('пустой пароль находится по пустой маске', async () => {
  const result = await search('md5', md5(''), signal(), 3, null, '');
  assert.equal(result.password, '');
  assert.equal(result.attempts, 1n);
});

test('словарь фильтруется маской, остаётся первым этапом и не даёт повторных проверок', async () => {
  const directory = await mkdtemp(join(tmpdir(), 'bruteforce-mask-'));
  const file = join(directory, 'dictionary.txt');
  try {
    await writeFile(file, 'outside\n9\n0\n0\n', 'utf8');
    const hit = await search('md5', md5('9'), signal(), 1, file, '?d');
    assert.equal(hit.password, '9');
    assert.equal(hit.attempts, 1n);
    const miss = await search('md5', md5('outside'), signal(), 3, file, '?d');
    assert.equal(miss.password, null);
    assert.equal(miss.cancelled, false);
    assert.equal(miss.attempts, 10n);
  } finally {
    await unlink(file);
    await rmdir(directory);
  }
});

test('отмена прекращает поиск по маске', async () => {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), 300);
  try {
    const result = await search('md5', md5('Ж'), controller.signal, 3, null, '?a?a?a?a?a?a');
    assert.equal(result.cancelled, true);
    assert.equal(result.password, null);
  } finally { clearTimeout(timer); }
});

test('CLI принимает маску, сообщает об исчерпании и отклоняет опечатки', async () => {
  const exec = promisify(execFile);
  const cli = fileURLToPath(new URL('../src/cli.js', import.meta.url));
  const found = await exec(process.execPath, [cli, 'md5', md5('🔑7'), '🔑?d']);
  assert.match(found.stdout, /Пароль найден: "🔑7"/);
  assert.equal(found.stdout.match(/Проверено:/g)?.length, 1);
  const exhausted = await exec(process.execPath, [cli, 'md5', md5('outside'), '?d']);
  assert.match(exhausted.stdout, /Пароль по заданной маске не найден/);
  assert.match(exhausted.stdout, /Проверено: 10\b/);
  await assert.rejects(exec(process.execPath, [cli, 'md5', md5('x'), '?x']), /Некорректная маска/);
});
