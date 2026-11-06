import test from 'node:test';
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { mkdtemp, writeFile, unlink, rmdir } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import bcrypt from 'bcryptjs';
import * as argon2 from 'argon2';
import { readDictionary, search } from '../src/search.js';

const signal = () => new AbortController().signal;
const md5 = (password: string) => createHash('md5').update(password).digest('hex');

async function withDictionary(content: string, run: (file: string) => Promise<void>): Promise<void> {
  const directory = await mkdtemp(join(tmpdir(), 'bruteforce-dictionary-'));
  const file = join(directory, 'passwords.txt');
  try {
    await writeFile(file, content, 'utf8');
    await run(file);
  } finally {
    await unlink(file);
    await rmdir(directory);
  }
}

test('чтение словаря сохраняет пробелы и Unicode, убирает BOM и повторы', async () => {
  await withDictionary('\uFEFFпароль\r\n  spaced  \r\nrepeat\r\nrepeat\r\n\r\n', async file => {
    assert.deepEqual(await readDictionary(file), ['пароль', '  spaced  ', 'repeat']);
    const result = await search('md5', md5('  spaced  '), signal(), 1, file);
    assert.equal(result.password, '  spaced  ');
    assert.equal(result.attempts, 2n);
  });
});

test('словарь проверяется первым для всех четырёх алгоритмов', async () => {
  const password = 'Длинный словарный пароль';
  await withDictionary(`${password}\nother\n`, async file => {
    const hashes = {
      md5: md5(password),
      sha1: createHash('sha1').update(password).digest('hex'),
      bcrypt: bcrypt.hashSync(password, 4),
      argon2: await argon2.hash(password, { memoryCost: 1024, timeCost: 1, parallelism: 1 }),
    };
    for (const [algorithm, hash] of Object.entries(hashes)) {
      const result = await search(algorithm, hash, signal(), 3, file);
      assert.equal(result.password, password);
      assert(result.attempts >= 1n && result.attempts <= 2n);
    }
  });
});

test('после словаря идёт полный перебор, проверки суммируются и не повторяются', async () => {
  await withDictionary('not a match\nnot a match\n0\n', async file => {
    const result = await search('md5', md5('2'), signal(), 1, file);
    assert.equal(result.password, '2');
    // Два уникальных словарных слова, затем пустой пароль, 1 и 2 (0 уже проверен).
    assert.equal(result.attempts, 5n);
  });
});

test('все потоки завершают словарь перед полным перебором', async () => {
  await withDictionary('word-one\nword-two\nword-three\n', async file => {
    const result = await search('md5', md5('a'), signal(), 3, file);
    assert.equal(result.password, 'a');
    // Три слова, пустой пароль и десять цифр должны быть проверены до буквы a.
    assert(result.attempts >= 15n);
  });
});

test('при отсутствии словаря сразу выполняется полный перебор', async () => {
  await withDictionary('', async file => {
    const result = await search('md5', md5('2'), signal(), 1, `${file}.missing`);
    assert.equal(result.password, '2');
    assert.equal(result.attempts, 4n);
  });
});

test('отмена во время словаря останавливает потоки без перехода к полному перебору', async () => {
  await withDictionary(Array.from({ length: 100 }, (_, i) => `word-${i}`).join('\n'), async file => {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), 300);
    try {
      const hash = bcrypt.hashSync('not-in-dictionary', 10);
      const result = await search('bcrypt', hash, controller.signal, 3, file);
      assert.equal(result.cancelled, true);
      assert.equal(result.password, null);
      assert(result.attempts < 100n);
    } finally { clearTimeout(timer); }
  });
});
