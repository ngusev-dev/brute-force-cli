import { createHash } from 'node:crypto';
import bcrypt from 'bcryptjs';
import * as argon2 from 'argon2';

export type Verifier = (password: string) => boolean | Promise<boolean>;

export function createVerifier(algorithm: string, input: string): Verifier {
  const hash = input.trim();

  switch (algorithm) {
    case 'md5':
    case 'sha1': {
      const length = algorithm === 'md5' ? 32 : 40;
      if (!new RegExp(`^[a-fA-F0-9]{${length}}$`).test(hash)) {
        throw new Error(`${algorithm}: хэш должен содержать ${length} шестнадцатеричных символов.`);
      }
      return password => createHash(algorithm).update(password).digest('hex') === hash.toLowerCase();
    }
    case 'bcrypt':
      if (!/^\$2[aby]\$(0[4-9]|[12]\d|3[01])\$[./A-Za-z0-9]{53}$/.test(hash)) {
        throw new Error('Некорректный bcrypt-хэш.');
      }
      return password => bcrypt.compareSync(password, hash);
    case 'argon2':
      if (!/^\$argon2(id|i|d)\$v=(16|19)\$m=\d+,t=\d+,p=\d+\$[A-Za-z0-9+/]+\$[A-Za-z0-9+/]+$/.test(hash)) {
        throw new Error('Некорректный Argon2-хэш: нужны параметры, соль и результат.');
      }
      return password => argon2.verify(hash, password);
    default:
      throw new Error('Поддерживаются md5, sha1, bcrypt и argon2.');
  }
}
