const lower = "abcdefghijklmnopqrstuvwxyz";
const upper = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
const digits = "0123456789";
const symbols = " !\"#$%&'()*+,-./:;<=>?@[\\]^_`{|}~";

export const CHARSETS: Record<string, string> = {
  l: lower,
  u: upper,
  d: digits,
  s: symbols,
  a: lower + upper + digits + symbols,
  h: "0123456789abcdef",
  H: "0123456789ABCDEF",
};

/** Каждая позиция маски — массив допустимых символов для этой позиции. */
export function parseMask(mask: string): string[][] {
  const characters = Array.from(mask);
  const positions: string[][] = [];
  for (let index = 0; index < characters.length; index++) {
    const character = characters[index]!;
    if (character !== "?") {
      positions.push([character]);
      continue;
    }
    const code = characters[++index];
    if (code === "?") positions.push(["?"]);
    else if (code !== undefined && Object.hasOwn(CHARSETS, code))
      positions.push(Array.from(CHARSETS[code]!));
    else
      throw new Error(
        `Некорректная маска: ${code === undefined ? "одинокий ? в конце" : `неизвестное обозначение ?${code}`}. Допустимы ?l, ?u, ?d, ?s, ?a, ?h, ?H и ??.`,
      );
  }
  return positions;
}

export function matchesMask(password: string, positions: string[][]): boolean {
  const characters = Array.from(password);
  return (
    characters.length === positions.length &&
    positions.every((choices, index) => choices.includes(characters[index]!))
  );
}

/** Счётчик с разным основанием для каждой позиции; диапазоны потоков не пересекаются. */
export function* maskCandidates(
  choices: string[][],
  id = 0,
  threads = 1,
): Generator<string> {
  const positions = new Array<number>(choices.length).fill(0);
  let offset = id;
  for (let index = positions.length - 1; index >= 0; index--) {
    const base = choices[index]!.length;
    positions[index] = offset % base;
    offset = Math.floor(offset / base);
  }
  if (offset > 0) return;

  while (true) {
    yield positions
      .map((position, index) => choices[index]![position])
      .join("");
    let carry = threads;
    for (let index = positions.length - 1; index >= 0 && carry > 0; index--) {
      const base = choices[index]!.length;
      const next = positions[index]! + carry;
      positions[index] = next % base;
      carry = Math.floor(next / base);
    }
    if (carry > 0) return;
  }
}
