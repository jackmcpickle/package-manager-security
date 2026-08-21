const STAR_PATTERN = /^\*+$/u;

export const isPlainObject = (
  value: unknown
): value is Record<string, unknown> =>
  typeof value === "object" &&
  value !== null &&
  !Array.isArray(value) &&
  !(value instanceof Date);

export const hasText = (value: unknown): value is string =>
  typeof value === "string" && value.trim() !== "";

export const mapSerial = async <T, R>(
  items: readonly T[],
  fn: (item: T) => Promise<R>
): Promise<R[]> => {
  const out: R[] = [];
  const runAt = async (index: number): Promise<void> => {
    if (index >= items.length) {
      return;
    }
    const item = items[index];
    if (item !== undefined) {
      out.push(await fn(item));
    }
    await runAt(index + 1);
  };
  await runAt(0);
  return out;
};

export const isStar = (entry: unknown): boolean =>
  typeof entry === "string" && STAR_PATTERN.test(entry.trim());
