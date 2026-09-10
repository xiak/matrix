export type ContractValidators = Readonly<Record<string, (value: unknown) => boolean>>;

/** Compiled at build time from the current public API; no eval or schema compilation in the browser. */
export function matchesContract(validators: ContractValidators, name: string, value: unknown): boolean {
  if (!Object.hasOwn(validators, name)) return false;
  return validators[name]!(value);
}
