/** Product bounds for a newly written password. Account-specific rules and
 * password history remain authoritative only in IAM's final transaction. */
export function withinNewPasswordProductBounds(value: string): boolean {
  const codePoints = Array.from(value).length;
  return codePoints >= 15 && codePoints <= 128 && new TextEncoder().encode(value).length <= 512;
}
