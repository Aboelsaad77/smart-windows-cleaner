export function sha512Base64(filePath: string): string;
export function buildPortableYml(opts: {
  version: string;
  fileName: string;
  size: number;
  sha512: string;
  releaseDate?: string;
}): string;
export function makePortableYml(
  version: string;
  zipPath: string,
  opts?: { releaseDate?: string }
): string;
