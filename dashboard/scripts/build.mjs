import { cp, mkdir, readFile, rm, writeFile } from 'node:fs/promises';

const html = await readFile(new URL('../index.html', import.meta.url), 'utf8');
if (!html.includes('./assets/styles.css')) {
  throw new Error('Dashboard stylesheet reference is missing.');
}
const css = await readFile(new URL('../assets/styles.css', import.meta.url), 'utf8');
if (!css.trim()) {
  throw new Error('Dashboard stylesheet is empty.');
}

const output = new URL('../dist/', import.meta.url);
await rm(output, { recursive: true, force: true });
await mkdir(output, { recursive: true });
await writeFile(new URL('index.html', output), html);
await cp(new URL('../assets/', import.meta.url), new URL('assets/', output), {
  recursive: true,
});

console.log('Dashboard built in dist/');
