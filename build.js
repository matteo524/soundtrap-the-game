#!/usr/bin/env node
/*
 * Soundtrap — The Game : password-gate builder
 * ------------------------------------------------------------------
 * Encrypts game.html with a password (AES-256-GCM, key stretched with
 * PBKDF2-SHA256) and bakes the ciphertext into a self-contained
 * index.html unlock page. The plaintext game is NEVER published — only
 * the encrypted index.html goes to GitHub.
 *
 * Usage:
 *    node build.js                 # prompts for the password (hidden)
 *    node build.js "my passphrase" # or pass it as an argument
 *
 * Re-run any time you want to change the password.
 */
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const readline = require('readline');

const DIR = __dirname;
const GAME = path.join(DIR, 'game.html');
const TEMPLATE = path.join(DIR, 'unlock.template.html');
const OUT = path.join(DIR, 'index.html');
const ITER = 250000;           // PBKDF2 iterations (must match the template)

function askHidden(query) {
  return new Promise((resolve) => {
    const rl = readline.createInterface({ input: process.stdin, output: process.stdout });
    rl.question(query, (value) => { rl.close(); process.stdout.write('\n'); resolve(value); });
    let muted = false;
    rl._writeToOutput = (str) => { if (!muted) rl.output.write(str); };
    muted = true;             // hide keystrokes after the prompt is printed
  });
}

(async () => {
  if (!fs.existsSync(GAME)) { console.error('✗ game.html not found next to build.js'); process.exit(1); }
  if (!fs.existsSync(TEMPLATE)) { console.error('✗ unlock.template.html not found next to build.js'); process.exit(1); }

  let pw = process.argv[2] || process.env.STG_PASSWORD;
  if (!pw) {
    if (process.stdin.isTTY) {
      pw = await askHidden('Enter the game password: ');
    } else {
      console.error('✗ No password given.');
      console.error('  This terminal can\'t show a hidden prompt, so pass the password as an argument:');
      console.error('      node build.js "your password here"');
      process.exit(1);
    }
  }
  if (!pw || pw.length < 4) {
    console.error('✗ Please choose a password of at least 4 characters, e.g.:');
    console.error('      node build.js "your password here"');
    process.exit(1);
  }

  const game = fs.readFileSync(GAME);
  const salt = crypto.randomBytes(16);
  const iv = crypto.randomBytes(12);
  const key = crypto.pbkdf2Sync(Buffer.from(pw, 'utf8'), salt, ITER, 32, 'sha256');
  const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
  const ct = Buffer.concat([cipher.update(game), cipher.final()]);
  const tag = cipher.getAuthTag();
  const blob = Buffer.concat([ct, tag]);   // Web Crypto expects ciphertext||tag

  let tpl = fs.readFileSync(TEMPLATE, 'utf8');
  tpl = tpl.replace(/%%SALT%%/g, salt.toString('base64'))
           .replace(/%%IV%%/g, iv.toString('base64'))
           .replace(/%%CT%%/g, blob.toString('base64'))
           .replace(/%%ITER%%/g, String(ITER));
  fs.writeFileSync(OUT, tpl);

  console.log(`✓ Wrote index.html  (${Math.round(blob.length / 1024)} KB encrypted, ${ITER} PBKDF2 iters)`);
  console.log('  Now commit index.html + cover.jpg (NOT game.html) and push to GitHub.');
})();
