/*
 * Drives the generated HTML report in a real browser.
 *
 * The report is a small self-contained app: tabs, sortable columns, per-column
 * filter popups, a global find box, a row-detail modal and CSV export. None of
 * that is exercised by the PowerShell tests, and it is rendered from strings
 * that an attacker can influence (a Defender exclusion path, a firewall rule
 * name, a service binary path), so it gets a real DOM and a real JS engine.
 */
'use strict';
const { chromium } = require('playwright');
const path = require('path');
const fs = require('fs');

const file = process.argv[2] || 'report.html';
const abs = path.resolve(file);
if (!fs.existsSync(abs)) {
  console.error(`report not found: ${abs}`);
  process.exit(1);
}

let passed = 0;
let failed = 0;
function ok(name, cond, extra) {
  if (cond) { passed++; console.log(`  PASS  ${name}`); }
  else { failed++; console.log(`  FAIL  ${name}${extra ? '  -> ' + extra : ''}`); }
}

(async () => {
  const browser = await chromium.launch();
  const page = await browser.newPage({ viewport: { width: 1500, height: 1000 } });
  const errors = [];
  page.on('pageerror', e => errors.push('pageerror: ' + e.message));
  page.on('console', m => { if (m.type() === 'error') errors.push('console: ' + m.text()); });

  await page.goto('file://' + abs);
  await page.waitForTimeout(400);

  console.log(`\nreport: ${abs}\n`);

  // ---------------------------------------------------------------- structure
  const tabs = await page.$$eval('nav button', b => b.map(x => x.dataset.tab));
  ok(`renders tabs (${tabs.length}): ${tabs.join(' | ')}`, tabs.length >= 10);
  ok('renders health cards', (await page.$$('.cards .card')).length >= 15);
  ok('shows exactly one section at a time', (await page.$$eval('main section.on', s => s.length)) === 1);
  ok('populates the header', (await page.textContent('#h1')).length > 10);

  // ---------------------------------------------------------------------- XSS
  // A Defender exclusion path is operator- or attacker-influenced text, and the
  // report gets emailed around. It must render as inert text.
  ok('no element injected from a hostile exclusion value', (await page.$$('img')).length === 0);
  const escaped = await page.$$eval('td', t => t.filter(x => x.textContent.includes('onerror')).length);
  await page.click('nav button[data-tab="Defender"]');
  await page.waitForTimeout(150);
  const escaped2 = await page.$$eval('td', t => t.filter(x => x.textContent.includes('onerror')).length);
  ok('hostile value is present as escaped text', escaped + escaped2 > 0);

  // ------------------------------------------------------------------ sorting
  await page.click('nav button[data-tab="Events"]');
  await page.waitForTimeout(150);
  const before = await page.$$eval('section.on tbody tr td:first-child', t => t.map(x => x.textContent));
  await page.click('section.on th .lbl');
  await page.waitForTimeout(120);
  const asc = await page.$$eval('section.on tbody tr td:first-child', t => t.map(x => x.textContent));
  await page.click('section.on th .lbl');
  await page.waitForTimeout(120);
  const desc = await page.$$eval('section.on tbody tr td:first-child', t => t.map(x => x.textContent));
  ok('clicking a header sorts', JSON.stringify(asc) !== JSON.stringify(before) || before.length < 2);
  ok('clicking again reverses the sort', JSON.stringify(desc) === JSON.stringify(asc.slice().reverse()));
  ok('sort direction is indicated', await page.$$eval('section.on th .arw', a => a.some(x => x.textContent.trim().length)));

  // ------------------------------------------------------------- quick filter
  const chips = await page.$$eval('section.on .chips button', b => b.map(x => x.textContent));
  ok(`quick filters present: ${chips.join(',')}`, chips[0] === 'All' && chips.includes('Blocked'));
  const blockedIdx = chips.indexOf('Blocked') + 1;
  await page.click(`section.on .chips button:nth-child(${blockedIdx})`);
  await page.waitForTimeout(150);
  const actions = await page.$$eval('section.on tbody tr', r => r.map(x => x.children[2].textContent));
  ok(`Blocked filter narrows to Blocked only (${actions.length} rows)`, actions.length > 0 && actions.every(a => a === 'Blocked'));
  ok('footer reports the filtered count', /of \d+ rows/.test(await page.textContent('section.on .foot span')));
  await page.click('section.on .chips button:nth-child(1)');
  await page.waitForTimeout(150);

  // ----------------------------------------------------------- column filters
  await page.click('section.on th:nth-child(2) .fb');
  await page.waitForTimeout(200);
  ok('column filter popup opens', await page.isVisible('#fp'));
  const values = await page.$$eval('#fp .vals input[type=checkbox]', c => c.map(x => x.dataset.v));
  ok(`popup lists distinct values (${values.length})`, values.length >= 2);
  await page.click('#fp #vn');
  await page.check(`#fp .vals input[data-v="${values[0]}"]`);
  await page.click('#fp #fa');
  await page.waitForTimeout(180);
  const sources = await page.$$eval('section.on tbody tr', r => r.map(x => x.children[1].textContent));
  ok('column filter applies', sources.length > 0 && sources.every(s => s === values[0]));
  ok('filtered column is marked', (await page.$$('section.on th.filtered')).length === 1);
  await page.click('section.on [data-rst]');
  await page.waitForTimeout(150);

  // ------------------------------------------------------------- row detail
  await page.click('section.on tbody tr:first-child');
  await page.waitForTimeout(180);
  ok('clicking a row opens the detail modal', await page.isVisible('#modal'));
  ok('modal shows full untruncated values', (await page.textContent('#mbody')).length > 100);
  await page.keyboard.press('Escape');
  await page.waitForTimeout(120);
  ok('Escape closes the modal', !(await page.isVisible('#modal')));

  // -------------------------------------------------------------- global find
  await page.fill('#find', 'defender');
  await page.waitForTimeout(500);
  const badges = await page.$$eval('nav .badge', b => b.map(x => parseInt(x.textContent, 10)));
  ok(`per-tab match badges appear (${badges.length})`, badges.length === tabs.length);
  ok('global find matches something', badges.reduce((a, b) => a + b, 0) > 0);
  await page.fill('#find', 'zzz-no-such-string-zzz');
  await page.waitForTimeout(500);
  const none = await page.$$eval('nav .badge', b => b.map(x => parseInt(x.textContent, 10)));
  ok('a nonsense search matches nothing', none.every(n => n === 0));
  await page.click('#clr');
  await page.waitForTimeout(300);
  ok('clear resets the search box', (await page.inputValue('#find')) === '');
  ok('clear removes the badges', (await page.$$('nav .badge')).length === 0);

  // ---------------------------------------------------------------- CSV export
  await page.click('nav button[data-tab="Events"]');
  await page.waitForTimeout(150);
  const download = page.waitForEvent('download');
  await page.click('section.on [data-csv]');
  const dl = await download;
  const csvPath = path.join(require('os').tmpdir(), 'report-test.csv');
  await dl.saveAs(csvPath);
  const csv = fs.readFileSync(csvPath, 'utf8');
  ok('CSV downloads with a sensible name', /\.csv$/.test(dl.suggestedFilename()));
  ok('CSV starts with a BOM so Excel reads UTF-8', csv.charCodeAt(0) === 0xFEFF);
  // Strip the BOM before inspecting the header row.
  ok('CSV is quoted and has a header row', csv.replace(/^\uFEFF/, '').split(/\r?\n/)[0].startsWith('"'));
  fs.unlinkSync(csvPath);

  // --------------------------------------------------------------- print mode
  await page.emulateMedia({ media: 'print' });
  await page.waitForTimeout(150);
  const visible = await page.$$eval('main section', s => s.filter(x => getComputedStyle(x).display !== 'none').length);
  ok(`print mode expands every tab (${visible})`, visible === tabs.length);
  ok('print mode hides the navigation', await page.$eval('nav', n => getComputedStyle(n).display === 'none'));
  await page.emulateMedia({ media: 'screen' });

  // ------------------------------------------------------------ no JS errors
  ok('no JavaScript errors', errors.length === 0, errors.join(' | '));

  await browser.close();
  console.log(`\n${passed} passed, ${failed} failed\n`);
  process.exit(failed ? 1 : 0);
})().catch(e => { console.error(e); process.exit(1); });
