/* Renders the report screenshots used in the README. */
'use strict';
const { chromium } = require('playwright');
const sample = process.argv[2];
const out = process.argv[3];

(async () => {
  const b = await chromium.launch();
  const p = await b.newPage({ viewport: { width: 1600, height: 1000 }, deviceScaleFactor: 2 });
  await p.goto('file://' + sample);
  await p.waitForTimeout(500);

  const shot = async (name, clip) => {
    await p.screenshot(clip ? { path: `${out}/${name}.png`, clip } : { path: `${out}/${name}.png` });
    console.log('  ' + name + '.png');
  };
  const tab = async (t) => { await p.click(`nav button[data-tab="${t}"]`); await p.waitForTimeout(280); };

  await shot('report-overview');
  await tab('Fleet');   await shot('report-fleet');
  await tab('Changes'); await shot('report-changes');

  await tab('Events');
  await p.click('section.on th:nth-child(2) .fb'); await p.waitForTimeout(350);
  await shot('report-events-filter');
  await p.keyboard.press('Escape'); await p.waitForTimeout(200);

  await p.fill('#find', 'lsass'); await p.waitForTimeout(600);
  await shot('report-find', { x: 0, y: 0, width: 1600, height: 320 });
  await p.click('#clr'); await p.waitForTimeout(300);

  await tab('Events');
  await p.click('section.on tbody tr:first-child'); await p.waitForTimeout(350);
  await shot('report-row-detail');
  await p.keyboard.press('Escape');

  await tab('Hardening'); await shot('report-hardening');

  await b.close();
})().catch(e => { console.error(e); process.exit(1); });
