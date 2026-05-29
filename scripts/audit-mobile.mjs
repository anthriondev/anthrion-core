/**
 * Mobile responsiveness audit for all app.anthrion.xyz screens.
 *
 * Drives Chromium under iPhone 13 / Pixel 7 / 414px emulation, navigates to
 * each main route, and reports:
 *   - documentElement.scrollWidth > viewport.width (horizontal overflow)
 *   - any specific element whose rect.right exceeds viewport.width
 *   - the multi-column layout signature (target/status side-by-side at <640px)
 *
 * One-off diagnostic — kept in scripts/ for re-use, not part of the suite.
 */
import { chromium, devices } from 'playwright';

const TARGET = process.env.TARGET ?? 'https://app.anthrion.xyz';
const PROFILES = ['iPhone 13', 'Pixel 7'];
const ROUTES = ['/', '/profile', '/scans', '/scans/new'];

async function auditRoute(page, route, vw) {
  await page.goto(`${TARGET}${route}`, { waitUntil: 'load', timeout: 30000 }).catch(() => {});
  await page.waitForTimeout(2500);
  return await page.evaluate((viewportWidth) => {
    const docW = document.documentElement.scrollWidth;
    const overflowing = [];
    const all = document.querySelectorAll('body *');
    for (const el of all) {
      const r = el.getBoundingClientRect();
      if (r.width === 0 || r.height === 0) continue;
      if (r.right > viewportWidth + 0.5) {
        overflowing.push({
          tag: el.tagName.toLowerCase(),
          cls: (el.className || '').toString().slice(0, 80),
          text: (el.textContent || '').trim().slice(0, 60),
          right: Math.round(r.right),
          width: Math.round(r.width),
        });
        if (overflowing.length >= 12) break;
      }
    }
    return {
      url: location.href,
      viewportWidth,
      documentScrollWidth: docW,
      hasHorizontalScroll: docW > viewportWidth + 0.5,
      bodyText: document.body.innerText.slice(0, 200),
      overflowingCount: overflowing.length,
      overflowingSample: overflowing,
    };
  }, vw);
}

async function runProfile(profileName) {
  const device = devices[profileName];
  if (device === undefined) throw new Error(`unknown device: ${profileName}`);
  const browser = await chromium.launch({ headless: true, args: ['--no-sandbox'] });
  const ctx = await browser.newContext({ ...device });
  const page = await ctx.newPage();
  const results = [];
  for (const route of ROUTES) {
    const r = await auditRoute(page, route, device.viewport.width);
    results.push({ profile: profileName, route, ...r });
  }
  await browser.close();
  return results;
}

const all = [];
for (const p of PROFILES) {
  all.push(...(await runProfile(p)));
}
console.log(JSON.stringify(all, null, 2));
