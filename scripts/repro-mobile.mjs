/**
 * One-off reproduction script for the mobile-render bug on app.anthrion.xyz.
 * Spins up Chromium under iPhone 13 + Pixel 7 emulation, captures console,
 * page errors, request failures, and the rendered DOM/computed styles.
 *
 * NOT part of the test suite — intended to be invoked manually to diagnose,
 * deleted (or kept under scripts/) once the fix lands.
 */
import { chromium, devices } from 'playwright';

const TARGET = process.env.TARGET ?? 'https://app.anthrion.xyz/';
const PROFILES = ['iPhone 13', 'Pixel 7', 'Desktop Chrome'];

async function runProfile(profileName) {
  const device = devices[profileName];
  if (device === undefined) throw new Error(`unknown device: ${profileName}`);

  const browser = await chromium.launch({ headless: true, args: ['--no-sandbox'] });
  const ctx = await browser.newContext({ ...device });
  const page = await ctx.newPage();

  const consoleMessages = [];
  page.on('console', (msg) =>
    consoleMessages.push({ type: msg.type(), text: msg.text(), location: msg.location() }),
  );
  const pageErrors = [];
  page.on('pageerror', (err) => pageErrors.push({ name: err.name, message: err.message, stack: err.stack }));
  const requestFailed = [];
  page.on('requestfailed', (req) =>
    requestFailed.push({ url: req.url(), method: req.method(), failure: req.failure()?.errorText }),
  );
  const responses = [];
  page.on('response', (res) =>
    responses.push({ url: res.url(), status: res.status(), type: res.request().resourceType() }),
  );

  console.log(`\n=========== ${profileName} (${device.viewport.width}x${device.viewport.height}) ===========`);
  const navResult = await page
    .goto(TARGET, { waitUntil: 'load', timeout: 30000 })
    .catch((e) => ({ error: e.message }));
  if (navResult && navResult.error) console.log('navigation error:', navResult.error);
  await page.waitForTimeout(5000); // let Privy / Next runtime settle

  const snapshot = await page.evaluate(() => {
    const main = document.querySelector('main') ?? document.body;
    const h1 = document.querySelector('h1');
    const mainStyle = main ? getComputedStyle(main) : null;
    const bodyStyle = getComputedStyle(document.body);
    const h1Style = h1 ? getComputedStyle(h1) : null;
    const ionSpan = document.querySelector('h1 span');
    const ionStyle = ionSpan ? getComputedStyle(ionSpan) : null;
    return {
      url: location.href,
      docElementClass: document.documentElement.className,
      bodyClass: document.body.className,
      bodyText: document.body.innerText.slice(0, 500),
      h1Text: h1?.textContent ?? null,
      hasIonSpan: ionSpan !== null,
      ionSpanText: ionSpan?.textContent ?? null,
      colors: {
        bodyBg: bodyStyle.backgroundColor,
        bodyColor: bodyStyle.color,
        bodyFont: bodyStyle.fontFamily,
        mainBg: mainStyle?.backgroundColor,
        h1Color: h1Style?.color,
        h1Font: h1Style?.fontFamily,
        ionColor: ionStyle?.color,
      },
      stylesheets: Array.from(document.styleSheets).map((s) => ({
        href: s.href,
        ruleCountSafe: (() => {
          try { return s.cssRules.length; } catch { return 'inaccessible'; }
        })(),
      })),
      stuckOnInitializing: document.body.innerText.includes('INITIALIZING'),
    };
  });

  await browser.close();
  return { profile: profileName, snapshot, consoleMessages, pageErrors, requestFailed, badResponses: responses.filter((r) => r.status >= 400) };
}

const out = [];
for (const p of PROFILES) {
  out.push(await runProfile(p));
}
console.log(JSON.stringify(out, null, 2));
