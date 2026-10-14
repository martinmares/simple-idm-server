// playwright-cli run-code against the isolated template fixture.
async (page) => {
  const check = (ok, message) => { if (!ok) throw new Error(message); };
  check(await page.getByRole('heading', {name:'Audit', exact:true}).isVisible(), 'Audit header');
  check(await page.locator('[data-audit-total]').getAttribute('data-audit-total') === '203', 'Summary is independent of displayed rows');
  check(await page.locator('tr[data-audit-id]').count() === 3, 'Fixture table');
  check(await page.getByRole('table').getByText('Unknown actor', {exact:true}).isVisible(), 'Historical missing actor');
  check(await page.getByRole('table').getByText('Root token', {exact:true}).isVisible(), 'Root credential is not a human');
  const exported = new URL(await page.getByRole('link', {name:'Export JSON',exact:true}).getAttribute('href'),page.url());
  check(exported.searchParams.has('from') && exported.searchParams.has('to'), 'Exports freeze applied range');
  const older = new URL(await page.getByRole('link',{name:'Older',exact:true}).getAttribute('href'),page.url());
  check(older.searchParams.has('before') && older.searchParams.get('snapshot') === exported.searchParams.get('snapshot'), 'Cursor and export share snapshot');
  await page.getByLabel('Time range',{exact:true}).selectOption('custom');
  check(await page.getByLabel('From (UTC, inclusive)',{exact:true}).isVisible(), 'Custom dates available');
  check(await page.getByLabel('From (UTC, inclusive)',{exact:true}).isEnabled(), 'Custom dates submitted');
  await page.getByLabel('Time range',{exact:true}).selectOption('7d');
  check(await page.getByLabel('From (UTC, inclusive)',{exact:true}).isDisabled(), 'Rolling preset omits custom dates');
  await page.getByText('More filters',{exact:true}).click();
  await page.getByLabel('Actor subject',{exact:true}).fill('verified-subject');
  await page.getByLabel('Actor client',{exact:true}).fill('cli-tools');
  await page.getByLabel('Target ID',{exact:true}).fill('00000000-0000-0000-0000-00000000000a');
  await page.getByRole('button',{name:'Details',exact:true}).first().click();
  const modal = page.locator('#audit-details-00000000-0000-0000-0000-000000000065');
  await modal.waitFor();
  await modal.getByText('Technical event data',{exact:true}).click();
  check((await modal.locator('pre').textContent()).includes('[redacted]'), 'Credential keys redacted');
  check(!(await modal.locator('pre').textContent()).includes('must-not-appear'), 'Secret absent from HTML');
  await modal.evaluate(el => Promise.all(el.getAnimations({subtree:true}).map(a => a.finished)));
  await modal.getByRole('button',{name:'Close',exact:true}).last().click();
  await modal.waitFor({state:'hidden'});
  await page.locator('.modal-backdrop').waitFor({state:'detached'});
  await page.evaluate(() => document.documentElement.setAttribute('data-bs-theme','dark'));
  await page.screenshot({path:'output/playwright/admin-audit-dark.png',fullPage:true});
  await page.setViewportSize({width:390,height:844});
  await page.screenshot({path:'output/playwright/admin-audit-mobile.png',fullPage:true});
  await page.setViewportSize({width:1440,height:1000});
}
