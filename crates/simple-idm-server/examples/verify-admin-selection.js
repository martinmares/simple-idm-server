// Browser fixture; SQL tests cover the real filtered read and its batch limit.
async (page) => {
  const origin = new URL(page.url()).origin;
  const check = (ok, message) => { if (!ok) throw new Error(message); };
  async function closeModal() {
    await page.locator('.modal.show').evaluate(el => Promise.all(el.getAnimations({subtree:true}).map(a => a.finished)));
    await page.locator('.modal.show .btn-close').click();
    await page.locator('.modal.show').waitFor({state:'detached'});
  }
  await page.goto(origin + '/admin/ui/users');
  let failSelection = false;
  await page.route('**/admin/ui/users?**', async route => {
    if (new URL(route.request().url()).searchParams.get('bulk_selection') !== 'true') { await route.continue(); return; }
    if (failSelection) { await route.fulfill({status:400,body:'Batch limit'}); return; }
    const response = await route.fetch();
    // Add a third, off-page object to the selection response only.
    const html = (await response.text()).replace('data-bulk-total="2"', 'data-bulk-total="3"')
      .replace('</tbody>', '<tr><td><input data-bulk-id="00000000-0000-0000-0000-000000000012" data-bulk-name="off-page-user"></td></tr></tbody>');
    await route.fulfill({response,body:html});
  });
  await page.locator('[data-bulk-filtered]').click();
  await page.waitForFunction(() => document.querySelector('[data-bulk-count]').textContent.startsWith('3 selected across'));
  await page.getByRole('checkbox', {name:'Select mares',exact:true}).uncheck();
  check((await page.locator('[data-bulk-count]').textContent()).startsWith('2 selected across'), 'Unchecking one row must keep off-page selection');
  await page.getByRole('button', {name:'Archive selected',exact:true}).click();
  const form = page.locator('[data-bulk-form]');
  check((await form.locator('[data-bulk-names]').textContent()).includes('off-page-user'), 'Confirmation names off-page objects');
  const ids = (await form.locator('[name=ids]').inputValue()).split(',');
  check(ids.includes('00000000-0000-0000-0000-000000000012') && !ids.includes('00000000-0000-0000-0000-00000000000a'), 'Exact selection is submitted, not a broad server-side flag');
  await closeModal();
  await page.getByRole('button', {name:'Clear selection',exact:true}).click();
  check((await page.locator('[data-bulk-count]').textContent()) === '0 selected', 'Clear selection removes all pages');
  await page.getByRole('checkbox', {name:'Select mares',exact:true}).check();
  failSelection = true;
  await page.locator('[data-bulk-filtered]').click();
  await page.locator('[data-bulk-selection-error]').waitFor();
  check((await page.locator('[data-bulk-count]').textContent()) === '1 selected', 'Failed selection preserves previous choices');
  await page.evaluate(() => {
    document.querySelector('[data-bulk-toolbar]').dataset.bulkTotal = '101';
    document.querySelector('[data-bulk-id]').dispatchEvent(new Event('change'));
  });
  check(await page.locator('[data-bulk-filtered]').isDisabled(), 'Oversized filtered result sets cannot be selected as one batch');
  await page.unroute('**/admin/ui/users?**');

  await page.goto(origin + '/admin/ui/groups?q=admin');
  await page.locator('[data-bulk-filtered]').click();
  await page.waitForFunction(() => document.querySelector('[data-bulk-count]').textContent.startsWith('2 selected across'));
  await page.getByRole('button', {name:'Archive selected',exact:true}).click();
  check((await page.locator('[data-bulk-names]').textContent()).includes('admin:all'), 'Group selection respects current search');
  await page.locator('.modal.show').evaluate(el => Promise.all(el.getAnimations({subtree:true}).map(a => a.finished)));
  await page.screenshot({path:'output/playwright/admin-filtered-selection.png'});
  await closeModal();
}
