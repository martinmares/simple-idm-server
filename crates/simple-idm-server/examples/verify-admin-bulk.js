// Run with playwright-cli run-code against admin_ui_browser_fixture.
async (page) => {
  const origin = new URL(page.url()).origin;
  const check = (ok, message) => { if (!ok) throw new Error(message); };
  async function closeModal() {
    await page.locator('.modal.show').evaluate(el => Promise.all(el.getAnimations({subtree:true}).map(a => a.finished)));
    await page.locator('.modal.show .btn-close').click();
    await page.locator('.modal.show').waitFor({state:'detached'});
  }
  await page.goto(origin + '/admin/ui/users');
  check(await page.getByRole('button', {name:'Archive selected', exact:true}).isDisabled(), 'Empty selection must disable actions');
  await page.getByRole('checkbox', {name:'Select mares', exact:true}).check();
  check(await page.getByRole('checkbox', {name:'Select visible users', exact:true}).evaluate(el => el.indeterminate), 'Partial selection header');
  await page.getByRole('button', {name:'Archive selected', exact:true}).click();
  await page.locator('#bulk-action-modal.show').waitFor();
  check((await page.locator('[data-bulk-names]').textContent()).trim() === 'mares', 'Confirmation must name only selected users');
  check(await page.locator('#bulk-group').isDisabled(), 'Archive must not submit the group field');
  await closeModal();
  await page.getByRole('checkbox', {name:'Select visible users', exact:true}).check();
  await page.getByRole('button', {name:'+ Add selected to group', exact:true}).click();
  await page.locator('#bulk-action-modal.show').waitFor();
  await page.getByLabel('Group', {exact:true}).selectOption({label:'admin:all (virtual bundle)'});
  let data;
  await page.route('**/admin/ui/users/bulk', async route => {
    data = new URLSearchParams(route.request().postData());
    await route.fulfill({status:200,contentType:'text/html',body:'Fixture: form received'});
  });
  await page.getByRole('button', {name:'Assign group', exact:true}).click();
  await page.waitForURL('**/admin/ui/users/bulk');
  check(data.get('action') === 'add_group' && data.get('ids').split(',').length === 2 && data.get('group_id'), 'Group form must send exact selection and action');
  await page.unroute('**/admin/ui/users/bulk');
  await page.goto(origin + '/admin/ui/groups');
  await page.getByRole('checkbox', {name:'Select visible groups', exact:true}).check();
  check((await page.locator('[data-bulk-count]').textContent()) === '2 selected', 'Archived groups must not be selected');
  await page.getByLabel('Search', {exact:true}).fill('gitlab');
  await page.getByRole('button', {name:'Apply', exact:true}).click();
  await page.waitForURL('**/admin/ui/groups?**');
  check((await page.locator('[data-bulk-count]').textContent()) === '0 selected', 'Applying server filters must reset selection');
  await page.getByRole('checkbox', {name:'Select gitlab-admins', exact:true}).check();
  check(!(await page.getByRole('checkbox', {name:'Select admin:all', exact:true, includeHidden:true}).isChecked()), 'Filtering must clear hidden group selection');
  await page.getByRole('button', {name:'Archive selected', exact:true}).click();
  await page.locator('#bulk-action-modal.show').waitFor();
  check((await page.locator('[data-bulk-names]').textContent()).trim() === 'gitlab-admins', 'Filtered confirmation must include only visible selection');
  await page.locator('.modal.show').evaluate(el => Promise.all(el.getAnimations({subtree:true}).map(a => a.finished)));
  await page.screenshot({path:'output/playwright/admin-bulk-confirmation.png',fullPage:true});
  await closeModal();
  console.log('Bulk selection, confirmation, form submission and filter reset passed.');
}
