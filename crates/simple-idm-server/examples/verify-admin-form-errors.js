// Browser fixture only; intercept POST responses to exercise real modal behavior.
async (page) => {
  const origin = new URL(page.url()).origin;
  const check = (ok, message) => { if (!ok) throw new Error(message); };
  async function closeModal() {
    await page.locator('.modal.show').evaluate(el => Promise.all(el.getAnimations({subtree:true}).map(a => a.finished)));
    await page.locator('.modal.show .btn-close').click();
    await page.locator('.modal.show').waitFor({state:'detached'});
  }
  await page.goto(origin + '/admin/ui/memberships');
  for (const [view, tab, listId] of [['by-user','Users','membership-users-list'], ['by-group','Groups','membership-groups-list']]) {
    await page.getByRole('tab', {name:tab,exact:true}).click();
    const list = page.locator('#' + listId);
    check(await list.evaluate(el => {
      const last = el.lastElementChild;
      return el.getBoundingClientRect().height > 300 && el.scrollHeight <= el.clientHeight + 1 && last.getBoundingClientRect().bottom <= el.getBoundingClientRect().bottom + 1;
    }), view + ' list must grow to show every item');
    const last = list.locator('a').last();
    await last.scrollIntoViewIfNeeded();
    check(await last.isVisible(), 'Last item remains accessible via page scrolling');
  }
  await page.evaluate(() => { window.scrollTo(0, 0); document.body.scrollTop = 0; });
  await page.screenshot({path:'output/playwright/admin-membership-full-list.png',fullPage:true});
  await page.context().grantPermissions(['clipboard-read','clipboard-write']);
  await page.getByRole('button', {name:'Copy group UUID',exact:true}).click();
  check(await page.evaluate(() => navigator.clipboard.readText()) === '00000000-0000-0000-0000-000000000002', 'Copy selected group UUID');

  await page.goto(origin + '/admin/ui/groups');
  let attempts = 0;
  await page.route('**/admin/ui/groups/create', async route => {
    const data = new URLSearchParams(route.request().postData());
    check(data.get('description') === 'A & B', 'Form values must be encoded correctly');
    attempts++;
    await route.fulfill({status:303,headers:{location: attempts === 1 ? '/admin/ui/groups?error=Group%20name%20already%20exists' : '/admin/ui/groups?message=Group%20created'}});
  });
  await page.getByRole('button', {name:/Create group$/}).click();
  const create = page.locator('#create-group-modal');
  await create.locator('[name=name]').fill('duplicate');
  await create.locator('[name=description]').fill('A & B');
  await create.getByRole('button', {name:'Create group',exact:true}).click();
  await create.locator('[data-admin-form-error]').waitFor();
  check(await create.isVisible(), 'Create modal remains open after server validation');
  check(await create.locator('[name=name]').inputValue() === 'duplicate', 'Entered name is preserved');
  check(await create.locator('[name=description]').inputValue() === 'A & B', 'Other entries are preserved');
  check(await create.locator('[name=name]').getAttribute('aria-invalid') === 'true', 'Matching field receives accessible validation feedback');
  check(new URL(page.url()).search === '', 'Validation does not navigate away from the editor');
  await page.screenshot({path:'output/playwright/admin-modal-validation.png'});
  await create.locator('[name=name]').fill('corrected');
  await create.getByRole('button', {name:'Create group',exact:true}).click();
  await page.waitForURL('**/admin/ui/groups?message=Group%20created');
  check(attempts === 2, 'Retry submits exactly once');
  await page.unroute('**/admin/ui/groups/create');

  await page.goto(origin + '/admin/ui/clients');
  await page.route('**/admin/ui/clients/*/update', route => route.fulfill({status:503,body:'Fixture failure'}));
  await page.getByRole('button', {name:'Edit',exact:true}).click();
  const edit = page.locator('.modal.show');
  await edit.locator('[name=name]').fill('Edited client name');
  await edit.getByRole('button', {name:/Save/}).click();
  await edit.locator('[data-admin-form-error]').waitFor();
  check(await edit.locator('[name=name]').inputValue() === 'Edited client name', 'HTTP failure preserves edit fields');
  check(!(await edit.getByRole('button', {name:/Save/}).isDisabled()), 'Failed save can be retried');
  await closeModal();
  await page.unroute('**/admin/ui/clients/*/update');

  await page.goto(origin + '/admin/ui/claims');
  let claims = 0;
  await page.route('**/admin/ui/client-claims/create', async route => {
    claims++;
    const data = new URLSearchParams(route.request().postData());
    check(data.get('claim_value') === 'team-a,team-b', 'Claim array must be synchronized before AJAX serialization');
    await route.fulfill({status:303,headers:{location:'/admin/ui/claims?error=Claim%20name%20already%20exists'}});
  });
  await page.getByRole('button', {name:/Add claim rule$/}).click();
  const claim = page.locator('#create-client-claim');
  await claim.locator('[name=claim_name]').fill('teams');
  await claim.locator('[name=claim_value_kind]').selectOption('array');
  await claim.locator('.claim-array-input').fill('team-a');
  await claim.getByRole('button', {name:/Add value$/}).click();
  await claim.locator('.claim-array-input').nth(1).fill('team-b');
  await claim.getByRole('button', {name:'Add claim rule',exact:true}).click();
  await claim.locator('[data-admin-form-error]').waitFor();
  check(await claim.locator('.claim-array-input').nth(1).inputValue() === 'team-b', 'Claim editor retains array values on validation failure');
  await claim.locator('[name=claim_value_kind]').selectOption('single');
  await claim.locator('.claim-single-input').fill('   ');
  await claim.getByRole('button', {name:'Add claim rule',exact:true}).click();
  check(claims === 1, 'Blank single claim must not submit');
  check(await claim.locator('.claim-single-input').evaluate(el => !el.validity.valid), 'Blank claim has contextual validation');
  await closeModal();
  await page.unroute('**/admin/ui/client-claims/create');

  // Type changes still require confirmation before the AJAX save.
  await page.goto(origin + '/admin/ui/groups');
  let updates = 0;
  await page.route('**/admin/ui/groups/*/update', async route => {
    updates++;
    await route.fulfill({status:303,headers:{location:'/admin/ui/groups?error=Group%20type%20change%20failed'}});
  });
  await page.locator('#group-00000000-0000-0000-0000-000000000003').getByRole('button', {name:'Edit',exact:true}).click();
  const groupEdit = page.locator('#group-edit-00000000-0000-0000-0000-000000000003');
  await groupEdit.locator('[name=is_virtual]').selectOption('on');
  await groupEdit.evaluate(el => Promise.all(el.getAnimations({subtree:true}).map(a => a.finished)));
  await groupEdit.locator('[name=is_virtual]').focus();
  await groupEdit.locator('form').evaluate(form => form.requestSubmit());
  await page.locator('#confirm-action-modal.show').waitFor();
  check(updates === 0, 'Save must wait for type confirmation');
  await page.locator('#confirm-action-modal').evaluate(el => Promise.all(el.getAnimations({subtree:true}).map(a => a.finished)));
  await page.getByRole('button', {name:'Change type',exact:true}).click();
  await groupEdit.locator('[data-admin-form-error]').waitFor();
  await page.locator('#group-edit-00000000-0000-0000-0000-000000000003.show').waitFor();
  check(updates === 1, 'Confirmed type change submits once');
  check(await groupEdit.locator('[name=is_virtual]').inputValue() === 'on', 'Confirmed editor keeps entered values on failure');
  await closeModal();
  await page.unroute('**/admin/ui/groups/*/update');
}
