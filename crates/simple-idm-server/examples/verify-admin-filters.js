// playwright-cli run-code; browser fixture only. SQL pagination is tested separately.
async (page) => {
  const origin = new URL(page.url()).origin;
  const check = (ok, message) => { if (!ok) throw new Error(message); };
  async function closeModal() {
    await page.locator('.modal.show').evaluate(el => Promise.all(el.getAnimations({subtree:true}).map(a => a.finished)));
    await page.locator('.modal.show .btn-close').click();
    await page.locator('.modal.show').waitFor({state:'detached'});
  }
  await page.goto(origin + '/admin/ui/groups?q=admin&type=virtual');
  await page.locator('tr[data-admin-search-row]:not([hidden])').getByRole('button', {name:'Details',exact:true}).click();
  await page.locator('.admin-detail-row:not([hidden])').getByRole('link', {name:'gitlab-admins',exact:true}).click();
  await page.locator('#group-edit-00000000-0000-0000-0000-000000000003.show').waitFor();
  check((await page.locator('.modal.show input[name=name]').inputValue()) === 'gitlab-admins', 'Filtered graph node must have an editor');
  await closeModal();
  await page.goto(origin + '/admin/ui/groups?q=gitlab#group-00000000-0000-0000-0000-000000000002');
  await page.locator('#group-edit-00000000-0000-0000-0000-000000000002.show').waitFor();
  await closeModal();
  await page.getByLabel('State', {exact:true}).selectOption('archived');
  await page.getByLabel('Search', {exact:true}).fill('old-admins');
  await page.getByRole('button', {name:'Apply',exact:true}).click();
  await page.getByRole('heading', {name:'Archived groups',exact:true}).waitFor();
  check(await page.getByRole('button', {name:'Restore',exact:true}).isVisible(), 'Archive filter exposes restore action');
  check(await page.getByRole('button', {name:'Archive selected',exact:true}).isHidden(), 'Archive list cannot be archived again');
  await page.screenshot({path:'output/playwright/admin-groups-archive.png'});

  await page.goto(origin + '/admin/ui/clients');
  await page.getByLabel('Type', {exact:true}).selectOption('public');
  await page.getByRole('button', {name:'Apply',exact:true}).click();
  check((await page.locator('.page-body').textContent()).includes('0 results'), 'Client count follows filter');
  await page.reload();
  check((await page.getByLabel('Type', {exact:true}).inputValue()) === 'public', 'Client type survives reload');
  await page.getByRole('link', {name:'Reset',exact:true}).click();
  check(await page.getByRole('button', {name:'Edit',exact:true}).isVisible(), 'Reset restores client list');

  await page.goto(origin + '/admin/ui/memberships#by-group');
  check(new URL(page.url()).searchParams.get('view') === 'by-group', 'Hash links must persist active view for form returns');
  await page.goto(origin + '/admin/ui/memberships?user_id=00000000-0000-0000-0000-000000000010');
  await page.getByLabel('Status', {exact:true}).selectOption('inactive');
  check((await page.locator('#membership-users-list [data-filter-text]:not([hidden])').count()) === 0, 'Membership status filter');
  check(await page.locator('#by-user .membership-detail-head h3').isVisible(), 'Filtered selection keeps detail');
  await page.reload();
  check((await page.getByLabel('Status', {exact:true}).inputValue()) === 'inactive', 'Picker filter survives reload');
  await page.getByRole('button', {name:'Reset',exact:true}).click();
  check((await page.locator('#membership-users-list [data-filter-text]:not([hidden])').count()) === 13, 'Membership reset');
  await page.getByRole('tab', {name:'Groups',exact:true}).click();
  await page.getByLabel('Type', {exact:true}).selectOption('regular');
  check(new URL(page.url()).searchParams.get('group_type') === 'regular', 'Group picker URL state');
  await page.screenshot({path:'output/playwright/admin-membership-filters.png'});

  await page.goto(origin + '/admin/ui/claims?client_id=00000000-0000-0000-0000-000000000005');
  await page.locator('#by-client').getByLabel('Claim rules', {exact:true}).selectOption('with');
  check((await page.locator('#by-client .claim-side-item:not([hidden])').count()) === 0, 'Clients without rules are excluded');
  check(await page.getByText('No claim rules for this client', {exact:true}).isVisible(), 'Selected client detail is preserved');
  await page.getByRole('tab', {name:'Group usage',exact:true}).click();
  await page.locator('#by-group').getByLabel('Claim rules', {exact:true}).selectOption('without');
  await page.reload();
  check((await page.locator('#by-group').getByLabel('Claim rules', {exact:true}).inputValue()) === 'without', 'Independent group filter survives reload');
  check(new URL(page.url()).searchParams.get('by-client-rules') === 'with', 'Client filter retained across views');
  await page.evaluate(() => document.documentElement.setAttribute('data-bs-theme','dark'));
  await page.screenshot({path:'output/playwright/admin-claim-filters-dark.png'});
}
