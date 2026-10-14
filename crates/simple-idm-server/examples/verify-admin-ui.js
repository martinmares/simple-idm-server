// Playwright CLI run-code --filename; run against admin_ui_browser_fixture only.
async (page) => {
  const origin = new URL(page.url()).origin;
  function check(value, message) {
    if (!value) throw new Error(message);
  }
  async function closeModal() {
    await page
      .locator(".modal.show")
      .evaluate((el) =>
        Promise.all(el.getAnimations({ subtree: true }).map((a) => a.finished)),
      );
    await page.locator(".modal.show .btn-close").click();
    await page.locator(".modal.show").waitFor({ state: "detached" });
  }
  await page.getByRole("button", { name: /Create user$/ }).click();
  await page.locator("#create-user-modal.show").waitFor();
  await closeModal();
  await page.getByRole("button", { name: "mares", exact: true }).click();
  await page.locator('[id^="user-details-"].show').waitFor();
  check(
    (await page.locator(".modal.show").textContent()).includes(
      "10 recovery codes",
    ),
    "User technical/security metadata must remain available",
  );
  await closeModal();
  await page.getByRole("button", { name: "More", exact: true }).last().click();
  await page.getByRole("button", { name: "Reset MFA", exact: true }).waitFor();
  check(
    await page
      .locator(".dropdown-menu.show")
      .getByRole("button", { name: "Archive", exact: true })
      .evaluate((el) => {
        const box = el.getBoundingClientRect();
        return el.contains(
          document.elementFromPoint(
            box.left + box.width / 2,
            box.top + box.height / 2,
          ),
        );
      }),
    "More menu must not be clipped by the table",
  );
  await page.getByRole("heading", { name: "Users", exact: true }).click();
  const heights = await page
    .locator(".admin-table tbody tr")
    .evaluateAll((rows) =>
      rows.map((row) => row.getBoundingClientRect().height),
    );
  check(
    heights.every((height) => height <= 70),
    "Users must have compact rows",
  );
  check(
    (await page.locator(".letter-filter").count()) === 0,
    "Alphabet must not occupy the primary filter",
  );
  await page
    .getByRole("textbox", { name: "Search", exact: true })
    .fill("alice");
  check(
    !page.url().includes("q="),
    "Typing alone must not apply the primary filter",
  );
  await page.screenshot({ path: "output/playwright/admin-users-phase1.png" });
  await page.goto(origin + "/admin/ui/groups");
  await page.getByRole("button", { name: /Create group$/ }).click();
  await page.locator("#create-group-modal.show").waitFor();
  await closeModal();
  const all = page
    .locator("tr[data-admin-search-row]")
    .filter({ hasText: "admin:all" });
  await all.getByRole("button", { name: "Details", exact: true }).click();
  await page
    .locator(".admin-detail-row:not([hidden]) .group-tree")
    .getByRole("link", { name: "gitlab-admins", exact: true })
    .waitFor();
  check(
    (
      await page.locator(".admin-detail-row:not([hidden])").textContent()
    ).includes("old-admins"),
    "Archived references must remain visible in details",
  );
  await page
    .getByRole("textbox", { name: "Search", exact: true })
    .fill("gitlab");
  await page.getByRole("button", { name: "Apply", exact: true }).click();
  check(
    (await page.locator("tr[data-admin-search-row]:not([hidden])").count()) ===
      1,
    "Group filter must apply",
  );
  check(
    new URL(page.url()).searchParams.get("q") === "gitlab",
    "Group filter must be bookmarkable",
  );
  await page.reload();
  check(
    (await page.locator("tr[data-admin-search-row]:not([hidden])").count()) ===
      1,
    "Group filter survives reload",
  );
  await page
    .locator("tr[data-admin-search-row]:not([hidden])")
    .getByRole("button", { name: "Details", exact: true })
    .click();
  check(
    (
      await page.locator(".admin-detail-row:not([hidden])").textContent()
    ).includes("role=admin"),
    "Claim mappings must remain visible",
  );
  await page.screenshot({ path: "output/playwright/admin-groups-phase1.png" });
  await page.goto(origin + "/admin/ui/clients");
  check(
    (await page.locator(".admin-table tbody tr").count()) === 1,
    "Clients use compact table",
  );
  await page.getByRole("button", { name: /Create client$/ }).click();
  await page.locator("#create-client-modal.show").waitFor();
  check(
    (await page
      .locator("#create-client-modal input[name=client_id]")
      .count()) === 1,
    "Create form must remain usable",
  );
  await closeModal();
  await page.getByRole("button", { name: "Edit", exact: true }).click();
  await page.locator('[id^="client-edit-"].show').waitFor();
  check(
    (
      await page.locator(".modal.show input[name=redirect_uris]").inputValue()
    ).includes("gitlab.example.test"),
    "Redirect metadata must remain in editor",
  );
  await closeModal();
  await page.screenshot({ path: "output/playwright/admin-clients-phase1.png" });
  await page.goto(origin + "/admin/ui/memberships");
  check(
    await page.locator("#by-group").isHidden(),
    "Memberships show one view",
  );
  await page.getByRole("tab", { name: "Groups", exact: true }).click();
  check(
    await page.locator("#by-user").isHidden(),
    "Users view hides when Groups selected",
  );
  check(
    new URL(page.url()).searchParams.get("view") === "by-group",
    "Membership tab must be bookmarkable",
  );
  await page.reload();
  check(
    await page.locator("#by-user").isHidden(),
    "Membership view must survive reload",
  );
  await page.getByRole("button", { name: /Add users$/ }).click();
  await page.locator("#add-users-modal.show").waitFor();
  await closeModal();
  await page.screenshot({
    path: "output/playwright/admin-memberships-phase1.png",
  });
  await page.goto(origin + "/admin/ui/claims");
  check(await page.locator("#by-group").isHidden(), "Claims show one view");
  await page.getByRole("tab", { name: "Group usage", exact: true }).click();
  check(await page.locator("#by-client").isHidden(), "Client view hides");
  await page.reload();
  check(
    await page.locator("#by-client").isHidden(),
    "Claim view survives reload",
  );
  await page
    .getByRole("button", { name: /Add client claim rule for group$/ })
    .click();
  await page.locator("#create-group-claim.show").waitFor();
  await closeModal();
  await page.screenshot({ path: "output/playwright/admin-claims-phase1.png" });
  await page.goto(origin + "/admin/ui/identity-providers");
  const alignment = await page.evaluate(() => {
    const input = document.querySelector(".admin-filter input"),
      button = document.querySelector(".admin-filter button");
    return Math.abs(
      input.getBoundingClientRect().bottom -
        button.getBoundingClientRect().bottom,
    );
  });
  check(alignment < 2, "Filter fields and buttons share baseline");
}
