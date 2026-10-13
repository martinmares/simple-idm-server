// Run with Playwright CLI's `run-code --filename` against web_browser_fixture.
// Fixture directory: hello.txt (text), binary.dat, folder/inside.txt, downloads/.
async (page) => {
  function check(condition, message) {
    if (!condition) throw new Error(message);
  }
  const button = (name) => page.getByRole("button", { name, exact: true });
  const cell = (name) => page.getByRole("cell", { name, exact: true });
  const closePreview = () => button("Close").click();
  await button("Files").click();
  await cell("hello.txt").waitFor();
  const root = await page
    .getByRole("textbox", { name: "Remote path", exact: true })
    .inputValue();
  await page
    .getByRole("textbox", { name: "Local path", exact: true })
    .fill(root + "/downloads");
  await page
    .getByRole("textbox", { name: "Local path", exact: true })
    .press("Enter");
  await page.waitForFunction(
    () =>
      document
        .querySelector("#local-panel .path")
        .value.endsWith("/downloads") &&
      document.querySelector("#local-panel .count").textContent ===
        "0 / 0 entries",
  );
  await cell("folder/").dblclick();
  await cell("inside.txt").waitFor();
  await page
    .locator("#remote-panel")
    .getByRole("cell", { name: "../", exact: true })
    .dblclick();
  await cell("folder/").waitFor();
  check(
    (await page
      .getByRole("row")
      .filter({ has: cell("folder/") })
      .getAttribute("aria-selected")) === "true",
    "Parent must select the exited directory",
  );
  await page
    .getByRole("searchbox", { name: "Remote filter", exact: true })
    .fill("HELLO");
  check(
    (await cell("binary.dat").count()) === 0,
    "Filter must be case-insensitive",
  );
  await cell("hello.txt").dblclick();
  await page.locator("#viewer[open]").waitFor();
  check(
    (await page.locator("#preview").textContent()).includes(
      "Hello from Bastion",
    ),
    "Text preview",
  );
  await page.getByRole("checkbox", { name: "Wrap w", exact: true }).uncheck();
  check(
    !(await page.locator("#preview").getAttribute("class")).includes("wrap"),
    "Unwrap",
  );
  await page.getByRole("checkbox", { name: "Wrap w", exact: true }).check();
  await closePreview();
  await button("SHA-256 h").click();
  await page.locator("#viewer[open]").waitFor();
  check(
    /[a-f0-9]{64}/.test(await page.locator("#preview").textContent()),
    "SHA-256 preview",
  );
  await closePreview();
  await button("Copy c").click();
  await page.getByRole("textbox", {name:"Name",exact:true}).press("Enter");
  await page
    .locator("#local-panel")
    .getByRole("cell", { name: "hello.txt", exact: true })
    .waitFor();
  await button("Copy c").click();
  await button("OK").click();
  await page
    .getByRole("heading", { name: "Replace existing file?", exact: true })
    .waitFor();
  await button("OK").click();
  await page.waitForFunction(() => document.querySelector("#cancel").hidden && !document.querySelector("#refresh").disabled);
  await page
    .getByRole("searchbox", { name: "Remote filter", exact: true })
    .fill("");
  await cell("binary.dat").dblclick();
  await page.locator("#viewer[open]").waitFor();
  check(
    (await page.locator("#viewer-title").textContent()).includes("Hex"),
    "Binary preview must be hexadecimal",
  );
  await closePreview();
  await button("Root read-only (e)").click();
  await button("Return to account (e)").waitFor();
  await page
    .locator("#remote-panel")
    .getByRole("cell", { name: "hello.txt", exact: true })
    .click();
  await button("Delete d").click();
  await page
    .getByRole("status")
    .filter({ hasText: "root panel is read-only" })
    .waitFor();
  check(
    (await page.locator("#prompt[open]").count()) === 0,
    "Root mutations must be refused before confirmation",
  );
  await button("Return to account (e)").click();
  await button("Root read-only (e)").waitFor();
  await page
    .locator("#local-panel")
    .getByRole("cell", { name: "hello.txt", exact: true })
    .click();
  await button("Rename r").click();
  await page
    .getByRole("textbox", { name: "Name", exact: true })
    .fill("copied.txt");
  await button("OK").click();
  await cell("copied.txt").waitFor();
  await cell("copied.txt").click();
  await button("Delete d").click();
  await page.keyboard.press("Escape");
  await page.locator("#prompt[open]").waitFor({state:"detached"});
  await button("Refresh u").click();
  await cell("copied.txt").waitFor();
  await button("New folder n").click();
  await page
    .getByRole("textbox", { name: "Name", exact: true })
    .fill("new-folder");
  await button("OK").click();
  await cell("new-folder/").waitFor();
  await cell("new-folder/").click();
  await button("Delete d").click();
  await button("OK").click();
  await cell("new-folder/").waitFor({ state: "detached" });
  await page.screenshot({ path: "output/playwright/bastion-web-files.png" });
  await button("Terminal").click();
  await page.waitForFunction(() =>
    document.querySelector("#terminal-state").textContent.includes("fixture"),
  );
  await page
    .locator(".xterm-helper-textarea")
    .pressSequentially("terminal-test");
  await page.locator(".xterm-helper-textarea").press("Enter");
  await page.waitForFunction(() =>
    Array.from({ length: state.term.buffer.active.length }, (_, i) =>
      state.term.buffer.active.getLine(i)?.translateToString(),
    )
      .join("\n")
      .includes("terminal-test"),
  );
  await page.evaluate(async () => {
    if (!document.fonts.check('14px "Bastion Nerd Font"', "M\uf31b\uf015\uf017")) throw new Error("Bundled Nerd Font was not loaded");
    if (!state.term.options.fontFamily.includes("Bastion Nerd Font")) throw new Error("Terminal is not using the bundled font");
    await new Promise(resolve => state.term.write("\r\nIcons: \uf31b \uf015 \uf017 \ue0b0\r\n",resolve));
    const resources=performance.getEntriesByType("resource").filter(e=>e.name.endsWith("/terminal-font.ttf"));
    if(resources.length!==1) throw new Error("Font must load once from local server");
  });
  await page.waitForFunction(() => document.querySelector(".xterm-rows")?.textContent.includes("Icons:"));
  await page.screenshot({path:"output/playwright/bastion-web-icons.png"});
  const cols = await page.evaluate(() => state.term.cols);
  await page.setViewportSize({ width: 1000, height: 800 });
  await page.waitForFunction((old) => state.term.cols !== old, cols);
  await page.evaluate(async () => {
    const text = Array.from({length:200},(_,i)=>`scroll-line-${i}\r\n`).join("")+"SCROLL-END-MARKER";
    await new Promise(resolve => state.term.write(text,resolve));
    state.term.scrollToBottom();
    await new Promise(requestAnimationFrame);
    const viewport=document.querySelector(".xterm-viewport");
    const screen=document.querySelector(".xterm-screen").getBoundingClientRect();
    const mount=document.querySelector("#terminal-mount").getBoundingClientRect();
    if(screen.bottom>mount.bottom+1) throw new Error("Terminal bottom is clipped");
    if(viewport.scrollHeight-viewport.clientHeight-viewport.scrollTop>2) throw new Error("Cannot reach scrollback bottom");
    const buffer=state.term.buffer.active;
    const visible=Array.from({length:state.term.rows},(_,i)=>buffer.getLine(buffer.viewportY+i)?.translateToString()).join("\n");
    if(!visible.includes("SCROLL-END-MARKER")) throw new Error("Last terminal line is not visible");
  });
  const protection = await page.evaluate(() => ({
    fragment: location.hash,
    cookies: document.cookie,
    storage: localStorage.length,
  }));
  check(
    protection.fragment === "" &&
      protection.cookies === "" &&
      protection.storage === 0,
    "Secrets must not remain in the URL, JS cookies or localStorage",
  );
  await page.screenshot({ path: "output/playwright/bastion-web-terminal.png" });
  await button("Stop client").click();
  await button("OK").click();
  await page
    .getByRole("status")
    .filter({ hasText: "Client stopped" })
    .waitFor();
}
