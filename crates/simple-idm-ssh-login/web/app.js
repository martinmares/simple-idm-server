"use strict";
const $ = (selector) => document.querySelector(selector);
const terminalFont = document.fonts.load(
  '14px "Bastion Nerd Font"',
  "M\uf31b\uf015\uf017",
);
// Register a rejection handler immediately; openTerminal still reports load failures.
terminalFont.catch(() => {});
const state = {
  hosts: [],
  host: null,
  remote: null,
  active: "local",
  busy: false,
  connecting: false,
  ws: null,
  term: null,
  fit: null,
  ready: false,
  cwd: "/",
};
const panels = Object.fromEntries(
  ["local", "remote"].map((side) => [
    side,
    {
      side,
      el: $(`#${side}-panel`),
      path: "/",
      entries: [],
      selected: "..",
      history: new Map(),
      generation: 0,
    },
  ]),
);
function status(message, error = false) {
  $("#status").textContent = message;
  $("#status").classList.toggle("error", error);
}
async function api(path, body) {
  const response = await fetch(
    path,
    body === undefined
      ? {}
      : {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify(body),
        },
  );
  const value = await response.json();
  if (!response.ok) {
    const error = new Error(
      value.message || `Request failed (${response.status})`,
    );
    error.collision = value.collision;
    throw error;
  }
  return value;
}
function safely(fn) {
  return (...args) => {
    try {
      return Promise.resolve(fn(...args)).catch((error) =>
        status(error.message, true),
      );
    } catch (error) {
      status(error.message, true);
    }
  };
}
function choose({ title, message = "", value = null, destructive = false }) {
  const dialog = $("#prompt");
  $("#prompt-title").textContent = title;
  $("#prompt-message").textContent = message;
  const input = $("#prompt-input");
  input.hidden = value === null;
  input.value = value ?? "";
  $("#prompt-ok").classList.toggle("danger", destructive);
  return new Promise((resolve) => {
    dialog.addEventListener(
      "close",
      () =>
        resolve(
          dialog.returnValue === "ok"
            ? value === null
              ? true
              : input.value
            : null,
        ),
      { once: true },
    );
    dialog.returnValue = "cancel";
    dialog.showModal();
    if (value !== null) {
      input.focus();
      input.select();
    }
  });
}
function child(path, name) {
  return (path === "/" ? "" : path.replace(/\/$/, "")) + "/" + name;
}
function parent(path) {
  const parts = path.replace(/\/+$/, "").split("/");
  parts.pop();
  return parts.join("/") || "/";
}
function basename(path) {
  return path.replace(/\/+$/, "").split("/").pop();
}
function validName(name) {
  if (!name || name === "." || name === ".." || /[\/\0]/.test(name))
    throw new Error("Enter a single file or folder name, without /");
  return name;
}
function size(value) {
  if (value < 1024) return `${value} B`;
  const units = ["KiB", "MiB", "GiB", "TiB"];
  let i = -1;
  do {
    value /= 1024;
    i++;
  } while (value >= 1024 && i < units.length - 1);
  return `${value.toFixed(1)} ${units[i]}`;
}
function renderHosts() {
  const filter = $("#host-filter").value.toLocaleLowerCase();
  const list = $("#hosts");
  list.replaceChildren();
  const visible = state.hosts.filter((h) =>
    [h.name, h.id, h.address, ...h.resolved_ips, h.environment, ...h.logins]
      .join(" ")
      .toLocaleLowerCase()
      .includes(filter),
  );
  $("#host-count").textContent = `${visible.length} / ${state.hosts.length}`;
  for (const host of visible) {
    const button = document.createElement("button");
    button.className = "host";
    button.classList.toggle("selected", host === state.host);
    button.textContent = host.name || host.id;
    const small = document.createElement("small");
    small.textContent = [host.address, ...host.resolved_ips, host.environment]
      .filter(Boolean)
      .join(" · ");
    button.append(small);
    button.onclick = () => selectHost(host);
    list.append(button);
  }
  if (!visible.length) list.textContent = "No matching hosts";
}
function selectHost(host) {
  if (state.busy || state.connecting) {
    status("Wait for or cancel the active operation", true);
    return;
  }
  if (state.host !== host) {
    closeTerminal();
    $("#file-view").hidden = true;
    $("#terminal-view").hidden = true;
    $("#welcome").hidden = false;
  }
  if (state.host === host) return;
  state.host = host;
  renderHosts();
  $("#target").textContent = host.name || host.id;
  $("#address").textContent = [
    host.address,
    ...host.resolved_ips,
    host.environment,
  ]
    .filter(Boolean)
    .join(" · ");
  $("#account").replaceChildren(
    ...host.logins.map((login) => new Option(login, login)),
  );
  $("#files").disabled = host.logins.length === 0;
  $("#terminal").disabled = host.logins.length === 0;
}
function controls() {
  const blocked = state.busy || state.connecting;
  for (const selector of [
    "#account",
    "#files",
    "#terminal",
    "#root",
    "#refresh",
    "[data-action]",
  ])
    document
      .querySelectorAll(selector)
      .forEach(
        (el) =>
          (el.disabled = blocked || (!state.host && selector !== "#refresh")),
      );
}
function show(view) {
  $("#welcome").hidden = true;
  $("#file-view").hidden = view !== "files";
  $("#terminal-view").hidden = view !== "terminal";
  $("#files").classList.toggle("primary", view === "files");
  $("#terminal").classList.toggle("primary", view === "terminal");
  if (view === "terminal") resizeTerminal();
}
function activate(side, focus = false) {
  state.active = side;
  for (const p of Object.values(panels))
    p.el.classList.toggle("active", p.side === side);
  if (focus) panels[side].el.querySelector(".listing").focus();
}
function visibleEntries(p) {
  const filter = p.el.querySelector(".filter").value.toLocaleLowerCase();
  return [
    { name: "..", directory: true, parent: true, size: 0 },
    ...p.entries.filter((e) => e.name.toLocaleLowerCase().includes(filter)),
  ];
}
function renderPanel(p) {
  const rows = visibleEntries(p);
  if (!rows.some((e) => e.name === p.selected)) p.selected = rows[0]?.name;
  const body = p.el.querySelector("tbody");
  body.replaceChildren();
  for (const entry of rows) {
    const row = document.createElement("tr");
    row.classList.toggle("selected", entry.name === p.selected);
    row.classList.toggle("disabled", entry.disabled);
    row.setAttribute("aria-selected", entry.name === p.selected);
    const name = document.createElement("td");
    name.textContent =
      entry.name + (entry.directory ? "/" : entry.symlink ? " @" : "");
    name.classList.toggle("folder", entry.directory);
    const bytes = document.createElement("td");
    bytes.textContent = entry.directory ? "<DIR>" : size(entry.size);
    row.append(name, bytes);
    row.onclick = () => {
      activate(p.side);
      p.selected = entry.name;
      for (const item of body.rows) {
        const selected = item === row;
        item.classList.toggle("selected", selected);
        item.setAttribute("aria-selected", selected);
      }
    };
    row.ondblclick = safely(() => openEntry(p, entry));
    body.append(row);
  }
  p.el.querySelector(".count").textContent =
    `${Math.max(rows.length - 1, 0)} / ${p.entries.length} entries`;
}
function remember(p) {
  p.history.set(p.path, {
    filter: p.el.querySelector(".filter").value,
    selected: p.selected,
    scroll: p.el.querySelector(".listing").scrollTop,
  });
}
async function load(p, path = p.path, selection = null) {
  const generation = ++p.generation;
  const session = state.remote.session;
  const response = await api(
    "/api/list?" + new URLSearchParams({ session, side: p.side, path }),
  );
  if (generation !== p.generation || session !== state.remote.session) return;
  const changed = path !== p.path;
  if (changed) remember(p);
  p.path = path;
  p.entries = response.entries;
  p.el.querySelector(".path").value = path;
  const saved = p.history.get(path);
  if (changed) {
    p.el.querySelector(".filter").value = saved?.filter || "";
    p.selected = selection || saved?.selected || "..";
  }
  if (selection) {
    p.selected = selection;
    const filter = p.el.querySelector(".filter");
    if (
      !selection.toLocaleLowerCase().includes(filter.value.toLocaleLowerCase())
    )
      filter.value = "";
  }
  renderPanel(p);
  if (changed) p.el.querySelector(".listing").scrollTop = saved?.scroll || 0;
}
async function up(p) {
  if (p.path === "/") return;
  await load(p, parent(p.path), basename(p.path));
}
async function openEntry(p, entry) {
  activate(p.side);
  if (entry.disabled)
    throw new Error("This filename cannot be represented as UTF-8");
  if (entry.parent) return up(p);
  if (entry.directory) return load(p, child(p.path, entry.name));
  p.selected = entry.name;
  renderPanel(p);
  return operate("view");
}
function selected(p) {
  const entry = visibleEntries(p).find((e) => e.name === p.selected);
  if (!entry || entry.parent || entry.disabled)
    throw new Error("Select a file or folder first");
  return entry;
}
async function openFiles(readonly = false, preserve = false) {
  if (state.busy || state.connecting)
    throw new Error("Wait for or cancel the active operation");
  const host = state.host,
    login = $("#account").value;
  if (!host) throw new Error("Select a host");
  state.connecting = true;
  status("Connecting file session…");
  controls();
  try {
    const remote = await api("/api/connect", {
      host: host.id,
      login,
      readonly,
      path: preserve ? panels.remote.path : null,
    });
    state.remote = remote;
    if (!preserve) {
      for (const p of Object.values(panels)) {
        p.history.clear();
        p.el.querySelector(".filter").value = "";
        p.selected = "..";
      }
      panels.local.path = state.cwd;
      panels.remote.path = remote.path;
    }
    $("#remote-mode").textContent =
      `${host.name || host.id} · ${login}${remote.readonly ? " → root · READ ONLY" : ""}`;
    panels.remote.el.classList.toggle("readonly", remote.readonly);
    $("#root").classList.toggle("enabled", remote.readonly);
    $("#root").textContent = remote.readonly
      ? "Return to account (e)"
      : "Root read-only (e)";
    await Promise.all([load(panels.local), load(panels.remote, remote.path)]);
    show("files");
    activate(state.active);
    status("Ready");
  } finally {
    state.connecting = false;
    controls();
  }
}
async function refresh() {
  await Promise.all(Object.values(panels).map((p) => load(p)));
}
async function operate(action) {
  if (state.busy) throw new Error("Operation already running");
  const p = panels[state.active],
    other = panels[p.side === "local" ? "remote" : "local"];
  const entry = action === "mkdir" ? null : selected(p);
  let source = {
      side: p.side,
      path: entry ? child(p.path, entry.name) : p.path,
    },
    destination = null;
  if (["view", "hash", "copy"].includes(action) && !entry.file)
    throw new Error(
      "Select a regular file; folders and links are not supported for this operation",
    );
  const writesRemote =
    action === "copy"
      ? other.side === "remote"
      : ["rename", "mkdir", "delete"].includes(action) && p.side === "remote";
  if (state.remote.readonly && writesRemote)
    throw new Error(
      "The root panel is read-only. Upload to your account, then use sudo in the terminal.",
    );
  if (action === "copy") {
    const name = await choose({
      title: `Copy to ${other.side}`,
      message: other.path,
      value: entry.name,
    });
    if (name === null) return;
    destination = {
      side: other.side,
      path: child(other.path, validName(name)),
    };
  }
  if (action === "rename") {
    const name = await choose({ title: "Rename", value: entry.name });
    if (name === null) return;
    destination = { side: p.side, path: child(p.path, validName(name)) };
  }
  if (action === "mkdir") {
    const name = await choose({ title: `New folder (${p.side})`, value: "" });
    if (name === null) return;
    source.path = child(p.path, validName(name));
  }
  if (
    action === "delete" &&
    !(await choose({
      title: "Delete?",
      message: `${p.side}: ${source.path}\nFolders must be empty.`,
      destructive: true,
    }))
  )
    return;
  const request = {
    session: state.remote.session,
    action,
    source,
    destination,
    directory: entry?.directory || false,
    overwrite: false,
  };
  state.busy = true;
  controls();
  $("#progress").hidden = false;
  try {
    try {
      await api("/api/operation", request);
    } catch (error) {
      if (!error.collision || action !== "copy") throw error;
      if (
        !(await choose({
          title: "Replace existing file?",
          message: destination.path,
          destructive: true,
        }))
      )
        return;
      request.overwrite = true;
      await api("/api/operation", request);
    }
    $("#cancel").hidden = false;
    let job;
    do {
      job = await api("/api/job");
      status(
        job.message +
          (job.total ? ` · ${size(job.bytes)} / ${size(job.total)}` : ""),
        job.failed,
      );
      const progress = $("#progress");
      if (job.total) {
        progress.max = job.total;
        progress.value = job.bytes;
      } else progress.removeAttribute("value");
      if (job.running) await new Promise((resolve) => setTimeout(resolve, 150));
    } while (job.running);
    if (job.result) {
      $("#viewer-title").textContent = job.result.title;
      $("#preview").textContent = job.result.lines.join("\n");
      $("#viewer").showModal();
      $("#preview").focus();
    }
    await refresh();
    if (destination) {
      const target = panels[destination.side];
      target.selected = basename(destination.path);
      const filter = target.el.querySelector(".filter");
      if (
        !target.selected
          .toLocaleLowerCase()
          .includes(filter.value.toLocaleLowerCase())
      )
        filter.value = "";
      renderPanel(target);
    }
    if (job.failed) throw new Error(job.message);
  } finally {
    state.busy = false;
    controls();
    $("#cancel").hidden = true;
    $("#progress").hidden = true;
  }
}
function closeTerminal() {
  if (state.ws) state.ws.close();
  state.ws = null;
  state.ready = false;
  if (state.term) state.term.dispose();
  state.term = null;
  state.fit = null;
}
function resizeTerminal() {
  if (!state.term || !state.fit || $("#terminal-view").hidden) return;
  const previous = { cols: state.term.cols, rows: state.term.rows };
  state.fit.fit();
  const cols = Math.min(1000, state.term.cols),
    rows = Math.min(1000, state.term.rows);
  if (cols !== state.term.cols || rows !== state.term.rows)
    state.term.resize(cols, rows);
  if (previous.cols === cols && previous.rows === rows) return;
  if (state.ready)
    state.ws.send(JSON.stringify({ type: "resize", version: 1, cols, rows }));
}
async function openTerminal() {
  // Wait before measuring cells so glyphs and FitAddon use the bundled font.
  await terminalFont;

  if (state.term && state.ready) {
    show("terminal");
    state.term.focus();
    return;
  }
  closeTerminal();
  show("terminal");
  status("Opening terminal…");
  const term = new Terminal({
    fontFamily: '"Bastion Nerd Font", monospace',
    fontSize: 14,
    lineHeight: 1.2,
    theme: { background: "#0d1117" },
    scrollback: 5000,
  });
  state.term = term;
  state.fit = new FitAddon.FitAddon();
  term.loadAddon(state.fit);
  term.open($("#terminal-mount"));
  resizeTerminal();
  const hostLabel = state.host.name || state.host.id,
    login = $("#account").value;
  const params = new URLSearchParams({
    host: state.host.id,
    login,
    cols: term.cols,
    rows: term.rows,
  });
  const ws = new WebSocket(`ws://${location.host}/api/terminal?${params}`);
  state.ws = ws;
  ws.binaryType = "arraybuffer";
  $("#terminal-state").textContent = "Connecting…";
  term.onData((data) => {
    if (state.ws === ws && state.ready) ws.send(new TextEncoder().encode(data));
  });
  term.onBinary((data) => {
    if (state.ws === ws && state.ready)
      ws.send(Uint8Array.from(data, (c) => c.charCodeAt(0)));
  });
  ws.onmessage = (event) => {
    if (state.ws !== ws) return;
    if (event.data instanceof ArrayBuffer) {
      term.write(new Uint8Array(event.data));
      return;
    }
    let message;
    try {
      message = JSON.parse(event.data);
    } catch {
      return;
    }
    if (message.type === "ready") {
      if (message.version !== 1) {
        status("Unsupported terminal protocol", true);
        ws.close();
        return;
      }
      state.ready = true;
      status("Terminal connected");
      $("#terminal-state").textContent = `${hostLabel} · ${login}`;
      term.focus();
    } else if (message.type === "error") {
      status(message.message || "Terminal error", true);
    } else if (message.type === "exit")
      $("#terminal-state").textContent =
        `Disconnected · exit ${message.code ?? message.status ?? "?"}`;
  };
  ws.onclose = () => {
    if (state.ws === ws) {
      state.ready = false;
      $("#terminal-state").textContent = "Disconnected";
    }
  };
  ws.onerror = () => status("Terminal connection failed", true);
}
$("#host-filter").oninput = renderHosts;
$("#account").onchange = () => {
  closeTerminal();
  $("#file-view").hidden = true;
  $("#terminal-view").hidden = true;
  $("#welcome").hidden = false;
};
$("#files").onclick = safely(async () => {
  if (
    state.remote &&
    state.remote.host === state.host.id &&
    state.remote.login === $("#account").value
  ) {
    show("files");
    await refresh();
    activate(state.active);
    status("Ready");
  } else {
    await openFiles();
  }
});
$("#terminal").onclick = safely(openTerminal);
$("#root").onclick = safely(() => {
  if (
    state.remote.host !== state.host.id ||
    state.remote.login !== $("#account").value
  )
    throw new Error("Open Files for the selected account first");
  return openFiles(!state.remote.readonly, true);
});
$("#refresh").onclick = safely(refresh);
$("#cancel").onclick = safely(() => api("/api/cancel", {}));
$("#disconnect").onclick = () => {
  closeTerminal();
  $("#terminal-state").textContent = "Disconnected";
};
$("#quit").onclick = safely(async () => {
  if (
    !(await choose({
      title: "Stop local client?",
      message: "Active connections will close.",
    }))
  )
    return;
  closeTerminal();
  await api("/api/quit", {});
  status("Client stopped. You can close this tab.");
  document
    .querySelectorAll("button,input,select")
    .forEach((el) => (el.disabled = true));
});
for (const button of document.querySelectorAll("[data-action]"))
  button.onclick = safely(() => operate(button.dataset.action));
for (const p of Object.values(panels)) {
  p.el.onpointerdown = () => activate(p.side);
  const filter = p.el.querySelector(".filter");
  filter.onfocus = () => {
    filter.dataset.previous = filter.value;
  };
  filter.oninput = () => renderPanel(p);
  p.el.querySelector(".filter").onkeydown = (event) => {
    if (event.key === "Enter" || event.key === "Escape") {
      event.preventDefault();
      if (event.key === "Escape") {
        filter.value = filter.dataset.previous || "";
        renderPanel(p);
      }
      activate(p.side, true);
    }
  };
  p.el.querySelector(".path-form").onsubmit = safely((event) => {
    event.preventDefault();
    return load(p, p.el.querySelector(".path").value);
  });
  p.el.querySelector(".parent").onclick = safely(() => up(p));
}
$("#close-viewer").onclick = () => $("#viewer").close();
$("#prompt-cancel").onclick = () => $("#prompt").close("cancel");
$("#wrap").onchange = () =>
  $("#preview").classList.toggle("wrap", $("#wrap").checked);
window.addEventListener(
  "keydown",
  safely(async (event) => {
    if ($("#viewer").open) {
      if (event.key === "w") {
        event.preventDefault();
        $("#wrap").checked = !$("#wrap").checked;
        $("#wrap").onchange();
      } else if (event.key === "q") $("#viewer").close();
      return;
    }
    if (
      $("#prompt").open ||
      /INPUT|SELECT|TEXTAREA/.test(event.target.tagName) ||
      $("#file-view").hidden ||
      !state.remote ||
      event.ctrlKey ||
      event.metaKey ||
      event.altKey
    )
      return;
    if (event.target.closest("button") && ["Enter", " "].includes(event.key))
      return;
    const p = panels[state.active],
      rows = visibleEntries(p),
      index = rows.findIndex((e) => e.name === p.selected);
    const actions = {
      c: "copy",
      s: "copy",
      F5: "copy",
      r: "rename",
      F6: "rename",
      n: "mkdir",
      F7: "mkdir",
      d: "delete",
      F8: "delete",
      v: "view",
      F3: "view",
      h: "hash",
    };
    if (actions[event.key]) {
      event.preventDefault();
      await operate(actions[event.key]);
    } else if (event.key === "Tab") {
      event.preventDefault();
      activate(state.active === "local" ? "remote" : "local", true);
    } else if (event.key === "/") {
      event.preventDefault();
      p.el.querySelector(".filter").focus();
    } else if (event.key === "Backspace") {
      event.preventDefault();
      await up(p);
    } else if (event.key === "Enter") {
      event.preventDefault();
      await openEntry(p, rows[index]);
    } else if (["ArrowDown", "ArrowUp", "Home", "End"].includes(event.key)) {
      event.preventDefault();
      const next =
        event.key === "Home"
          ? 0
          : event.key === "End"
            ? rows.length - 1
            : Math.min(
                rows.length - 1,
                Math.max(0, index + (event.key === "ArrowDown" ? 1 : -1)),
              );
      p.selected = rows[next]?.name;
      renderPanel(p);
      p.el.querySelector("tr.selected")?.scrollIntoView({ block: "nearest" });
    } else if (event.key === "u" || event.key === "F4") {
      event.preventDefault();
      await refresh();
    } else if (event.key === "e") {
      event.preventDefault();
      $("#root").click();
    }
  }),
);
new ResizeObserver(resizeTerminal).observe($("#terminal-screen"));
async function start() {
  const token = new URLSearchParams(location.hash.slice(1)).get("token");
  history.replaceState(null, "", location.pathname);
  if (token) await api("/session", { token });
  const data = await api("/api/catalog");
  state.hosts = data.catalog.hosts;
  state.cwd = data.cwd || "/";
  $("#identity").textContent = data.context.join(" · ");
  $("#version").textContent = `v${data.version}`;
  renderHosts();
  status("Ready");
  if (state.hosts.length) selectHost(state.hosts[0]);
}
start().catch((error) =>
  status(
    `${error.message}. Start the CLI with --web to open a new local session.`,
    true,
  ),
);
