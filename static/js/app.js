(() => {
  "use strict";

  const storage = {
    get(key, fallback = null) {
      try { return window.localStorage.getItem(key) ?? fallback; } catch (_) { return fallback; }
    },
    set(key, value) {
      try { window.localStorage.setItem(key, value); } catch (_) { /* storage is optional */ }
    }
  };

  const root = document.documentElement;
  const preferredTheme = storage.get("connx-theme", window.matchMedia("(prefers-color-scheme: dark)").matches ? "dark" : "light");
  root.setAttribute("data-bs-theme", preferredTheme);

  document.querySelectorAll("[data-theme-toggle]").forEach((button) => {
    button.addEventListener("click", () => {
      const next = root.getAttribute("data-bs-theme") === "dark" ? "light" : "dark";
      root.setAttribute("data-bs-theme", next);
      storage.set("connx-theme", next);
      button.setAttribute("aria-label", `Use ${next === "dark" ? "light" : "dark"} theme`);
    });
  });

  document.querySelectorAll("[data-password-toggle]").forEach((button) => {
    button.addEventListener("click", () => {
      const password = document.getElementById("password");
      if (!password) return;
      const showing = password.type === "text";
      password.type = showing ? "password" : "text";
      button.setAttribute("aria-label", showing ? "Show password" : "Hide password");
      const label = button.querySelector("[data-password-label]");
      if (label) label.textContent = showing ? "Show" : "Hide";
    });
  });

  document.querySelectorAll("form[data-validate]").forEach((form) => {
    form.addEventListener("submit", (event) => {
      if (!form.checkValidity()) {
        event.preventDefault();
        event.stopPropagation();
      }
      form.classList.add("was-validated");
    });
  });

  document.querySelectorAll(".progress-bar[data-value]").forEach((bar) => {
    const value = Math.max(0, Math.min(100, Number(bar.dataset.value) || 0));
    bar.style.width = `${value}%`;
  });

  const timezone = Intl.DateTimeFormat().resolvedOptions().timeZone || "Local";
  document.querySelectorAll("[data-timezone]").forEach((element) => { element.textContent = timezone; });
  const dateTimeFormatter = new Intl.DateTimeFormat(undefined, {
    dateStyle: "medium",
    timeStyle: "short"
  });
  document.querySelectorAll("time[data-timestamp]").forEach((element) => {
    const source = element.dataset.timestamp?.trim();
    if (!source) return;
    const parsed = new Date(source);
    element.title = `Source timestamp: ${source}`;
    if (!Number.isNaN(parsed.getTime())) {
      element.textContent = dateTimeFormatter.format(parsed);
      element.setAttribute("datetime", parsed.toISOString());
    }
  });
  const numberFormatter = new Intl.NumberFormat(undefined, { maximumFractionDigits: 2 });
  document.querySelectorAll("[data-number]").forEach((element) => {
    const value = Number(element.dataset.number);
    if (Number.isFinite(value)) element.textContent = numberFormatter.format(value);
  });

  document.querySelectorAll("[data-bs-toggle='tooltip']").forEach((element) => {
    window.bootstrap?.Tooltip.getOrCreateInstance(element);
  });

  const helpCanvas = document.getElementById("helpAbout");
  const primaryCanvas = document.getElementById("primaryNavigation");
  const navigationToggle = document.querySelector("[data-bs-target='#primaryNavigation']");
  let helpReturnTarget = null;
  const showHelp = (trigger) => {
    if (!helpCanvas || !window.bootstrap) return;
    const targetId = trigger.dataset.helpTarget;
    const target = targetId ? document.getElementById(targetId) : null;
    const primaryOpen = primaryCanvas?.classList.contains("show") || primaryCanvas?.classList.contains("showing");
    helpReturnTarget = primaryOpen ? navigationToggle : trigger;
    const reveal = () => {
      const helpInstance = window.bootstrap.Offcanvas.getOrCreateInstance(helpCanvas);
      helpInstance.show(helpReturnTarget || trigger);
      if (!target) return;
      const collapse = target.closest(".accordion-collapse");
      const focusTarget = () => window.setTimeout(() => target.focus(), 50);
      if (collapse && !collapse.classList.contains("show")) {
        collapse.addEventListener("shown.bs.collapse", focusTarget, { once: true });
        window.bootstrap.Collapse.getOrCreateInstance(collapse, { toggle: false }).show();
      } else {
        helpCanvas.addEventListener("shown.bs.offcanvas", focusTarget, { once: true });
      }
    };
    const hidePrimaryThenReveal = () => {
      primaryCanvas.addEventListener("hidden.bs.offcanvas", reveal, { once: true });
      window.bootstrap.Offcanvas.getOrCreateInstance(primaryCanvas).hide();
    };
    if (primaryCanvas?.classList.contains("showing") && !primaryCanvas.classList.contains("show")) {
      primaryCanvas.addEventListener("shown.bs.offcanvas", hidePrimaryThenReveal, { once: true });
    } else if (primaryCanvas?.classList.contains("show")) {
      hidePrimaryThenReveal();
    } else {
      reveal();
    }
  };
  document.querySelectorAll("[data-help-open]").forEach((trigger) => {
    trigger.addEventListener("click", () => showHelp(trigger));
  });
  helpCanvas?.addEventListener("hidden.bs.offcanvas", () => {
    const target = helpReturnTarget;
    window.setTimeout(() => {
      if (target?.isConnected) target.focus();
    }, 50);
  });

  const detailsCanvas = document.getElementById("recordDetails");
  if (detailsCanvas) {
    detailsCanvas.addEventListener("show.bs.offcanvas", (event) => {
      const sourceId = event.relatedTarget?.dataset.detailTarget;
      const source = sourceId ? document.getElementById(sourceId) : null;
      const output = detailsCanvas.querySelector("[data-record-json]");
      const title = detailsCanvas.querySelector("[data-record-title]");
      if (!source || !output) return;
      try {
        const record = JSON.parse(source.textContent);
        output.textContent = JSON.stringify(record, null, 2);
        if (title) title.textContent = record.itemname || record.table || record.groupname || record.transformname || "Record details";
      } catch (_) {
        output.textContent = "This record could not be displayed.";
      }
    });
  }

  const scope = document.getElementById("analysis-scope");
  const jobChecks = [...document.querySelectorAll(".job-select")];
  const selectedBar = document.querySelector("[data-selected-bar]");
  const selectedCount = document.querySelector("[data-selected-count]");
  const updateSelection = () => {
    if (!scope) return;
    const selecting = scope.value === "selected";
    jobChecks.forEach((checkbox) => { checkbox.disabled = !selecting; });
    const count = jobChecks.filter((checkbox) => checkbox.checked).length;
    if (selectedCount) selectedCount.textContent = String(count);
    selectedBar?.classList.toggle("is-visible", selecting);
  };
  scope?.addEventListener("change", updateSelection);
  jobChecks.forEach((checkbox) => checkbox.addEventListener("change", updateSelection));
  document.querySelector("[data-clear-selection]")?.addEventListener("click", () => {
    jobChecks.forEach((checkbox) => { checkbox.checked = false; });
    updateSelection();
  });
  updateSelection();

  document.querySelectorAll("form[data-loading-form]").forEach((form) => {
    form.addEventListener("submit", () => {
      if (!form.checkValidity()) return;
      const button = form.querySelector("button[type='submit'], button:not([type])");
      if (!button) return;
      button.dataset.originalLabel = button.innerHTML;
      button.innerHTML = `<span class="spinner-border spinner-border-sm me-2" aria-hidden="true"></span>${button.dataset.loadingLabel || "Working…"}`;
      button.setAttribute("aria-disabled", "true");
    });
  });

  const refreshToggle = document.getElementById("auto-refresh");
  const countdown = document.querySelector("[data-refresh-countdown]");
  let remaining = 30;
  let timer = null;
  const shouldPause = () => document.querySelector(".offcanvas.show, .modal.show") || document.activeElement?.matches("input, select, textarea");
  const runRefreshTimer = () => {
    window.clearInterval(timer);
    if (!refreshToggle?.checked) {
      if (countdown) countdown.textContent = "Off";
      return;
    }
    remaining = 30;
    if (countdown) countdown.textContent = `${remaining}s`;
    timer = window.setInterval(() => {
      if (shouldPause()) return;
      remaining -= 1;
      if (countdown) countdown.textContent = `${remaining}s`;
      if (remaining <= 0) window.location.reload();
    }, 1000);
  };
  if (refreshToggle) {
    refreshToggle.checked = storage.get("connx-auto-refresh", "false") === "true";
    refreshToggle.addEventListener("change", () => {
      storage.set("connx-auto-refresh", String(refreshToggle.checked));
      runRefreshTimer();
    });
    runRefreshTimer();
  }

  const updated = document.querySelector("[data-last-updated]");
  if (updated) updated.textContent = new Intl.DateTimeFormat(undefined, { hour: "numeric", minute: "2-digit", second: "2-digit" }).format(new Date());

  if (document.body.dataset.aiJobStatus === "pending") {
    window.setTimeout(() => window.location.reload(), 2000);
  }
})();
