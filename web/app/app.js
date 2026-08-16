// The legitimate first-party Meridian Payroll application.
//
// It runs on https://app.meridianpay.example and calls https://api.meridianpay.example,
// so every request here is a *credentialed cross-origin* request. It works only because
// the API's exact-match allowlist contains this page's origin verbatim. Nothing on this
// page is privileged: the same code served from any other origin would be refused.

const API_ORIGIN = "https://api.meridianpay.example";
const DEMO_EMPLOYEE_ID = "EMP-4417";
const DEMO_PASSWORD = "demo-only-password";

const statusEl = document.getElementById("status");
const payslipPanel = document.getElementById("payslip-panel");
const payslipEl = document.getElementById("payslip");
const payoutPanel = document.getElementById("payout-panel");
const payoutEl = document.getElementById("payout");
const payoutForm = document.getElementById("payout-form");
const payoutStatusEl = document.getElementById("payout-status");

let csrfToken = null;

function money(minorUnits, currency) {
  return new Intl.NumberFormat("en-GB", { style: "currency", currency }).format(
    minorUnits / 100,
  );
}

function renderDefinitions(target, rows) {
  target.replaceChildren();
  for (const [label, value] of rows) {
    const dt = document.createElement("dt");
    dt.textContent = label;
    const dd = document.createElement("dd");
    dd.textContent = value;
    target.append(dt, dd);
  }
}

function renderPayslip(data) {
  renderDefinitions(payslipEl, [
    ["Employee", `${data.display_name} (${data.employee_id})`],
    ["Role", data.job_title],
    ["Period", data.payslip.period],
    ["Gross pay", money(data.payslip.gross_pay_minor, data.payslip.currency)],
    ["Net pay", money(data.payslip.net_pay_minor, data.payslip.currency)],
    ["Tax reference", data.payslip.tax_reference],
    ["Session API token", data.api_token],
  ]);
  payslipPanel.hidden = false;

  renderDefinitions(payoutEl, [
    ["Bank", data.payout_account.bank_name],
    ["Account tail", `•••• ${data.payout_account.account_tail}`],
  ]);
  payoutPanel.hidden = false;
}

async function signIn() {
  const response = await fetch(`${API_ORIGIN}/session`, {
    method: "POST",
    credentials: "include",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({
      employee_id: DEMO_EMPLOYEE_ID,
      demo_password: DEMO_PASSWORD,
    }),
  });
  if (!response.ok) {
    throw new Error(`sign-in failed with ${response.status}`);
  }
  const session = await response.json();
  csrfToken = session.csrf_token;
  return session;
}

async function loadPayslip() {
  const response = await fetch(`${API_ORIGIN}/me/payslip`, {
    method: "GET",
    credentials: "include",
  });
  if (!response.ok) {
    throw new Error(`payslip read failed with ${response.status}`);
  }
  return response.json();
}

async function start() {
  try {
    const session = await signIn();
    statusEl.textContent = `Signed in as ${session.display_name}. The credentialed cross-origin read below was permitted because this origin is on the API's allowlist.`;
    renderPayslip(await loadPayslip());
  } catch (error) {
    statusEl.textContent = `Could not load the portal: ${error.message}`;
  }
}

payoutForm.addEventListener("submit", async (event) => {
  event.preventDefault();
  payoutStatusEl.textContent = "Updating…";
  try {
    const response = await fetch(`${API_ORIGIN}/me/payout-account`, {
      method: "POST",
      credentials: "include",
      headers: {
        "content-type": "application/json",
        "x-meridian-csrf": csrfToken,
      },
      body: JSON.stringify({
        bank_name: document.getElementById("bank-name").value,
        account_tail: document.getElementById("account-tail").value,
      }),
    });
    if (!response.ok) {
      throw new Error(`update failed with ${response.status}`);
    }
    const updated = await response.json();
    renderDefinitions(payoutEl, [
      ["Bank", updated.bank_name],
      ["Account tail", `•••• ${updated.account_tail}`],
    ]);
    payoutStatusEl.textContent = "Payout account updated through the CSRF-protected route.";
  } catch (error) {
    payoutStatusEl.textContent = `Update refused: ${error.message}`;
  }
});

start();
