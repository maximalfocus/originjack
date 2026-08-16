// A page on an unrelated third-party origin, making the same credentialed cross-origin
// read the first-party application makes.
//
// Nothing here is an attack. There is no trick, no injected script, no stolen token: it
// is the ordinary `fetch` any site can write, aimed at an API where the victim already
// has a session. Whether it succeeds is decided entirely by two response headers the API
// chooses to send — and, because those headers are absent for this origin, by the
// browser refusing to hand this page the response it received.

const API_ORIGIN = "https://api.meridianpay.example";

const statusEl = document.getElementById("status");
const detailEl = document.getElementById("detail");
const payslipPanel = document.getElementById("payslip-panel");
const payslipEl = document.getElementById("payslip");

function render(rows) {
  payslipEl.replaceChildren();
  for (const [label, value] of rows) {
    const dt = document.createElement("dt");
    dt.textContent = label;
    const dd = document.createElement("dd");
    dd.textContent = value;
    payslipEl.append(dt, dd);
  }
  payslipPanel.hidden = false;
}

async function attemptRead() {
  try {
    const response = await fetch(`${API_ORIGIN}/me/payslip`, {
      method: "GET",
      credentials: "include",
    });

    // Reaching this line at all means the browser released the response to this origin.
    const data = await response.json();
    document.body.dataset.outcome = "released";
    statusEl.textContent = `The browser released the response to this origin (HTTP ${response.status}).`;
    detailEl.textContent = "";
    render([
      ["Employee", `${data.display_name} (${data.employee_id})`],
      ["Net pay", `${data.payslip.net_pay_minor / 100} ${data.payslip.currency}`],
      ["Tax reference", data.payslip.tax_reference],
      ["Payout account tail", data.payout_account.account_tail],
      ["Session API token", data.api_token],
    ]);
  } catch (error) {
    // The request was sent and the server answered it. This page never sees that answer.
    document.body.dataset.outcome = "blocked";
    statusEl.textContent =
      "The browser refused to give this page the response. No payslip data is available here.";
    detailEl.textContent = `${error.name}: ${error.message}`;
    payslipPanel.hidden = true;
  }
}

attemptRead();
