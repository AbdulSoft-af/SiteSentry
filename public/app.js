const form = document.querySelector("#scan-form");
const input = document.querySelector("#target-url");
const apiTokenInput = document.querySelector("#api-token");
const button = document.querySelector("#scan-button");
const errorBox = document.querySelector("#error-box");
const results = document.querySelector("#results");
const exportButton = document.querySelector("#export-button");
const exportCsvButton = document.querySelector("#export-csv-button");
const checkSearch = document.querySelector("#check-search");
const checkFilter = document.querySelector("#check-filter");
const filterEmpty = document.querySelector("#filter-empty");
let latestReport = null;

function showError(message) {
  errorBox.textContent = message;
  errorBox.hidden = false;
}
function clearError() {
  errorBox.textContent = "";
  errorBox.hidden = true;
}
function element(tag, className, text) {
  const node = document.createElement(tag);
  if (className) node.className = className;
  if (text !== undefined) node.textContent = text;
  return node;
}
function renderChecks(checks) {
  const list = document.querySelector("#checks-list");
  list.replaceChildren();
  for (const check of checks) {
    const card = element("article", "check-card");
    const status = check.status === "pass" ? "pass" : check.status === "warning" ? "warning" : "info";
    card.append(element("div", `check-icon ${status}`, status === "pass" ? "✓" : status === "warning" ? "!" : "i"));
    const copy = element("div", "check-copy");
    copy.append(element("h4", "", check.title), element("p", "", check.detail));
    if (check.status === "warning") copy.append(element("p", "recommendation", `Recommendation: ${check.recommendation}`));
    card.append(copy, element("span", "severity", check.severity));
    list.append(card);
  }
}
function renderReport(report) {
  latestReport = report;
  document.querySelector("#report-title").textContent = report.title || new URL(report.finalUrl).hostname;
  document.querySelector("#report-subtitle").textContent = `${report.finalUrl} · ${new Date(report.scannedAt).toLocaleString()}`;
  document.querySelector("#status-value").textContent = report.statusCode;
  document.querySelector("#passed-value").textContent = report.summary.passed;
  document.querySelector("#warnings-value").textContent = report.summary.warnings;
  document.querySelector("#check-count").textContent = `${report.summary.total} checks`;
  renderChecks(report.checks);
  document.querySelector("#metadata").textContent = JSON.stringify({
    requestedUrl: report.requestedUrl, finalUrl: report.finalUrl, contentType: report.contentType,
    responseBytesInspected: report.responseBytesInspected, redirectChain: report.redirectChain,
    headers: report.headers, limitations: report.limitations
  }, null, 2);
  results.hidden = false;
  results.scrollIntoView({ behavior: "smooth", block: "start" });
}
form.addEventListener("submit", async event => {
  event.preventDefault();
  clearError();
  button.disabled = true;
  button.querySelector("span:first-child").textContent = "Scanning…";
  try {
    const headers = { "content-type": "application/json" };
    const apiToken = apiTokenInput?.value.trim();
    if (apiToken) headers.authorization = `Bearer ${apiToken}`;
    const response = await fetch("/api/scan", {
      method: "POST",
      headers,
      body: JSON.stringify({ url: input.value.trim() })
    });
    const data = await response.json();
    if (!response.ok) throw new Error(data.error || "Scan failed.");
    renderReport(data);
  } catch (error) {
    showError(error.message || "Something went wrong. Please try again.");
  } finally {
    button.disabled = false;
    button.querySelector("span:first-child").textContent = "Scan website";
  }
});
exportButton.addEventListener("click", () => {
  if (!latestReport) return;
  const blob = new Blob([JSON.stringify(latestReport, null, 2)], { type: "application/json" });
  const url = URL.createObjectURL(blob);
  const link = document.createElement("a");
  link.href = url;
  link.download = `sitesentry-report-${new URL(latestReport.finalUrl).hostname}-${new Date().toISOString().slice(0, 10)}.json`;
  document.body.append(link);
  link.click();
  link.remove();
  URL.revokeObjectURL(url);
});

checkSearch.addEventListener("input", () => {
  if (latestReport) renderChecks(latestReport.checks);
});
checkFilter.addEventListener("change", () => {
  if (latestReport) renderChecks(latestReport.checks);
});

function csvCell(value) {
  const text = String(value ?? "");
  return `"${text.replaceAll('"', '""')}"`;
}
exportCsvButton.addEventListener("click", () => {
  if (!latestReport) return;
  const rows = [
    ["Website", latestReport.finalUrl],
    ["Scanned at", latestReport.scannedAt],
    ["HTTP status", latestReport.statusCode],
    [],
    ["Check", "Status", "Severity", "Details", "Recommendation"],
    ...latestReport.checks.map(check => [
      check.title, check.status, check.severity, check.detail, check.recommendation
    ])
  ];
  const csv = rows.map(row => row.map(csvCell).join(",")).join("\r\n");
  const blob = new Blob(["\uFEFF", csv], { type: "text/csv;charset=utf-8" });
  const url = URL.createObjectURL(blob);
  const link = document.createElement("a");
  link.href = url;
  link.download = `sitesentry-report-${new URL(latestReport.finalUrl).hostname}-${new Date().toISOString().slice(0, 10)}.csv`;
  document.body.append(link);
  link.click();
  link.remove();
  URL.revokeObjectURL(url);
});
