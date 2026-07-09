const API_BASE = "http://localhost:8000";

export async function runScan(url) {
  const response = await fetch(`${API_BASE}/api/v1/scan`, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
    },
    body: JSON.stringify({
      url,
    }),
  });

  if (!response.ok) {
    throw new Error("Scan failed");
  }

  return await response.json();
}

export async function getHistory() {
  const response = await fetch(
    `${API_BASE}/api/v1/history`
  );

  return await response.json();
}

export async function getReport(scanId) {
  const response = await fetch(
    `${API_BASE}/api/v1/report/${scanId}`
  );

  return await response.json();
}