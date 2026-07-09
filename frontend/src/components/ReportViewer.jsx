import { useEffect, useState } from "react";
import { useParams } from "react-router-dom";

const API = import.meta.env.VITE_API_URL || "http://localhost:8000";

export default function ReportViewer() {
const { scanId } = useParams();

const [report, setReport] = useState(null);
const [loading, setLoading] = useState(true);
const [error, setError] = useState("");

useEffect(() => {
loadReport();
}, [scanId]);

async function loadReport() {
try {
const response = await fetch(
`${API}/api/v1/report/${scanId}`
);

  if (!response.ok) {
    throw new Error(`HTTP ${response.status}`);
  }

  const data = await response.json();
  setReport(data);
} catch (err) {
  setError(err.message);
} finally {
  setLoading(false);
}


}

if (loading) {
return ( <main className="main"> <div className="card">
Loading report... </div> </main>
);
}

if (error) {
return ( <main className="main"> <div className="card">
Error: {error} </div> </main>
);
}

return ( <main className="main"> <div className="card">

```
    <h1 style={{ marginBottom: 20 }}>
      Scan Report
    </h1>

    <div style={{ marginBottom: 20 }}>
      <p><strong>URL:</strong> {report.url}</p>
      <p><strong>Status:</strong> {report.status}</p>
      <p><strong>Score:</strong> {report.score?.total}</p>
      <p><strong>Grade:</strong> {report.score?.grade}</p>
      <p><strong>Duration:</strong> {report.duration_ms} ms</p>
      <p><strong>Provider:</strong> {report.cloud?.provider}</p>
    </div>

    <h2>Issues Found</h2>

    {report.issues?.length === 0 ? (
      <p>No issues found.</p>
    ) : (
      report.issues?.map((issue) => (
        <div
          key={issue.id}
          style={{
            border: "1px solid var(--border)",
            padding: 16,
            marginBottom: 12,
            borderRadius: 8,
          }}
        >
          <h3>{issue.title}</h3>

          <p>
            <strong>Severity:</strong>{" "}
            {issue.severity}
          </p>

          <p>{issue.description}</p>

          <p>
            <strong>Recommendation:</strong>{" "}
            {issue.recommendation}
          </p>
        </div>
      ))
    )}

    {report.subdomains?.length > 0 && (
      <>
        <h2>Subdomains</h2>

        <ul>
          {report.subdomains.map((sub) => (
            <li key={sub}>{sub}</li>
          ))}
        </ul>
      </>
    )}
  </div>
</main>

);
}
