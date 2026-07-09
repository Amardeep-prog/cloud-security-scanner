import { useEffect, useState } from "react";


import {
  PieChart,
  Pie,
  Cell,
  ResponsiveContainer,
  Tooltip,
  Legend,
  LineChart,
  Line,
  CartesianGrid,
  XAxis,
  YAxis,
} from "recharts";
const API =
  import.meta.env.VITE_API_URL ||
  "http://localhost:8000";


export default function Dashboard() {
      const [history, setHistory] = useState([]);
const [loading, setLoading] = useState(true);
useEffect(() => {
  const interval = setInterval(() => {
    loadHistory();
  }, 30000);

  return () => clearInterval(interval);
}, []);

useEffect(() => {
  loadHistory();
}, []);


async function loadHistory() {
  try {
    const response = await fetch(
      `${API}/api/v1/history?page=1&page_size=100`
    );


    const data = await response.json();


    setHistory(data.items || []);
  } catch (err) {
    console.error(err);
  } finally {
    setLoading(false);
  }
}


const totalScans = history.length;


const criticalFindings = history.reduce(
  (sum, item) => sum + (item.critical_count || 0),
  0
);


const averageScore =
  history.length > 0
    ? (
        history.reduce(
          (sum, item) => sum + (item.score || 0),
          0
        ) / history.length
      ).toFixed(1)
    : "0";


const secureAssets =
  history.filter(
    (item) =>
      item.grade === "A" ||
      item.grade === "A+"
  ).length;


const recentScans = [...history]
  .sort(
    (a, b) =>
      new Date(b.timestamp) -
      new Date(a.timestamp)
  )
  .slice(0, 10);
const criticalCount = history.reduce(
  (sum, item) => sum + (item.critical_count || 0),
  0
);


const highCount = history.filter(
  (item) => item.grade === "D" || item.grade === "F"
).length;


const mediumCount = history.filter(
  (item) => item.grade === "C"
).length;


const lowCount = history.filter(
  (item) =>
    item.grade === "A" ||
    item.grade === "A+" ||
    item.grade === "B"
).length;


if (loading) {
  return (
    <main className="dashboard-page">
      Loading dashboard...
    </main>
  );
}


const gradeData = [
  {
    name: "A/A+",
    value: history.filter(
      (r) => r.grade === "A" || r.grade === "A+"
    ).length,
  },
  {
    name: "B",
    value: history.filter(
      (r) => r.grade === "B"
    ).length,
  },
  {
    name: "C/D",
    value: history.filter(
      (r) =>
        r.grade === "C" ||
        r.grade === "D"
    ).length,
  },
  {
    name: "F",
    value: history.filter(
      (r) => r.grade === "F"
    ).length,
  },
];


const trendData = history
  .slice()
  .reverse()
  .slice(0, 10)
  .map((item) => ({
    name: new Date(
      item.timestamp
    ).toLocaleTimeString([], {
      hour: "2-digit",
      minute: "2-digit",
    }),


    score: item.score || 0,
  }));


const COLORS = [
  "#22c55e",
  "#3b82f6",
  "#f59e0b",
  "#ef4444",
];


  return (
    <main className="dashboard-page">


      <div className="section-label">
        [005]
      </div>


      <h1 className="dashboard-title">
        SECURITY
        <br />
        DASHBOARD
      </h1>


      {/* TOP CARDS */}


      <div className="dashboard-grid">


 <div className="metric-card">
   <div className="metric-title">
     Average Risk Score
   </div>


   <div className="metric-value">
     {averageScore}
   </div>


   <div className="metric-status">
     Live
   </div>
 </div>


 <div className="metric-card">
   <div className="metric-title">
     Total Scans
   </div>


   <div className="metric-value">
     {totalScans}
   </div>


   <div className="metric-status">
     Reports
   </div>
 </div>


 <div className="metric-card">
   <div className="metric-title">
     Critical Findings
   </div>


   <div className="metric-value">
     {criticalFindings}
   </div>


   <div className="metric-status">
     Active
   </div>
 </div>


 <div className="metric-card">
   <div className="metric-title">
     Secure Assets
   </div>


   <div className="metric-value">
     {secureAssets}
   </div>


   <div className="metric-status">
     Grade A
   </div>
 </div>


</div>


      {/* SCORE PANEL */}


      <div className="dashboard-row">


        <div className="score-panel">


          <div className="score-gauge">


 <div className="gauge-ring">


   <div className="gauge-inner">
     <span>{averageScore}</span>
<small>Live</small>
   </div>


 </div>


</div>


          <div>
            <h3>Security Posture</h3>


            <p>
              Strong overall cloud security posture
              with minimal critical findings.
            </p>
          </div>


        </div>


 

 <div className="risk-panel">


 <h3>Risk Distribution</h3>


 <div className="risk-item">
   <span>Critical</span>
   <span>{criticalCount}</span>
 </div>


 <div className="risk-bar-wrap">
   <div
     className="risk-bar critical"
     style={{
       width: `${Math.min(criticalCount * 10, 100)}%`,
     }}
   />
 </div>


 <div className="risk-item">
   <span>High</span>
   <span>{highCount}</span>
 </div>


 <div className="risk-bar-wrap">
   <div
     className="risk-bar high"
     style={{
       width: `${Math.min(highCount * 10, 100)}%`,
     }}
   />
 </div>


 <div className="risk-item">
   <span>Medium</span>
   <span>{mediumCount}</span>
 </div>


 <div className="risk-bar-wrap">
   <div
     className="risk-bar medium"
     style={{
       width: `${Math.min(mediumCount * 10, 100)}%`,
     }}
   />
 </div>


 <div className="risk-item">
   <span>Low</span>
   <span>{lowCount}</span>
 </div>


 <div className="risk-bar-wrap">
   <div
     className="risk-bar low"
     style={{
       width: `${Math.min(lowCount * 10, 100)}%`,
     }}
   />
 </div>


</div>
      </div>
      {/* RECENT SCANS */}


      <div className="recent-panel">
        
        <div
 style={{
   display: "grid",
   gridTemplateColumns:
     "repeat(auto-fit,minmax(420px,1fr))",
   gap: "24px",
   marginBottom: "30px",
 }}
>


 {/* PIE CHART */}


 <div className="metric-card">
   <h3
     style={{
       marginBottom: "20px",
     }}
   >
     Grade Distribution
   </h3>


   <ResponsiveContainer
     width="100%"
     height={350}
   >
     <PieChart>
       <Pie
         data={gradeData}
         dataKey="value"
         nameKey="name"
         cx="50%"
         cy="50%"
innerRadius={70}
outerRadius={120}
paddingAngle={5}         label={({ name, percent }) =>
           `${name} ${(percent * 100).toFixed(0)}%`
         }
       >
         {gradeData.map(
           (entry, index) => (
             <Cell
               key={index}
               fill={
                 COLORS[
                   index %
                     COLORS.length
                 ]
               }
             />
           )
         )}
       </Pie>


       <Tooltip
  formatter={(value, name) => [
    `${value} reports`,
    name,
  ]}
/>
<Legend
  verticalAlign="bottom"
  height={36}
/>     </PieChart>
   </ResponsiveContainer>
 </div>


 {/* TREND CHART */}


 <div className="metric-card">
   <h3
     style={{
       marginBottom: "20px",
     }}
   >
     Security Score Trend
   </h3>


   <ResponsiveContainer
     width="100%"
     height={300}
   >
     <LineChart
       data={trendData}
     >
       <CartesianGrid
         strokeDasharray="3 3"
       />


       <XAxis dataKey="name" />


       <YAxis />


       <Tooltip />


       <Line
         type="monotone"
         dataKey="score"
         stroke="#22c55e"
         strokeWidth={3}
       />
     </LineChart>
   </ResponsiveContainer>
 </div>


</div>


<h3>Security Posture Summary</h3>

<div
  style={{
    display: "grid",
    gridTemplateColumns:
      "repeat(auto-fit,minmax(350px,1fr))",
    gap: "24px",
    marginBottom: "30px",
  }}
>

  <div className="metric-card">

    <h3>Cloud Providers</h3>

    <div className="risk-item">
      <span>AWS</span>
      <span>
        {
          history.filter(
            (r) => r.cloud?.provider === "AWS"
          ).length
        }
      </span>
    </div>

    <div className="risk-item">
      <span>Azure</span>
      <span>
        {
          history.filter(
            (r) => r.cloud?.provider === "Azure"
          ).length
        }
      </span>
    </div>

    <div className="risk-item">
      <span>GCP</span>
      <span>
        {
          history.filter(
            (r) => r.cloud?.provider === "GCP"
          ).length
        }
      </span>
    </div>

  </div>

  <div className="metric-card">

    <h3>Executive Summary</h3>

    <p>
      Total Reports:
      <strong>{totalScans}</strong>
    </p>

    <p>
      Average Security Score:
      <strong>{averageScore}</strong>
    </p>

    <p>
      Critical Findings:
      <strong>{criticalFindings}</strong>
    </p>

    <p>
      Secure Assets:
      <strong>{secureAssets}</strong>
    </p>

  </div>

</div>

<div
  style={{
    display: "grid",
    gridTemplateColumns:
      "repeat(auto-fit,minmax(220px,1fr))",
    gap: "20px",
    marginBottom: "30px",
  }}
>

  <div className="metric-card">
    <div className="metric-title">Grade A/A+</div>
    <div className="metric-value">
      {
        history.filter(
          (r) =>
            r.grade === "A" ||
            r.grade === "A+"
        ).length
      }
    </div>
  </div>

  <div className="metric-card">
    <div className="metric-title">Grade B</div>
    <div className="metric-value">
      {
        history.filter(
          (r) => r.grade === "B"
        ).length
      }
    </div>
  </div>

  <div className="metric-card">
    <div className="metric-title">Grade C/D</div>
    <div className="metric-value">
      {
        history.filter(
          (r) =>
            r.grade === "C" ||
            r.grade === "D"
        ).length
      }
    </div>
  </div>

  <div className="metric-card">
    <div className="metric-title">Grade F</div>
    <div className="metric-value">
      {
        history.filter(
          (r) => r.grade === "F"
        ).length
      }
    </div>
  </div>

</div>

<h3 style={{ marginTop: 30 }}>
  Recent Assessments
</h3>


<table className="scan-table">
  <thead>
    <tr>
      <th>URL</th>
      <th>Score</th>
      <th>Grade</th>
      <th>Date</th>
    </tr>
  </thead>


  <tbody>
    {recentScans.map((scan) => (
      <tr key={scan.scan_id}>
        <td>{scan.url}</td>
        <td>
{scan.score != null
  ? Number(scan.score).toFixed(1)
  : "-"}
</td>
        <td
          style={{
            color:
              scan.grade === "A+" ||
              scan.grade === "A"
                ? "#22c55e"
                : scan.grade === "B"
                ? "#3b82f6"
                : scan.grade === "C"
                ? "#f59e0b"
                : "#ef4444",
            fontWeight: 700,
          }}
        >
          {scan.grade}
        </td>
        <td>{new Date(scan.timestamp).toLocaleDateString()}</td>
      </tr>
    ))}
  </tbody>
</table>


</div>
</main>
  );
}