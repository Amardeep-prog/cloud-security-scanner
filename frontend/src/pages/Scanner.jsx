import { useState } from "react";
import ScanForm from "../components/ScanForm";
import ScanResult from "../components/ScanResult";
import ScannerShell from "../sections/ScannerShell";

export default function Scanner() {
  const [scanResult, setScanResult] = useState(null);

  return (
    <main className="main">

      <ScannerShell>
        <ScanForm onResult={setScanResult} />
      </ScannerShell>

      {scanResult && (
        <ScanResult report={scanResult} />
      )}

    </main>
  );
}