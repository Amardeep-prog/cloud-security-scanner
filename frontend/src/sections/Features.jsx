export default function Features() {
  const features = [
    {
      title: "Cloud Misconfiguration Detection",
      description:
        "Identify insecure cloud settings, public resources, and risky configurations before attackers exploit them.",
    },
    {
      title: "API Security Assessment",
      description:
        "Analyze APIs for authentication flaws, exposed endpoints, insecure headers, and data leakage risks.",
    },
    {
      title: "Attack Surface Discovery",
      description:
        "Map exposed assets, services, and entry points across your cloud infrastructure.",
    },
    {
      title: "Risk Prioritization",
      description:
        "Classify findings by severity and focus remediation efforts on the most critical issues.",
    },
  ];

  return (
    <section className="features-section">
      <div className="section-label">[004]</div>

      <h2 className="section-title">
        PLATFORM
        <br />
        CAPABILITIES
      </h2>

      <div className="features-grid">
        {features.map((feature) => (
          <div
            key={feature.title}
            className="feature-card"
          >
            <h3>{feature.title}</h3>

            <p>{feature.description}</p>
          </div>
        ))}
      </div>
    </section>
  );
}