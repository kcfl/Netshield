export default function LayerStatusCard({ title, description, value, tone = "low" }) {
  return (
    <article className={`card summary-card summary-card--${tone}`}>
      <p className="summary-card__title">{title}</p>
      <h3 className="summary-card__value">{value}</h3>
      <p className="summary-card__description">{description}</p>
    </article>
  );
}
