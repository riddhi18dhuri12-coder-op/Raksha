export default function PredictionBanner({ prediction }) {
  if (!prediction) {
    return (
      <div className="prediction-banner idle">
        <span className="prediction-eyebrow">RAKSHA prediction</span>
        <span className="prediction-text">Monitoring baseline behavior. No deviation detected.</span>
      </div>
    );
  }

  return (
    <div className="prediction-banner active">
      <span className="prediction-eyebrow">Predicted next stage · {Math.round(prediction.confidence * 100)}% confidence</span>
      <span className="prediction-text">{prediction.next_stage}</span>
      <span className="prediction-rationale">{prediction.rationale}</span>
    </div>
  );
}
