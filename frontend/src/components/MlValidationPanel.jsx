import { useEffect, useState } from 'react';
import { fetchMlMetrics, fetchMlSamplePrediction } from '../api';

export default function MlValidationPanel() {
  const [metrics, setMetrics] = useState(null);
  const [prediction, setPrediction] = useState(null);
  const [loading, setLoading] = useState(false);

  useEffect(() => {
    fetchMlMetrics().then(setMetrics);
  }, []);

  const runSample = async () => {
    setLoading(true);
    const res = await fetchMlSamplePrediction();
    setPrediction(res);
    setLoading(false);
  };

  if (!metrics) return null;

  if (!metrics.ready) {
    return (
      <div className="panel">
        <div className="panel-header">
          <span className="panel-title">ML Model Validation</span>
        </div>
        <div className="empty-state">
          Model not trained yet. Run <code>python ml/train_anomaly_model.py</code> from the project root.
        </div>
      </div>
    );
  }

  return (
    <div className="panel">
      <div className="panel-header">
        <span className="panel-title">ML Model Validation</span>
        <span className="panel-count">real NSL-KDD data</span>
      </div>
      <div className="ml-metrics-grid">
        <div className="ml-metric">
          <span className="ml-metric-value" style={{ color: 'var(--signal-green)' }}>
            {Math.round(metrics.detection_rate * 100)}%
          </span>
          <span className="ml-metric-label">Detection rate</span>
        </div>
        <div className="ml-metric">
          <span className="ml-metric-value" style={{ color: 'var(--signal-amber)' }}>
            {(metrics.false_positive_rate * 100).toFixed(1)}%
          </span>
          <span className="ml-metric-label">False positive rate</span>
        </div>
        <div className="ml-metric">
          <span className="ml-metric-value">{metrics.test_records_total.toLocaleString()}</span>
          <span className="ml-metric-label">Test records (real)</span>
        </div>
      </div>
      <div className="ml-note">
        Model is an Isolation Forest trained only on normal traffic —
        it never saw an attack during training. These numbers are its
        performance recognizing real, unseen attacks in the NSL-KDD
        benchmark test set purely from behavioral deviation.
      </div>

      <button className="btn-ml-test" onClick={runSample} disabled={loading}>
        {loading ? 'Running…' : 'Test model on a random real record'}
      </button>

      {prediction && prediction.ready && (
        <div className={`ml-prediction-result ${prediction.correct ? 'correct' : 'incorrect'}`}>
          <div className="ml-prediction-row">
            <span>True label</span>
            <strong>{prediction.true_label}</strong>
          </div>
          <div className="ml-prediction-row">
            <span>Model verdict</span>
            <strong>{prediction.flagged_as_anomaly ? 'ANOMALY' : 'normal'}</strong>
          </div>
          <div className="ml-prediction-row">
            <span>Anomaly score</span>
            <strong>{prediction.anomaly_score}</strong>
          </div>
          <div className="ml-prediction-verdict">
            {prediction.correct ? '✓ Correct' : '✗ Missed'}
          </div>
        </div>
      )}
    </div>
  );
}
