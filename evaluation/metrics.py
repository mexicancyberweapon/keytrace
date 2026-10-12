from collections import Counter


def divide(numerator, denominator):
    return numerator / denominator if denominator else None


def score(labels, predictions):
    """Missing predictions count as negatives; explicit abstentions are reported."""
    counts = Counter()
    confusion = Counter()
    for label in labels:
        prediction = predictions.get(label['id'], {})
        positive = prediction.get('is_secret') is True
        counts['tp' if label['is_secret'] and positive else
               'fn' if label['is_secret'] else 'fp' if positive else 'tn'] += 1
        counts['missing'] += label['id'] not in predictions
        counts['abstained'] += label['id'] in predictions and prediction.get('is_secret') is None
        if label.get('purpose_labeled', True):
            purpose = prediction.get('purpose', 'unknown')
            confusion[(label['purpose'], purpose)] += 1
            counts['purpose_labeled'] += 1
            counts['purpose_correct'] += purpose == label['purpose']
    tp, fp, tn, fn = (counts[key] for key in ('tp', 'fp', 'tn', 'fn'))
    return {**{key: counts[key] for key in ('tp', 'fp', 'tn', 'fn', 'missing', 'abstained')},
            'n': len(labels), 'precision': divide(tp, tp + fp), 'recall': divide(tp, tp + fn),
            'f1': divide(2 * tp, 2 * tp + fp + fn), 'false_positive_rate': divide(fp, fp + tn),
            'false_negative_rate': divide(fn, fn + tp),
            'purpose_labeled_n': counts['purpose_labeled'],
            'purpose_accuracy': divide(counts['purpose_correct'], counts['purpose_labeled']),
            'purpose_confusion': [{'actual': a, 'predicted': p, 'count': n} for (a, p), n in sorted(confusion.items())]}
