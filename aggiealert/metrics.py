"""Dependency-free agreement metrics (verified against scikit-learn in tests)."""

LEVELS = ["Low", "Medium", "High", "Critical"]


def confusion(y_true, y_pred, labels=LEVELS):
    idx = {l: i for i, l in enumerate(labels)}
    m = [[0] * len(labels) for _ in labels]
    for t, p in zip(y_true, y_pred):
        if t in idx and p in idx:
            m[idx[t]][idx[p]] += 1
    return m


def accuracy(y_true, y_pred):
    return sum(t == p for t, p in zip(y_true, y_pred)) / len(y_true) if y_true else 0.0


def cohen_kappa(y_true, y_pred, labels=LEVELS):
    n = len(y_true)
    if n == 0:
        return 0.0
    m = confusion(y_true, y_pred, labels)
    po = sum(m[i][i] for i in range(len(labels))) / n
    rows = [sum(r) for r in m]
    cols = [sum(m[i][j] for i in range(len(labels))) for j in range(len(labels))]
    pe = sum(r * c for r, c in zip(rows, cols)) / (n * n)
    if pe == 1:
        return 1.0 if po == 1 else 0.0
    return (po - pe) / (1 - pe)


def report(y_true, y_pred):
    return {
        "n": len(y_true),
        "accuracy": round(accuracy(y_true, y_pred), 4),
        "cohen_kappa": round(cohen_kappa(y_true, y_pred), 4),
        "confusion": confusion(y_true, y_pred),
        "labels": LEVELS,
    }
