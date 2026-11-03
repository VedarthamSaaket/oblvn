import numpy as np


def robust_stats(X: np.ndarray) -> dict:
    median = np.nanmedian(X, axis=0)
    mad = np.nanmedian(np.abs(X - median), axis=0) * 1.4826
    std = np.nanstd(X, axis=0)
    scale = np.where(mad > 1e-9, mad, np.where(std > 1e-9, std, 1.0))
    return {"median": median.tolist(), "scale": scale.tolist()}


def top_contributors(x: np.ndarray, stats: dict, names: list[str], k: int = 3) -> list[dict]:
    median = np.asarray(stats["median"])
    scale = np.asarray(stats["scale"])
    z = (x - median) / scale
    order = np.argsort(-np.abs(np.nan_to_num(z)))[:k]
    return [
        {"feature": names[i], "value": round(float(x[i]), 4), "typical": round(float(median[i]), 4),
         "robust_z": round(float(z[i]), 2)}
        for i in order if abs(np.nan_to_num(z[i])) >= 1.0
    ]
