"""Generate simulated SIEM-style alerts based on CICIDS2017 attack categories."""
import numpy as np
import pandas as pd

LABELS = ["benign", "brute_force", "dos", "port_scan", "web_attack"]
FEATURES = ["protocol", "dst_port", "duration", "packets", "bytes",
            "failed_logins", "request_rate", "unique_ports", "syn_ratio", "http_error_ratio"]


def _row(label, rng):
    if label == "benign":
        port = rng.choice([80, 443, 53, 22, 3306, 8080])
        packets = rng.poisson(25) + 1
        return dict(protocol=rng.choice([0, 1], p=[.8, .2]), dst_port=port,
                    duration=rng.lognormal(1, .8), packets=packets,
                    bytes=packets * rng.uniform(200, 900),
                    failed_logins=rng.choice([0, 0, 0, 1, 2]), request_rate=rng.uniform(.5, 6),
                    unique_ports=rng.integers(1, 3), syn_ratio=rng.uniform(.05, .35),
                    http_error_ratio=rng.uniform(0, .12))
    if label == "brute_force":
        return dict(protocol=0, dst_port=rng.choice([22, 3389, 21]),
                    duration=rng.uniform(15, 150), packets=rng.integers(40, 250),
                    bytes=rng.uniform(5e3, 6e4), failed_logins=rng.integers(8, 90),
                    request_rate=rng.uniform(4, 18), unique_ports=1,
                    syn_ratio=rng.uniform(.2, .5), http_error_ratio=rng.uniform(0, .1))
    if label == "dos":
        packets = rng.integers(1500, 25000)
        return dict(protocol=rng.choice([0, 1], p=[.7, .3]), dst_port=rng.choice([80, 443, 53]),
                    duration=rng.uniform(4, 70), packets=packets,
                    bytes=packets * rng.uniform(60, 400), failed_logins=0,
                    request_rate=rng.uniform(150, 2500), unique_ports=rng.integers(1, 3),
                    syn_ratio=rng.uniform(.6, 1), http_error_ratio=rng.uniform(0, .3))
    if label == "port_scan":
        return dict(protocol=0, dst_port=rng.integers(1, 65000),
                    duration=rng.uniform(1, 40), packets=rng.integers(20, 400),
                    bytes=rng.uniform(1e3, 2e4), failed_logins=0,
                    request_rate=rng.uniform(8, 120), unique_ports=rng.integers(15, 1000),
                    syn_ratio=rng.uniform(.75, 1), http_error_ratio=0)
    return dict(protocol=0, dst_port=rng.choice([80, 443, 8080]),  # web_attack
                duration=rng.uniform(5, 90), packets=rng.integers(30, 400),
                bytes=rng.uniform(1e4, 2e5), failed_logins=rng.integers(0, 4),
                request_rate=rng.uniform(8, 90), unique_ports=1,
                syn_ratio=rng.uniform(.1, .4), http_error_ratio=rng.uniform(.3, .9))


def generate(n=3000, seed=42):
    rng = np.random.default_rng(seed)
    weights = [.40, .15, .15, .15, .15]
    labels = rng.choice(LABELS, size=n, p=weights)
    rows = []
    for lab in labels:
        r = _row(lab, rng)
        for k in ("duration", "packets", "bytes", "request_rate"):  # measurement noise
            r[k] = float(r[k]) * rng.uniform(.8, 1.25)
        r["label"] = lab
        rows.append(r)
    df = pd.DataFrame(rows)
    flip = rng.random(n) < .03  # a few mislabeled alerts, as in real SOC data
    df.loc[flip, "label"] = rng.choice(LABELS, size=int(flip.sum()))
    df.insert(0, "alert_id", [f"A-{1000 + i}" for i in range(n)])
    df.insert(1, "src_ip", [".".join(str(x) for x in rng.integers(1, 255, 4)) for _ in range(n)])
    return df


if __name__ == "__main__":
    df = generate()
    df.to_csv("data/alerts.csv", index=False)
    print(df.label.value_counts())
    print("Saved data/alerts.csv with", len(df), "alerts")
