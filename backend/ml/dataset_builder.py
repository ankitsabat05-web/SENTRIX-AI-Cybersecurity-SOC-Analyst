import pandas as pd
import numpy as np
from pathlib import Path

np.random.seed(42)

TOTAL_ROWS = 50000
BENIGN_ROWS = 25000
MALICIOUS_ROWS = 25000

ATTACK_TYPES = [
    "BRUTE_FORCE",
    "PORT_SCAN",
    "MALWARE",
    "DDOS",
    "SQL_INJECTION",
    "PHISHING",
    "BOTNET",
    "DATA_EXFILTRATION",
    "SUSPICIOUS_LOGIN"
]


def random_ip():
    return (
        f"{np.random.randint(10, 223)}."
        f"{np.random.randint(0, 256)}."
        f"{np.random.randint(0, 256)}."
        f"{np.random.randint(1, 255)}"
    )


def create_benign_data(count):

    data = []

    for _ in range(count):

        row = {
            "timestamp":
                pd.Timestamp("2026-01-01")
                + pd.Timedelta(
                    seconds=np.random.randint(0, 31536000)
                ),

            "source_ip": random_ip(),
            "destination_ip": random_ip(),

            "protocol": np.random.choice(
                ["TCP", "UDP", "HTTP", "HTTPS", "DNS"]
            ),

            "port": np.random.choice(
                [53, 80, 443, 22, 25, 110, 143]
            ),

            "failed_logins": np.random.poisson(0.4),

            "bytes": int(
                np.random.lognormal(
                    np.log(1800), 0.65
                )
            ),

            "request_count":
                np.random.poisson(25) + 1,

            "login_success":
                np.random.choice([0, 1], p=[0.08, 0.92]),

            "packet_count":
                np.random.poisson(45) + 5,

            "session_duration":
                max(
                    1,
                    int(np.random.normal(180, 70))
                ),

            "unique_ports":
                np.random.randint(1, 5),

            "connection_rate":
                round(
                    max(
                        0.1,
                        np.random.normal(1.2, 0.5)
                    ),
                    3
                ),

            "payload_size":
                int(
                    np.random.lognormal(
                        np.log(500), 0.55
                    )
                ),

            "attack_type": "BENIGN",

            "label": 0
        }

        data.append(row)

    return data


def create_attack_data(count, attack_type):

    data = []

    for _ in range(count):

        if attack_type == "BRUTE_FORCE":

            failed_logins = np.random.poisson(28) + 5
            request_count = np.random.poisson(220) + 40
            packet_count = np.random.poisson(380) + 60
            connection_rate = max(
                0.5,
                np.random.normal(7, 2.5)
            )
            port = np.random.choice(
                [21, 22, 23, 3389]
            )

        elif attack_type == "PORT_SCAN":

            failed_logins = np.random.poisson(2)
            request_count = np.random.poisson(450) + 100
            packet_count = np.random.poisson(900) + 150
            connection_rate = max(
                1,
                np.random.normal(25, 9)
            )
            port = np.random.randint(1, 65536)

        elif attack_type == "MALWARE":

            failed_logins = np.random.poisson(2)
            request_count = np.random.poisson(140) + 30
            packet_count = np.random.poisson(280) + 50
            connection_rate = max(
                0.5,
                np.random.normal(5, 2)
            )
            port = np.random.choice(
                [80, 443, 445, 8080, 8443]
            )

        elif attack_type == "DDOS":

            failed_logins = np.random.poisson(1)
            request_count = np.random.poisson(1800) + 500
            packet_count = np.random.poisson(3500) + 800
            connection_rate = max(
                5,
                np.random.normal(80, 25)
            )
            port = np.random.choice(
                [53, 80, 443]
            )

        elif attack_type == "SQL_INJECTION":

            failed_logins = np.random.poisson(2)
            request_count = np.random.poisson(160) + 30
            packet_count = np.random.poisson(250) + 50
            connection_rate = max(
                0.5,
                np.random.normal(4, 1.5)
            )
            port = np.random.choice(
                [80, 443, 8080]
            )

        elif attack_type == "PHISHING":

            failed_logins = np.random.poisson(3)
            request_count = np.random.poisson(100) + 20
            packet_count = np.random.poisson(180) + 40
            connection_rate = max(
                0.5,
                np.random.normal(3.5, 1.4)
            )
            port = np.random.choice(
                [80, 443]
            )

        elif attack_type == "BOTNET":

            failed_logins = np.random.poisson(4)
            request_count = np.random.poisson(350) + 50
            packet_count = np.random.poisson(700) + 100
            connection_rate = max(
                0.5,
                np.random.normal(12, 4)
            )
            port = np.random.randint(1, 65536)

        elif attack_type == "DATA_EXFILTRATION":

            failed_logins = np.random.poisson(2)
            request_count = np.random.poisson(300) + 80
            packet_count = np.random.poisson(1500) + 250
            connection_rate = max(
                0.5,
                np.random.normal(9, 3)
            )
            port = np.random.choice(
                [21, 22, 80, 443, 445]
            )

        else:

            failed_logins = np.random.poisson(10) + 1
            request_count = np.random.poisson(80) + 10
            packet_count = np.random.poisson(150) + 30
            connection_rate = max(
                0.5,
                np.random.normal(4, 1.5)
            )
            port = np.random.choice(
                [22, 80, 443, 3389]
            )

        row = {

            "timestamp":
                pd.Timestamp("2026-01-01")
                + pd.Timedelta(
                    seconds=np.random.randint(0, 31536000)
                ),

            "source_ip": random_ip(),

            "destination_ip": random_ip(),

            "protocol": np.random.choice(
                ["TCP", "UDP", "HTTP", "HTTPS"]
            ),

            "port": port,

            "failed_logins": failed_logins,

            "bytes": int(
                np.random.lognormal(
                    np.log(10000), 0.8
                )
            ),

            "request_count": request_count,

            "login_success":
                np.random.choice(
                    [0, 1],
                    p=[0.65, 0.35]
                ),

            "packet_count": packet_count,

            "session_duration":
                max(
                    1,
                    int(
                        np.random.normal(
                            250, 100
                        )
                    )
                ),

            "unique_ports":
                np.random.randint(1, 50),

            "connection_rate":
                round(connection_rate, 3),

            "payload_size":
                int(
                    np.random.lognormal(
                        np.log(2500), 0.8
                    )
                ),

            "attack_type": attack_type,

            "label": 1
        }

        data.append(row)

    return data


# -------------------------------------------------------
# Generate data
# -------------------------------------------------------

print("Generating benign data...")

dataset = create_benign_data(BENIGN_ROWS)

print("Generating malicious data...")

base_attack_count = MALICIOUS_ROWS // len(ATTACK_TYPES)

remaining = MALICIOUS_ROWS

for i, attack_type in enumerate(ATTACK_TYPES):

    if i == len(ATTACK_TYPES) - 1:
        count = remaining
    else:
        count = base_attack_count

    remaining -= count

    print(
        f"Generating {count} records: "
        f"{attack_type}"
    )

    dataset.extend(
        create_attack_data(
            count,
            attack_type
        )
    )


# -------------------------------------------------------
# DataFrame
# -------------------------------------------------------

df = pd.DataFrame(dataset)

df = df.sample(
    frac=1,
    random_state=42
).reset_index(drop=True)

df.insert(
    0,
    "id",
    range(1, len(df) + 1)
)


# -------------------------------------------------------
# Save
# -------------------------------------------------------

output_directory = (
    Path(__file__)
    .resolve()
    .parent
    .parent
    / "data"
)

output_directory.mkdir(
    parents=True,
    exist_ok=True
)

output_file = (
    output_directory /
    "security_logs.csv"
)

df.to_csv(
    output_file,
    index=False
)


# -------------------------------------------------------
# Information
# -------------------------------------------------------

print("\n======================================")
print("CYBER-X DATASET CREATED")
print("======================================")

print(
    f"Total records : {len(df)}"
)

print(
    f"Benign        : "
    f"{len(df[df['label'] == 0])}"
)

print(
    f"Malicious     : "
    f"{len(df[df['label'] == 1])}"
)

print("\nAttack distribution:")

print(
    df["attack_type"]
    .value_counts()
)

print("\nSaved to:")

print(
    output_file.resolve()
)

print("\nDataset generation completed.")