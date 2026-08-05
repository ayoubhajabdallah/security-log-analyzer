DASHBOARD_HTML = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta
        name="viewport"
        content="width=device-width, initial-scale=1.0"
    >
    <title>Security Log Analyzer</title>

    <style>
        * {
            box-sizing: border-box;
        }

        body {
            margin: 0;
            font-family: Arial, sans-serif;
            background: #0f172a;
            color: #e2e8f0;
        }

        .container {
            width: min(1000px, 92%);
            margin: 40px auto;
        }

        .subtitle {
            color: #94a3b8;
        }

        .card {
            margin-bottom: 24px;
            padding: 24px;
            border: 1px solid #334155;
            border-radius: 12px;
            background: #1e293b;
        }

        .form-grid,
        .summary-grid {
            display: grid;
            grid-template-columns: repeat(
                auto-fit,
                minmax(170px, 1fr)
            );
            gap: 16px;
        }

        .form-grid {
            margin-top: 18px;
        }

        label {
            display: block;
            margin-bottom: 6px;
            color: #cbd5e1;
            font-size: 14px;
        }

        input {
            width: 100%;
            padding: 10px;
            border: 1px solid #475569;
            border-radius: 7px;
            background: #0f172a;
            color: #f8fafc;
        }

        button {
            margin-top: 20px;
            padding: 12px 20px;
            border: 0;
            border-radius: 8px;
            background: #2563eb;
            color: white;
            font-size: 15px;
            cursor: pointer;
        }

        button:disabled {
            background: #475569;
            cursor: not-allowed;
        }

        .summary-item {
            padding: 16px;
            border-radius: 9px;
            background: #0f172a;
        }

        .summary-label {
            color: #94a3b8;
            font-size: 13px;
        }

        .summary-value {
            margin-top: 6px;
            font-size: 25px;
            font-weight: bold;
        }

        .alert {
            margin-top: 12px;
            padding: 14px;
            border-left: 4px solid #ef4444;
            border-radius: 7px;
            background: #321c24;
        }

        .ml-alert {
            border-left-color: #a855f7;
            background: #2d1b3d;
        }

        .success {
            border-left-color: #22c55e;
            background: #163025;
        }

        .hidden {
            display: none;
        }

        .error {
            margin-top: 16px;
            color: #fca5a5;
        }

        pre {
            overflow-x: auto;
            padding: 16px;
            border-radius: 8px;
            background: #020617;
            color: #cbd5e1;
        }
    </style>
</head>

<body>
    <main class="container">
        <header>
            <h1>Security Log Analyzer</h1>
            <p class="subtitle">
                Detect suspicious authentication activity using
                security rules and machine-learning anomaly detection.
            </p>
        </header>

        <section class="card">
            <h2>Analyze a log file</h2>

            <form id="analysis-form">
                <label for="log-file">
                    Authentication log
                </label>

                <input
                    id="log-file"
                    type="file"
                    accept=".log,.txt"
                    required
                >

                <div class="form-grid">
                    <div>
                        <label for="failed-threshold">
                            Failed-login threshold
                        </label>
                        <input
                            id="failed-threshold"
                            type="number"
                            min="1"
                            value="5"
                        >
                    </div>

                    <div>
                        <label for="minimum-users">
                            Minimum targeted users
                        </label>
                        <input
                            id="minimum-users"
                            type="number"
                            min="1"
                            value="2"
                        >
                    </div>

                    <div>
                        <label for="window-threshold">
                            Time-window threshold
                        </label>
                        <input
                            id="window-threshold"
                            type="number"
                            min="1"
                            value="3"
                        >
                    </div>

                    <div>
                        <label for="window-minutes">
                            Window length in minutes
                        </label>
                        <input
                            id="window-minutes"
                            type="number"
                            min="1"
                            value="2"
                        >
                    </div>
                </div>

                <button id="analyze-button" type="submit">
                    Analyze log
                </button>

                <p id="error-message" class="error hidden"></p>
            </form>
        </section>

        <section id="results" class="card hidden">
            <h2>Analysis result</h2>

            <div class="summary-grid">
                <div class="summary-item">
                    <div class="summary-label">Total events</div>
                    <div id="total-events" class="summary-value">0</div>
                </div>

                <div class="summary-item">
                    <div class="summary-label">
                        Failed-login alerts
                    </div>
                    <div id="failed-alerts" class="summary-value">0</div>
                </div>

                <div class="summary-item">
                    <div class="summary-label">
                        Multi-user alerts
                    </div>
                    <div id="multi-user-alerts" class="summary-value">
                        0
                    </div>
                </div>

                <div class="summary-item">
                    <div class="summary-label">
                        Brute-force alerts
                    </div>
                    <div id="brute-force-alerts" class="summary-value">
                        0
                    </div>
                </div>

                <div class="summary-item">
                    <div class="summary-label">
                        ML anomaly alerts
                    </div>
                    <div id="ml-alerts" class="summary-value">0</div>
                </div>
            </div>

            <div id="alert-list"></div>

            <h3>Raw JSON report</h3>
            <pre id="json-output"></pre>
        </section>
    </main>

    <script>
        const form = document.getElementById("analysis-form");
        const button = document.getElementById("analyze-button");
        const results = document.getElementById("results");
        const alertList = document.getElementById("alert-list");
        const errorMessage = document.getElementById(
            "error-message"
        );

        function createAlert(message, extraClass = "") {
            const element = document.createElement("div");
            element.className = `alert ${extraClass}`;
            element.textContent = message;
            alertList.appendChild(element);
        }

        form.addEventListener("submit", async (event) => {
            event.preventDefault();

            results.classList.add("hidden");
            errorMessage.classList.add("hidden");
            button.disabled = true;
            button.textContent = "Analyzing...";

            const file = document.getElementById(
                "log-file"
            ).files[0];

            const formData = new FormData();
            formData.append("file", file);

            const parameters = new URLSearchParams({
                failed_threshold:
                    document.getElementById(
                        "failed-threshold"
                    ).value,
                minimum_users:
                    document.getElementById(
                        "minimum-users"
                    ).value,
                window_threshold:
                    document.getElementById(
                        "window-threshold"
                    ).value,
                window_minutes:
                    document.getElementById(
                        "window-minutes"
                    ).value,
            });

            try {
                const response = await fetch(
                    `/analyze?${parameters.toString()}`,
                    {
                        method: "POST",
                        body: formData,
                    }
                );

                const data = await response.json();

                if (!response.ok) {
                    throw new Error(
                        data.detail || "Analysis failed."
                    );
                }

                document.getElementById(
                    "total-events"
                ).textContent = data.total_events;

                document.getElementById(
                    "failed-alerts"
                ).textContent = Object.keys(
                    data.suspicious_ips
                ).length;

                document.getElementById(
                    "multi-user-alerts"
                ).textContent = Object.keys(
                    data.multi_user_ips
                ).length;

                document.getElementById(
                    "brute-force-alerts"
                ).textContent = Object.keys(
                    data.brute_force_ips
                ).length;

                document.getElementById(
                    "ml-alerts"
                ).textContent = Object.keys(
                    data.ml_anomalies
                ).length;

                alertList.innerHTML = "";

                for (
                    const [ipAddress, attempts]
                    of Object.entries(data.suspicious_ips)
                ) {
                    createAlert(
                        `${ipAddress} has ${attempts} ` +
                        "failed login attempts."
                    );
                }

                for (
                    const [ipAddress, usernames]
                    of Object.entries(data.multi_user_ips)
                ) {
                    createAlert(
                        `${ipAddress} targeted multiple users: ` +
                        `${usernames.join(", ")}.`
                    );
                }

                for (
                    const [ipAddress, attempts]
                    of Object.entries(data.brute_force_ips)
                ) {
                    createAlert(
                        `${ipAddress} made ${attempts} failed ` +
                        "attempts inside the configured time window."
                    );
                }

                for (
                    const [ipAddress, anomaly]
                    of Object.entries(data.ml_anomalies)
                ) {
                    createAlert(
                        `${ipAddress} shows unusual ML behavior. ` +
                        `Score: ${anomaly.anomaly_score}, ` +
                        `failures: ${anomaly.failed_attempts}, ` +
                        `users: ${anomaly.unique_users}.`,
                        "ml-alert"
                    );
                }

                if (alertList.children.length === 0) {
                    createAlert(
                        "No suspicious activity detected.",
                        "success"
                    );
                }

                document.getElementById(
                    "json-output"
                ).textContent = JSON.stringify(
                    data,
                    null,
                    2
                );

                results.classList.remove("hidden");
            } catch (error) {
                errorMessage.textContent = error.message;
                errorMessage.classList.remove("hidden");
            } finally {
                button.disabled = false;
                button.textContent = "Analyze log";
            }
        });
    </script>
</body>
</html>
"""