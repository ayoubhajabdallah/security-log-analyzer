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
            width: min(900px, 92%);
            margin: 40px auto;
        }

        .header {
            margin-bottom: 28px;
        }

        h1 {
            margin-bottom: 8px;
        }

        .subtitle {
            color: #94a3b8;
        }

        .card {
            background: #1e293b;
            border: 1px solid #334155;
            border-radius: 12px;
            padding: 24px;
            margin-bottom: 24px;
        }

        .form-grid {
            display: grid;
            grid-template-columns: repeat(
                auto-fit,
                minmax(180px, 1fr)
            );
            gap: 16px;
            margin-top: 18px;
        }

        label {
            display: block;
            margin-bottom: 6px;
            font-size: 14px;
            color: #cbd5e1;
        }

        input {
            width: 100%;
            padding: 10px;
            border: 1px solid #475569;
            border-radius: 7px;
            background: #0f172a;
            color: #f8fafc;
        }

        input[type="file"] {
            padding: 8px;
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

        button:hover {
            background: #1d4ed8;
        }

        button:disabled {
            background: #475569;
            cursor: not-allowed;
        }

        .summary-grid {
            display: grid;
            grid-template-columns: repeat(
                auto-fit,
                minmax(160px, 1fr)
            );
            gap: 14px;
        }

        .summary-item {
            background: #0f172a;
            border-radius: 9px;
            padding: 16px;
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
            border-left: 4px solid #ef4444;
            background: #321c24;
            border-radius: 7px;
            padding: 14px;
            margin-top: 12px;
        }

        .success {
            border-left-color: #22c55e;
            background: #163025;
        }

        .hidden {
            display: none;
        }

        pre {
            overflow-x: auto;
            padding: 16px;
            border-radius: 8px;
            background: #020617;
            color: #cbd5e1;
        }

        .error {
            color: #fca5a5;
            margin-top: 16px;
        }
    </style>
</head>

<body>
    <main class="container">
        <header class="header">
            <h1>Security Log Analyzer</h1>
            <p class="subtitle">
                Upload authentication logs and detect suspicious activity.
            </p>
        </header>

        <section class="card">
            <h2>Analyze a log file</h2>

            <form id="analysis-form">
                <div>
                    <label for="log-file">
                        Authentication log
                    </label>
                    <input
                        id="log-file"
                        name="file"
                        type="file"
                        accept=".log,.txt"
                        required
                    >
                </div>

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
                    <div class="summary-label">
                        Total events
                    </div>
                    <div
                        id="total-events"
                        class="summary-value"
                    >
                        0
                    </div>
                </div>

                <div class="summary-item">
                    <div class="summary-label">
                        Failed-login alerts
                    </div>
                    <div
                        id="failed-alerts"
                        class="summary-value"
                    >
                        0
                    </div>
                </div>

                <div class="summary-item">
                    <div class="summary-label">
                        Multi-user alerts
                    </div>
                    <div
                        id="multi-user-alerts"
                        class="summary-value"
                    >
                        0
                    </div>
                </div>

                <div class="summary-item">
                    <div class="summary-label">
                        Brute-force alerts
                    </div>
                    <div
                        id="brute-force-alerts"
                        class="summary-value"
                    >
                        0
                    </div>
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
        const errorMessage = document.getElementById(
            "error-message"
        );
        const results = document.getElementById("results");
        const alertList = document.getElementById("alert-list");

        function createAlert(message, isSuccess = false) {
            const alert = document.createElement("div");
            alert.className = isSuccess
                ? "alert success"
                : "alert";
            alert.textContent = message;
            alertList.appendChild(alert);
        }

        form.addEventListener("submit", async (event) => {
            event.preventDefault();

            errorMessage.classList.add("hidden");
            results.classList.add("hidden");
            button.disabled = true;
            button.textContent = "Analyzing...";

            const fileInput = document.getElementById("log-file");
            const formData = new FormData();
            formData.append("file", fileInput.files[0]);

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

                if (alertList.children.length === 0) {
                    createAlert(
                        "No suspicious activity detected.",
                        true
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