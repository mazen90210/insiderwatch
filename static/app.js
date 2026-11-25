// ==========================================
// InsiderWatch - Dashboard & Incident Management
// Session Authentication
// ==========================================

let activityChart;
let authPromise = null;


// ==========================================
// GENERAL HELPERS
// ==========================================

function number(value) {
    return Number(value || 0).toLocaleString();
}

function setText(id, value) {
    const element = document.getElementById(id);
    if (element) element.textContent = value;
}

function escapeHTML(value) {
    return String(value ?? "").replace(/[&<>"']/g, char => ({
        "&": "&amp;",
        "<": "&lt;",
        ">": "&gt;",
        '"': "&quot;",
        "'": "&#039;"
    })[char]);
}

function formatDate(value) {
    return value ? new Date(value).toLocaleString() : "—";
}


// ==========================================
// SESSION AUTHENTICATION
// ==========================================

async function login() {
    const adminKey = prompt("Enter InsiderWatch Admin Key:");

    if (!adminKey || !adminKey.trim()) {
        throw new Error("Admin login is required.");
    }

    const response = await fetch("/api/auth/login", {
        method: "POST",
        credentials: "same-origin",
        headers: {
            "Content-Type": "application/json"
        },
        body: JSON.stringify({
            admin_key: adminKey.trim()
        })
    });

    const data = await response.json();

    if (!response.ok) {
        throw new Error(data.error || "Login failed.");
    }

    return true;
}


async function ensureAdminSession() {

    if (authPromise) {
        return authPromise;
    }

    authPromise = (async () => {

        const response = await fetch("/api/auth/status", {
            credentials: "same-origin"
        });

        if (!response.ok) {
            throw new Error("Unable to check authentication.");
        }

        const data = await response.json();

        if (data.authenticated) {
            return true;
        }

        return await login();

    })();

    try {
        return await authPromise;
    } finally {
        authPromise = null;
    }
}


async function apiFetch(url, options = {}) {

    await ensureAdminSession();

    const settings = {
        ...options,
        credentials: "same-origin",
        headers: {
            ...(options.headers || {})
        }
    };

    let response = await fetch(url, settings);

    if (response.status === 401) {

        authPromise = null;

        await login();

        response = await fetch(url, settings);
    }

    return response;
}


async function logout() {

    try {

        const response = await fetch("/api/auth/logout", {
            method: "POST",
            credentials: "same-origin"
        });

        if (!response.ok) {
            throw new Error("Logout failed.");
        }

        location.reload();

    } catch (error) {

        console.error(error);
        alert(error.message);

    }
}


// ==========================================
// DASHBOARD - RISK PROFILES
// ==========================================

function renderRisk(results) {

    const body = document.getElementById("risk-table");

    if (!results || !results.length) {

        body.innerHTML =
            '<tr><td colspan="5" class="empty">No AI profiles available</td></tr>';

        return;
    }

    body.innerHTML = results.slice(0, 10).map(item => {

        const level = (item.threat_level || "Low").toLowerCase();

        return `
            <tr>
                <td>${escapeHTML(item.host || "Unknown")}</td>
                <td>${escapeHTML(item.username || "Unknown")}</td>
                <td class="score">${number(item.risk_score)}/100</td>
                <td>
                    <span class="badge-level level-${escapeHTML(level)}">
                        ${escapeHTML(item.threat_level)}
                    </span>
                </td>
                <td>
                    ${item.is_anomaly
                        ? "<span style='color:#ff8394'>Detected</span>"
                        : "<span style='color:#66dfb4'>Normal</span>"}
                </td>
            </tr>
        `;

    }).join("");
}


// ==========================================
// DASHBOARD - SECURITY EVENTS
// ==========================================

let allSecurityEvents = [];

function renderEvents(events) {
    allSecurityEvents = events || [];
    applyEventFilters();
}

function applyEventFilters() {
    const search = (
        document.getElementById("event-search")?.value || ""
    ).toLowerCase().trim();

    const eventType =
        document.getElementById("event-type-filter")?.value || "";

    const filtered = allSecurityEvents.filter(event => {
        const searchableText = [
            event.host,
            event.username,
            event.message,
            event.event_type
        ].join(" ").toLowerCase();

        const matchesSearch = searchableText.includes(search);
        const matchesType = !eventType || event.event_type === eventType;

        return matchesSearch && matchesType;
    });

    const body = document.getElementById("events-table");

    if (!filtered.length) {
        body.innerHTML =
            '<tr><td colspan="5" class="empty">No matching events found</td></tr>';
        return;
    }

    body.innerHTML = filtered.map(event => `
        <tr>
            <td>${escapeHTML(formatDate(event.ts))}</td>
            <td>${escapeHTML(event.host || "—")}</td>
            <td>${escapeHTML(event.username || "—")}</td>
            <td>${escapeHTML(event.event_type || "—")}</td>
            <td class="event-message-cell">
                <div class="event-message-preview">
                    ${escapeHTML(event.message || "—")}
                </div>
                <details class="event-message-details">
                    <summary>View Full Message</summary>
                    <div class="event-full-message">
                        ${escapeHTML(event.message || "—")}
                    </div>
                </details>
            </td>
        </tr>
    `).join("");
}

function resetEventFilters() {
    document.getElementById("event-search").value = "";
    document.getElementById("event-type-filter").value = "";
    applyEventFilters();
}

document.getElementById("event-search")?.addEventListener(
    "input",
    applyEventFilters
);

document.getElementById("event-type-filter")?.addEventListener(
    "change",
    applyEventFilters
);


// ==========================================
// DASHBOARD - ACTIVITY CHART
// ==========================================

function renderChart(stats) {

    const labels = Object.keys(stats)
        .filter(key => key !== "total_events");

    const values = labels.map(key => Number(stats[key] || 0));

    if (activityChart) {
        activityChart.destroy();
    }

    activityChart = new Chart(
        document.getElementById("activityChart"),
        {
            type: "bar",

            data: {
                labels,

                datasets: [{
                    label: "Events",
                    data: values,
                    backgroundColor: "#6688ff",
                    borderRadius: 5,
                    maxBarThickness: 38
                }]
            },

            options: {
                responsive: true,
                maintainAspectRatio: false,

                plugins: {
                    legend: {
                        display: false
                    }
                },

                scales: {
                    x: {
                        ticks: {
                            color: "#91a0ba",
                            font: { size: 10 }
                        },
                        grid: { display: false }
                    },

                    y: {
                        beginAtZero: true,
                        ticks: {
                            color: "#71819d",
                            precision: 0
                        },
                        grid: {
                            color: "#253149"
                        }
                    }
                }
            }
        }
    );
}


// ==========================================
// LOAD DASHBOARD
// ==========================================

async function loadDashboard() {

    try {

        const [
            statsResponse,
            aiResponse,
            eventsResponse
        ] = await Promise.all([

            apiFetch("/api/stats"),
            apiFetch("/api/ai/analyze"),
            apiFetch("/api/events")

        ]);

        if (
            !statsResponse.ok ||
            !aiResponse.ok ||
            !eventsResponse.ok
        ) {
            throw new Error("Dashboard API request failed");
        }

        const stats = await statsResponse.json();
        const ai = await aiResponse.json();
        const events = await eventsResponse.json();

        setText("total-events", number(stats.total_events));
        setText("failed-logins", number(stats.failed_login));
        setText("profiles", number(ai.profiles_analyzed));

        const results = ai.results || [];

        setText(
            "anomalies",
            number(results.filter(item => item.is_anomaly).length)
        );

        ["Critical", "High", "Medium", "Low"].forEach(level => {

            setText(
                level.toLowerCase() + "-count",
                number(
                    results.filter(item =>
                        item.threat_level === level
                    ).length
                )
            );

        });

        setText(
            "ai-status",
            ai.model_trained
                ? "AI ENGINE ONLINE · ISOLATION FOREST TRAINED"
                : "AI ENGINE ONLINE · RULE-BASED MODE"
        );

        renderRisk(results);
        renderEvents(events.events || []);
        renderChart(stats);

        setText(
            "last-updated",
            "Last updated: " + new Date().toLocaleTimeString()
        );

    } catch (error) {

        setText(
            "ai-status",
            "Unable to load dashboard data. Check API connection."
        );

        console.error(error);
    }
}


// ==========================================
// INCIDENT MANAGEMENT - LOAD INCIDENTS
// ==========================================

async function loadIncidents() {

    const body = document.getElementById("incidents-table");

    try {

        body.innerHTML =
            '<tr><td colspan="9" class="empty">Loading incidents...</td></tr>';

        const response = await apiFetch("/api/incidents");

        if (!response.ok) {
            throw new Error("Could not load incidents");
        }

        const data = await response.json();

        const incidents = Array.isArray(data)
            ? data
            : (data.incidents || []);

        if (!incidents.length) {

            body.innerHTML =
                '<tr><td colspan="9" class="empty">No incidents found</td></tr>';

            return;
        }

        body.innerHTML = incidents.map(incident => `

            <tr>

                <td>#${escapeHTML(incident.id)}</td>

                <td>${escapeHTML(incident.title)}</td>

                <td>${escapeHTML(incident.host || "—")}</td>

                <td>${escapeHTML(incident.username || "—")}</td>

                <td>${escapeHTML(incident.severity)}</td>

                <td>${escapeHTML(incident.risk_score)}/100</td>

                <td>
                    <span class="badge-level">
                        ${escapeHTML(incident.status)}
                    </span>
                </td>

                <td>${escapeHTML(formatDate(incident.created_at))}</td>

                <td>
                    <button
                        class="refresh-btn"
                        onclick="openIncidentDetails(${Number(incident.id)})">
                        Manage
                    </button>
                </td>

            </tr>

        `).join("");

    } catch (error) {

        body.innerHTML = `
            <tr>
                <td colspan="9" class="empty">
                    Unable to load incidents.
                </td>
            </tr>
        `;

        console.error(error);
    }
}


// ==========================================
// CREATE INCIDENT
// ==========================================

document.getElementById("incident-form")
    .addEventListener("submit", async function(event) {

        event.preventDefault();

        const message = document.getElementById(
            "incident-form-message"
        );

        const payload = {

            title: document.getElementById(
                "incident-title"
            ).value.trim(),

            description: document.getElementById(
                "incident-description"
            ).value.trim(),

            host: document.getElementById(
                "incident-host"
            ).value.trim(),

            username: document.getElementById(
                "incident-username"
            ).value.trim(),

            severity: document.getElementById(
                "incident-severity"
            ).value,

            risk_score: Number(
                document.getElementById("incident-risk").value
            )

        };

        try {

            message.textContent = "Creating incident...";

            const response = await apiFetch("/api/incidents", {

                method: "POST",

                headers: {
                    "Content-Type": "application/json"
                },

                body: JSON.stringify(payload)

            });

            const data = await response.json();

            if (!response.ok) {

                throw new Error(
                    data.error || "Failed to create incident"
                );

            }

            message.textContent = "Incident created successfully!";
            message.style.color = "#66dfb4";

            this.reset();

            await loadIncidents();

            if (data.incident_id) {
                await openIncidentDetails(data.incident_id);
            }

        } catch (error) {

            message.textContent = error.message;
            message.style.color = "#ff8394";

            console.error(error);
        }
    });


// ==========================================
// OPEN INCIDENT DETAILS
// ==========================================

async function openIncidentDetails(id) {

    const section = document.getElementById("incident-details");

    section.style.display = "block";

    section.scrollIntoView({
        behavior: "smooth",
        block: "start"
    });

    setText("incident-details-subtitle", "Incident #" + id);

    document.getElementById("selected-incident-id").value = id;

    document.getElementById("incident-details-content").innerHTML =
        "Loading incident details...";

    document.getElementById("incident-audit-table").innerHTML =
        '<tr><td colspan="4" class="empty">Loading activity log...</td></tr>';

    try {

        const [
            incidentsResponse,
            auditResponse
        ] = await Promise.all([

            apiFetch("/api/incidents"),
            apiFetch(`/api/incidents/${id}/audit`)

        ]);

        if (!incidentsResponse.ok || !auditResponse.ok) {

            throw new Error("Unable to load incident information");

        }

        const incidentsData = await incidentsResponse.json();
        const auditData = await auditResponse.json();

        const incidents = Array.isArray(incidentsData)
            ? incidentsData
            : (incidentsData.incidents || []);

        const incident = incidents.find(
            item => Number(item.id) === Number(id)
        );

        if (!incident) {
            throw new Error("Incident not found");
        }

        window.currentIncidentReport = {
            incident: incident,
            audit: auditData.audit || auditData.entries || auditData
        };

        document.getElementById("incident-details-content").innerHTML = `

            <div class="row g-3">

                <div class="col-md-6">
                    <strong>Incident ID:</strong>
                    #${escapeHTML(incident.id)}
                </div>

                <div class="col-md-6">
                    <strong>Title:</strong>
                    ${escapeHTML(incident.title)}
                </div>

                <div class="col-md-6">
                    <strong>Host:</strong>
                    ${escapeHTML(incident.host || "—")}
                </div>

                <div class="col-md-6">
                    <strong>Username:</strong>
                    ${escapeHTML(incident.username || "—")}
                </div>

                <div class="col-md-6">
                    <strong>Severity:</strong>
                    ${escapeHTML(incident.severity)}
                </div>

                <div class="col-md-6">
                    <strong>Risk Score:</strong>
                    ${escapeHTML(incident.risk_score)}/100
                </div>

                <div class="col-md-6">
                    <strong>Status:</strong>
                    ${escapeHTML(incident.status)}
                </div>

                <div class="col-md-6">
                    <strong>Created:</strong>
                    ${escapeHTML(formatDate(incident.created_at))}
                </div>

                <div class="col-12">
                    <strong>Description:</strong>
                    <p>${escapeHTML(incident.description || "No description")}</p>
                </div>

                <div class="col-12 mt-3">
                    <button type="button" class="refresh-btn"
                        onclick="requestIncidentLogCollection(${Number(incident.id)})">
                        Collect Security Logs
                    </button>

                    <button type="button" class="refresh-btn"
                        onclick="generateIncidentReport()">
                        Generate PDF Report
                    </button>
                    <div id="incident-response-message" class="mt-2"></div>
                </div>

            </div>

        `;

        document.getElementById("incident-status").value =
            incident.status || "Open";

        document.getElementById("investigation-notes").value =
            incident.investigation_notes || "";

        document.getElementById("incident-resolution").value =
            incident.resolution || "";

        renderIncidentAudit(
            auditData.audit || auditData.entries || auditData
        );

    } catch (error) {

        document.getElementById("incident-details-content").textContent =
            error.message;

        console.error(error);
    }
}


// ==========================================
// RENDER INCIDENT ACTIVITY LOG
// ==========================================

function renderIncidentAudit(audit) {

    const body = document.getElementById("incident-audit-table");

    if (!Array.isArray(audit) || !audit.length) {

        body.innerHTML =
            '<tr><td colspan="4" class="empty">No activity records found</td></tr>';

        return;
    }

    body.innerHTML = audit.map(entry => `

        <tr>

            <td>${escapeHTML(formatDate(entry.created_at))}</td>

            <td>${escapeHTML(entry.actor || "admin")}</td>

            <td>${escapeHTML(entry.action || "—")}</td>

            <td>${escapeHTML(entry.details || "—")}</td>

        </tr>

    `).join("");
}


// ==========================================
// UPDATE INCIDENT
// ==========================================

document.getElementById("incident-update-form")
    .addEventListener("submit", async function(event) {

        event.preventDefault();

        const id = document.getElementById(
            "selected-incident-id"
        ).value;

        const message = document.getElementById(
            "incident-update-message"
        );

        const payload = {

            status: document.getElementById(
                "incident-status"
            ).value,

            investigation_notes: document.getElementById(
                "investigation-notes"
            ).value.trim(),

            resolution: document.getElementById(
                "incident-resolution"
            ).value.trim()

        };

        try {

            message.textContent = "Saving changes...";

            const response = await apiFetch(`/api/incidents/${id}`, {

                method: "PATCH",

                headers: {
                    "Content-Type": "application/json"
                },

                body: JSON.stringify(payload)

            });

            const data = await response.json();

            if (!response.ok) {

                throw new Error(
                    data.error || "Failed to update incident"
                );

            }

            message.textContent = "Incident updated successfully!";
            message.style.color = "#66dfb4";

            await loadIncidents();
            await openIncidentDetails(id);

            message.textContent = "Changes saved successfully!";

        } catch (error) {

            message.textContent = error.message;
            message.style.color = "#ff8394";

            console.error(error);
        }
    });


// ==========================================
// CLOSE INCIDENT DETAILS
// ==========================================

function closeIncidentDetails() {

    document.getElementById("incident-details").style.display = "none";

}


// ==========================================
// INITIALIZATION
// ==========================================

loadDashboard();

loadIncidents();

setInterval(loadDashboard, 15000);

setInterval(loadIncidents, 30000);
// ==========================================
// RESPONSE CENTER
// ==========================================

async function loadResponseActions() {

    const table = document.getElementById("response-actions-table");

    if (!table) return;

    try {

        const response = await apiFetch("/api/response-actions");
        const data = await response.json();

        if (!response.ok) {
            throw new Error(data.error || "Failed to load response actions");
        }

        const actions = data.actions || [];
        const stats = data.stats || {};

        document.getElementById("response-total").textContent =
            stats.total ?? 0;

        document.getElementById("response-completed").textContent =
            stats.completed ?? 0;

        document.getElementById("response-failed").textContent =
            stats.failed ?? 0;

        document.getElementById("response-pending").textContent =
            stats.pending ?? 0;

        document.getElementById("response-events-collected").textContent =
            stats.events_collected ?? 0;

        renderResponseChart(stats);

        if (!actions.length) {
            table.innerHTML = `
                <tr><td colspan="8" class="empty">
                    No response actions found.
                </td></tr>`;
            return;
        }

        table.innerHTML = actions.map(action => {

            const result = action.result || {};

            return `
                <tr>
                    <td>#${Number(action.id)}</td>
                    <td>#${Number(action.incident_id)}</td>
                    <td>${escapeHTML(action.action_type)}</td>
                    <td><span class="response-status response-${String(action.status || "").toLowerCase()}">${escapeHTML(action.status)}</span></td>
                    <td>${result.events_found ?? "—"}</td>
                    <td>${result.events_uploaded ?? "—"}</td>
                    <td>
                        <div class="response-result-details">
                            <strong>${escapeHTML(result.host || result.hostname || "Unknown Host")}</strong>
                            <div>${escapeHTML(result.summary || "No summary available")}</div>
                            <small>Requested: ${result.requested_events ?? "—"} events</small>
                            <br>
                            <small>Completed: ${escapeHTML(formatDate(action.completed_at) || "—")}</small>
                        </div>
                    </td>
                    <td>
                        ${escapeHTML(formatDate(action.created_at))}
                        <br>
                        <button type="button"
                            class="btn-secondary"
                            onclick="toggleResponseDetails(${Number(action.id)})">
                            View Details
                        </button>
                    </td>
                </tr>
                <tr id="response-details-${Number(action.id)}" style="display:none;">
                    <td colspan="8">
                        <div class="response-result-details">
                            <strong>Response Action #${Number(action.id)}</strong>
                            <div>Host: ${escapeHTML(result.host || result.hostname || "Unknown")}</div>
                            <small>Action: ${escapeHTML(action.action_type)}</small><br>
                            <small>Status: ${escapeHTML(action.status)}</small><br>
                            <small>Requested By: ${escapeHTML(action.requested_by || "—")}</small><br>
                            <small>Events Found: ${result.events_found ?? "—"}</small><br>
                            <small>Events Uploaded: ${result.events_uploaded ?? "—"}</small><br>
                            <small>Summary: ${escapeHTML(result.summary || "—")}</small><br>
                            <small>Created: ${escapeHTML(formatDate(action.created_at))}</small><br>
                            <small>Completed: ${escapeHTML(formatDate(action.completed_at) || "—")}</small>
                        </div>
                    </td>
                </tr>
            `;

        }).join("");

    } catch (error) {

        console.error("Response Center:", error);

        table.innerHTML = `
            <tr><td colspan="8" class="empty">
                Failed to load response actions.
            </td></tr>`;
    }
}


// ==========================================
// CREATE RESPONSE ACTION
// ==========================================

document.getElementById("response-action-form")
    .addEventListener("submit", async function(event) {

        event.preventDefault();

        const message = document.getElementById("response-message");

        const incidentId = Number(
            document.getElementById("response-incident-id").value
        );

        const maxEvents = Number(
            document.getElementById("response-max-events").value
        );

        if (!Number.isInteger(incidentId) || incidentId <= 0) {
            message.textContent = "Enter a valid Incident ID.";
            message.style.color = "#ff8394";
            return;
        }

        if (!Number.isInteger(maxEvents) ||
            maxEvents < 1 || maxEvents > 200) {

            message.textContent = "Maximum Events must be between 1 and 200.";
            message.style.color = "#ff8394";
            return;
        }

        const button = this.querySelector('button[type="submit"]');

        try {

            button.disabled = true;
            message.textContent = "Submitting request...";

            const response = await apiFetch("/api/response-actions", {
                method: "POST",
                headers: {
                    "Content-Type": "application/json"
                },
                body: JSON.stringify({
                    incident_id: incidentId,
                    action_type: "collect_security_logs",
                    max_events: maxEvents
                })
            });

            const data = await response.json();

            if (!response.ok) {
                throw new Error(data.error || "Failed to create response action");
            }

            message.textContent =
                `Request #${data.action_id} created successfully!`;

            message.style.color = "#66dfb4";

            await loadResponseActions();

        } catch (error) {

            message.textContent = error.message;
            message.style.color = "#ff8394";

            console.error(error);

        } finally {

            button.disabled = false;
        }
    });


// ==========================================
// RESPONSE CENTER INITIALIZATION
// ==========================================

loadResponseActions();

setInterval(loadResponseActions, 10000);


// ==========================================
// RESPONSE ACTION DETAILS
// ==========================================

function toggleResponseDetails(actionId) {

    const row = document.getElementById(`response-details-${actionId}`);

    if (!row) return;

    row.style.display =
        row.style.display === "none" ? "table-row" : "none";
}


// ==========================================
// INCIDENT - REQUEST SECURITY LOG COLLECTION
// ==========================================

async function requestIncidentLogCollection(incidentId) {

    const message = document.getElementById("incident-response-message");

    if (!confirm(`Request Security Log Collection for Incident #${incidentId}?`)) {
        return;
    }

    try {

        message.textContent = "Submitting log collection request...";
        message.style.color = "#78a7ff";

        const response = await apiFetch("/api/response-actions", {
            method: "POST",
            headers: {
                "Content-Type": "application/json"
            },
            body: JSON.stringify({
                incident_id: Number(incidentId),
                action_type: "collect_security_logs",
                max_events: 50
            })
        });

        const data = await response.json();

        if (!response.ok) {
            throw new Error(data.error || "Request failed");
        }

        message.textContent =
            `Request #${data.action_id} created successfully!`;

        message.style.color = "#66dfb4";

        await loadResponseActions();

    } catch (error) {

        message.textContent = error.message;
        message.style.color = "#ff8394";

        console.error("Incident Response:", error);
    }
}


// ==========================================
// RESPONSE ACTIONS DISTRIBUTION CHART
// ==========================================

let responseStatusChart = null;

function renderResponseChart(stats) {

    const canvas = document.getElementById("responseStatusChart");

    if (!canvas || typeof Chart === "undefined") return;

    const completed = Number(stats.completed || 0);
    const failed = Number(stats.failed || 0);
    const pending = Number(stats.pending || 0);

    if (responseStatusChart) {
        responseStatusChart.destroy();
    }

    responseStatusChart = new Chart(canvas, {
        type: "doughnut",

        data: {
            labels: [
                "Completed",
                "Failed",
                "Pending / Running"
            ],

            datasets: [{
                data: [completed, failed, pending],
                backgroundColor: [
                    "#28c997",
                    "#ff647c",
                    "#f5b942"
                ],
                borderWidth: 2,
                borderColor: "#111d32"
            }]
        },

        options: {
            responsive: true,
            maintainAspectRatio: false,

            plugins: {
                legend: {
                    position: "bottom",
                    labels: {
                        color: "#c5d1e5",
                        padding: 20
                    }
                }
            }
        }
    });
}
function exportSecurityEvents() {
    const search = (
        document.getElementById("event-search")?.value || ""
    ).toLowerCase().trim();

    const eventType =
        document.getElementById("event-type-filter")?.value || "";

    const filtered = allSecurityEvents.filter(event => {
        const text = [
            event.host,
            event.username,
            event.message,
            event.event_type
        ].join(" ").toLowerCase();

        return text.includes(search) &&
            (!eventType || event.event_type === eventType);
    });

    if (!filtered.length) {
        alert("No security events to export.");
        return;
    }

    const headers = [
        "Time",
        "Host",
        "Username",
        "Event Type",
        "Message"
    ];

    const escapeCSV = value =>
        '"' + String(value ?? "").replace(/"/g, '""') + '"';

    const rows = filtered.map(event => [
        event.ts,
        event.host,
        event.username,
        event.event_type,
        event.message
    ]);

    const csv = "\uFEFF" + [
        headers,
        ...rows
    ].map(row => row.map(escapeCSV).join(",")).join("\r\n");

    const blob = new Blob([csv], {
        type: "text/csv;charset=utf-8;"
    });

    const url = URL.createObjectURL(blob);
    const link = document.createElement("a");

    link.href = url;
    link.download = "InsiderWatch_Security_Events.csv";
    document.body.appendChild(link);
    link.click();
    link.remove();

    URL.revokeObjectURL(url);
}


async function generateIncidentReport() {

    const reportData = window.currentIncidentReport;

    if (!reportData || !reportData.incident) {
        alert("Please open an incident first.");
        return;
    }

    const printWindow = window.open("", "_blank");

    if (!printWindow) {
        alert("Please allow pop-ups to generate the report.");
        return;
    }

    const incident = reportData.incident;
    const audit = Array.isArray(reportData.audit)
        ? reportData.audit
        : [];

    try {
        const response = await apiFetch(
            `/api/response-actions?incident_id=${incident.id}`
        );

        if (!response.ok) {
            throw new Error("Unable to load response actions.");
        }

        const responseData = await response.json();
        const actions = responseData.actions || [];

        const field = (value) =>
            escapeHTML(value ?? "�");

        const auditRows = audit.map(entry => `
            <tr>
                <td>${field(formatDate(entry.created_at))}</td>
                <td>${field(entry.actor)}</td>
                <td>${field(entry.action)}</td>
                <td>${field(entry.details)}</td>
            </tr>
        `).join("");

        const actionRows = actions.map(action => `
            <tr>
                <td>${field(action.id)}</td>
                <td>${field(action.action_type)}</td>
                <td>${field(action.status)}</td>
                <td>${field(action.requested_by)}</td>
                <td>${field(JSON.stringify(action.result || {}))}</td>
            </tr>
        `).join("");

        printWindow.document.write(`
            <!DOCTYPE html>
            <html>
            <head>
                <meta charset="UTF-8">
                <title>InsiderWatch Incident Report #${incident.id}</title>

                <style>
                    body {
                        font-family: Arial, sans-serif;
                        color: #202b3c;
                        padding: 35px;
                        line-height: 1.6;
                    }

                    h1 {
                        color: #244b85;
                        margin-bottom: 5px;
                    }

                    h2 {
                        color: #244b85;
                        border-bottom: 2px solid #dce5f1;
                        padding-bottom: 8px;
                        margin-top: 30px;
                    }

                    .subtitle {
                        color: #68778c;
                        margin-bottom: 30px;
                    }

                    .info-grid {
                        display: grid;
                        grid-template-columns: 1fr 1fr;
                        gap: 12px;
                    }

                    .info-card {
                        padding: 12px;
                        background: #f3f6fa;
                        border-radius: 6px;
                    }

                    .label {
                        font-size: 11px;
                        color: #68778c;
                        font-weight: bold;
                    }

                    .value {
                        font-weight: bold;
                        overflow-wrap: anywhere;
                    }

                    .description {
                        white-space: pre-wrap;
                        overflow-wrap: anywhere;
                    }

                    table {
                        width: 100%;
                        border-collapse: collapse;
                        font-size: 11px;
                        margin-top: 12px;
                    }

                    th, td {
                        border: 1px solid #dce3ec;
                        padding: 9px;
                        text-align: left;
                        overflow-wrap: anywhere;
                    }

                    th {
                        background: #edf2f8;
                    }

                    .footer {
                        margin-top: 40px;
                        padding-top: 12px;
                        border-top: 1px solid #ddd;
                        font-size: 11px;
                        color: #68778c;
                        text-align: center;
                    }

                    @media print {
                        body { padding: 10px; }
                        tr { page-break-inside: avoid; }
                    }
                </style>
            </head>

            <body>

                <h1>InsiderWatch</h1>
                <div class="subtitle">
                    Security Incident Investigation Report
                </div>

                <h2>Incident Information</h2>

                <div class="info-grid">

                    <div class="info-card">
                        <div class="label">INCIDENT ID</div>
                        <div class="value">#${field(incident.id)}</div>
                    </div>

                    <div class="info-card">
                        <div class="label">TITLE</div>
                        <div class="value">${field(incident.title)}</div>
                    </div>

                    <div class="info-card">
                        <div class="label">HOST</div>
                        <div class="value">${field(incident.host)}</div>
                    </div>

                    <div class="info-card">
                        <div class="label">USERNAME</div>
                        <div class="value">${field(incident.username)}</div>
                    </div>

                    <div class="info-card">
                        <div class="label">SEVERITY</div>
                        <div class="value">${field(incident.severity)}</div>
                    </div>

                    <div class="info-card">
                        <div class="label">RISK SCORE</div>
                        <div class="value">${field(incident.risk_score)}/100</div>
                    </div>

                    <div class="info-card">
                        <div class="label">STATUS</div>
                        <div class="value">${field(incident.status)}</div>
                    </div>

                    <div class="info-card">
                        <div class="label">CREATED</div>
                        <div class="value">${field(formatDate(incident.created_at))}</div>
                    </div>

                </div>

                <h2>Incident Description</h2>
                <p class="description">${field(incident.description || "No description")}</p>

                <h2>Investigation Notes</h2>
                <p class="description">${field(incident.investigation_notes || "No investigation notes")}</p>

                <h2>Resolution</h2>
                <p class="description">${field(incident.resolution || "No resolution recorded")}</p>

                <h2>Response Actions</h2>

                <table>
                    <thead>
                        <tr>
                            <th>ID</th>
                            <th>Action</th>
                            <th>Status</th>
                            <th>Requested By</th>
                            <th>Result</th>
                        </tr>
                    </thead>
                    <tbody>
                        ${actionRows || '<tr><td colspan="5">No response actions recorded.</td></tr>'}
                    </tbody>
                </table>

                <h2>Activity Log</h2>

                <table>
                    <thead>
                        <tr>
                            <th>Time</th>
                            <th>Actor</th>
                            <th>Action</th>
                            <th>Details</th>
                        </tr>
                    </thead>
                    <tbody>
                        ${auditRows || '<tr><td colspan="4">No activity records.</td></tr>'}
                    </tbody>
                </table>

                <div class="footer">
                    Generated by InsiderWatch |
                    ${field(new Date().toLocaleString())}
                </div>

            </body>
            </html>
        `);

        printWindow.document.close();

        printWindow.onload = () => {
            printWindow.focus();
            printWindow.print();
        };

    } catch (error) {
        printWindow.close();
        alert("Report generation failed: " + error.message);
        console.error(error);
    }
}

