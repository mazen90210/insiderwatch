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
    return value ? new Date(value).toLocaleString() : "-";
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
            <td>${escapeHTML(event.host || "-")}</td>
            <td>${escapeHTML(event.username || "-")}</td>
            <td>${escapeHTML(event.event_type || "-")}</td>
            <td class="event-message-cell">
                <div class="event-message-preview">
                    ${escapeHTML(event.message || "-")}
                </div>
                <details class="event-message-details">
                    <summary>View Full Message</summary>
                    <div class="event-full-message">
                        ${escapeHTML(event.message || "-")}
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
                ? "AI ENGINE ONLINE | ISOLATION FOREST TRAINED"
                : "AI ENGINE ONLINE | RULE-BASED MODE"
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

        body.innerHTML = incidents.map(incident => {

            const severity = String(incident.severity || "Low").toLowerCase();
            const status = String(incident.status || "Open").toLowerCase();
            const risk = Math.min(100, Math.max(0, Number(incident.risk_score) || 0));

            const severityClass = {
                low: "severity-low",
                medium: "severity-medium",
                high: "severity-high",
                critical: "severity-critical"
            }[severity] || "severity-low";

            const statusClass = {
                open: "status-open",
                investigating: "status-investigating",
                resolved: "status-resolved",
                closed: "status-closed"
            }[status] || "status-open";

            const riskColor =
                risk >= 75 ? "#ff536b" :
                risk >= 40 ? "#f2cb60" :
                "#38d6a0";

            return `
                <tr>
                    <td><span class="incident-id">#${escapeHTML(incident.id)}</span></td>
                    <td class="incident-title-cell">${escapeHTML(incident.title)}</td>
                    <td>${escapeHTML(incident.host || "-")}</td>
                    <td>${escapeHTML(incident.username || "-")}</td>

                    <td>
                        <span class="incident-severity ${severityClass}">
                            ${escapeHTML(incident.severity)}
                        </span>
                    </td>

                    <td>
                        <div class="incident-risk">
                            <div class="incident-risk-value">
                                ${risk}<small>/100</small>
                            </div>
                            <div class="incident-risk-track">
                                <div class="incident-risk-fill"
                                     style="width:${risk}%; background:${riskColor};">
                                </div>
                            </div>
                        </div>
                    </td>

                    <td>
                        <span class="incident-status ${statusClass}">
                            ${escapeHTML(incident.status)}
                        </span>
                    </td>

                    <td>${escapeHTML(formatDate(incident.created_at))}</td>

                    <td>
                        <button
                            class="incident-manage-btn"
                            onclick="openIncidentDetails(${Number(incident.id)})">
                            Manage &rarr;
                        </button>
                    </td>
                </tr>
            `;
        }).join("");

    } catch (error) {
        body.innerHTML = `
            <tr>
                <td colspan="9" class="empty">Unable to load incidents.</td>
            </tr>
        `;
        console.error(error);
    }
}

// ==========================================
// ==========================================
// INCIDENT PAGINATION
// ==========================================

let incidentCurrentPage = 1;
const incidentItemsPerPage = 10;

function getFilteredIncidentRows() {

    const search = (document.getElementById("incident-search")?.value || "")
        .trim().toLowerCase();

    const severity = (document.getElementById("incident-severity-filter")?.value || "")
        .toLowerCase();

    const status = (document.getElementById("incident-status-filter")?.value || "")
        .toLowerCase();

    return Array.from(document.querySelectorAll("#incidents-table tr")).filter(row => {

        if (row.querySelector(".empty")) return false;

        const text = row.textContent.toLowerCase();

        const rowSeverity = row.querySelector(".incident-severity")
            ?.textContent.trim().toLowerCase() || "";

        const rowStatus = row.querySelector(".incident-status")
            ?.textContent.trim().toLowerCase() || "";

        return text.includes(search)
            && (!severity || rowSeverity === severity)
            && (!status || rowStatus === status);
    });
}

function renderIncidentPagination(totalItems) {

    const container = document.getElementById("incident-pagination");

    if (!container) return;

    const totalPages = Math.ceil(totalItems / incidentItemsPerPage);

    if (totalPages <= 1) {
        container.innerHTML = totalItems
            ? `<span class="pagination-info">Showing ${totalItems} incidents</span>`
            : "";
        return;
    }

    let buttons = `
        <button class="page-btn"
            ${incidentCurrentPage === 1 ? "disabled" : ""}
            onclick="changeIncidentPage(${incidentCurrentPage - 1})">
            Previous
        </button>
    `;

    for (let page = 1; page <= totalPages; page++) {
        buttons += `
            <button class="page-btn ${page === incidentCurrentPage ? "active" : ""}"
                onclick="changeIncidentPage(${page})">
                ${page}
            </button>
        `;
    }

    buttons += `
        <button class="page-btn"
            ${incidentCurrentPage === totalPages ? "disabled" : ""}
            onclick="changeIncidentPage(${incidentCurrentPage + 1})">
            Next
        </button>
    `;

    container.innerHTML = `
        <span class="pagination-info">
            Page ${incidentCurrentPage} of ${totalPages} ط·آ¢ط¢آ· ${totalItems} incidents
        </span>
        <div class="pagination-buttons">${buttons}</div>
    `;
}

function changeIncidentPage(page) {
    incidentCurrentPage = page;
    filterIncidents();
}
// INCIDENT SEARCH AND FILTERS
// ==========================================

function filterIncidents() {

    const rows = Array.from(
        document.querySelectorAll("#incidents-table tr")
    );

    const filteredRows = getFilteredIncidentRows();

    const totalPages = Math.max(
        1,
        Math.ceil(filteredRows.length / incidentItemsPerPage)
    );

    incidentCurrentPage = Math.min(incidentCurrentPage, totalPages);

    const startIndex = (incidentCurrentPage - 1) * incidentItemsPerPage;
    const endIndex = startIndex + incidentItemsPerPage;

    const visibleRows = new Set(
        filteredRows.slice(startIndex, endIndex)
    );

    rows.forEach(row => {
        row.style.display = visibleRows.has(row) ? "" : "none";
    });

    renderIncidentPagination(filteredRows.length);
}
 function setupIncidentFilters() {

    const searchInput = document.getElementById("incident-search");
    const severityFilter = document.getElementById("incident-severity-filter");
    const statusFilter = document.getElementById("incident-status-filter");
    const clearButton = document.getElementById("clear-incident-filters");

    if (!searchInput || !severityFilter || !statusFilter || !clearButton) return;

    searchInput.addEventListener("input", filterIncidents);
    severityFilter.addEventListener("change", filterIncidents);
    statusFilter.addEventListener("change", filterIncidents);

    clearButton.addEventListener("click", () => {
        searchInput.value = "";
        severityFilter.value = "";
        statusFilter.value = "";
        filterIncidents();
    });
}

document.addEventListener("DOMContentLoaded", setupIncidentFilters);


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

        const severityClass = `severity-${String(incident.severity || "low").toLowerCase()}`;
        const statusClass = `status-${String(incident.status || "open").toLowerCase().replace(/\s+/g, "-")}`;
        const riskScore = Math.max(0, Math.min(100, Number(incident.risk_score) || 0));

        document.getElementById("incident-details-content").innerHTML = `
            <div class="incident-overview">

                <div class="incident-overview-header">
                    <div>
                        <span class="incident-section-label">INCIDENT OVERVIEW</span>
                        <h2>${escapeHTML(incident.title || "Untitled Incident")}</h2>
                        <span class="incident-reference">Incident #${escapeHTML(incident.id)}</span>
                    </div>

                    <div class="incident-overview-badges">
                        <span class="incident-detail-badge ${severityClass}">
                            ${escapeHTML(incident.severity || "Unknown")}
                        </span>
                        <span class="incident-detail-badge ${statusClass}">
                            ${escapeHTML(incident.status || "Open")}
                        </span>
                    </div>
                </div>

                <div class="incident-risk-card">
                    <div class="incident-risk-heading">
                        <span>Risk Score</span>
                        <strong>${riskScore}<small>/100</small></strong>
                    </div>
                    <div class="incident-detail-risk-track">
                        <div class="incident-detail-risk-fill" style="width:${riskScore}%"></div>
                    </div>
                    <div class="incident-risk-scale">
                        <span>Low Risk</span>
                        <span>High Risk</span>
                    </div>
                </div>

                <div class="incident-metadata-grid">
                    <div class="incident-metadata-card">
                        <span>HOST</span>
                        <strong>${escapeHTML(incident.host || "-")}</strong>
                    </div>

                    <div class="incident-metadata-card">
                        <span>USERNAME</span>
                        <strong>${escapeHTML(incident.username || "-")}</strong>
                    </div>

                    <div class="incident-metadata-card">
                        <span>CREATED</span>
                        <strong>${escapeHTML(formatDate(incident.created_at))}</strong>
                    </div>

                    <div class="incident-metadata-card">
                        <span>INCIDENT ID</span>
                        <strong>#${escapeHTML(incident.id)}</strong>
                    </div>
                </div>

                <div class="incident-description-card">
                    <span class="incident-section-label">DESCRIPTION</span>
                    <p>${escapeHTML(incident.description || "No description provided.")}</p>
                </div>

                <div class="incident-detail-actions">
                    <button type="button" class="refresh-btn"
                        onclick="requestIncidentLogCollection(${Number(incident.id)})">
                        Collect Security Logs
                    </button>

                    <button type="button" class="refresh-btn"
                        onclick="generateIncidentReport()">
                        Generate PDF Report
                    </button>
                </div>

                <div id="incident-response-message" class="mt-2"></div>
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

            <td>${escapeHTML(entry.action || "-")}</td>

            <td>${escapeHTML(entry.details || "-")}</td>

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

        document.getElementById("response-total").textContent = stats.total ?? 0;
        document.getElementById("response-completed").textContent = stats.completed ?? 0;
        document.getElementById("response-failed").textContent = stats.failed ?? 0;
        document.getElementById("response-pending").textContent = stats.pending ?? 0;
        document.getElementById("response-events-collected").textContent = stats.events_collected ?? 0;

        renderResponseChart(stats);

        if (!actions.length) {
            table.innerHTML = `
                <tr>
                    <td colspan="8" class="empty">
                        No response actions found.
                    </td>
                </tr>`;
            return;
        }

        table.innerHTML = actions.map(action => {
            const result = action.result || {};
            const id = Number(action.id);
            const status = String(action.status || "unknown").toLowerCase();
            const statusClass = status.replace(/[^a-z0-9_-]/g, "");
            const dash = "-";

            const host = result.host || result.hostname || "Unknown Host";
            const summary = result.summary || "No summary available";

            return `
                <tr class="response-action-row">
                    <td><strong>#${id}</strong></td>

                    <td>#${Number(action.incident_id)}</td>

                    <td>
                        <span class="response-action-type">
                            ${escapeHTML(action.action_type || "Unknown")}
                        </span>
                    </td>

                    <td>
                        <span class="response-status response-${statusClass}">
                            ${escapeHTML(action.status || "Unknown")}
                        </span>
                    </td>

                    <td>${escapeHTML(String(result.events_found ?? dash))}</td>

                    <td>${escapeHTML(String(result.events_uploaded ?? dash))}</td>

                    <td>
                        <div class="response-result-details">
                            <strong>${escapeHTML(host)}</strong>
                            <div>${escapeHTML(summary)}</div>
                            <small>
                                Requested: ${escapeHTML(String(result.requested_events ?? dash))} events
                            </small>
                            <br>
                            <small>
                                Completed: ${escapeHTML(formatDate(action.completed_at) || dash)}
                            </small>
                        </div>
                    </td>

                    <td>
                        <div class="response-created-date">
                            ${escapeHTML(formatDate(action.created_at) || dash)}
                        </div>

                        <button type="button"
                            class="response-details-btn"
                            onclick="toggleResponseDetails(${id})">
                            View Details
                        </button>
                    </td>
                </tr>

                <tr id="response-details-${id}" class="response-expanded-row" style="display:none;">
                    <td colspan="8">
                        <div class="response-expanded-content">
                            <div class="response-expanded-header">
                                <strong>Response Action #${id}</strong>
                                <span class="response-status response-${statusClass}">
                                    ${escapeHTML(action.status || "Unknown")}
                                </span>
                            </div>

                            <div class="response-expanded-grid">
                                <div>
                                    <small>Host</small>
                                    <strong>${escapeHTML(host)}</strong>
                                </div>

                                <div>
                                    <small>Action Type</small>
                                    <strong>${escapeHTML(action.action_type || dash)}</strong>
                                </div>

                                <div>
                                    <small>Requested By</small>
                                    <strong>${escapeHTML(action.requested_by || dash)}</strong>
                                </div>

                                <div>
                                    <small>Events Requested</small>
                                    <strong>${escapeHTML(String(result.requested_events ?? dash))}</strong>
                                </div>

                                <div>
                                    <small>Events Found</small>
                                    <strong>${escapeHTML(String(result.events_found ?? dash))}</strong>
                                </div>

                                <div>
                                    <small>Events Uploaded</small>
                                    <strong>${escapeHTML(String(result.events_uploaded ?? dash))}</strong>
                                </div>

                                <div>
                                    <small>Created</small>
                                    <strong>${escapeHTML(formatDate(action.created_at) || dash)}</strong>
                                </div>

                                <div>
                                    <small>Completed</small>
                                    <strong>${escapeHTML(formatDate(action.completed_at) || dash)}</strong>
                                </div>
                            </div>

                            <div class="response-expanded-summary">
                                <small>Execution Summary</small>
                                <p>${escapeHTML(summary)}</p>
                            </div>
                        </div>
                    </td>
                </tr>
            `;
        }).join("");

    } catch (error) {
        console.error("Response Center:", error);

        table.innerHTML = `
            <tr>
                <td colspan="8" class="empty">
                    Failed to load response actions.
                </td>
            </tr>`;
    }
}
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
// LOAD INCIDENTS INTO RESPONSE CENTER DROPDOWN
// ==========================================

async function loadResponseIncidentOptions() {

    const select = document.getElementById("response-incident-id");
    const preview = document.getElementById("response-incident-preview");

    if (!select) return;

    try {
        select.innerHTML = '<option value="">Loading incidents...</option>';

        const response = await apiFetch("/api/incidents");

        if (!response.ok) {
            throw new Error("Could not load incidents");
        }

        const data = await response.json();

        const incidents = Array.isArray(data)
            ? data
            : (data.incidents || []);

        select.innerHTML = '<option value="">Select an incident...</option>';

        if (!incidents.length) {
            select.innerHTML = '<option value="">No incidents available</option>';
            preview.textContent = "There are currently no incidents.";
            return;
        }

        incidents.forEach(incident => {
            const option = document.createElement("option");

            option.value = incident.id;
            option.textContent =
                `#${incident.id} - ${incident.title || "Untitled"} - ${incident.host || "Unknown host"}`;

            select.appendChild(option);
        });

        select.onchange = function () {
            const incident = incidents.find(
                item => String(item.id) === select.value
            );

            if (!incident) {
                preview.textContent = "Select an incident to view its details.";
                return;
            }

            preview.textContent =
                `Host: ${incident.host || "Unknown"} | ` +
                `User: ${incident.username || "Unknown"} | ` +
                `Severity: ${incident.severity || "Unknown"} | ` +
                `Status: ${incident.status || "Unknown"}`;
        };

        preview.textContent = "Select an incident to view its details.";

    } catch (error) {
        select.innerHTML = '<option value="">Failed to load incidents</option>';
        preview.textContent = error.message;
        console.error("Incident dropdown error:", error);
    }
}


// ==========================================
// RESPONSE CENTER INITIALIZATION
// ==========================================

loadResponseActions();
loadResponseIncidentOptions();

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
            escapeHTML(value ?? "-");

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


/* Incident Risk Score Live Update */

const incidentRiskInput = document.getElementById("incident-risk");
const incidentRiskValue = document.getElementById("risk-value");

if (incidentRiskInput && incidentRiskValue) {
    const updateIncidentRisk = () => {
        const score = Number(incidentRiskInput.value);

        incidentRiskValue.textContent = score;

        incidentRiskValue.style.color =
            score >= 75 ? "#ff536b" :
            score >= 40 ? "#f2cb60" :
            "#38d6a0";
    };

    incidentRiskInput.addEventListener("input", updateIncidentRisk);
    updateIncidentRisk();
}
