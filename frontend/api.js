const API_BASE = "http://127.0.0.1:8000";

async function apiFetch(path, options = {}) {
    const response = await fetch(`${API_BASE}${path}`, {
        ...options,
        headers: {
            ...(options.body instanceof FormData
                ? {}
                : { "Content-Type": "application/json" }),
            ...(options.headers || {})
        }
    });

    const text = await response.text();

    let data;
    try {
        data = text ? JSON.parse(text) : {};
    } catch {
        data = { raw: text };
    }

    if (!response.ok) {
        throw new Error(
            data.detail ||
            data.message ||
            `API request failed: ${response.status}`
        );
    }

    return data;
}

async function getHealth() {
    return apiFetch("/health");
}

async function getScans() {
    return apiFetch("/api/scans");
}

async function getScan(id) {
    return apiFetch(`/api/scans/${id}`);
}

async function getEndpoints() {
    return apiFetch("/api/endpoints");
}

async function getFindings() {
    return apiFetch("/api/findings");
}

async function getPredictions() {
    return apiFetch("/api/predictions");
}

async function getProbes() {
    return apiFetch("/api/probes");
}

async function getAgentTrace(scanId) {
    return apiFetch(`/api/agent-trace/${scanId}`);
}

async function getReport(scanId) {
    return apiFetch(`/api/reports/${scanId}`);
}

async function importOpenAPI(file, target, openapiUrl = "") {
    const formData = new FormData();

    if (file) {
        formData.append("file", file);
    }

    formData.append("target", target || "");

    if (openapiUrl) {
        formData.append("openapi_url", openapiUrl);
    }

    return apiFetch("/api/import", {
        method: "POST",
        body: formData
    });
}

async function startScan({
    target,
    ownerIdentity,
    testIdentity,
    resourceSeeds,
    openapiUrl
}) {
    const body = new URLSearchParams();

    body.append("target", target);
    body.append("owner_identity", ownerIdentity);
    body.append("test_identity", testIdentity);
    body.append(
        "resource_seeds",
        JSON.stringify(resourceSeeds || {})
    );

    if (openapiUrl) {
        body.append("openapi_url", openapiUrl);
    }

    const response = await fetch(`${API_BASE}/api/scan`, {
        method: "POST",
        body
    });

    const text = await response.text();

    let data;
    try {
        data = text ? JSON.parse(text) : {};
    } catch {
        data = { raw: text };
    }

    if (!response.ok) {
        throw new Error(
            data.detail ||
            data.message ||
            `Scan failed: ${response.status}`
        );
    }

    return data;
}

async function downloadReport(scanId) {
    window.open(
        `${API_BASE}/api/reports/${scanId}/html`,
        "_blank"
    );
}