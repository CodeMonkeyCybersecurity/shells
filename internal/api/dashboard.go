// internal/api/dashboard.go
package api

import (
	"context"
	"database/sql"
	"net/http"
	"time"

	"github.com/CodeMonkeyCybersecurity/artemis/internal/logger"
	"github.com/gin-gonic/gin"
	"github.com/jmoiron/sqlx"
)

// RegisterDashboardRoutes registers the web UI dashboard routes
func RegisterDashboardRoutes(router *gin.Engine, db *sqlx.DB, log *logger.Logger) {
	// Serve the dashboard HTML with no-cache headers
	router.GET("/", func(c *gin.Context) {
		c.Header("Content-Type", "text/html; charset=utf-8")
		c.Header("Cache-Control", "no-cache, no-store, must-revalidate")
		c.Header("Pragma", "no-cache")
		c.Header("Expires", "0")
		c.String(http.StatusOK, dashboardHTML)
	})

	// API endpoint for scan list
	router.GET("/api/dashboard/scans", func(c *gin.Context) {
		ctx, cancel := context.WithTimeout(c.Request.Context(), 5*time.Second)
		defer cancel()

		rows, err := db.QueryContext(ctx, `
			SELECT id, target, type, status, created_at, started_at, completed_at, error_message
			FROM scans
			ORDER BY created_at DESC
			LIMIT 100
		`)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}
		defer rows.Close()

		type ScanInfo struct {
			ID          string     `json:"id"`
			Target      string     `json:"target"`
			Type        string     `json:"type"`
			Status      string     `json:"status"`
			CreatedAt   time.Time  `json:"created_at"`
			StartedAt   *time.Time `json:"started_at,omitempty"`
			CompletedAt *time.Time `json:"completed_at,omitempty"`
			ErrorMsg    *string    `json:"error_message,omitempty"`
		}

		scans := []ScanInfo{}
		for rows.Next() {
			var s ScanInfo
			if err := rows.Scan(&s.ID, &s.Target, &s.Type, &s.Status, &s.CreatedAt, &s.StartedAt, &s.CompletedAt, &s.ErrorMsg); err != nil {
				continue
			}
			scans = append(scans, s)
		}

		c.JSON(http.StatusOK, scans)
	})

	// API endpoint for scan details and findings
	router.GET("/api/dashboard/scans/:id", func(c *gin.Context) {
		scanID := c.Param("id")
		ctx, cancel := context.WithTimeout(c.Request.Context(), 5*time.Second)
		defer cancel()

		// Get scan info with metadata (requires migration v1 for config/result/checkpoint columns)
		var scan struct {
			ID          string     `json:"id"`
			Target      string     `json:"target"`
			Type        string     `json:"type"`
			Status      string     `json:"status"`
			CreatedAt   time.Time  `json:"created_at"`
			StartedAt   *time.Time `json:"started_at,omitempty"`
			CompletedAt *time.Time `json:"completed_at,omitempty"`
			ErrorMsg    *string    `json:"error_message,omitempty"`
			Config      *string    `json:"config,omitempty"`
			Result      *string    `json:"result,omitempty"`
			Checkpoint  *string    `json:"checkpoint,omitempty"`
		}

		err := db.QueryRowContext(ctx, `
			SELECT id, target, type, status, created_at, started_at, completed_at, error_message,
			       config, result, checkpoint
			FROM scans WHERE id = $1
		`, scanID).Scan(&scan.ID, &scan.Target, &scan.Type, &scan.Status, &scan.CreatedAt, &scan.StartedAt, &scan.CompletedAt, &scan.ErrorMsg, &scan.Config, &scan.Result, &scan.Checkpoint)

		if err == sql.ErrNoRows {
			log.Warnw("Scan not found in database",
				"scan_id", scanID,
				"component", "dashboard_api",
			)
			c.JSON(http.StatusNotFound, gin.H{"error": "Scan not found"})
			return
		}
		if err != nil {
			log.Errorw("Database error fetching scan details",
				"error", err,
				"scan_id", scanID,
				"component", "dashboard_api",
			)
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}

		// Get findings
		rows, err := db.QueryContext(ctx, `
			SELECT id, tool, type, severity, title, description, evidence, solution, refs, metadata, created_at
			FROM findings WHERE scan_id = $1 ORDER BY severity DESC, created_at DESC
		`, scanID)
		if err != nil {
			log.Errorw("Database error fetching findings",
				"error", err,
				"scan_id", scanID,
				"component", "dashboard_api",
			)
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}
		defer rows.Close()

		type Finding struct {
			ID          string    `json:"id"`
			Tool        string    `json:"tool"`
			Type        string    `json:"type"`
			Severity    string    `json:"severity"`
			Title       string    `json:"title"`
			Description *string   `json:"description,omitempty"`
			Evidence    *string   `json:"evidence,omitempty"`
			Solution    *string   `json:"solution,omitempty"`
			Refs        *string   `json:"refs,omitempty"`
			Metadata    *string   `json:"metadata,omitempty"`
			CreatedAt   time.Time `json:"created_at"`
		}

		findings := []Finding{}
		for rows.Next() {
			var f Finding
			if err := rows.Scan(&f.ID, &f.Tool, &f.Type, &f.Severity, &f.Title, &f.Description, &f.Evidence, &f.Solution, &f.Refs, &f.Metadata, &f.CreatedAt); err != nil {
				continue
			}
			findings = append(findings, f)
		}

		c.JSON(http.StatusOK, gin.H{
			"scan":     scan,
			"findings": findings,
		})
	})

	// NEW: API endpoint for scan events/logs
	router.GET("/api/dashboard/scans/:id/events", func(c *gin.Context) {
		scanID := c.Param("id")
		ctx, cancel := context.WithTimeout(c.Request.Context(), 5*time.Second)
		defer cancel()

		// Query scan_events table for real-time progress logs
		rows, err := db.QueryContext(ctx, `
			SELECT event_type, component, message, metadata, created_at
			FROM scan_events
			WHERE scan_id = $1
			ORDER BY created_at ASC
			LIMIT 1000
		`, scanID)
		if err != nil {
			log.Warnw("Failed to fetch scan events, returning empty list",
				"error", err,
				"scan_id", scanID,
				"component", "dashboard_api",
			)
			c.JSON(http.StatusOK, []interface{}{}) // Return empty if no events table
			return
		}
		defer rows.Close()

		type Event struct {
			Type      string    `json:"type"`
			Component string    `json:"component"`
			Message   string    `json:"message"`
			Metadata  *string   `json:"metadata,omitempty"`
			CreatedAt time.Time `json:"created_at"`
		}

		events := []Event{}
		for rows.Next() {
			var e Event
			if err := rows.Scan(&e.Type, &e.Component, &e.Message, &e.Metadata, &e.CreatedAt); err != nil {
				continue
			}
			events = append(events, e)
		}

		c.JSON(http.StatusOK, events)
	})

	// API endpoint for statistics
	router.GET("/api/dashboard/stats", func(c *gin.Context) {
		ctx, cancel := context.WithTimeout(c.Request.Context(), 5*time.Second)
		defer cancel()

		var stats struct {
			TotalScans    int `json:"total_scans"`
			ActiveScans   int `json:"active_scans"`
			TotalFindings int `json:"total_findings"`
			CriticalCount int `json:"critical_count"`
			HighCount     int `json:"high_count"`
			MediumCount   int `json:"medium_count"`
			LowCount      int `json:"low_count"`
		}

		// Total scans
		db.QueryRowContext(ctx, "SELECT COUNT(*) FROM scans").Scan(&stats.TotalScans)

		// Active scans
		db.QueryRowContext(ctx, "SELECT COUNT(*) FROM scans WHERE status IN ('pending', 'running')").Scan(&stats.ActiveScans)

		// Total findings
		db.QueryRowContext(ctx, "SELECT COUNT(*) FROM findings").Scan(&stats.TotalFindings)

		// Findings by severity
		db.QueryRowContext(ctx, "SELECT COUNT(*) FROM findings WHERE severity = 'CRITICAL'").Scan(&stats.CriticalCount)
		db.QueryRowContext(ctx, "SELECT COUNT(*) FROM findings WHERE severity = 'HIGH'").Scan(&stats.HighCount)
		db.QueryRowContext(ctx, "SELECT COUNT(*) FROM findings WHERE severity = 'MEDIUM'").Scan(&stats.MediumCount)
		db.QueryRowContext(ctx, "SELECT COUNT(*) FROM findings WHERE severity = 'LOW'").Scan(&stats.LowCount)

		c.JSON(http.StatusOK, stats)
	})
}

const dashboardHTML = `<!DOCTYPE html>
<!--suppress ALL -->

<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Shells - Security Scanner Dashboard</title>
    <style>
        /* Anthropic Theme - Inspired by Claude's design system */
        :root {
            --bg-primary: #09090B;
            --bg-card: #131314;
            --bg-table-header: #1a1a1c;
            --bg-hover: #1f1f21;
            --border-color: rgba(212, 162, 127, 0.15);
            --text-primary: #FAFAF5;
            --text-secondary: #9ca3af;
            --text-muted: #6b7280;
            --accent-primary: #D4A27F;
            --accent-secondary: #EBDBBC;
            --accent-dark: #09090B;
        }

        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }

        @media (prefers-reduced-motion: reduce) {
            *, *::before, *::after {
                animation-duration: 0.01ms !important;
                animation-iteration-count: 1 !important;
                transition-duration: 0.01ms !important;
            }
        }

        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen, Ubuntu, Cantarell, sans-serif;
            background: var(--bg-primary);
            color: var(--text-primary);
            line-height: 1.6;
        }

        .container {
            max-width: 1400px;
            margin: 0 auto;
            padding: 20px;
        }

        h1 {
            font-size: 2.5rem;
            margin-bottom: 10px;
            color: var(--accent-primary);
            font-weight: 400;
            letter-spacing: -0.02em;
        }

        h2 {
            font-size: 1.5rem;
            margin: 30px 0 15px;
            color: var(--accent-secondary);
            font-weight: 400;
        }

        .subtitle {
            color: var(--text-muted);
            margin-bottom: 30px;
            font-size: 1rem;
        }

        .stats-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 20px;
            margin-bottom: 30px;
        }

        .stat-card {
            background: var(--bg-card);
            border-radius: 12px;
            padding: 20px;
            border: 1px solid var(--border-color);
            box-shadow: 0 1px 3px rgba(0,0,0,0.3);
            transition: all 0.2s ease;
        }

        .stat-card:hover {
            transform: translateY(-2px);
            box-shadow: 0 4px 6px rgba(0,0,0,0.4);
            border-color: rgba(212, 162, 127, 0.3);
        }

        .stat-value {
            font-size: 2.5rem;
            font-weight: 500;
            margin-bottom: 5px;
        }

        .stat-label {
            color: var(--text-secondary);
            font-size: 0.875rem;
            font-weight: 400;
        }

        .severity-critical { color: #ef4444; }
        .severity-high { color: #f59e0b; }
        .severity-medium { color: #fbbf24; }
        .severity-low { color: #3b82f6; }

        .scans-table {
            background: var(--bg-card);
            border-radius: 12px;
            overflow: hidden;
            border: 1px solid var(--border-color);
            box-shadow: 0 1px 3px rgba(0,0,0,0.3);
        }

        table {
            width: 100%;
            border-collapse: collapse;
        }

        th {
            background: var(--bg-table-header);
            padding: 15px;
            text-align: left;
            font-weight: 500;
            color: var(--accent-secondary);
            border-bottom: 1px solid var(--border-color);
        }

        td {
            padding: 15px;
            border-bottom: 1px solid var(--border-color);
        }

        tr:hover {
            background: var(--bg-hover);
            cursor: pointer;
            transition: background 0.2s ease;
        }

        .status-badge {
            display: inline-block;
            padding: 4px 12px;
            border-radius: 16px;
            font-size: 0.75rem;
            font-weight: 500;
            text-transform: uppercase;
            letter-spacing: 0.05em;
        }

        .status-completed {
            background: rgba(16, 185, 129, 0.15);
            color: #10b981;
            border: 1px solid rgba(16, 185, 129, 0.3);
        }

        .status-running {
            background: rgba(212, 162, 127, 0.15);
            color: var(--accent-primary);
            border: 1px solid rgba(212, 162, 127, 0.3);
        }

        .status-failed {
            background: rgba(239, 68, 68, 0.15);
            color: #ef4444;
            border: 1px solid rgba(239, 68, 68, 0.3);
        }

        .status-pending {
            background: rgba(107, 114, 128, 0.15);
            color: #9ca3af;
            border: 1px solid rgba(107, 114, 128, 0.3);
        }

        .loading {
            text-align: center;
            padding: 40px;
            color: var(--text-muted);
        }

        .error {
            color: #ef4444;
            padding: 20px;
            text-align: center;
        }

        .refresh-btn {
            background: var(--accent-primary);
            color: var(--accent-dark);
            border: none;
            padding: 10px 20px;
            border-radius: 8px;
            cursor: pointer;
            font-size: 0.875rem;
            font-weight: 500;
            float: right;
            margin-bottom: 15px;
            transition: all 0.2s ease;
        }

        .refresh-btn:hover {
            background: var(--accent-secondary);
            transform: translateY(-1px);
            box-shadow: 0 2px 4px rgba(0,0,0,0.3);
        }

        .modal {
            display: none;
            position: fixed;
            top: 0;
            left: 0;
            width: 100%;
            height: 100%;
            background: rgba(0,0,0,0.85);
            z-index: 1000;
            overflow-y: auto;
        }

        .modal-content {
            background: var(--bg-card);
            margin: 50px auto;
            padding: 30px;
            max-width: 1000px;
            border-radius: 12px;
            border: 1px solid var(--border-color);
            box-shadow: 0 8px 16px rgba(0,0,0,0.5);
        }

        .close-btn {
            float: right;
            font-size: 28px;
            font-weight: 400;
            color: var(--text-secondary);
            cursor: pointer;
            transition: color 0.2s ease;
        }

        .close-btn:hover {
            color: var(--accent-primary);
        }

        .finding-card {
            background: var(--bg-hover);
            padding: 20px;
            margin: 15px 0;
            border-radius: 8px;
            border-left: 4px solid;
            transition: all 0.2s ease;
        }

        .finding-card:hover {
            transform: translateX(4px);
        }

        .finding-card.critical { border-color: #ef4444; }
        .finding-card.high { border-color: #f59e0b; }
        .finding-card.medium { border-color: #fbbf24; }
        .finding-card.low { border-color: #3b82f6; }

        .finding-title {
            font-size: 1.1rem;
            font-weight: 500;
            margin-bottom: 10px;
            color: var(--text-primary);
        }

        .finding-meta {
            font-size: 0.875rem;
            color: var(--text-secondary);
            margin-bottom: 10px;
        }

        .finding-description {
            margin-top: 10px;
            color: var(--text-primary);
        }

        pre {
            background: var(--bg-primary);
            padding: 15px;
            border-radius: 6px;
            overflow-x: auto;
            margin-top: 10px;
            border: 1px solid var(--border-color);
        }

        code {
            font-family: 'Fira Code', 'Courier New', monospace;
            font-size: 0.875rem;
            color: var(--accent-secondary);
        }
    </style>
</head>
<body>
    <div class="container">
        <h1> Shells Security Scanner</h1>
        <p class="subtitle">Real-time vulnerability scanning and bug bounty automation</p>

        <div id="stats" class="stats-grid">
            <div class="stat-card">
                <div class="stat-value" id="totalScans">-</div>
                <div class="stat-label">Total Scans</div>
            </div>
            <div class="stat-card">
                <div class="stat-value" id="activeScans">-</div>
                <div class="stat-label">Active Scans</div>
            </div>
            <div class="stat-card">
                <div class="stat-value" id="totalFindings">-</div>
                <div class="stat-label">Total Findings</div>
            </div>
            <div class="stat-card">
                <div class="stat-value severity-critical" id="criticalCount">-</div>
                <div class="stat-label">Critical</div>
            </div>
            <div class="stat-card">
                <div class="stat-value severity-high" id="highCount">-</div>
                <div class="stat-label">High</div>
            </div>
            <div class="stat-card">
                <div class="stat-value severity-medium" id="mediumCount">-</div>
                <div class="stat-label">Medium</div>
            </div>
        </div>

        <!-- Live Events Section for Active Scans -->
        <div id="liveEventsSection" style="display: none; margin-bottom: 30px;">
            <h2> Live Scan Progress</h2>
            <div id="liveEvents" style="background: #1a1a2e; border: 1px solid #2a2a3e; border-radius: 8px; padding: 20px;">
                <div id="liveEventsContent"></div>
            </div>
        </div>

        <h2>Recent Scans</h2>
        <button class="refresh-btn" onclick="loadData()">🔄 Refresh</button>
        <div class="scans-table">
            <table>
                <thead>
                    <tr>
                        <th>Target</th>
                        <th>Status</th>
                        <th>Type</th>
                        <th>Started</th>
                        <th>Duration</th>
                        <th>Actions</th>
                    </tr>
                </thead>
                <tbody id="scansBody">
                    <tr><td colspan="6" class="loading">Loading scans...</td></tr>
                </tbody>
            </table>
        </div>
    </div>

    <div id="scanModal" class="modal">
        <div class="modal-content">
            <span class="close-btn" onclick="closeModal()">&times;</span>
            <div id="scanDetails"></div>
        </div>
    </div>

    <script>
        async function loadData() {
            try {
                // Load stats
                const statsRes = await fetch('/api/dashboard/stats');
                const stats = await statsRes.json();
                document.getElementById('totalScans').textContent = stats.total_scans;
                document.getElementById('activeScans').textContent = stats.active_scans;
                document.getElementById('totalFindings').textContent = stats.total_findings;
                document.getElementById('criticalCount').textContent = stats.critical_count;
                document.getElementById('highCount').textContent = stats.high_count;
                document.getElementById('mediumCount').textContent = stats.medium_count;

                // Load scans
                const scansRes = await fetch('/api/dashboard/scans');
                const scans = await scansRes.json();

                const tbody = document.getElementById('scansBody');
                tbody.innerHTML = '';

                if (scans.length === 0) {
                    tbody.innerHTML = '<tr><td colspan="6" class="loading">No scans found</td></tr>';
                    document.getElementById('liveEventsSection').style.display = 'none';
                    return;
                }

                // Track if we have any running scans
                let hasRunningScans = false;

                scans.forEach(scan => {
                    const row = document.createElement('tr');
                    row.onclick = () => viewScan(scan.id);

                    const duration = scan.completed_at
                        ? formatDuration(new Date(scan.started_at), new Date(scan.completed_at))
                        : scan.started_at ? 'Running...' : '-';

                    // Check if scan is running
                    if (scan.status === 'running') {
                        hasRunningScans = true;
                    }

                    // Add Actions column with View button
                    const actionsHtml = '<button onclick="event.stopPropagation(); viewScan(\'' + scan.id + '\')" style="background: #667eea; color: white; border: none; padding: 5px 10px; border-radius: 4px; cursor: pointer;">View Details</button>';

                    row.innerHTML =
                        '<td>' + escapeHtml(scan.target) + '</td>' +
                        '<td><span class="status-badge status-' + scan.status + '">' + scan.status + '</span></td>' +
                        '<td>' + escapeHtml(scan.type) + '</td>' +
                        '<td>' + formatDate(scan.created_at) + '</td>' +
                        '<td>' + duration + '</td>' +
                        '<td>' + actionsHtml + '</td>';
                    tbody.appendChild(row);
                });

                // Show live events for running scans
                if (hasRunningScans) {
                    showLiveEvents(scans);
                } else {
                    document.getElementById('liveEventsSection').style.display = 'none';
                }
            } catch (error) {
                document.getElementById('scansBody').innerHTML =
                    '<tr><td colspan="6" class="error">Error loading data: ' + escapeHtml(error.message) + '</td></tr>';
            }
        }

        async function refreshLiveEvents() {
            try {
                const scansRes = await fetch('/api/dashboard/scans');
                const scans = await scansRes.json();
                const runningScans = scans.filter(s => s.status === 'running');

                if (runningScans.length === 0) {
                    document.getElementById('liveEventsSection').style.display = 'none';
                    return;
                }

                await showLiveEvents(scans);
            } catch (error) {
                console.error('Error refreshing live events:', error);
            }
        }

        async function showLiveEvents(scans) {
            const runningScans = scans.filter(s => s.status === 'running');
            if (runningScans.length === 0) {
                document.getElementById('liveEventsSection').style.display = 'none';
                return;
            }

            document.getElementById('liveEventsSection').style.display = 'block';
            const container = document.getElementById('liveEventsContent');
            container.innerHTML = '';

            for (const scan of runningScans) {
                try {
                    const eventsRes = await fetch('/api/dashboard/scans/' + scan.id + '/events');
                    const events = await eventsRes.json();

                    // Create section for this scan
                    const scanDiv = document.createElement('div');
                    scanDiv.style.marginBottom = '20px';
                    scanDiv.style.border = '1px solid #2a2a3e';
                    scanDiv.style.borderRadius = '6px';
                    scanDiv.style.padding = '15px';
                    scanDiv.style.background = '#0f0f23';

                    // Scan header
                    const headerDiv = document.createElement('div');
                    headerDiv.style.marginBottom = '10px';
                    headerDiv.style.display = 'flex';
                    headerDiv.style.justifyContent = 'space-between';
                    headerDiv.style.alignItems = 'center';
                    headerDiv.innerHTML = '<div>' +
                        '<span style="color: #667eea; font-weight: 600; font-size: 1.1rem;"> ' + escapeHtml(scan.target) + '</span> ' +
                        '<span style="color: #6b7280; font-size: 0.875rem;">(' + events.length + ' events)</span>' +
                        '</div>' +
                        '<button onclick="viewScan(\'' + scan.id + '\')" style="background: #667eea; color: white; border: none; padding: 5px 12px; border-radius: 4px; cursor: pointer; font-size: 0.875rem;">Full Details</button>';
                    scanDiv.appendChild(headerDiv);

                    // Events log (show last 20 events)
                    const eventsDiv = document.createElement('div');
                    eventsDiv.style.maxHeight = '300px';
                    eventsDiv.style.overflowY = 'auto';
                    eventsDiv.style.fontFamily = 'monospace';
                    eventsDiv.style.fontSize = '0.875rem';
                    eventsDiv.style.background = '#000000';
                    eventsDiv.style.padding = '10px';
                    eventsDiv.style.borderRadius = '4px';

                    // Show most recent events first (reverse order)
                    const recentEvents = events.slice(-20).reverse();
                    recentEvents.forEach(e => {
                        const timestamp = new Date(e.created_at).toLocaleTimeString();
                        const typeColor = e.type === 'error' ? '#ef4444' : e.type === 'warning' ? '#f59e0b' : '#3b82f6';

                        const eventDiv = document.createElement('div');
                        eventDiv.style.marginBottom = '6px';
                        eventDiv.innerHTML = '<span style="color: #6b7280;">[' + timestamp + ']</span> ' +
                            '<span style="color: ' + typeColor + '; font-weight: 600;">' + e.type.toUpperCase() + '</span> ' +
                            '<span style="color: #9ca3af;">[' + escapeHtml(e.component) + ']</span> ' +
                            '<span style="color: #e0e0e0;">' + escapeHtml(e.message) + '</span>';
                        eventsDiv.appendChild(eventDiv);
                    });

                    if (recentEvents.length === 0) {
                        eventsDiv.innerHTML = '<span style="color: #6b7280;">No events yet...</span>';
                    }

                    scanDiv.appendChild(eventsDiv);
                    container.appendChild(scanDiv);
                } catch (error) {
                    console.error('Error loading events for scan ' + scan.id, error);
                }
            }
        }

        async function viewScan(scanId) {
            try {
                const res = await fetch('/api/dashboard/scans/' + scanId);
                if (!res.ok) {
                    throw new Error('Failed to fetch scan: ' + res.status + ' ' + res.statusText);
                }
                const data = await res.json();

                // Validate response structure
                if (!data || !data.scan) {
                    throw new Error('Invalid scan data received from API');
                }

                // Fetch scan events/logs
                const eventsRes = await fetch('/api/dashboard/scans/' + scanId + '/events');
                const events = eventsRes.ok ? await eventsRes.json() : [];

                let html = '<h2>Scan Details</h2>' +
                    '<p><strong>Target:</strong> ' + escapeHtml(data.scan.target || 'Unknown') + '</p>' +
                    '<p><strong>Status:</strong> <span class="status-badge status-' + (data.scan.status || 'unknown') + '">' + (data.scan.status || 'unknown') + '</span></p>' +
                    '<p><strong>Started:</strong> ' + formatDate(data.scan.created_at) + '</p>' +
                    (data.scan.error_message ? '<p class="error"><strong>Error:</strong> ' + escapeHtml(data.scan.error_message) + '</p>' : '');

                // Show scan events/progress
                if (events && events.length > 0) {
                    html += '<h3 style="margin-top: 30px;">Scan Progress (' + events.length + ' events)</h3>';
                    html += '<div style="max-height: 400px; overflow-y: auto; background: #0f0f23; border: 1px solid #2a2a3e; border-radius: 6px; padding: 15px;">';
                    events.forEach(e => {
                        const timestamp = new Date(e.created_at).toLocaleTimeString();
                        const typeColor = e.type === 'error' ? '#ef4444' : e.type === 'warning' ? '#f59e0b' : '#3b82f6';
                        html += '<div style="margin-bottom: 8px; font-family: monospace; font-size: 0.875rem;">' +
                            '<span style="color: #6b7280;">[' + timestamp + ']</span> ' +
                            '<span style="color: ' + typeColor + '; font-weight: 600;">' + e.type.toUpperCase() + '</span> ' +
                            '<span style="color: #9ca3af;">[' + escapeHtml(e.component) + ']</span> ' +
                            '<span style="color: #e0e0e0;">' + escapeHtml(e.message) + '</span>' +
                            '</div>';
                    });
                    html += '</div>';
                }

                const findings = data.findings || [];
                html += '<h3 style="margin-top: 30px;">Findings (' + findings.length + ')</h3>';

                if (findings.length === 0) {
                    html += '<p style="color: #6b7280;">No findings for this scan.</p>';
                } else {
                    findings.forEach(f => {
                        html += '<div class="finding-card ' + f.severity.toLowerCase() + '">' +
                            '<div class="finding-title">' + escapeHtml(f.title) + '</div>' +
                            '<div class="finding-meta">' +
                            '<span class="status-badge severity-' + f.severity.toLowerCase() + '">' + f.severity + '</span> ' +
                            f.tool + ' | ' + f.type +
                            '</div>' +
                            (f.description ? '<div class="finding-description">' + escapeHtml(f.description) + '</div>' : '') +
                            (f.evidence ? '<pre><code>' + escapeHtml(f.evidence) + '</code></pre>' : '') +
                            (f.solution ? '<p style="margin-top: 10px;"><strong>Solution:</strong> ' + escapeHtml(f.solution) + '</p>' : '') +
                            '</div>';
                    });
                }

                document.getElementById('scanDetails').innerHTML = html;
                document.getElementById('scanModal').style.display = 'block';
            } catch (error) {
                alert('Error loading scan details: ' + error.message);
            }
        }

        function closeModal() {
            document.getElementById('scanModal').style.display = 'none';
        }

        function formatDate(dateStr) {
            const date = new Date(dateStr);
            return date.toLocaleString();
        }

        function formatDuration(start, end) {
            const ms = end - start;
            const seconds = Math.floor(ms / 1000);
            const minutes = Math.floor(seconds / 60);
            const hours = Math.floor(minutes / 60);

            if (hours > 0) return hours + 'h ' + (minutes % 60) + 'm';
            if (minutes > 0) return minutes + 'm ' + (seconds % 60) + 's';
            return seconds + 's';
        }

        function escapeHtml(text) {
            const div = document.createElement('div');
            div.textContent = text;
            return div.innerHTML;
        }

        // Load initial data
        loadData();

        // Auto-refresh only live events every 5 seconds (not the whole table)
        setInterval(refreshLiveEvents, 5000);

        // Refresh full table every 30 seconds (less disruptive)
        setInterval(loadData, 30000);

        // Close modal on outside click
        window.onclick = function(event) {
            const modal = document.getElementById('scanModal');
            if (event.target == modal) {
                closeModal();
            }
        }
    </script>
</body>
</html>`
