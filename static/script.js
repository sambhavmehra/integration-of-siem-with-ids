let ipChart, severityChart;
let alertAudio = new Audio('/static/siren.mp3');

async function fetchData() {
  const res = await fetch('/data');
  const data = await res.json();

  // Total Alerts
  document.getElementById('total_alerts').innerText = data.total_alerts;

  // Top Attacker IP Chart
  const ips = data.top_ips.map(i => i[0]);
  const counts = data.top_ips.map(i => i[1]);

  const ipCanvas = document.getElementById('ipChart');
  const ipCtx = getCrispCanvasContext(ipCanvas);

  if (ipChart) {
    ipChart.data.labels = ips;
    ipChart.data.datasets[0].data = counts;
    ipChart.update();
  } else {
    ipChart = new Chart(ipCtx, {
      type: 'bar',
      data: {
        labels: ips,
        datasets: [{
          label: 'Top Attacker IPs',
          data: counts,
          backgroundColor: 'orange'
        }]
      },
      options: {
        responsive: false,
        maintainAspectRatio: false,
        scales: {
          y: {
            beginAtZero: true
          }
        }
      }
    });
  }

  // Severity Chart
  const severities = Object.keys(data.severity);
  const severity_counts = Object.values(data.severity);

  const severityCanvas = document.getElementById('severityChart');
  const severityCtx = getCrispCanvasContext(severityCanvas);

  if (severityChart) {
    severityChart.data.labels = severities;
    severityChart.data.datasets[0].data = severity_counts;
    severityChart.update();
  } else {
    severityChart = new Chart(severityCtx, {
      type: 'pie',
      data: {
        labels: severities,
        datasets: [{
          label: 'Alerts by Severity',
          data: severity_counts,
          backgroundColor: ['red', 'yellow', 'green']
        }]
      },
      options: {
        responsive: false,
        maintainAspectRatio: false
      }
    });
  }

  // Alerts Table
  const tableBody = document.getElementById("alertsBody");
  tableBody.innerHTML = "";

  data.alerts.forEach(alert => {
    const row = document.createElement("tr");
    row.innerHTML = `
      <td>${alert.timestamp}</td>
      <td>${alert.src_ip}</td>
      <td>${alert.dest_ip}</td>
      <td>${alert.severity}</td>
      <td>${alert.signature}</td>
    `;
    tableBody.appendChild(row);
  });

  // ✅ Play Siren if High Severity
  playSoundForHighSeverity(data.alerts);
}

// Fix canvas blur on high DPI
function getCrispCanvasContext(canvas) {
  const dpr = window.devicePixelRatio || 1;
  const rect = canvas.getBoundingClientRect();

  canvas.width = rect.width * dpr;
  canvas.height = rect.height * dpr;
  canvas.style.width = `${rect.width}px`;
  canvas.style.height = `${rect.height}px`;

  const ctx = canvas.getContext('2d');
  ctx.setTransform(1, 0, 0, 1, 0, 0);
  ctx.scale(dpr, dpr);

  return ctx;
}

// 🔊 Sound Alert Function
function playSoundForHighSeverity(alerts) {
  if (alerts.some(a => a.severity <= 2)) {
    alertAudio.play().catch(err => {
      console.log("Autoplay Blocked or Error:", err);
    });
  }
}

// ⏱️ Initial fetch + refresh every 5 sec
fetchData();
setInterval(fetchData, 5000);
