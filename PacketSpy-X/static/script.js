let trafficChart = null;

function initChart() {
    const ctx = document.getElementById("trafficChart").getContext("2d");

    trafficChart = new Chart(ctx, {
        data: {
            labels: ["Traffic"],
            datasets: [
                {
                    type: "bar",
                    label: "TCP",
                    data: [0],
                    backgroundColor: "#38bdf8"
                },
                {
                    type: "bar",
                    label: "UDP",
                    data: [0],
                    backgroundColor: "#22c55e"
                },
                {
                    type: "line",
                    label: "Suspicious",
                    data: [0],
                    borderColor: "#ef4444",
                    backgroundColor: "#ef4444",
                    tension: 0.4,
                    fill: false,
                    pointRadius: 5
                }
            ]
        },
        options: {
            responsive: true,
            animation: {
                duration: 800
            },
            plugins: {
                legend: {
                    labels: {
                        color: "#e5e7eb",
                        font: { size: 14 }
                    }
                }
            },
            scales: {
                x: {
                    ticks: { color: "#e5e7eb" },
                    grid: { color: "#1e293b" }
                },
                y: {
                    beginAtZero: true,
                    ticks: { color: "#e5e7eb" },
                    grid: { color: "#1e293b" }
                }
            }
        }
    });
}

function loadPackets() {
    fetch("/packets")
        .then(res => res.json())
        .then(data => {
            const body = document.getElementById("packetBody");
            body.innerHTML = "";

            data.slice().reverse().forEach(p => {
                const row = document.createElement("tr");
                row.innerHTML = `
                    <td>${p.time}</td>
                    <td>${p.src}</td>
                    <td class="ip" onclick="showOSINT('${p.dst}')">${p.dst}</td>
                    <td>${p.protocol}</td>
                    <td>${p.size}</td>
                    <td class="${p.status === 'Suspicious' ? 'bad' : 'ok'}">${p.status}</td>
                    <td>${p.reason}</td>
                `;
                body.appendChild(row);
            });
        });
}

function loadStats() {
    fetch("/stats")
        .then(res => res.json())
        .then(s => {
            document.getElementById("total").innerText = s.total;
            document.getElementById("tcp").innerText = s.tcp;
            document.getElementById("udp").innerText = s.udp;
            document.getElementById("suspicious").innerText = s.suspicious;

            if (trafficChart) {
                trafficChart.data.datasets[0].data[0] = s.tcp;
                trafficChart.data.datasets[1].data[0] = s.udp;
                trafficChart.data.datasets[2].data[0] = s.suspicious;
                trafficChart.update();
            }
        });
}

function showOSINT(ip) {
    fetch(`/osint/${ip}`)
        .then(res => res.json())
        .then(d => {
            alert(
                `IP: ${d.ip}\nCountry: ${d.country}\nCity: ${d.city}\nOrganization: ${d.org}`
            );
        });
}

function exportCSV() {
    window.location.href = "/export";
}

function enableDemo() {
    fetch("/demo").then(() => alert("Demo mode enabled"));
}

function disableDemo() {
    fetch("/demo_off").then(() => alert("Demo mode disabled"));
}

initChart();

setInterval(() => {
    loadPackets();
    loadStats();
}, 2000);
