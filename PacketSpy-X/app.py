from flask import Flask, render_template, jsonify, Response
import threading
import packet_sniffer
from osint import ip_osint
from database import init_db, get_recent_packets

app = Flask(__name__)

@app.route("/")
def index():
    return render_template("index.html")

@app.route("/packets")
def get_packets():
    return jsonify(packet_sniffer.packets_data)

@app.route("/stats")
def get_stats():
    return jsonify(packet_sniffer.stats)

@app.route("/osint/<ip>")
def osint_lookup(ip):
    return jsonify(ip_osint(ip))

@app.route("/history")
def history():
    return jsonify(get_recent_packets(200))

@app.route("/threats")
def threat_summary():
    return jsonify(packet_sniffer.suspicious_ips)

@app.route("/traffic")
def traffic():
    return jsonify(packet_sniffer.traffic_history)

@app.route("/export")
def export_csv():
    def generate():
        yield "Time,Source IP,Destination IP,Protocol,Size,Status,Reason\n"
        for p in packet_sniffer.packets_data:
            yield f"{p['time']},{p['src']},{p['dst']},{p['protocol']},{p['size']},{p['status']},{p['reason']}\n"

    return Response(
        generate(),
        mimetype="text/csv",
        headers={"Content-Disposition": "attachment;filename=packets.csv"}
    )

if __name__ == "__main__":
    init_db()

    sniff_thread = threading.Thread(
        target=packet_sniffer.start_sniffing,
        args=(None,),
        daemon=True
    )
    sniff_thread.start()

    app.run(host="0.0.0.0", port=5000, debug=False)