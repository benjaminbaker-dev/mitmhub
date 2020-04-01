from flask import Flask, request, jsonify
from flask_cors import cross_origin

from network.network import Network

network = Network("default")
app = Flask(__name__)


@app.route("/api/network", methods=["GET"])
@cross_origin()
def get_network():
    try:
        return network.get_json_str()
    except Exception as e:
        return jsonify({"status": "Error: {}".format(e)})


@app.route("/api/refresh", methods=["GET"])
@cross_origin()
def refresh_network():
    try:
        network.refresh_network()
        return jsonify({"status": "Success"})
    except Exception as e:
        return jsonify({"status": "Error: {}".format(e)})


@app.route("/api/fill_tags", methods=["POST"])
@cross_origin()
def get_tags():
    try:
        mac = request.json["node_id"]
        network.run_detailed_scan_on_node(mac)
        return jsonify({"status": "Successfully got tags"})
    except Exception as e:
        return jsonify({"status": "Error: {}".format(e)})


@app.route("/api/get_rules", methods=["POST"])
@cross_origin()
def get_available_rules_for_node():
    try:
        return network.json_node_query_supported_rules(request.json)
    except Exception as e:
        return jsonify({"status": "Error: {}".format(e)})


@app.route("/api/get_running_rules", methods=["POST"])
@cross_origin()
def get_running_rules_for_node():
    try:
        return network.json_node_query_active_rules(request.json)
    except Exception as e:
        return jsonify({"status": "Error: {}".format(e)})


@app.route("/api/set_rule", methods=["POST"])
@cross_origin()
def add_rule_for_node():
    try:
        network.json_node_request_add_rule(request.json)
        return jsonify({"status": "Successfully added rule"})
    except Exception as e:
        return jsonify({"status": "Error: {}".format(e)})


@app.route("/api/remove_rule", methods=["POST"])
@cross_origin()
def delete_rule_for_node():
    try:
        network.json_node_request_remove_rule(request.json)
        return jsonify({"status": "Successfully removed rule"})
    except Exception as e:
        return jsonify({"status": "Error: {}".format(e)})


@app.route("/api/start_mitm", methods=["POST"])
@cross_origin()
def start_mitm():
    try:
        mac = request.json["node_id"]
        network.start_mitm_by_mac(mac)
        return jsonify({"status": "Successfully started mitm"})
    except Exception as e:
        return jsonify({"status": "Error: {}".format(e)})


@app.route("/api/stop_mitm", methods=["POST"])
@cross_origin()
def stop_mitm():
    try:
        mac = request.json["node_id"]
        network.stop_mitm_by_mac(mac)
        return jsonify({"status": "Successfully stopped mitm"})
    except Exception as e:
        return jsonify({"status": "Error: {}".format(e)})


@app.route("/shutdown_server", methods=["POST"])
@cross_origin()
def stop_server():
    func = request.environ.get('werkzeug.server.shutdown')
    auth = request.json["id"] == "YEET"

    if func and auth:
        func()

    return jsonify({})


if __name__ == '__main__':
    app.run(port=9846)
