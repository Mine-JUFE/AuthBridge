const util = require("util");

function formatTimestamp(date = new Date()) {
  const year = date.getFullYear();
  const month = String(date.getMonth() + 1).padStart(2, "0");
  const day = String(date.getDate()).padStart(2, "0");
  const hours = String(date.getHours()).padStart(2, "0");
  const minutes = String(date.getMinutes()).padStart(2, "0");
  const seconds = String(date.getSeconds()).padStart(2, "0");
  const millis = String(date.getMilliseconds()).padStart(3, "0");

  const offsetMinutes = -date.getTimezoneOffset();
  const sign = offsetMinutes >= 0 ? "+" : "-";
  const absOffsetMinutes = Math.abs(offsetMinutes);
  const offsetHours = String(Math.floor(absOffsetMinutes / 60)).padStart(2, "0");
  const offsetRemainMinutes = String(absOffsetMinutes % 60).padStart(2, "0");

  return `${year}-${month}-${day} ${hours}:${minutes}:${seconds}.${millis} ${sign}${offsetHours}:${offsetRemainMinutes}`;
}

function patchConsoleWithTimestamp() {
  if (global.__AUTHBRIDGE_CONSOLE_TS_PATCHED__) {
    return;
  }

  const methods = ["log", "info", "warn", "error", "debug"];
  methods.forEach((method) => {
    const original = console[method].bind(console);
    console[method] = (...args) => {
      const prefix = `[${formatTimestamp()}]`;
      if (!args.length) {
        return original(prefix);
      }

      return original(`${prefix} ${util.format(...args)}`);
    };
  });

  global.__AUTHBRIDGE_CONSOLE_TS_PATCHED__ = true;
}

patchConsoleWithTimestamp();

const app = require("./app");
const config = require("./config");

const PORT = config.port || 3000;

app.listen(PORT, () => {
  console.log(`
   █████╗ ██╗   ██╗████████╗██╗  ██╗██████╗ ██████╗ ██╗██████╗ ██████╗ ███████╗
  ██╔══██╗██║   ██║╚══██╔══╝██║  ██║██╔══██╗██╔══██╗██║██╔══██╗██╔══██╗██╔════╝
  ███████║██║   ██║   ██║   ███████║██████╔╝██████╔╝██║██║  ██║██████╔╝█████╗  
  ██╔══██║██║   ██║   ██║   ██╔══██║██╔══██╗██╔══██╗██║██║  ██║██╔══██╗██╔══╝  
  ██║  ██║╚██████╔╝   ██║   ██║  ██║██████╔╝██║  ██║██║██████╔╝██████╔╝███████╗
  ╚═╝  ╚═╝ ╚═════╝    ╚═╝   ╚═╝  ╚═╝╚═════╝ ╚═╝  ╚═╝╚═╝╚═════╝ ╚═════╝ ╚══════╝
                            Author: Tobby_000
-------------------------------------------------------------------------------
AuthBridge 已启动
地址: ${config.appUrl}
本地端口: ${PORT}
环境: ${config.env}
CAS 服务: ${config.cas.baseUrl}
时间: ${new Date().toLocaleString()}
-------------------------------------------------------------------------------
  `);
});

// 优雅关闭
process.on("SIGTERM", () => {
  console.log("正在关闭服务器...");
  process.exit(0);
});
