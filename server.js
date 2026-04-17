const fs = require("fs");
const path = require("path");
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

function resolveLogFilePath() {
  const envLogFile = String(process.env.LOG_FILE || "").trim();
  if (envLogFile) {
    return path.isAbsolute(envLogFile)
      ? envLogFile
      : path.join(process.cwd(), envLogFile);
  }

  const envLogDir = String(process.env.LOG_DIR || "").trim();
  const logDir = envLogDir
    ? (path.isAbsolute(envLogDir) ? envLogDir : path.join(process.cwd(), envLogDir))
    : path.join(process.cwd(), "logs");
  return path.join(logDir, "authbridge.log");
}

function createLogFileStream() {
  const logFilePath = resolveLogFilePath();
  try {
    fs.mkdirSync(path.dirname(logFilePath), { recursive: true });
    const stream = fs.createWriteStream(logFilePath, {
      flags: "a",
      encoding: "utf8",
    });

    stream.on("error", (error) => {
      process.stderr.write(`[${formatTimestamp()}] [LOGGER] 日志文件写入失败: ${error.message}\n`);
    });

    return {
      logFilePath,
      stream,
    };
  } catch (error) {
    process.stderr.write(`[${formatTimestamp()}] [LOGGER] 初始化日志文件失败: ${error.message}\n`);
    return {
      logFilePath,
      stream: null,
    };
  }
}

const fileLogger = createLogFileStream();

function writeLineToLogFile(line) {
  if (!fileLogger.stream) {
    return;
  }

  try {
    fileLogger.stream.write(`${line}\n`);
  } catch (error) {
    process.stderr.write(`[${formatTimestamp()}] [LOGGER] 写入日志时异常: ${error.message}\n`);
  }
}

function closeLogFileStream() {
  if (!fileLogger.stream) {
    return;
  }

  try {
    fileLogger.stream.end();
  } catch (_error) {
    // ignore close failure
  }
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
      const level = method.toUpperCase();
      const content = args.length ? util.format(...args) : "";
      const message = content
        ? `${prefix} [${level}] ${content}`
        : `${prefix} [${level}]`;

      writeLineToLogFile(message);
      return original(message);
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

  console.log(`日志文件: ${fileLogger.logFilePath}`);
});

// 优雅关闭
process.on("SIGTERM", () => {
  console.log("正在关闭服务器...");
  closeLogFileStream();
  process.exit(0);
});

process.on("SIGINT", () => {
  console.log("收到中断信号，正在关闭服务器...");
  closeLogFileStream();
  process.exit(0);
});
