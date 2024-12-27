const fs = require("fs");
const path = require("path");

const configPath = path.join(__dirname, "config.json");

let config;
try {
  const data = fs.readFileSync(configPath, "utf8");
  config = JSON.parse(data);
  console.log("Config file read successfully");
} catch (error) {
  console.error("Error reading config file:", error);
  config = {};
}

module.exports = config;
