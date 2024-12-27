const nodeExternals = require("webpack-node-externals");

module.exports = {
  entry: "./handler.mjs",
  target: "node",
  externals: [nodeExternals()],
  mode: "production",
};
f;
