const app = require("./app");
const { NODE_PORT } = require("./config");

app.listen(NODE_PORT, () => {
  console.log(`[server]: Server is running at https://localhost:${NODE_PORT}`);
});
