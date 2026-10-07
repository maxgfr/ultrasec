const express = require("express");
const routes = require("./express-export");

const app = express();
app.use(routes);
app.listen(3000);
