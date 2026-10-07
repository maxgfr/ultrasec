const express = require("express");
const helmet = require("helmet");
const routes = require("./express-export");

const app = express();
app.use(helmet());
app.use(routes);
app.listen(3000);
