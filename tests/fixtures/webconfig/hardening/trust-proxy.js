const express = require("express");
const helmet = require("helmet");
const app = express();
app.use(helmet());
app.set("trust proxy", true);
app.listen(3000);
