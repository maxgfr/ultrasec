const express = require("express");
const helmet = require("helmet");
const app = express();
app.use(helmet());
app.set("trust proxy", false);
app.use(express.json({ limit: "100kb" }));
app.use(express.urlencoded({ extended: true, limit: "100kb" }));
app.listen(3000);
