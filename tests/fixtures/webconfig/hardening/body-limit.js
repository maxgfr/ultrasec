const express = require("express");
const helmet = require("helmet");
const app = express();
app.use(helmet());
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.listen(3000);
