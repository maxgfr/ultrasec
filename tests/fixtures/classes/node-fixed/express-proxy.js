module.exports = function configure(app) {
  app.locals.clientIp = (req) => req.socket.remoteAddress;
};
