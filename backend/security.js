const jwt = require('jsonwebtoken');
const basicAuth = require('basic-auth');

const secretKey = 'mysecretkey';

const checkCredentials = (req, res, next) => {
  const user = basicAuth(req);

  if (!user || user.name !== 'test' || user.pass !== 'test') {
    res.set('WWW-Authenticate', 'Basic realm=Authorization Required');
    return res.sendStatus(401);
  }

  // If credentials are correct, proceed to the Swagger UI route
  next();
};

function verifyToken(req, res, next) {
  const tokenHeader = req.headers.authorization;
  if (!tokenHeader) return res.status(401).json('Unauthorized user');

  // Split the header to get just the token part (after "Bearer ")
  const token = tokenHeader.split(' ')[1];

  try {
    const decoded = jwt.verify(token, secretKey);
    next();
  } catch (e) {
    res.status(403).json('Token not valid');
  }
}

 module.exports = {checkCredentials, verifyToken}