const jwt = require('jsonwebtoken');
const basicAuth = require('basic-auth');

const {secretKey, swaggerKey, allowedOrigins} = require('./config')

const checkCredentials = (req, res, next) => {
  const user = basicAuth(req);

  if (!user || user.name !== swaggerKey || user.pass !== swaggerKey) {
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

function verifyTokenAdmin(req, res, next) {
  const tokenHeader = req.headers.authorization;
  if (!tokenHeader) return res.status(401).json('Unauthorized user');

  // Split the header to get just the token part (after "Bearer ")
  const token = tokenHeader.split(' ')[1];

  try {
    const decoded = jwt.verify(token, secretKey);

    if (decoded.isAdmin) {
      // The user is an admin
      next();
    } else {
      // The user is not an admin
      res.status(403).json('Permission denied. User is not an admin');
    }
  } catch (e) {
    res.status(403).json('Token not valid');
  }
}

const corsOptions = {
  origin: (origin, callback) => {
    if (allowedOrigins.indexOf(origin) !== -1 || !origin) {
      // Allow the request if the origin is in the allowedOrigins list or is not provided (for same-origin requests)
      callback(null, true);
    } else {
      // Deny the request if the origin is not in the allowedOrigins list
      callback(new Error('Not allowed by CORS'));
    }
  },
};

 module.exports = {checkCredentials, verifyToken, verifyTokenAdmin, corsOptions}