const jwt = require('jsonwebtoken');
const basicAuth = require('basic-auth');

const secretKey = 'your-secret-key';

function verifyToken(req, res, next) {
    const token = req.header('Authorization');
    if (!token) {
      return res.status(401).json({ message: 'Unauthorized' });
    }
  
    try {
      const decoded = jwt.verify(token, secretKey);
      req.user = decoded.user;
      next();
    } catch (err) {
      res.status(403).json({ message: 'Token is not valid' });
    }
  }

  const checkCredentials = (req, res, next) => {
    const user = basicAuth(req);
  
    if (!user || user.name !== 'test' || user.pass !== 'test') {
      res.set('WWW-Authenticate', 'Basic realm=Authorization Required');
      return res.sendStatus(401);
    }
  
    // If credentials are correct, proceed to the Swagger UI route
    next();
  };

 module.exports = {secretKey, verifyToken, checkCredentials}