const swaggerJSDoc = require('swagger-jsdoc');
const YAML = require('yamljs'); // Import the YAML library

const swaggerDefinition = YAML.load('./backend/swagger.yaml'); // Load the YAML file

const options = {
  swaggerDefinition,
  apis: ['./backend/app.js', './backend/security.js'], // Path to the API route files
};

const swaggerSpec = swaggerJSDoc(options);

module.exports = swaggerSpec;
