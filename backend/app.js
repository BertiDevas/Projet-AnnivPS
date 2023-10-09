const express = require('express');
const swaggerUi = require('swagger-ui-express');
const crypto = require('crypto');
const jwt = require('jsonwebtoken');

const db = require('./db_create.js');
const swaggerSpec = require('./swagger');
const {checkCredentials, verifyToken} = require('./security');

const app = express();
const port = 3000;
const codeApp = '0000';
const codeAdmin = '0001';
const secretKey = 'mysecretkey';


// Add middleware to serve Swagger UI at /api-docs
app.use('/api-docs', checkCredentials, swaggerUi.serve, swaggerUi.setup(swaggerSpec));
app.use(express.json());

// Define an API endpoint for user authentication
/**
 * @swagger
 * /authenticate-user:
 *   post:
 *     summary: Authenticate a user
 *     description: Authenticate a user by their username and password.
 *     requestBody:
 *       description: User authentication details.
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             properties:
 *               lastname:
 *                 type: string
 *                 default: Test
 *               mdpentered:
 *                 type: string
 *                 default: Test
 *     responses:
 *       200:
 *         description: User authenticated successfully
 *       401:
 *         description: Authentication failed
 *       500:
 *         description: Error authenticating user
 * 
 * 
 */
app.post('/authenticate-user', (req, res) => {

   const { lastname, mdpentered } = req.body;
   // Retrieve the salt from the database for the user
   db.get('SELECT Id, Salt, mdp, isAdmin FROM User WHERE lastname = ?', [lastname], (err, row) => {
      if (err) {
         console.error('Error retrieving user:', err.message);
         res.status(500).json({ message: 'Error authenticating user.' });
      } else if (row) {
         const { Id, Salt, mdp: storedmdp, isAdmin } = row;

         // Hash the entered password with the retrieved salt
         const hashedmdp = crypto.createHash('sha256').update(mdpentered + Salt).digest('hex');

         // Compare the hashed password with the stored hashed password
         if (hashedmdp === storedmdp) {

          const payload = {
            Id,
          };
          
          // Define the payload for the JWT, including the admin claim
          if (isAdmin) {
            payload.isAdmin = true;
          }
          
          // Sign the JWT with the secret key
          jwt.sign(payload, secretKey, { expiresIn: '24h' }, (err, token) => {
            if (err) {
              res.sendStatus(500);
            } else {
              // Include the token in the 'Authorization' header of the response
              res.setHeader('Authorization', `Bearer ${token}`);
              res.json({ authenticated: true, UserId: Id });
            }
          });

         } else {
           res.json({ authenticated: false });
         }
      } else {
         res.json({ authenticated: false });
      }
   });
 });

/**
 * @swagger
 * /register-user:
 *   post:
 *     summary: Register a new user
 *     description: Create a new user in the system.
 *     requestBody:
 *       description: User registration details.
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             properties:
 *               firstname:
 *                 type: string
 *                 default: Test
 *               lastname:
 *                 type: string
 *                 default: Test
 *               mdp:
 *                 type: string
 *                 default: Test
 *               code:
 *                 type: string
 *                 default: '0001'
 *     responses:
 *       200:
 *         description: User registered successfully
 *       400:
 *         description: Invalid request data
 *       500:
 *         description: Error registering user
 */
app.post('/register-user', (req, res) => {
   const { lastname, firstname, mdp, code } = req.body; 
   if (code !== codeApp & code !== codeAdmin) {
      res.status(400).json({ message: 'Invalid request data' });
      } else {

        isAdmin = false;
        if (code === codeAdmin) isAdmin = true;
         
         // Generate a unique salt for the user
         const salt = crypto.randomBytes(16).toString('hex');
      
         // Hash the password with the salt
         const hashedMdP = crypto.createHash('sha256').update(mdp + salt).digest('hex'); 
      
         // Insert the user into the User table
         db.run(
         'INSERT INTO User (lastname, firstname, MdP, Salt, isAdmin) VALUES (?, ?, ?, ?, ?)',
         [lastname, firstname, hashedMdP, salt, isAdmin],
         (err) => {
            if (err) {
               console.error('Error registering user:', err.message);
               res.status(500).json({ message: 'Error registering user.' });
            } else {
               console.log('User registered successfully');
               res.json({ message: 'User registered successfully' });
            }
         });
      }
 });


/**
 * @swagger
 * /update-confirmation/{id}:
 *   put:
 *     security:
 *       - BearerAuth: []
 *     summary: Update Confirmation value by user ID
 *     description: Update the Confirmation value (true/false) for a user based on their ID.
 *     parameters:
 *       - in: path
 *         name: id
 *         description: User ID
 *         required: true
 *         schema:
 *         type: integer
 *     requestBody:
 *       description: Confirmation value to update (true/false)
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             properties:
 *               Confirmation:
 *                 type: boolean
 *     responses:
 *       200:
 *         description: Confirmation value updated successfully
 *       401:
 *         description: Unauthorized (Invalid or missing token)
 *       403:
 *         description: Forbidden (Token is not valid)
 *       404:
 *         description: User not found
 *       500:
 *         description: Error updating Confirmation value
 */

app.put('/update-confirmation/:id', verifyToken, (req, res) => {
  const userId = req.params.id;
  const { Confirmation } = req.body;

  // Ensure that Confirmation is a boolean, true, false
  if (Confirmation !== true && Confirmation !== false) {
    return res.status(400).json({ message: 'Invalid Confirmation value' });
  }

  // Update the Confirmation value for the user based on the ID
  db.run('UPDATE User SET Confirmation = ? WHERE Id = ?', [Confirmation, userId], (err) => {
    if (err) {
      console.error('Error updating Confirmation value:', err.message);
      return res.status(500).json({ message: 'Error updating Confirmation value' });
    }

    if (this.changes === 0) {
      return res.status(404).json({ message: 'User not found' });
    }

    // Return a success message
    res.json({ message: 'Confirmation value updated successfully' });
  });
});

/**
 * @swagger
 * /get-all-users:
 *   get:
 *     summary: Get all users' firstname and lastname
 *     description: Retrieve the firstname and lastname of all users from the database.
 *     responses:
 *       200:
 *         description: Successfully retrieved user data.
 *         content:
 *           application/json:
 *             schema:
 *               type: array
 *               items:
 *                 type: object
 *                 properties:
 *                   firstname:
 *                     type: string
 *                     description: The user's firstname.
 *                   lastname:
 *                     type: string
 *                     description: The user's lastname.
 *       500:
 *         description: Error fetching user data from the database.
 */
app.get('/get-all-users', (req, res) => {
   // Query the database to retrieve all users' firstname and lastname
   db.all('SELECT firstname, lastname FROM User', (err, rows) => {
     if (err) {
       console.error('Error fetching users:', err.message);
       res.status(500).json({ message: 'Error fetching users.' });
     } else {
       // Extract the firstname and lastname from the query result
       const users = rows.map((row) => ({ firstname: row.firstname, lastname: row.lastname }));
       res.json(users);
     }
   });
 });

 // Define an endpoint to get user information by ID (requires JWT authentication)
/**
 * @swagger
 * /user/{id}:
 *   get:
 *     summary: Get user information by ID
 *     description: Retrieve user information based on the user's ID.
 *     parameters:
 *       - in: path
 *         name: id
 *         description: User ID
 *         required: true
 *         schema:
 *         type: integer
 *     responses:
 *       200:
 *         description: User information retrieved successfully
 *       401:
 *         description: Unauthorized (Invalid or missing token)
 *       403:
 *         description: Forbidden (Token is not valid)
 *       404:
 *         description: User not found
 *       500:
 *         description: Error retrieving user information
 */
app.get('/user/:id', (req, res) => {
  const userId = req.params.id;

  // Query the database to retrieve user information based on the ID
  db.get('SELECT Id, firstname, lastname FROM User WHERE Id = ?', [userId], (err, row) => {
    if (err) {
      console.error('Error retrieving user information:', err.message);
      return res.status(500).json({ message: 'Error retrieving user information' });
    }

    if (!row) {
      return res.status(404).json({ message: 'User not found' });
    }

    // Return the user information as a JSON response
    res.json(row);
  });
});

 app.get('/', (req, res) => {
   res.send('>:(');
 });

 // Start the Express server
 app.listen(port, () => {
   console.log(`Server is running on port ${port}`);
 });