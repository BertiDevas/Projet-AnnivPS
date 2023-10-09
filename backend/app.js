const express = require('express');
const swaggerUi = require('swagger-ui-express');
const crypto = require('crypto');
const jwt = require('jsonwebtoken');

const db = require('./db_create.js');
const swaggerSpec = require('./swagger');
const {secretKey, verifyToken, checkCredentials} = require('./security');

const app = express();
const port = 3000;

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
 *               mdp:
 *                 type: string
 *     responses:
 *       200:
 *         description: User authenticated successfully
 *       401:
 *         description: Authentication failed
 *       500:
 *         description: Error authenticating user
 */
app.post('/authenticate-user', (req, res) => {

   const { lastname, mdp } = req.body;
   // Retrieve the salt from the database for the user
   db.get('SELECT Id, Salt, mdp FROM User WHERE lastname = ?', [lastname], (err, row) => {
      if (err) {
         console.error('Error retrieving user:', err.message);
         res.status(500).json({ message: 'Error authenticating user.' });
      } else if (row) {
         const { Id, Salt, mdp: storedmdp } = row;

         // Hash the entered password with the retrieved salt
         const hashedmdp = crypto.createHash('sha256').update(mdp + Salt).digest('hex');

         // Compare the hashed password with the stored hashed password
         if (hashedmdp === storedmdp) {
           jwt.sign({ Id }, secretKey, (err, token) => {
               if (err) {
                 res.sendStatus(500);
               } else {
                  res.json({ authenticated: true, UserId: Id, token });
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
 *               lastname:
 *                 type: string
 *               mdp:
 *                 type: string
 *               code:
 *                 type: string
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
   if (code != '0000') {
      res.status(400).json({ message: 'Invalid request data' });
      } else {
         
         // Generate a unique salt for the user
         const salt = crypto.randomBytes(16).toString('hex');
      
         // Hash the password with the salt
         const hashedMdP = crypto.createHash('sha256').update(mdp + salt).digest('hex'); 
      
         // Insert the user into the User table
         db.run(
         'INSERT INTO User (lastname, firstname, MdP, Confirmation, Salt) VALUES (?, ?, ?, ?, ?)',
         [lastname, firstname, hashedMdP, salt],
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

 // Define an API endpoint to update the Confirmation value for a user
 /**
 * @swagger
 * /update-confirmation/{userId}:
 *   put:
 *     summary: Update Confirmation value for a user
 *     description: Update the Confirmation value for a user by their user ID.
 *     parameters:
 *       - name: userId
 *         in: path
 *         description: User ID to update Confirmation value.
 *         required: true
 *         schema:
 *           type: string
 *       - name: Confirmation
 *         in: body
 *         description: Updated Confirmation value (null, true, or false).
 *         required: true
 *         schema:
 *           type: boolean
 *     responses:
 *       200:
 *         description: Confirmation value updated successfully
 *       400:
 *         description: Invalid request data
 *       404:
 *         description: User not found
 *       500:
 *         description: Error updating Confirmation value
 */
app.put('/update-confirmation/:userId', (req, res) => {
   const { userId } = req.params;
   const { Confirmation } = req.body;
 
   // Check if Confirmation is one of the allowed values (null, true, false)
   if (Confirmation === true || Confirmation === false) {
     // Update the Confirmation value in the User table
     db.run('UPDATE User SET Confirmation = ? WHERE Id = ?', [Confirmation, userId], (err) => {
       if (err) {
         console.error('Error updating Confirmation:', err.message);
         res.status(500).json({ message: 'Error updating Confirmation.' });
       } else {
         console.log('Confirmation updated successfully');
         res.json({ message: 'Confirmation updated successfully' });
       }
     });
   } else {
     res.status(400).json({ message: 'Invalid Confirmation value. Allowed values are null, true, false.' });
   }
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

 app.get('/', (req, res) => {
   res.send('>:(');
 });

 // Start the Express server
 app.listen(port, () => {
   console.log(`Server is running on port ${port}`);
 });

module.exports = app;