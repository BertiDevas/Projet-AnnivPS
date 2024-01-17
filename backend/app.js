const express = require('express');
const swaggerUi = require('swagger-ui-express');
// const crypto = require('crypto');
const bcrypt= require('bcrypt');
const jwt = require('jsonwebtoken');
const fs = require('fs');
const path = require('path')
const cors = require('cors');

const db = require('./db_create');
const swaggerSpec = require('./swagger');
const {checkCredentials, verifyToken, verifyTokenAdmin, corsOptions} = require('./security');
const {upload, dir, mime} = require('./gestion_photo');
const {codeApp, codeAdmin, secretKey, saltRounds} = require('./config')

const app = express();

let port = process.env.PORT;
if (port == null || port == "") {
  port = 8000;
}

// Add middleware to serve Swagger UI at /api-docs
app.use('/api-docs', checkCredentials, swaggerUi.serve, swaggerUi.setup(swaggerSpec));
app.use(express.json());
app.use(cors(corsOptions));

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
 *                 default: TestTest
 *     responses:
 *       200:
 *         description: User authenticated successfully
 *         content:
 *           application/json:
 *             example:
 *               authenticated: true
 *               userId: 1
 *               Authorization: "Bearer <your-token>"
 *       401:
 *         description: Authentication failed
 *       500:
 *         description: Error authenticating user
 */
app.post('/authenticate-user', async (req, res) => {
  const { lastname, mdpentered } = req.body;

  try {
    // Retrieve user information from the database
    const rows = await new Promise((resolve, reject) => {
      db.all('SELECT id, mdp, isAdmin, isRegistered FROM User WHERE lastname = ?', [lastname], (err, rows) => {
        if (err) {
          reject(err);
        } else {
          resolve(rows);
        }
      });
    });

    if (rows.length > 0) {
      for (const row of rows) {
        const { id, mdp: storedmdp, isAdmin, isRegistered } = row;

        if (isRegistered && storedmdp !== null) {
          const result = await new Promise((resolve, reject) => {
            bcrypt.compare(mdpentered, storedmdp, (err, result) => {
              if (err) {
                reject(err);
              } else {
                resolve(result);
              }
            });
          });

          if (result) {
            const payload = {
              id,
            };

            if (isAdmin) {
              payload.isAdmin = true;
            }

            const token = await new Promise((resolve, reject) => {
              jwt.sign(payload, secretKey, { expiresIn: '24h' }, (err, token) => {
                if (err) {
                  reject(err);
                } else {
                  resolve(token);
                }
              });
            });

            res.setHeader('Authorization', `Bearer ${token}`);
            res.json({
              authenticated: true,
              userId: id,
              Authorization: `Bearer ${token}`,
            });
            console.log(new Date().toISOString() + " : Authentication Successful by : " + id)
            // Exit the loop after successful authentication
            return;
          }
        }
      }

      // If none of the passwords matched
      res.status(401).json({ message: 'Authentication failed. Incorrect password.' });
    } else {
      // No matching user found
      res.status(401).json({ message: 'Authentication failed. User not found.' });
    }
  } catch (error) {
    console.error('Error:', error.message);
    res.status(500).json({ message: 'Internal server error.' });
  }
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
 *                 default: TestTest
 *               code:
 *                 type: string
 *                 default: 'Fete35StSAdminParents'
 *     responses:
 *       200:
 *         description: User registered successfully
 *       400:
 *         description: Invalid request data
 *       401:
 *         description: Password less than 8 caracters
 *       409:
 *         description: User with the same name already
 *       500:
 *         description: Error registering user
 */
app.post('/register-user', (req, res) => {
  const { lastname, firstname, mdp, code } = req.body; 
  if (code !== codeApp && code !== codeAdmin) {
     res.status(400).json({ message: 'Invalid code sent' });
  } else {
    
    const formattedLastname = lastname.trim().replace('/[\s-]+/g', ' ');
    const formattedfirstname = firstname.trim().replace('/[\s-]+/g', ' ');

    db.get(
      'SELECT * FROM User WHERE LOWER(TRIM(lastname)) = LOWER(?) AND LOWER(TRIM(firstname)) = LOWER(?)',
      [formattedLastname, formattedfirstname],
      (err, existingUser) => {
        if (err) {
          console.error('Error checking for existing user:', err.message);
          return res.status(500).json({ message: 'Error registering user.' });
        }

        if (existingUser) {
          // If a user with the same firstname and lastname exists, return a 409 response
          return res.status(409).json({ message: 'User with the same name already exists.' });
        }

        if (mdp.length < 8) {
          return res.status(401).json({ message: 'Password less than 8 caracters' });
        }

        isRegistered = true;
        isAdmin = false;
        if (code === codeAdmin) isAdmin = true;

        bcrypt.genSalt(saltRounds, function(err, salt) {
          bcrypt.hash(mdp, salt, function(err, hash) {
            db.run(
              'INSERT INTO User (lastname, firstname, MdP, Salt, isAdmin, isRegistered) VALUES (?, ?, ?, ?, ?, ?)',
              [lastname, firstname, hash, salt, isAdmin, isRegistered],
              (err) => {
                if (err) {
                  console.error('Error registering user:', err.message);
                  res.status(500).json({ message: 'Error registering user.' });
                } else {
                  console.log(new Date().toISOString() + " : User registered successfully : " + id)
                  res.json({ message: 'User registered successfully' });
                }
              }
            );
          });
        });  
      }
    );
  }
});

/**
 * @swagger
 * /create-user:
 *   post:
 *     summary: Create a new user (Admin)
 *     description: Create a new user in the system (Admin access required).
 *     requestBody:
 *       description: User creation details.
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             properties:
 *               idCreator:
 *                 type: integer
 *                 description: The user's creator id.
 *               firstname:
 *                 type: string
 *                 description: The user's first name.
 *               lastname:
 *                 type: string
 *                 description: The user's last name.
 *               confirmation:
 *                 type: boolean
 *                 description: The user's confirmation status.
 *               confirmation_dej:
 *                 type: boolean
 *                 description: The user's confirmation_dej status.
 *               confirmation_balade:
 *                 type: boolean
 *                 description: The user's confirmation_balade status.
 *               confirmation_diner:
 *                 type: boolean
 *                 description: The user's confirmation_diner status.
 *     responses:
 *       200:
 *         description: User created successfully.
 *       400:
 *         description: Invalid request format or missing fields.
 *       409:
 *         description: User with the same name already exists.
 *       500:
 *         description: Error creating user.
 *       403:
 *         description: Permission denied. Admin access required.
 */
app.post('/create-user', verifyToken, (req, res) => {
  const {idCreator, firstname, lastname, confirmation, confirmation_dej, confirmation_balade, confirmation_diner} = req.body;

  const formattedLastname = lastname.trim().replace('/[\s-]+/g', ' ');
  const formattedfirstname = firstname.trim().replace('/[\s-]+/g', ' ');

  db.get(
    'SELECT * FROM User WHERE LOWER(TRIM(lastname)) = LOWER(?) AND LOWER(TRIM(firstname)) = LOWER(?)',
    [formattedLastname, formattedfirstname],
    (err, existingUser) => {
      if (err) {
        console.error('Error checking for existing user:', err.message);
        return res.status(500).json({ message: 'Error registering user.' });
      }

      if (existingUser) {
        // If a user with the same firstname and lastname exists, return a 409 response
        return res.status(409).json({ message: 'User with the same name already exists.' });
      }
      // If no existing user or member with the same name, proceed with user creation
      db.run(
        'INSERT INTO User (idCreator, firstname, lastname, confirmation, confirmation_dej, confirmation_balade, confirmation_diner, isRegistered) VALUES (?, ?, ?, ?, ?, ?, ?, ?)',
        [idCreator, firstname, lastname, confirmation, confirmation_dej, confirmation_balade, confirmation_diner, false],
        (err) => {
          if (err) {
            console.error('Error creating user:', err.message);
            return res.status(500).json({ message: 'Error creating user' });
          } else {
            console.log(new Date().toISOString() + " : User created successfully : " + id)
            db.get('SELECT id FROM User WHERE lastname = ? AND firstname = ?', [lastname, firstname], (err, row) => {
              if (err) {
                console.error('Error getting user id:', err.message);
                return res.status(500).json({ message: 'Error creating user' });
              } else {
                res.json({ message: 'User created successfully',
                           id: row.id });
              }
            })
          }
        }
      );
    }
  );
});

/**
 * @swagger
 * /change-password:
 *   post:
 *     summary: Change the password of a user
 *     description: Change the password (mdp) of an existing user in the system.
 *     requestBody:
 *       description: User's information to change the password.
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
 *             example:
 *               firstname: John
 *               lastname: Doe
 *               mdp: new_password
 *               code: '0001'
 *     responses:
 *       200:
 *         description: Password changed successfully
 *       400:
 *         description: Invalid request data
 *       401:
 *         description: Unauthorized
 *       404:
 *         description: User not found
 *       500:
 *         description: Error changing the password
 */
app.post('/change-password', (req, res) => {
  const { firstname, lastname, mdp, code } = req.body;

  // Check if user is authorized based on the code
  if (code !== codeApp && code !== codeAdmin) {
    return res.status(401).json({ message: 'Unauthorized' });
  }

  // Check if the user with the provided firstname and lastname exists
  db.get(
    'SELECT id, Salt FROM User WHERE firstname = ? AND lastname = ?',
    [firstname, lastname],
    (err, user) => {
      if (err) {
        console.error('Error checking for user:', err.message);
        return res.status(500).json({ message: 'Error changing the password' });
      }

      if (!user) {
        return res.status(404).json({ message: 'User not found' });
      }

      bcrypt.genSalt(saltRounds, function(err, salt) {
        bcrypt.hash(mdp, salt, function(err, hash) {
        db.run(
          'UPDATE User SET MdP = ?, Salt = ? WHERE id = ?',
          [hash, salt, user.id],
          (err) => {
            if (err) {
              console.error('Error changing the password:', err.message);
              return res.status(500).json({ message: 'Error changing the password' });
            }
  
            console.log(new Date().toISOString() + " : Password changed successfully : " + id);
            res.json({ message: 'Password changed successfully' });
          }
        );
        });
      });
    }
  );
});

/**
 * @swagger
 * /get-all-users:
 *   get:
 *     summary: Get all users with associated members
 *     description: Retrieve all users' information with their associated members from the database.
 *     responses:
 *       200:
 *         description: Successfully retrieved users with associated members.
 *         content:
 *           application/json:
 *             schema:
 *               type: array
 *               items:
 *                 type: object
 *                 properties:
 *                   id:
 *                     type: integer
 *                     description: The user's id.
 *                     example: 1
 *                   idCreator:
 *                     type: integer
 *                     description: The user's creator id (if exists).
 *                     example: null
 *                   firstname:
 *                     type: string
 *                     description: The user's firstname.
 *                     example: John
 *                   lastname:
 *                     type: string
 *                     description: The user's lastname.
 *                     example: Smith
 *                   confirmation:
 *                     type: boolean
 *                     description: The user's confirmation status.
 *                     example: true
 *                   confirmation_dej:
 *                     type: boolean
 *                     description: The user's confirmation status for lunch.
 *                     example: true
 *                   confirmation_balade:
 *                     type: boolean
 *                     description: The user's confirmation status for a walk.
 *                     example: true
 *                   confirmation_diner:
 *                     type: boolean
 *                     description: The user's confirmation status for diner.
 *                     example: true
 *                   isRegistered:
 *                     type: boolean
 *                     description: The user is registered or entered by an admin.
 *                     example: true
 *       500:
 *         description: Error fetching users with members from the database.
 */
app.get('/get-all-users', verifyToken, async (req, res) => {
  try {
    db.all('SELECT id, idCreator, firstname, lastname, confirmation, confirmation_dej, confirmation_balade, confirmation_diner, isRegistered FROM User', (err, rows) => {
      if (err) {
        reject(err);
      } else {
        const users = rows.map((row) => ({
          id: row.id,
          idCreator: row.idCreator,
          firstname: row.firstname,
          lastname: row.lastname,
          confirmation: row.confirmation,
          confirmation_dej: row.confirmation_dej,
          confirmation_balade: row.confirmation_balade,
          confirmation_diner: row.confirmation_diner,
          isRegistered: row.isRegistered
        }));

        users.forEach(user => {
        if (user.confirmation != null) user.confirmation = Boolean(user.confirmation);
        if (user.confirmation_dej != null) user.confirmation_dej = Boolean(user.confirmation_dej);
        if (user.confirmation_balade != null) user.confirmation_balade = Boolean(user.confirmation_balade);
        if (user.confirmation_diner != null) user.confirmation_diner = Boolean(user.confirmation_diner);
        if (user.isRegistered != null) user.isRegistered = Boolean(user.isRegistered);
        });
        
        res.json(users);
      }
    });
  } catch (err) {
    console.error('Error fetching users with members:', err.message);
    res.status(500).json({ message: 'Error fetching users with members.' });
  }
});

/**
 * @swagger
 * /user/{id}:
 *   get:
 *     summary: Get user information with associated members
 *     description: Retrieve user information along with associated members based on the user's ID.
 *     parameters:
 *       - in: path
 *         name: id
 *         description: User ID
 *         required: true
 *         schema:
 *           type: integer
 *     responses:
 *       200:
 *         description: Successfully retrieved user information with associated members.
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 id:
 *                   type: integer
 *                   description: The user's ID.
 *                 idCreator:
 *                   type: integer
 *                   description: The user's creator ID (if exists).
 *                 firstname:
 *                   type: string
 *                   description: The user's first name.
 *                 lastname:
 *                   type: string
 *                   description: The user's last name.
 *                 confirmation:
 *                   type: boolean
 *                   description: The user's confirmation status.
 *                 confirmation_dej:
 *                   type: boolean
 *                   description: The user's confirmation_dej status.
 *                 confirmation_balade:
 *                   type: boolean
 *                   description: The user's confirmation_balade status.
 *                 confirmation_diner:
 *                   type: boolean
 *                   description: The user's confirmation_diner status.                
 *       404:
 *         description: User not found.
 *       500:
 *         description: Error retrieving user information with associated members.
 */
app.get('/user/:id', verifyToken, (req, res) => {
  const userId = req.params.id;

  // Query the database to retrieve user information based on the ID
  db.get('SELECT id, idCreator, firstname, lastname, confirmation, confirmation_dej, confirmation_balade, confirmation_diner FROM User WHERE id = ?', [userId], (err, userRow) => {
    if (err) {
      console.error('Error retrieving user information:', err.message);
      return res.status(500).json({ message: 'Error retrieving user information' });
    }

    if (!userRow) {
      return res.status(404).json({ message: 'User not found' });
    }

    if (userRow.confirmation != null) userRow.confirmation = Boolean(userRow.confirmation);
    if (userRow.confirmation_dej != null) userRow.confirmation_dej = Boolean(userRow.confirmation_dej);
    if (userRow.confirmation_balade != null) userRow.confirmation_balade = Boolean(userRow.confirmation_balade);
    if (userRow.confirmation_diner != null) userRow.confirmation_diner = Boolean(userRow.confirmation_diner);
    if (userRow.isRegistered != null) userRow.isRegistered = Boolean(userRow.isRegistered);
    
    res.json(userRow)
  });
});

/**
 * @swagger
 * /get-users-by-creator/{idCreator}:
 *   get:
 *     summary: Get all users with the same idCreator
 *     description: Retrieve all users with the same idCreator from the database.
 *     parameters:
 *       - in: path
 *         name: idCreator
 *         description: The idCreator to filter users.
 *         required: true
 *         schema:
 *           type: integer
 *     responses:
 *       200:
 *         description: Successfully retrieved users.
 *         content:
 *           application/json:
 *             schema:
 *               type: array
 *               items:
 *                 $ref: '#/components/schemas/User'
 *       500:
 *         description: Error fetching user data from the database.
 */
app.get('/get-users-by-creator/:idCreator', verifyToken, (req, res) => {
  const { idCreator } = req.params;

  // Query the database to retrieve users with the same idCreator
  db.all('SELECT id, lastname, firstname, confirmation, confirmation_dej, confirmation_balade, confirmation_diner FROM User WHERE idCreator = ?', [idCreator], (err, rows) => {
    if (err) {
      console.error('Error fetching users:', err.message);
      res.status(500).json({ message: 'Error fetching users.' });
    } else {
      // Return the users as a JSON response
      res.json(rows);
    }
  });
});

/**
 * @swagger
 * /get-all-files:
 *   get:
 *     summary: Get all files
 *     description: Retrieve and serve a list of all files from the server's 'uploads' directory.
 *     responses:
 *       200:
 *         description: File list retrieved successfully.
 *         content:
 *           application/json:
 *             schema:
 *               type: array
 *               items:
 *                 type: string
 *                 format: binary
 *                 description: List of file names in the 'uploads' directory.
 *       403:
 *         description: Forbidden, file access denied.
 *       500:
 *         description: Internal Server Error, error while retrieving file list.
 */
app.get('/get-all-files', verifyToken, (req, res) => {
  fs.readdir(dir, (err, files) => {
    if (err) {
      console.error('Error reading directory:', err.message);
      return res.status(500).json({ message: 'Error reading directory.' });
    }

    res.json(files);
  });
});

/**
 * @swagger
 * /download-file:
 *   get:
 *     summary: Download a file
 *     description: Download a specific file from the server's 'uploads' directory.
 *     parameters:
 *       - in: query
 *         name: filename
 *         required: true
 *         description: The name of the file to download.
 *         schema:
 *           type: string
 *     responses:
 *       200:
 *         description: File downloaded successfully.
 *         content:
 *           application/octet-stream::
 *             schema:
 *               type: string
 *               format: binary
 *               description: The content of the requested file.
 *       403:
 *         description: Forbidden, file access denied.
 *       404:
 *         description: Not Found, requested file not found.
 *       500:
 *         description: Internal Server Error, error while serving the file.
 */
app.get('/download-file', verifyToken, (req, res) => {
  const { filename } = req.query;
  const filePath = path.join(dir, filename);

  if (fs.existsSync(filePath)) {
    res.download(filePath);
  } else {
    res.status(404).json({ message: 'File not found' });
  }
});

/**
 * @swagger
 * /update-confirmation/{id}:
 *   put:
 *     summary: Update Confirmation values by user ID
 *     description: Update the Confirmation values (true/false/null) for a user based on their ID.
 *     parameters:
 *       - in: path
 *         name: id
 *         description: User ID
 *         required: true
 *         schema:
 *           type: integer
 *     requestBody:
 *       description: Confirmation values to update (true/false/null).
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             properties:
 *               confirmation:
 *                 type: boolean
 *                 description: The confirmation value for a specific event.
 *               confirmation_dej:
 *                 type: boolean
 *                 description: The confirmation value for another event.
 *               confirmation_balade:
 *                 type: boolean
 *                 description: The confirmation value for a different event.
 *               confirmation_diner:
 *                 type: boolean
 *                 description: The confirmation value for yet another event.
 *     responses:
 *       200:
 *         description: Confirmation values updated successfully.
 *       400:
 *         description: Invalid Confirmation values or missing fields.
 *       401:
 *         description: Unauthorized (Invalid or missing token).
 *       403:
 *         description: Forbidden (Token is not valid).
 *       404:
 *         description: User not found.
 *       500:
 *         description: Error updating Confirmation values.
 */
app.put('/update-confirmation/:id', verifyToken, (req, res) => {
  const userId = req.params.id;
  const { confirmation, confirmation_dej, confirmation_balade, confirmation_diner } = req.body;

  // Ensure that Confirmation is a boolean, true, false
  if (confirmation !== null  && confirmation !== true && confirmation !== false && 
    confirmation_dej !== null  && confirmation_dej !== true && confirmation_dej !== false &&
    confirmation !== null  && confirmation !== true && confirmation !== false &&
    confirmation !== null  && confirmation !== true && confirmation !== false) {
    return res.status(400).json({ message: 'Invalid Confirmation value' });
  }

  // Update the Confirmation value for the user based on the ID
  db.run('UPDATE User SET confirmation = ?, confirmation_dej = ?, confirmation_balade = ?, confirmation_diner = ? WHERE id = ?', 
  [confirmation, confirmation_dej, confirmation_balade, confirmation_diner, userId], (err) => {
    if (err) {
      console.error('Error updating Confirmation value:', err.message);
      return res.status(500).json({ message: 'Error updating Confirmation value' });
    }

    if (this.changes === 0) {
      return res.status(404).json({ message: 'User not found' });
    }

    // Return a success message
    res.json({ message: 'Confirmations values updated successfully' });
  });
});

/**
 * @swagger
 * /upload:
 *   post:
 *     summary: Upload multiple images
 *     description: Upload multiple images to the server.
 *     requestBody:
 *       content:
 *         multipart/form-data:
 *           schema:
 *             type: object
 *             properties:
 *               files:
 *                 type: array
 *                 items:
 *                   type: string
 *                   format: binary
 *     responses:
 *       200:
 *         description: Images uploaded successfully.
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 message:
 *                   type: string
 *                   description: A success message.
 *                 imageUrls:
 *                   type: array
 *                   items:
 *                     type: string
 *                   description: URLs of the uploaded images.
 *       400:
 *         description: No images uploaded.
 *       500:
 *         description: Error uploading images to the server.
 */
app.post('/upload', verifyToken, upload.array('files', 10), (req, res) => {
  if (!req.files || req.files.length === 0) {
    return res.status(400).json({ message: 'No images uploaded' });
  }

  // Specify the destination directory
  const destinationDirectory = './uploads/';

  // Create the destination directory if it doesn't exist
  if (!fs.existsSync(destinationDirectory)) {
    fs.mkdirSync(destinationDirectory, { recursive: true });
  }

  // Move each file to the destination directory
  req.files.forEach((file) => {
    const sourcePath = file.path;
    const destinationPath = path.join(destinationDirectory, file.originalname);

    fs.renameSync(sourcePath, destinationPath);
  });

  const imageUrls = req.files.map((file) => `/uploads/${file.originalname}`);
  res.json({ message: 'Images uploaded successfully', imageUrls });
});

/**
 * @swagger
 * /delete-user/{id}:
 *   delete:
 *     summary: Delete a user by ID
 *     description: Delete a user from the database based on their ID.
 *     parameters:
 *       - in: path
 *         name: id
 *         description: User ID to delete.
 *         required: true
 *         schema:
 *           type: integer
 *     responses:
 *       200:
 *         description: User deleted successfully.
 *       401:
 *         description: Unauthorized (Invalid or missing token).
 *       404:
 *         description: User not found.
 *       500:
 *         description: Error deleting user from the database.
 */
app.delete('/delete-user/:id', verifyToken, (req, res) => {
  const userId = req.params.id;

  // Check if the user with the specified ID exists
  db.get('SELECT id FROM User WHERE id = ?', [userId], (err, row) => {
    if (err) {
      console.error('Error checking user existence:', err.message);
      return res.status(500).json({ message: 'Error deleting user from the database' });
    }

    if (!row) {
      return res.status(404).json({ message: 'User not found' });
    }

    // User exists, proceed with the deletion
    db.run('DELETE FROM User WHERE id = ?', [userId], (err) => {
      if (err) {
        console.error('Error deleting user:', err.message);
        return res.status(500).json({ message: 'Error deleting user from the database' });
      }

      res.json({ message: 'User deleted successfully' });
    });
  });
});

/**
 * @swagger
 * /delete-file:
 *   delete:
 *     summary: Delete a file
 *     description: Delete a specific file from the server's 'uploads' directory based on its filename.
 *     parameters:
 *       - in: query
 *         name: filename
 *         required: true
 *         description: The name of the file to delete.
 *         schema:
 *           type: string
 *     responses:
 *       204:
 *         description: File deleted successfully.
 *       404:
 *         description: Not Found, requested file not found.
 *       500:
 *         description: Internal Server Error, error while deleting the file.
 */
app.delete('/delete-file', verifyToken, (req, res) => {
  const { filename } = req.query;
  const filePath = path.join(dir, filename);

  if (fs.existsSync(filePath)) {
    try {
      fs.unlinkSync(filePath);
      res.status(204).end();
    } catch (err) {
      console.error('Error deleting file:', err);
      res.status(500).json({ message: 'Error deleting file' });
    }
  } else {
    res.status(404).json({ message: 'File not found' });
  }
});

 app.get('/', (req, res) => {
   res.send('>:(');
 });

 // Start the Express server
 app.listen(port, () => {
   console.log(new Date().toISOString() + ` : Server is running on port ${port}`);
 });