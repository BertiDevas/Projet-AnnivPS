const express = require('express');
const swaggerUi = require('swagger-ui-express');
const crypto = require('crypto');
const jwt = require('jsonwebtoken');
const fs = require('fs');
const path = require('path')

const db = require('./db_create.js');
const swaggerSpec = require('./swagger');
const {checkCredentials, verifyToken} = require('./security');
const {upload, dir, mime} = require('./gestion_photo.js');

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
 *       409:
 *         description: User with the same name already or as member of another user
 *       500:
 *         description: Error registering user
 */
app.post('/register-user', (req, res) => {
  const { lastname, firstname, mdp, code } = req.body; 
  if (code !== codeApp && code !== codeAdmin) {
     res.status(400).json({ message: 'Invalid request data' });
  } else {
    
     // Check if a user with the same firstname and lastname already exists
    db.get(
      'SELECT * FROM User WHERE lastname = ? AND firstname = ?',
      [lastname, firstname],
      (err, existingUser) => {
        if (err) {
          console.error('Error checking for existing user:', err.message);
          return res.status(500).json({ message: 'Error registering user.' });
        }

        if (existingUser) {
          // If a user with the same firstname and lastname exists, return a 400 response
          return res.status(409).json({ message: 'User with the same name already exists.' });
        }

        // Check if a member with the same firstname and lastname already exists
        db.get(
        'SELECT * FROM userAddedMembers WHERE lastname = ? AND firstname = ?',
        [lastname, firstname],
        (err, existingMember) => {
          if (err) {
            console.error('Error checking for existing member:', err.message);
            return res.status(500).json({ message: 'Error registering user while checking for members.' });
          }
      
          if (existingMember) {
            // If a user with the same firstname and lastname exists as a member, return a 409 response
            db.get(
              'SELECT * FROM userAddedMembers WHERE Id = ?',
              [existingMember.UserId],
              (err, associatedUser) => {
                if (err) {
                  console.error('Error fetching associated user:', err.message);
                  return res.status(500).json({ message: 'Error registering user while fetching associated user.' });
                }
      
                if (associatedUser) {
                  return res.status(409).json({
                    message: 'Member with the same name already exists.',
                    associatedUser: {
                      firstname: associatedUser.firstname,
                      lastname: associatedUser.lastname,
                      id: associatedUser.id,
                    },
                  });
                }
              }
            );
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
              }
            );
          }
        }
      );
      }
    );
  }
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
    'SELECT Id, Salt FROM User WHERE firstname = ? AND lastname = ?',
    [firstname, lastname],
    (err, user) => {
      if (err) {
        console.error('Error checking for user:', err.message);
        return res.status(500).json({ message: 'Error changing the password' });
      }

      if (!user) {
        return res.status(404).json({ message: 'User not found' });
      }

      // Generate a unique salt for the user
      const salt = crypto.randomBytes(16).toString('hex');

      // Hash the new password with the salt
      const hashedMdP = crypto.createHash('sha256').update(mdp + salt).digest('hex');

      // Update the user's password in the database
      db.run(
        'UPDATE User SET MdP = ?, Salt = ? WHERE Id = ?',
        [hashedMdP, salt, user.Id],
        (err) => {
          if (err) {
            console.error('Error changing the password:', err.message);
            return res.status(500).json({ message: 'Error changing the password' });
          }

          console.log('Password changed successfully');
          res.json({ message: 'Password changed successfully' });
        }
      );
    }
  );
});

/**
 * @swagger
 * /get-all-users:
 *   get:
 *     summary: Get all users' firstname and lastname
 *     description: Retrieve the firstname, lastname, id, and confirmation of all users from the database.
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
 *                   id:
 *                     type: integer
 *                     description: The user's id.
 *                     example: 1
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
 *       500:
 *         description: Error fetching user data from the database.
 */
app.get('/get-all-users', verifyToken, (req, res) => {
  // Query the database to retrieve all users' firstname, lastname, id, and confirmation
  db.all('SELECT Id, firstname, lastname, confirmation FROM User', (err, rows) => {
    if (err) {
      console.error('Error fetching users:', err.message);
      res.status(500).json({ message: 'Error fetching users.' });
    } else {
      // Extract the firstname, lastname, id, and confirmation from the query result
      const users = rows.map((row) => ({ id: row.Id, firstname: row.firstname, lastname: row.lastname, confirmation: row.confirmation }));
      res.json(users);
    }
  });
});

/**
 * @swagger
 * /user/{Id}:
 *   get:
 *     summary: Get user information with associated members
 *     description: Retrieve user information along with associated members based on the user's ID.
 *     parameters:
 *       - in: path
 *         name: Id
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
 *                 firstname:
 *                   type: string
 *                   description: The user's first name.
 *                 lastname:
 *                   type: string
 *                   description: The user's last name.
 *                 confirmation:
 *                   type: string
 *                   description: The user's confirmation status.
 *                 members:
 *                   type: array
 *                   items:
 *                     type: object
 *                     properties:
 *                       id:
 *                         type: integer
 *                         description: The member's ID.
 *                       firstname:
 *                         type: string
 *                         description: The member's first name.
 *                       lastname:
 *                         type: string
 *                         description: The member's last name.
 *       404:
 *         description: User not found.
 *       500:
 *         description: Error retrieving user information with associated members.
 */
app.get('/user/:Id', verifyToken, (req, res) => {
  const userId = req.params.Id;

  // Query the database to retrieve user information based on the ID
  db.get('SELECT Id, firstname, lastname, confirmation FROM User WHERE Id = ?', [userId], (err, userRow) => {
    if (err) {
      console.error('Error retrieving user information:', err.message);
      return res.status(500).json({ message: 'Error retrieving user information' });
    }

    if (!userRow) {
      return res.status(404).json({ message: 'User not found' });
    }

    // Query the database to retrieve all members associated with the user
    db.all('SELECT Id, lastname, firstname FROM userAddedMembers WHERE UserId = ?', [userId], (err, membersRows) => {
      if (err) {
        console.error('Error retrieving associated members:', err.message);
        return res.status(500).json({ message: 'Error retrieving associated members' });
      }

      // Create an object that includes both user information and associated members
      const userWithMembers = {
        id: userRow.Id,
        firstname: userRow.firstname,
        lastname: userRow.lastname,
        confirmation: userRow.confirmation,
        members: membersRows, // Include the associated members
      };

      // Return the user information along with associated members as a JSON response
      res.json(userWithMembers);
    });
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
 * /update-confirmation/{Id}:
 *   put:
 *     summary: Update Confirmation value by user ID
 *     description: Update the Confirmation value (true/false) for a user based on their ID.
 *     parameters:
 *       - in: path
 *         name: Id
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
app.put('/update-confirmation/:Id', verifyToken, (req, res) => {
  const userId = req.params.Id;
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
 * /add-members/{UserId}:
 *   post:
 *     summary: Add multiple members
 *     description: Add multiple members to the userAddMembers table.
 *     parameters:
 *       - in: path
 *         name: UserId
 *         description: The ID of the user to associate the members with.
 *         required: true
 *         schema:
 *           type: integer
 *           example: 1
 *     requestBody:
 *       description: Array of members to add.
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: array
 *             items:
 *               type: object
 *               properties:
 *                 lastname:
 *                   type: string
 *                   description: The last name of the member.
 *                 firstname:
 *                   type: string
 *                   description: The first name of the member.
 *             example:
 *               - lastname: Smith
 *                 firstname: John
 *               - lastname: Johnson
 *                 firstname: Emily
 *     responses:
 *       200:
 *         description: Members added successfully.
 *       400:
 *         description: Invalid request format or missing fields.
 *       500:
 *         description: Error adding members to the database.
 */
app.post('/add-members/:UserId', verifyToken, (req, res) => {
  const { UserId } = req.params;
  const members = JSON.parse(JSON.stringify(req.body));

  if (!members || !Array.isArray(members)) {
    return res.status(400).json({ message: 'Invalid request format or missing fields' });
  }

  // Insert members into the userAddedMembers table with the common UserId
  const values = members.map((member) => [UserId, member.lastname, member.firstname]);
  let membersAddedCount = 0; // Track the number of members added

  values.forEach((member) => {
    db.run(
      'INSERT INTO userAddedMembers (UserId, lastname, firstname) VALUES (?, ?, ?)',
      member,
      function (err) {
        if (err) {
          console.error('Error adding members to the database:', err.message);
          return res.status(500).json({ message: 'Error adding members to the database' });
        }

        membersAddedCount++;

        // Check if all members have been added
        if (membersAddedCount === values.length) {
          console.log(`Added ${membersAddedCount} members to the userAddMembers table`);
          res.json({ message: 'Members added successfully' });
        }
      }
    );
  });
});

/**
 * @swagger
 * /delete-user/{Id}:
 *   delete:
 *     summary: Delete a user by ID
 *     description: Delete a user from the database based on their ID.
 *     parameters:
 *       - in: path
 *         name: Id
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
app.delete('/delete-user/:Id', verifyToken, (req, res) => {
  const userId = req.params.Id;

  // Check if the user with the specified ID exists
  db.get('SELECT Id FROM User WHERE Id = ?', [userId], (err, row) => {
    if (err) {
      console.error('Error checking user existence:', err.message);
      return res.status(500).json({ message: 'Error deleting user from the database' });
    }

    if (!row) {
      return res.status(404).json({ message: 'User not found' });
    }

    // User exists, proceed with the deletion
    db.run('DELETE FROM User WHERE Id = ?', [userId], (err) => {
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
 * /delete-members/{UserId}:
 *   delete:
 *     summary: Delete multiple members by User ID
 *     description: Delete multiple members from the userAddedMembers table based on the User ID.
 *     parameters:
 *       - in: path
 *         name: UserId
 *         description: The ID of the user whose members to delete.
 *         required: true
 *         schema:
 *           type: integer
 *     requestBody:
 *       description: Array of members to delete.
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: array
 *             items:
 *               type: object
 *               properties:
 *                 memberIds:
 *                   type: array
 *                   description: An array of member IDs to delete.
 *                   example: [1, 2, 3]
 *     responses:
 *       200:
 *         description: Members deleted successfully.
 *       400:
 *         description: Invalid request format or missing fields.
 *       500:
 *         description: Error deleting members from the database.
 */
app.delete('/delete-members/:UserId', verifyToken, (req, res) => {
  const { UserId } = req.params;
  const { memberIds } = req.body;

  if (!memberIds || !Array.isArray(memberIds)) {
    return res.status(400).json({ message: 'Invalid request format or missing fields' });
  }

  // Convert member IDs to integers
  const memberIdsInt = memberIds.map((id) => parseInt(id));

  // Delete members from the userAddedMembers table based on User ID and member IDs
  db.run(
    'DELETE FROM userAddedMembers WHERE UserId = ? AND Id IN (?)',
    [UserId, memberIdsInt],
    function (err) {
      if (err) {
        console.error('Error deleting members from the database:', err.message);
        return res.status(500).json({ message: 'Error deleting members from the database' });
      }

      console.log(`Deleted ${this.changes} members from the userAddedMembers table`);
      res.json({ message: 'Members deleted successfully' });
    }
  );
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
   console.log(`Server is running on port ${port}`);
 });