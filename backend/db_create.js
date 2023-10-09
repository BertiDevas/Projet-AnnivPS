const sqlite3 = require('sqlite3').verbose();

// Create a new SQLite database or open an existing one
const db = new sqlite3.Database('db.sql', (err) => {
  if (err) {
    console.error('Error opening database:', err.message);
  } else {
    console.log('Connected to the database.');
    
    // Create the User table if it doesn't exist
    db.run(`CREATE TABLE IF NOT EXISTS User (
      Id INTEGER PRIMARY KEY AUTOINCREMENT,
      lastname TEXT,
      firstname TEXT,
      mdp TEXT,
      confirmation TEXT Null,
      isAdmin TEXT false,
      Salt TEXT
    )`, (err) => {
      if (err) {
        console.error('Error creating User table:', err.message);
      } else {
        console.log('User table created.');
        
        // Create the UserInfo table
        db.run(`CREATE TABLE IF NOT EXISTS UserInfo (
          Id INTEGER PRIMARY KEY AUTOINCREMENT,
          UserId TEXT,
          lastname TEXT,
          firstname TEXT,
          FOREIGN KEY (UserId) REFERENCES User(Id)
        )`, (err) => {
          if (err) {
            console.error('Error creating UserInfo table:', err.message);
          } else {
            console.log('UserInfo table created.');
          }
        });
      }
    });

    db.all('SELECT * FROM User', [], (err, rows) => {
      if (err) {
        throw err;
      }
      rows.forEach((row) => console.log(row))
    })
  }
});

module.exports = db;