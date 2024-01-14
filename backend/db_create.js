const sqlite3 = require('sqlite3').verbose();

// Create a new SQLite database or open an existing one
const db = new sqlite3.Database('db.sql', (err) => {
  if (err) {
    console.error('Error opening database:', err.message);
  } else {
    console.log('Connected to the database.');
    
    // Create the User table if it doesn't exist
    db.run(`CREATE TABLE IF NOT EXISTS User (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      idCreator INTEGER, 
      lastname TEXT,
      firstname TEXT,
      mdp TEXT,
      isRegistered BOOLEAN false,
      confirmation BOOLEAN null,
      confirmation_dej BOOLEAN null,
      confirmation_balade BOOLEAN null,
      confirmation_diner BOOLEAN null,
      isAdmin BOOLEAN false,
      Salt TEXT
    )`, (err) => {
      if (err) {
        console.error('Error creating User table:', err.message);
      } else {
        console.log('User table created.');
        
        db.all('SELECT * FROM User', (err, rows) => {
          if (err) {
            console.error('Error fetching users:', err.message);
          } else {
            console.log('All Users:');
            rows.forEach((row) => {
              console.log(`ID: ${row.id}, ID Creator: ${row.idCreator}, Last Name: ${row.lastname}, First Name: ${row.firstname}, isRegistered: ${row.isRegistered}, isAdmin: ${row.isAdmin}, 
              confirmation: ${row.confirmation}, confirmation_dej: ${row.confirmation_dej}, confirmation_balade: ${row.confirmation_balade}, confirmation_diner: ${row.confirmation_diner}`);
            });
          }
        });
      }
    });
  }
});

module.exports = db;