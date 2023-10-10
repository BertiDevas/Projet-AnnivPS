const multer = require('multer');
const path = require('path');
const fs = require('fs');

// Define storage for uploaded files
const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    cb(null, 'uploads'); // Specify the destination directory
  },
  filename: (req, file, cb) => {
    const customFilename = `${file.originalname}`;
    cb(null, customFilename);
  },
});

const dir = './uploads'

const mime = {
    html: 'text/html',
    txt: 'text/plain',
    css: 'text/css',
    gif: 'image/gif',
    jpg: 'image/jpeg',
    png: 'image/png',
    svg: 'image/svg+xml',
    js: 'application/javascript'
};
  
const upload = multer({ storage });

module.exports = {upload, dir, mime}