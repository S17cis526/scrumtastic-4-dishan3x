CREATE TABLE users (
    id INTEGER PRIMARY KEY,
    eid TEXT UNIQUE,
    cryptedPassword TEXT,
    salt TEXT,
    firstName TEXT,
    lastName TEXT,
    email TEXT
);
