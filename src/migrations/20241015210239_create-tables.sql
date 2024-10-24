-- Add migration script here

DROP TABLE IF EXISTS users, stores, files;

CREATE TABLE users (
    id SERIAL PRIMARY KEY,
    username VARCHAR(30),
    password VARCHAR(97)
);

CREATE TABLE stores (
    id SERIAL PRIMARY KEY,
    name VARCHAR(30),
    userId VARCHAR(30),
    cover INT,
);

CREATE TABLE files (
    id SERIAL PRIMARY KEY,
    name VARCHAR(256),
    content_type VARCHAR(255) NOT NULL,
    md5 VARCHAR(32) NOT NULL,
    created_at TIMESTAMP NOT NULL DEFAULT NOW()
);

CREATE TABLE user_store (
    id SERIAL PRIMARY KEY,
    userId INTEGER NOT NULL,
    storeId INTEGER NOT NULL,
    FOREIGN KEY(userId)
    REFERENCES users(id)
    FOREIGN KEY(storeId)
    REFERENCES stores(id)
)

CREATE TABLE file_store (
    id SERIAL PRIMARY KEY,
    fileId INTEGER NOT NULL,
    storeId INTEGER NOT NULL,
    FOREIGN KEY(fileId)
    REFERENCES files(id)
    FOREIGN KEY(storeId)
    REFERENCES stores(id)
);