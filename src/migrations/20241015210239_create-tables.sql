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
    cover INT
);

CREATE TABLE files (
    id SERIAL PRIMARY KEY,
    name VARCHAR(256)
);