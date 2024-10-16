-- Add migration script here
CREATE TABLE users (
    id SERIAL PRIMARY KEY,
    username VARCHAR(30),
    password VARCHAR(30)
);

CREATE TABLE stores (
    id SERIAL PRIMARY KEY,
    name VARCHAR(30),
    userId VARCHAR(30)
);

CREATE TABLE files (
    id SERIAL PRIMARY KEY,
    name VARCHAR(256)
);