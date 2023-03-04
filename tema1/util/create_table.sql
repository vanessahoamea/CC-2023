CREATE TABLE users (
    id int(11) PRIMARY KEY AUTO_INCREMENT NOT NULL,
    name varchar(100) NOT NULL,
    email varchar(320) NOT NULL,
    password varchar(100) NOT NULL
);

CREATE TABLE posts (
    id int(11) PRIMARY KEY AUTO_INCREMENT NOT NULL,
    user_id int(11) NOT NULL,
    title varchar(100) NOT NULL,
    body varchar(500) NOT NULL,
    FOREIGN KEY (user_id) REFERENCES users(id)
);