const http = require("http");
const mysql = require("mysql");
const crypto = require("crypto");
const functions = require("./functions.js");

const conn = mysql.createConnection({
    host: "localhost",
    user: "root",
    password: "",
    database: "cclab"
});

const server = http.createServer((req, res) => {
    res.setHeader("Access-Control-Allow-Origin", "*");
    res.setHeader("Content-Type", "application/json");

    let body = {};

    if(req.url == "/")
    {
        res.write(JSON.stringify({
            "message": "Welcome to the API!"
        }));
        res.end();
    }
    else if(req.url == "/users" || req.url == "/users/")
    {
        if(req.method == "POST" || req.method == "PUT" || req.method == "DELETE")
        {
            res.statusCode = 400;
            res.write(JSON.stringify({
                "message": "This method requires an ID."
            }));
            res.end();
        }

        if(req.method == "GET")
        {
            //get all users from database
            conn.query("SELECT id, name, email FROM users", (err, result, _) => {
                if(err)
                    functions.serverError(res);
                
                res.write(JSON.stringify(result));
                res.end();
            });
        }
        else if(req.method == "POST")
        {
            //create new user
            req.on("data", (chunk) => {
                body = JSON.parse(chunk);
            }).on("end", () => {
                if(("name" in body) && ("email" in body) && ("password" in body))
                {
                    body.name = body.name.trim();
                    body.email = body.email.trim().toLowerCase();
                    body.password = crypto.createHash("sha256").update(body.password).digest("hex");

                    conn.query("SELECT * FROM users WHERE email = ?", [body.email], (err, result, _) => {
                        if(err)
                            functions.serverError(res);
                        
                        if(result.length > 0)
                        {
                            res.write(JSON.stringify({
                                "message": "Email is already in use."
                            }));
                            res.end();
                        }
                        else
                        {
                            conn.query("INSERT INTO users SET ?", body, (err, result) => {
                                if(err)
                                    functions.serverError(res);

                                res.statusCode = 201;
                                res.write(JSON.stringify({
                                    id: result.insertId,
                                    name: body.name,
                                    email: body.email
                                }));
                                res.end();
                            });
                        }
                    });
                }
                else
                {
                    res.statusCode = 400;
                    res.write(JSON.stringify({
                        "message": "Fields 'name', 'email', 'password' are required."
                    }));
                    res.end();
                }
            });
        }
    }
    else if(req.url.startsWith("/users/"))
    {
        const id = req.url.split("/users/")[1];

        if(req.method == "GET")
        {
            //get user by ID
            conn.query("SELECT id, name, email FROM users WHERE id = ?", [id], (err, result, _) => {
                if(err)
                    functions.serverError(res);

                if(result.length == 0)
                {
                    res.statusCode = 404;
                    res.write(JSON.stringify({
                        "message": `User with the ID ${id} does not exist.`
                    }));
                    res.end();
                }
                else
                {
                    res.write(JSON.stringify(result[0]));
                    res.end();
                }
            });
        }
        else if(req.method == "PUT")
        {
            //edit user
            req.on("data", (chunk) => {
                body = JSON.parse(chunk);
            }).on("end", () => {
                if(("name" in body) && ("email" in body) && ("password" in body))
                {
                    body.name = body.name.trim();
                    body.email = body.email.trim().toLowerCase();
                    body.password = crypto.createHash("sha256").update(body.password).digest("hex");

                    if(req.headers.authorization == undefined)
                    {
                        res.statusCode = 401;
                        res.write(JSON.stringify({
                            "message": "Bearer token is required."
                        }));
                        res.end();
                    }
                    else
                    {
                        const token = req.headers.authorization.split("Bearer ")[1];
                        if(functions.validateToken(token, parseInt(id)))
                        {
                            conn.query("UPDATE users SET ? WHERE id = ?", [body, id], (err, _) => {
                                if(err)
                                    functions.serverError(res);

                                res.write(JSON.stringify({
                                    id: parseInt(id),
                                    name: body.name,
                                    email: body.email
                                }));
                                res.end();
                            });
                        }
                        else
                        {
                            res.statusCode = 401;
                            res.write(JSON.stringify({
                                "message": "You don't have access to this resource."
                            }));
                            res.end();
                        }
                    }
                }
                else
                {
                    res.statusCode = 400;
                    res.write(JSON.stringify({
                        "message": "Fields 'name', 'email', 'password' are required."
                    }));
                    res.end();
                }
            });
        }
        else if(req.method == "PATCH")
        {
            //edit user partially
            req.on("data", (chunk) => {
                body = JSON.parse(chunk);
            }).on("end", () => {
                body.name == undefined ? delete body.name : body.name = body.name.trim();
                body.email == undefined? delete body.email : body.email = body.email.trim().toLowerCase();
                body.password == undefined ? delete body.password : body.password = crypto.createHash("sha256").update(body.password).digest("hex");

                if(req.headers.authorization == undefined)
                {
                    res.statusCode = 401;
                    res.write(JSON.stringify({
                        "message": "Bearer token is required."
                    }));
                    res.end();
                }
                else
                {
                    const token = req.headers.authorization.split("Bearer ")[1];
                    if(functions.validateToken(token, parseInt(id)))
                    {
                        conn.query("UPDATE users SET ? WHERE id = ?", [body, id], (err, _) => {
                            if(err)
                                functions.serverError(res);

                            res.write(JSON.stringify({
                                id: parseInt(id),
                                name: body.name,
                                email: body.email
                            }));
                            res.end();
                        });
                    }
                    else
                    {
                        res.statusCode = 401;
                        res.write(JSON.stringify({
                            "message": "You don't have access to this resource."
                        }));
                        res.end();
                    }
                }
            });
        }
        else if(req.method == "DELETE")
        {
            //delete user
            if(req.headers.authorization == undefined)
            {
                res.statusCode = 401;
                res.write(JSON.stringify({
                    "message": "Bearer token is required."
                }));
                res.end();
            }
            else
            {
                const token = req.headers.authorization.split("Bearer ")[1];
                if(functions.validateToken(token, parseInt(id)))
                {
                    conn.query("DELETE FROM users WHERE id = ?", [id], (err, result) => {
                        if(err)
                            functions.serverError(res);
                        
                        if(result.affectedRows == 0)
                        {
                            res.statusCode = 404;
                            res.write(JSON.stringify({
                                "message": `User with the ID ${id} does not exist.`
                            }));
                            res.end();
                        }
                        else
                        {
                            res.write(JSON.stringify({
                                "message": "Successfully deleted user."
                            }));
                            res.end();
                        }
                    });
                }
                else
                {
                    res.statusCode = 401;
                    res.write(JSON.stringify({
                        "message": "You don't have access to this resource."
                    }));
                    res.end();
                }
            }
        }
    }
    else if(req.url == "/posts" || req.url == "/posts/")
    {
        if(req.method == "POST" || req.method == "PUT" || req.method == "DELETE")
        {
            res.statusCode = 400;
            res.write(JSON.stringify({
                "message": "This method requires an ID."
            }));
            res.end();
        }

        if(req.method == "POST")
        {
            //create post
            req.on("data", (chunk) => {
                body = JSON.parse(chunk);
            }).on("end", () => {
                if(("title" in body) && ("body" in body))
                {
                    if(req.headers.authorization == undefined)
                    {
                        res.statusCode = 401;
                        res.write(JSON.stringify({
                            "message": "Bearer token is required."
                        }));
                        res.end();
                    }
                    else
                    {
                        const token = req.headers.authorization.split("Bearer ")[1];
                        if(functions.validateToken(token, null))
                        {
                            body.user_id = functions.getUserId(token);
                            conn.query("INSERT INTO posts SET ?", body, (err, result) => {
                                if(err)
                                    functions.serverError(res);

                                res.statusCode = 201;
                                res.write(JSON.stringify({
                                    id: result.insertId,
                                    title: body.title,
                                    body: body.body
                                }));
                                res.end();
                            });
                        }
                        else
                        {
                            res.statusCode = 401;
                            res.write(JSON.stringify({
                                "message": "You need a valid bearer token to create a new post."
                            }));
                            res.end();
                        }
                    }
                }
                else
                {
                    res.statusCode = 400;
                    res.write(JSON.stringify({
                        "message": "Fields 'title', 'body' are required."
                    }));
                    res.end();
                }
            });
        }
    }
    else if(req.url.startsWith("/posts/"))
    {
        const id = req.url.split("/posts/")[1];

        if(req.method == "GET")
        {
            //get user posts
            conn.query("SELECT id, title, body FROM posts WHERE user_id = ?", [id], (err, result, _) => {
                if(err)
                    functions.serverError(res);
                
                if(result.length == 0)
                {
                    res.statusCode = 204;
                    res.write(JSON.stringify({
                        "message": "This user has no posts."
                    }));
                    res.end();
                }

                res.write(JSON.stringify(result));
                res.end();
            });
        }
        else if(req.method == "DELETE")
        {
            //delete post
            if(req.headers.authorization == undefined)
            {
                res.statusCode = 401;
                res.write(JSON.stringify({
                    "message": "Bearer token is required."
                }));
                res.end();
            }
            else
            {
                const token = req.headers.authorization.split("Bearer ")[1];
                if(functions.validateToken(token, null))
                {
                    user_id = functions.getUserId(token);
                    conn.query("DELETE FROM posts WHERE id = ? AND user_id = ?", [id, user_id], (err, result) => {
                        if(err)
                            functions.serverError(res);
                        
                        if(result.affectedRows == 0)
                        {
                            res.statusCode = 404;
                            res.write(JSON.stringify({
                                "message": `Post with the ID ${id} does not exist.`
                            }));
                            res.end();
                        }
                        else
                        {
                            res.write(JSON.stringify({
                                "message": "Successfully deleted post."
                            }));
                            res.end();
                        }
                    });
                }
                else
                {
                    res.statusCode = 401;
                    res.write(JSON.stringify({
                        "message": "You don't have access to this resource."
                    }));
                    res.end();
                }
            }
        }
    }
    else if(req.url == "/login" || req.url.startsWith("/login/"))
    {
        //login + get bearer token
        req.on("data", (chunk) => {
            body = JSON.parse(chunk);
        }).on("end", () => {
            if(("email" in body) && ("password" in body))
            {
                body.email = body.email.trim().toLowerCase();
            
                conn.query("SELECT * FROM users WHERE email = ?", [body.email], (err, result, _) => {
                    if(err)
                        functions.serverError(res);

                    if(result.length == 0)
                    {
                        res.statusCode = 404;
                        res.write(JSON.stringify({
                            "message": "User not found."
                        }));
                        res.end();
                    }
                    else
                    {
                        result = result[0];
                        if(result.password != crypto.createHash("sha256").update(body.password).digest("hex"))
                        {
                            res.statusCode = 403;
                            res.write(JSON.stringify({
                                "message": "Incorrect password."
                            }));
                            res.end();
                        }
                        else
                        {
                            const jwt = functions.generateJWT(result.id, result.name);
                            res.statusCode = 201;
                            res.write(JSON.stringify({
                                "message": "Signed in successfully.",
                                "jwt": jwt
                            }));
                            res.end();
                        }
                    }
                });
            }
            else
            {
                res.statusCode = 400;
                res.write(JSON.stringify({
                    "message": "Fields 'email', 'password' are required."
                }));
                res.end();
            }
        });
    }
    else
    {
        res.statusCode = 404;
        res.write(JSON.stringify({
            "message": "Not a valid endpoint."
        }));
        res.end();
    }
});

server.listen(3000, () => {
    console.log("Listening on port 3000...");
});