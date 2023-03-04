const crypto = require("crypto");
const dotenv = require("dotenv");

dotenv.config({ path: "../util/.env" });

function serverError(res)
{
    res.statusCode = 500;
    res.write(JSON.stringify({
        "message": "Something went wrong. Try again later."
    }));
    res.end();
}

function generateJWT(id, name)
{
    const header = Buffer.from(JSON.stringify({
        "alg": "HS256",
        "typ": "JWT"
    })).toString("base64").replace("+", "-").replace("/", "_").replace("=", "");

    const payload = Buffer.from(JSON.stringify({
        "id": id,
        "name": name,
        "iat": new Date().getTime(),
        "exp": new Date().getTime() + (30 * 24 * 60 * 60) //valid for 30 days
    })).toString("base64").replace("+", "-").replace("/", "_").replace("=", "");

    const signature = crypto.createHmac("sha256", process.env.SECRET_KEY).update(header + "." + payload).digest()
                      .toString("base64").replace("+", "-").replace("/", "_").replace("=", "");
    
    const jwt = header + "." + payload + "." + signature;
    return jwt;
}

function validateToken(token, id)
{
    const tokenParts = token.split(".");
    const header = tokenParts[0];
    const payload = tokenParts[1];
    const signature = tokenParts[2];

    if(tokenParts.length < 3)
        return false;

    const correctSig = crypto.createHmac("sha256", process.env.SECRET_KEY).update(header + "." + payload).digest()
                       .toString("base64").replace("+", "-").replace("/", "_").replace("=", "");
    if(signature != correctSig)
        return false;
    
    const decodedPayload = JSON.parse(Buffer.from(payload, "base64").toString("ascii"));
    if(!("id" in decodedPayload) || !("name" in decodedPayload) || !("iat" in decodedPayload) || !("exp" in decodedPayload))
        return false;
    
    if(new Date().getTime() > decodedPayload.exp)
        return false;
    
    if(id != null)
    {
        if(decodedPayload.id != id)
        return false;
    }

    return true;
}

function getUserId(token)
{
    const tokenParts = token.split(".");
    const decodedPayload = JSON.parse(Buffer.from(tokenParts[1], "base64").toString("ascii"));
    
    return decodedPayload.id;
}

module.exports = { serverError, generateJWT, validateToken, getUserId };