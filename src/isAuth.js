const {verify} = require('jsonwebtoken'); //this is to verify the token in our header
const isAuth = req => {
    const authorization = req.headers['authorization'];

    if (!authorization) throw new Error("You need to login"); //if a token is not sent, then we know that the user needs to login
    const token = authorization.split(' ')[1];
    //we grab from index 1 because the authorization header will look like below
    // 'Bearer token'
    const{userId} = verify(token, process.env.ACCESS_TOKEN_SECRET);
    console.log(userId)
    return userId;
}

module.exports = {
    isAuth
}