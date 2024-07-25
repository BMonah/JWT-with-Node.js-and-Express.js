require('dotenv/config');
const express = require('express');
const cookieParser = require('cookie-parser');
const cors = require('cors');
const {verify} = require('jsonwebtoken');
const {hash, compare} = require('bcryptjs');
const { request, response } = require('express');
const{fakeDB} = require('./fakeDB.js')
const{createAccessToken,
    sendAccessToken,
    sendRefreshToken,
    createRefreshToken,
} = require('./tokens.js')
const{isAuth} = require('./isAuth.js')

//1. Register a user
//2. login a user
//3. logout a user
//4. setup a protected route
//5. Get a new accesstoken with a refresh token

const server = express();

//use an express middleware for easier cookie handling
server.use(cookieParser());

server.use(
    cors({
        origin: 'http://localhost:3000', //our frontend will be in port 3000
        credentials: true,
    })
);

//needed to be able to read body data
server.use(express.json()); //to support JSON-encoded bodies
server.use(express.urlencoded({extended: true})); //support URL-encoded bodies

server.listen(process.env.PORT, () =>
    console.log(`Server listening on this port ${process.env.PORT}`)
);

//1. Register a user
server.post('/register', async (req, res) => {
    const{ email, password} = req.body;

    try{
        //1. check if user exists
        const user = fakeDB.find(user => user.email === email);
        if(user) throw new Error('User already exists');
        const hashedPassword = await hash(password, 10);
        fakeDB.push({
            id: fakeDB.length,
            email,
            password: hashedPassword
        });
        res.send({message: 'User Created'})
        console.log(hashedPassword);
    } catch (err){
        res.send({
            error:`${err.message}`,
        })

    }
})

//test with #curl -d "email=value1" -d "password=value2" -X POST http://localhost:4000/register


// 2. Login Endpoint

server.post('/login', async(req, res) => {
    const {email, password} = req.body;
    try {
        //1. find user in database. if not exist, send error
        const user = fakeDB.find(user => user.email == email);
        if (!user) throw new Error("User does not exist");
        //2. compare crypted password and see if it checks out. Send error if not
        const valid = await compare(password, user.password);
        if (!valid) throw new Error("Password not correct");
        //3. Create Refresh and Accesstoken
        const accesstoken = createAccessToken(user.id);
        const refreshtoken = createRefreshToken(user.id);
        //4. Put the refreshtoken in the database
        user.refreshtoken = refreshtoken;
        console.log(fakeDB);
        //5. Send token. Refreshtoken as a cookie and accesstoken as a regular response
        sendRefreshToken (res, refreshtoken);
        sendAccessToken(res, req, accesstoken);

    } catch(err){
        res.send({
            error: `${err.message}`,
        })

    }
})


// 3. Logout endpoint
server.post('/logout', (_req, res) =>{
    res.clearCookie('refreshtoken', {path: '/refresh_token'});
    return res.send({
        message: 'Logged out',
    })
});


// 4. Create Protected route
server.post('/protected', async(req, res) =>{
    try{
        const userId = isAuth(req)
        if (userId !== null)
        res.send({
            data: 'This is protected data',
        })
    } catch(err){
        res.send({
            error: `${err.message}`,
        })
    }
})


//5. Get a new access token with a refresh token
server.post('/refresh_token', (req, res) =>{
    const token = req.cookies.refreshtoken;
    //if we don't have a token in our request
    if (!token) return res.send({ accesstoken: ''});
    //we have a token, let's verify it!
    let payload = null;
    try {
        payload = verify(token, process.env.REFRESH_TOKEN_SECRET);
    } catch (err){
        return res.send({accesstoken: ''});
    }
    //Token is valid, check if user exists
    const user = fakeDB.find(user => user.id === payload.userId)
    if(!user) return res.send({ accesstoken: ''});
    //User exists, check if refreshtoken exist on user
    if(user.refreshtoken !== token){
        return res.send({ accesstoken: ''});
    }
    //Token exist, create new refresh- and accesstoken
    const accesstoken = createAccessToken(user.id);
    const refreshtoken = createRefreshToken(user.id);
    user.refreshtoken = refreshtoken;
    //send new refreshtoken and accesstoken
    sendRefreshToken(res, refreshtoken);
    return res.send({accesstoken});

})