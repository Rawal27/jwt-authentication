require('dotenv/config');
const express = require('express');
const cookieParser = require('cookie-parser');
const cors = require('cors');
const { verify } = require('jsonwebtoken');
const { hash, compare } = require('bcryptjs');
const { testDB } = require('./testDB.js');
const { createAccessToken, createRefreshToken, sendRefreshToken, sendAccessToken } = require('./token.js');
const { isAuth } = require('./isAuth');


//1. Register a user
//2. Login a user
//3. Logout a user
//4. Setup a protected route
//5. Get a new accesstoken with a refresh token


const server = express();


//Use express middleware for easier cookie handling
server.use(cookieParser());

server.use(
	cors({
		origin: 'http://localhost:3000',
		credentials: true
	})
);


// Needed to able to read body data
server.use(express.json()); // to support JSON-encoded bodies
server.use(express.urlencoded({ extended: true })); //support URL-encoded bodies


//1. Register a user

server.post('/register', async (req, res) => {
	const { email, password } = req.body;

	try {
		//1. Check if user exists
		const user = testDB.find(user => user.email === email);
		if(user) throw new Error('User already exist');
		//2. if user doesn't exists, hash the password
		const hashedPassword = await hash(password, 10);
		//3. Insert the user in DB
		testDB.push({
			id: testDB.length,
			email,
			password: hashedPassword
		});
		res.send({ message: 'User Created'});
		console.log(testDB);
	} catch (err) {
		res.send({
			error: `${err.message}`
		})		
	}
})


server.post('/login', async (req, res) => {
	const { email, password } = req.body;
	console.log(testDB);	
	try {
		//1. Find user in the DB
		const user = testDB.find(user => user.email === email);
		if(!user) throw new Error("User doesn't exist.");

		//2. Compare entered & store password
		const valid = await compare(password, user.password);
		if(!valid) throw new Error("Incorrect Password");

		//3. Create Refresh token and Access token 
		const accesstoken = createAccessToken(user.id);
		const refreshtoken = createRefreshToken(user.id);

		//4. Insert refresh token in the DB
		user.refreshtoken = refreshtoken;
		console.log(testDB);
		sendRefreshToken(res, refreshtoken);
		sendAccessToken(res, req, accesstoken);
	} catch(err){
		res.send({
			error: `${err.message}`
		})		
	}
})


//3. Logout a user
server.post('/logout', (_req, res) => {
	res.clearCookie('refreshtoken', { path: '/refresh_token' });
	return res.send({
		message: 'Logged out'	
	})
});


//4. Protected route
server.post('/protected', async (req, res) => {
	try{
		const userId = isAuth(req);
		if(userId!== null){
			res.send({
				data: 'This is protected data.'
			});
		}
	}catch (err){
		res.send({
			error: `${err.message}`
		});
	}	
});


//5. Get a new access token with a refresh token
server.post('/refresh_token', (req, res) => {
	const token = req.cookies.refreshtoken;

	if(!token) return res.send({ accesstoken: ''}); 

	let payload = null;
	try {
		payload = verify(token, process.env.REFRESH_TOKEN_SECRET);
	}catch(err){
		return res.send({ accesstoken: '' });
	}

	const user = testDB.find(user => user.id === payload.userId)

	if(!user) return res.send({ accesstoken: ''});

	if(user.refreshtoken!== token){
		return res.send({ accesstoken: ''});
	}

	const accesstoken = createAccessToken(user.id);
	const refreshtoken = createRefreshToken(user.id);
	user.refreshtoken = refreshtoken;

	sendRefreshToken(res, refreshtoken);
	return res.send({ accesstoken });
})




server.listen(process.env.PORT, () =>
        console.log(`Server listening on port ${process.env.PORT}`)



);
