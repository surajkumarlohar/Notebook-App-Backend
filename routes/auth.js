const express = require("express");
const router = express.Router();
const User = require("../models/User");
const { body, validationResult } = require("express-validator");
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const fetchuser = require('../middleware/fetchuser');

const JWT_SECRET = 'Suraj@home';

// ROUTE 1: Create a User using: POST "/api/auth/createuser". Doesn't require Auth/LogIn
router.post("/createuser",
    [
        body("name", "Enter a valid Name").isLength({ min: 5, max: 18 }),
        body("email", "Enter a valid mail").isEmail(),
        body("password", "Enter a valid Password, Length should between 8 to 16 characters").isLength({ min: 8, max: 16 }),
    ],
    async (req, res) => {
        // console.log(req.body);
        // const user = User(req.body);
        // user.save();

        let success = false;
        // if there are errors, return bad request and the errors
        const errors = validationResult(req);
        if (!errors.isEmpty()) {
        return res.status(400).json({success, errors: errors.array() });
        }
        try {
            // Check whether the user with this email exists already
            let user = await User.findOne({ email: req.body.email });
            if (user) {
                return res.status(400).json({success, error: "Sorry a user with this email already exists" });
            }

            // Hashing to make sucure password by including salt
                const salt = await bcrypt.genSalt(10);
                const secPass = await bcrypt.hash(req.body.password, salt);

            user = await User.create({
                name: req.body.name,
                email: req.body.email,
                password: secPass,
            });
            
            // Providing Tokens to the User
            const data = {
                user:{
                    id:user.id
                }
            }
            const authtoken = jwt.sign(data, JWT_SECRET);
            success= true;
            res.json({success, authtoken});
            //   res.json(user);

        } catch (error) {
            res.status(500).send("Internal Server Error");
            console.error(error.message);
        }
        // .then(user =>{res.json(user)})
        // .catch(err=> {console.log(err)
        // res.json({error: 'Kindly enter a unique value for email', message: err.message})})
        // res.send(req.body);
    }
);

// ROUTE 2: Create a User using: POST "/api/auth/login". Doesn't require Auth/LogIn
router.post("/login",
    [
      body("email", "Enter a valid mail").isEmail(),
      body("password", "Enter a valid Password, Length should between 8 to 16 characters").isLength({ min: 8, max: 16 }).exists(),
    ],
    async (req, res) => {
        let success = false;
        // if there are errors, return bad request and the errors
        const errors = validationResult(req);
        if (!errors.isEmpty()) {
          return res.status(400).json({ errors: errors.array() });
        }
        const {email, password} = req.body;
        try{
            let user = await User.findOne({email: email});
            if(!user){
                return res.status(400).json({error: "Please try to login with correct Credentials / Incorrect Email"}); 
            }
            // Comparing the Password
            const passwordCompare = await bcrypt.compare(password, user.password);
            if(!passwordCompare){
                return res.status(400).json({success, error: "Please try to login with correct Credentials / Incorrect password"});
            }
            const data = {
                user:{
                    id: user.id
                }
            }
            const authtoken = jwt.sign(data, JWT_SECRET);
            success= true;
            res.json({success, authtoken});
        } 
        catch(error){
            res.status(500).send("Internal Server Error");
            console.error(error.message);            
        }
    }
);

// ROUTE 3: Get loggedin User details using: POST "api/auth/getuser". Login required
router.post('/getuser', fetchuser, async (req, res)=>{
    try{
        const userId = req.user.id;
        const user = await User.findById(userId).select("-password");
        res.send(user);
    }
    catch(error){
        res.status(500).send("Internal Server Error");
        console.error(error.message);
    }
});

module.exports = router;
