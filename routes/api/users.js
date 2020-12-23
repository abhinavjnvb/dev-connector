const express =  require('express');
const router = express.Router();
const {body, validationResult} = require('express-validator');
const bcrypt = require('bcryptjs');
const User = require('../../Models/User');
const gravatar = require('gravatar');
const jwt = require('jsonwebtoken');
const config = require('config');

// @route POST api/users
// @desc  Test route
// @access Public

router.post('/',[
    body("name","Name is required.").not().isEmpty(),
    body("email","Please enter a valid email.").isEmail(),
    body("password","Please enter a password with 6 or more characters.").isLength({min:6})
]
    ,async (req,res)=>{
     const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).json({ errors: errors.array() });
  }
  const {name,email,password} = req.body;
  try{
        let user = await User.findOne({email});

        if(user) {
         return  res.status(400).json({errors:[{msg : "User already exists."}]})
        }

        const avatar = gravatar.url(email, {
            s: '200',
            r: 'pg',
            d: 'mm'
        });

        user = new User({
            name,
            email,
            avatar,
            password
        })

        const salt = await bcrypt.genSalt(10);
        user.password = await bcrypt.hash(password,salt);
        await user.save();

       //Return jsonwebtoken
        const payLoad = {
          user:{
            id : user.id
          }
        }
        const privateKey=config.get('jwtSecret');
          jwt.sign(payLoad,
          privateKey,
          {expiresIn:360000},
          (error,token)=>{
            if(error)throw error;
            return res.json({token})
          })
  }
  catch(error){
    console.error(error.message);
    res.status(500).send("Server Error.")
  }    
});

module.exports = router;