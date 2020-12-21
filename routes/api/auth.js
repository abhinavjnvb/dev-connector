const express =  require('express');
const router = express.Router();
const auth = require('../../Middleware/auth');
const User = require('../../Models/User');
const bcrypt = require('bcryptjs');
const {body, validationResult} = require('express-validator');
const jwt = require('jsonwebtoken');
const config = require('config');
// @route GET api/auth
// @desc  Test route
// @access Public

router.get('/',auth,async (req,res)=>{
   try{ const user = await User.findById(req.user.id).select('-password');
    res.json(user);
    }catch(err){
       console.error(err.message);
       res.status(400).json({message:"Server error"});
    }

});


// @route POST api/auth
// @desc  Authenticate user and get token
// @access Public

router.post('/',[
    body("email","Please enter a valid email.").isEmail(),
    body("password","Password is required.").exists()
]
    ,async (req,res)=>{
     const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).json({ errors: errors.array() });
  }
  const {email,password} = req.body;
  try{
        let user = await User.findOne({email});

        if(!user) {
         return  res.status(400).json({errors:[{message:"Invalid Credentials"}]})
        }
       const isMatch = await bcrypt.compare(password,user.password);
       if(!isMatch){
        return res.status(400).json({errors:[{message:"Invalid Credentials"}]});
       }

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