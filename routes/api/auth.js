const express =  require('express');
const router = express.Router();
const auth = require('../../Middleware/auth');

// @route GET api/auth
// @desc  Test route
// @access Public

router.get('/',auth,(req,res)=>res.send("Auth Route."));

module.exports = router;