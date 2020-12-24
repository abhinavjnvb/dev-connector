const express = require('express');
const router = express.Router();
const auth = require('../../middleware/auth');
const { body, validationResult } = require('express-validator');


const Profile = require('../../models/Profile');
const User = require('../../Models/User');
// @route GET api/profile/me 
// @desc  Get current user's profile 
// @access Private

router.get('/me', auth, async(req, res) => {
    try {
        const profile = await Profile
            .findOne({user: req.user.id})
            .populate('user', ['name', 'avatar']);
        if (!profile) {
            return res
                .status(400)
                .json({message: 'There is no profile for this user.'})
        }
        res
            .status(200)
            .json(profile);
    } catch (err) {
        console.error(err.message);
        res
            .status(400)
            .send('Server Error')
    }

});

// @route POST api/profile 
// @desc  Create or update user profile
//  @access Private
router.post('/', [
    auth,
    [
        body("status", "Status is required")
            .not()
            .isEmpty(),
        body("skills", "Skills is required")
            .not()
            .isEmpty()
    ]
], async(req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
        return res
            .status(400)
            .json({
                errors: errors.array()
            });
    }
    const {
        company,
        website,
        location,
        bio,
        status,
        githubusername,
        skills,
        youtube,
        facebook,
        twitter,
        instagram,
        linkedin
    } = req.body;

    // Build profile object
    const profileFields = {};
    profileFields.user = req.user.id;
    if (company) 
        profileFields.company = company;
    if (website) 
        profileFields.website = website;
    if (location) 
        profileFields.location = location;
    if (bio) 
        profileFields.bio = bio;
    if (status) 
        profileFields.status = status;
    if (githubusername) 
        profileFields.githubusername = githubusername;
    if (skills) {
        profileFields.skills = skills
            .split(',')
            .map(skill => skill.trim());
       
    }
    // Build social object
    profileFields.social = {}
    if (youtube) 
        profileFields.social.youtube = youtube;
    if (twitter) 
        profileFields.social.twitter = twitter;
    if (facebook) 
        profileFields.social.facebook = facebook;
    if (linkedin) 
        profileFields.social.linkedin = linkedin;
    if (instagram) 
        profileFields.social.instagram = instagram;
    
    try {
        // Update
        let profile = await Profile.findOne({user: req.user.id})
        if (profile) {
            profile = await Profile.findOneAndUpdate({
                user: req.user.id
            }, {
                $set: profileFields
            }, {new: true})
            return res.json(profile);
        }
        // Create
        profile = new Profile(profileFields);
        await profile.save();
        return res.json(profile);
    } catch (err) {
        console.error(err.message)
        res
            .status(500)
            .send('Server Error')
    }
})

// @route GET api/profile 
// @desc  Get all profiles 
// @access Public
router.get('/', async(req, res) => {
    try {
        const profiles = await Profile
            .find()
            .populate('user', ['name', 'avatar']);
        res.json(profiles);
    } catch (err) {
        console.error(err.message);
        res
            .status(500)
            .send("Server Error");
    }
});

// @route GET api/profile/user/:user_id 
// @desc  Get profile by user ID 
// @access Public
router.get('/user/:user_id', async(req, res) => {
    try {
        const profile = await Profile
            .findOne({user: req.params.user_id})
            .populate('user', ['name', 'avatar']);
        if (!profile) {
            return res
                .status(400)
                .json({msg: "Profile not found"})
        }
        res.json(profile);
    } catch (err) {
        console.error(err.message);
        if (err.kind == 'ObjectId') {
            return res
                .status(400)
                .json({msg: "Profile not found"})
        }
        res
            .status(500)
            .send("Server Error");
    }
});
// @route DELETE api/profile/user
// @desc  Delete profile by user ID
// @access Private
router.delete('/', auth, async(req, res) => {
    try {
        // @todo - remove users posts Remove Profile
        await Profile.findOneAndRemove({user: req.user.id});
        //  Remove User
        await User.findOneAndRemove({_id: req.user.id});

        res.json({message: "User Deleted"});
    } catch (err) {
        console.error(err.message);
        res
            .status(500)
            .send("Server Error");
    }
});
// @route PUT api/profile/experience 
// @desc  Add experience to profile
//  @access Private
router.put('/experience/', [
    auth,
    body("title", "Title is required")
        .not()
        .isEmpty(),
    body("company", "Company is required")
        .not()
        .isEmpty(),
    body("from", "From date is required")
        .not()
        .isEmpty()
], async(req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
        return res
            .status(400)
            .json({
                errors: errors.array()
            });
    }
    const {
        title,
        company,
        location,
        from,
        to,
        current,
        description
    } = req.body;
       const newExp = {
      title,
      company,
      location,
      from,
      to,
      current,
      description
    };

    try {
      const profile = await Profile.findOne({ user: req.user.id });
      profile.experience.unshift(newExp);

      await profile.save();

      res.json(profile);
    } catch (err) {
      console.error(err.message);
      res.status(500).send('Server Error');
    }
});
// @route DELETE api/profile/experience/:exp_id
// @desc  Delete profile experience
// @access Private
router.delete('/experience/:exp_id',auth,async(req,res)=>{
    try{
        const foundProfile = await Profile.findOne({ user: req.user.id });

    foundProfile.experience = foundProfile.experience.filter(
      (exp) => exp._id.toString() !== req.params.exp_id
    );

    await foundProfile.save();
    return res.status(200).json(foundProfile);
    }
    catch(err){
        console.error(err.message);
        res.status(500).send("Server Error")
    }
});
// @route PUT api/profile/education 
// @desc  Add education to profile
//  @access Private
router.put('/education/', [
    auth,
    body("school", "School is required")
        .not()
        .isEmpty(),
    body("degree", "Degree is required")
        .not()
        .isEmpty(),
    body("fieldofstudy", "Field of Study is required")
        .not()
        .isEmpty(),
    body("from", "From date is required")
        .not()
        .isEmpty()
], async(req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
        return res
            .status(400)
            .json({
                errors: errors.array()
            });
    }
    const {
        school,
        degree,
        fieldofstudy,
        from,
        to,
        current,
        description
    } = req.body;
      const newEdu = {
      school,
      degree,
      fieldofstudy,
      from,
      to,
      current,
      description
    };

    try {
      const profile = await Profile.findOne({ user: req.user.id });
      profile.education.unshift(newEdu);

      await profile.save();

      res.json(profile);
    } catch (err) {
      console.error(err.message);
      res.status(500).send('Server Error');
    }
});
// @route DELETE api/profile/education/:edu_id
// @desc  Delete profile education
// @access Private
router.delete('/education/:edu_id',auth,async(req,res)=>{
    try{
        const foundProfile = await Profile.findOne({ user: req.user.id });

    foundProfile.education = foundProfile.education.filter(
      (edu) => edu._id.toString() !== req.params.edu_id
    );

    await foundProfile.save();
    return res.status(200).json(foundProfile);
    }
    catch(err){
        console.error(err.message);
        res.status(500).send("Server Error")
    }
});
module.exports = router;